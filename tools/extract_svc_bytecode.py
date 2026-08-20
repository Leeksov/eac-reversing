#!/usr/bin/env python3
"""Extract the opcode-to-handler mapping and bytecode stream for the EAC service VM.

Reads the service binary's dispatch table from __CV_0, correlates with the
dynamic trace to produce:
  - data/svc_opcode_map.json  (table_index -> handler, semantics)
  - stdout summary of the 66-dispatch bytecode program

Usage:
    python3 tools/extract_svc_bytecode.py devirt/eac_service_decoded.dylib \
        --trace /tmp/svc_trace_full.json \
        --report /tmp/svc_report.json \
        --output data/svc_opcode_map.json
"""
from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ---------- constants ----------
# __CV_0 segment: vm=0xC4000  size=0x8000  fo=0xC0000
# __CV_1 segment: vm=0xCC000  size=0x578000  fo=0xC8000
CV0_VM = 0xC4000
CV0_FO = 0xC0000
CV1_VM = 0xCC000
CV1_FO = 0xC8000

# Dispatch table lives at vm 0xC42D0 inside __CV_0
DISP_TABLE_VM = 0xC42D0
DISP_TABLE_ENTRIES = 247

# Dispatch handler code range (in __CV_1)
DISP_HANDLER_START = 0x1000E0
DISP_HANDLER_END   = 0x100478   # inclusive: br x2

# Return-to-dispatch trampoline
DISP_RETURN = 0x11E850          # b #0x1000E0


def va_to_fo(va: int) -> int:
    """Convert a virtual address to file offset for __CV segments."""
    if CV1_VM <= va < CV1_VM + 0x578000:
        return va - 0x4000
    if CV0_VM <= va < CV0_VM + 0x8000:
        return va - 0x4000
    return va  # __TEXT / __DATA use identity mapping


# ---------- dispatch table ----------

def read_dispatch_table(binary: bytes) -> list[tuple[int, int]]:
    """Read 247 dispatch table entries.  Each entry is (handler_ptr_0, handler_ptr_1)."""
    fo = DISP_TABLE_VM - 0x4000
    table = []
    for i in range(DISP_TABLE_ENTRIES):
        off = fo + i * 16
        a0 = struct.unpack_from("<Q", binary, off)[0]
        a1 = struct.unpack_from("<Q", binary, off + 8)[0]
        table.append((a0, a1))
    return table


def resolve_trampoline(binary: bytes, addr: int) -> int | None:
    """Decode the B instruction at *addr* and return its target, or None."""
    if not HAS_CAPSTONE:
        return None
    fo = va_to_fo(addr)
    if fo + 4 > len(binary):
        return None
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    insn = next(md.disasm(bytes(binary[fo:fo+4]), addr), None)
    if insn and insn.mnemonic == "b":
        return int(insn.op_str.lstrip("#"), 0)
    return None


def build_handler_map(binary: bytes, table):
    """For every table slot (index, side), resolve to the actual handler address."""
    handlers = {}
    for i, (a0, a1) in enumerate(table):
        for side, addr in enumerate([a0, a1]):
            target = resolve_trampoline(binary, addr)
            handlers[(i, side)] = {
                "trampoline": addr,
                "handler": target or addr,
            }
    return handlers


# ---------- trace analysis ----------

def find_dispatch_cycles(pcs: list[int]):
    """Identify every entry into the dispatch handler and the trampoline + handler it reaches."""
    entries: list[int] = []
    prev_in = False
    for i, pc in enumerate(pcs):
        cur_in = DISP_HANDLER_START <= pc <= DISP_HANDLER_END
        if cur_in and not prev_in:
            entries.append(i)
        prev_in = cur_in

    cycles = []
    for idx, entry in enumerate(entries):
        tramp = None
        handler = None
        for j in range(entry, min(entry + 500, len(pcs))):
            pc = pcs[j]
            if pc < DISP_HANDLER_START or pc > DISP_HANDLER_END:
                tramp = pc
                handler = pcs[j + 1] if j + 1 < len(pcs) else None
                break
        next_entry = entries[idx + 1] if idx + 1 < len(entries) else len(pcs)
        # Find handler start for size calculation
        h_start_idx = None
        for j in range(entry, min(entry + 500, len(pcs))):
            if pcs[j] < DISP_HANDLER_START or pcs[j] > DISP_HANDLER_END:
                h_start_idx = j
                break
        handler_insn_count = (next_entry - h_start_idx) if h_start_idx else 0
        cycles.append({
            "cycle": idx,
            "trace_entry": entry,
            "trampoline": tramp,
            "handler": handler,
            "handler_insn_count": handler_insn_count,
        })
    return cycles


def map_cycles_to_table(cycles, table):
    """Annotate each cycle with (table_index, slot)."""
    addr_to_slot = {}
    for i, (a0, a1) in enumerate(table):
        addr_to_slot[a0] = (i, 0)
        addr_to_slot[a1] = (i, 1)
    for c in cycles:
        t = c["trampoline"]
        if t in addr_to_slot:
            c["table_index"], c["table_slot"] = addr_to_slot[t]
        else:
            c["table_index"], c["table_slot"] = -1, -1
    return cycles


# ---------- opcode inference ----------

# Known service opcode byte values (from static UXTB+CMP+B.eq/ne scan of __CV_1):
KNOWN_OPCODES = sorted([
    0x02, 0x03, 0x07, 0x0C, 0x0D, 0x11, 0x20, 0x2C,
    0x2E, 0x33, 0x44, 0x6E, 0x83, 0x85, 0x8F, 0x93,
    0xA3, 0xB5, 0xBC, 0xBE, 0xC4, 0xD7, 0xE1, 0xEE,
    0xFA, 0xFE,
])

# Observed table indices from dynamic trace (26 unique):
OBSERVED_INDICES = sorted([
    5, 7, 8, 10, 43, 49, 54, 56, 65, 69, 79, 93,
    109, 130, 134, 136, 151, 169, 185, 192, 200, 207,
    227, 237, 239, 241,
])


def infer_opcode_mapping(cycles, handler_map):
    """Attempt to infer which opcode byte maps to which table index.

    Strategy: match by handler complexity / behaviour fingerprint.
    This is a heuristic -- the definitive mapping requires reversing
    the obfuscated dispatch computation or instrumenting the Unicorn
    harness to capture the raw opcode byte at each dispatch.
    """
    # Compute per-index stats
    idx_stats = {}
    for c in cycles:
        idx = c["table_index"]
        if idx < 0:
            continue
        if idx not in idx_stats:
            idx_stats[idx] = {"count": 0, "sizes": [], "handler": c["handler"]}
        idx_stats[idx]["count"] += 1
        idx_stats[idx]["sizes"].append(c["handler_insn_count"])

    for idx, s in idx_stats.items():
        s["avg_size"] = sum(s["sizes"]) // max(len(s["sizes"]), 1)
        s["min_size"] = min(s["sizes"])
        s["max_size"] = max(s["sizes"])

    # Without the decrypted opcode bytes, we assign symbolic names
    # based on observed behaviour
    mapping = {}
    for rank, idx in enumerate(OBSERVED_INDICES):
        stats = idx_stats.get(idx, {})
        mapping[idx] = {
            "table_index": idx,
            "table_slot_used": None,  # filled below
            "handler_addr": stats.get("handler"),
            "trampoline": None,       # filled below
            "dispatch_count": stats.get("count", 0),
            "avg_insn_count": stats.get("avg_size", 0),
            "opcode_byte": None,      # unknown until dispatch is reversed
            "semantic_hint": "",
        }

    # Fill trampoline and slot from first cycle using each index
    for c in cycles:
        idx = c["table_index"]
        if idx in mapping and mapping[idx]["trampoline"] is None:
            mapping[idx]["trampoline"] = c["trampoline"]
            mapping[idx]["table_slot_used"] = c["table_slot"]

    # Assign semantic hints based on behaviour
    for idx, m in mapping.items():
        avg = m["avg_insn_count"]
        cnt = m["dispatch_count"]
        if avg < 1000:
            m["semantic_hint"] = "lightweight (NOP / VPC-advance / flag-set)"
        elif avg < 20000:
            m["semantic_hint"] = "medium (register move / ALU / load-store)"
        elif avg < 100000:
            m["semantic_hint"] = "moderate (memory op / computed branch)"
        elif avg < 300000:
            m["semantic_hint"] = "heavy (complex computation / native call setup)"
        else:
            m["semantic_hint"] = "very heavy (multi-native-call / init sequence)"

    return mapping


# ---------- bytecode stream ----------

def extract_bytecode_stream(cycles):
    """Extract the sequence of (table_index, slot) as the 'bytecode program'."""
    stream = []
    for c in cycles:
        stream.append({
            "cycle": c["cycle"],
            "table_index": c["table_index"],
            "table_slot": c["table_slot"],
            "handler": c["handler"],
            "insn_count": c["handler_insn_count"],
        })
    return stream


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", type=Path, help="Path to eac_service_decoded.dylib")
    ap.add_argument("--trace", type=Path, default=Path("/tmp/svc_trace_full.json"),
                    help="Full PC trace JSON")
    ap.add_argument("--report", type=Path, default=Path("/tmp/svc_report.json"),
                    help="Harness report JSON")
    ap.add_argument("--output", type=Path, default=Path("data/svc_opcode_map.json"),
                    help="Output opcode map JSON")
    args = ap.parse_args()

    print(f"[*] Loading binary: {args.binary}")
    binary = args.binary.read_bytes()

    print(f"[*] Reading dispatch table at {DISP_TABLE_VM:#x}")
    table = read_dispatch_table(binary)
    print(f"    {len(table)} entries")

    handler_map = build_handler_map(binary, table) if HAS_CAPSTONE else {}

    print(f"[*] Loading trace: {args.trace}")
    trace_data = json.loads(args.trace.read_text())
    pcs = trace_data["pcs"]
    print(f"    {len(pcs)} PCs")

    print(f"[*] Finding dispatch cycles")
    cycles = find_dispatch_cycles(pcs)
    cycles = map_cycles_to_table(cycles, table)
    print(f"    {len(cycles)} dispatch cycles found")

    unique_indices = sorted(set(c["table_index"] for c in cycles if c["table_index"] >= 0))
    print(f"    {len(unique_indices)} unique table indices: {unique_indices}")

    print(f"\n[*] Inferring opcode mapping")
    opcode_map = infer_opcode_mapping(cycles, handler_map)

    print(f"\n[*] Extracting bytecode stream")
    stream = extract_bytecode_stream(cycles)

    # ---------- output ----------
    output = {
        "schema": "svc-opcode-map-v1",
        "binary": str(args.binary),
        "dispatch_table": {
            "vm_addr": hex(DISP_TABLE_VM),
            "entry_count": DISP_TABLE_ENTRIES,
            "entry_size": 16,
            "format": "paired (handler_ptr_slot0, handler_ptr_slot1)",
        },
        "dispatch_handler": {
            "start": hex(DISP_HANDLER_START),
            "end": hex(DISP_HANDLER_END),
            "return_trampoline": hex(DISP_RETURN),
            "key_instructions": {
                "halfword_fetch_1": "0x100168: ldrh w27, [x16]",
                "halfword_fetch_2": "0x1002E8: ldrh w27, [x9]",
                "table_load": "0x1003F4: ldr x2, [x14]",
                "dispatch_branch": "0x100478: br x2",
                "vpc_store": "0x100474: str x26, [x8]  (x8 = x29+0x150)",
            },
            "vpc_state_offset": "0x150",
            "notes": [
                "Opcode bytes are read as halfwords and transformed through",
                "obfuscated arithmetic (ADD/XOR with VM state at [x29+0x114]",
                "and [x29+0x118]) before indexing the dispatch table.",
                "The transformation key is per-build and cannot be statically",
                "recovered without reversing the obfuscation or instrumenting",
                "the harness to capture pre-transform values.",
            ],
        },
        "known_opcode_bytes": [hex(o) for o in KNOWN_OPCODES],
        "observed_table_indices": OBSERVED_INDICES,
        "opcode_handlers": {},
        "bytecode_stream": stream,
        "bytecode_summary": {
            "total_dispatches": len(stream),
            "unique_handlers": len(unique_indices),
            "patterns": [],
        },
    }

    # Fill opcode_handlers
    for idx in sorted(opcode_map.keys()):
        m = opcode_map[idx]
        key = str(idx)
        output["opcode_handlers"][key] = {
            "table_index": m["table_index"],
            "table_slot_used": m["table_slot_used"],
            "handler_addr": hex(m["handler_addr"]) if m["handler_addr"] else None,
            "trampoline_addr": hex(m["trampoline"]) if m["trampoline"] else None,
            "dispatch_count": m["dispatch_count"],
            "avg_insn_count": m["avg_insn_count"],
            "opcode_byte": m["opcode_byte"],
            "semantic_hint": m["semantic_hint"],
        }

    # Detect patterns in the bytecode stream
    idx_stream = [c["table_index"] for c in cycles]
    # Find repeating subsequences
    for length in range(3, 8):
        for start in range(len(idx_stream) - length):
            subseq = idx_stream[start:start + length]
            count = 0
            for i in range(len(idx_stream) - length + 1):
                if idx_stream[i:i + length] == subseq:
                    count += 1
            if count >= 3:
                pattern = {"subsequence": subseq, "length": length,
                           "occurrences": count, "first_at": start}
                if pattern not in output["bytecode_summary"]["patterns"]:
                    # Deduplicate
                    already = False
                    for p in output["bytecode_summary"]["patterns"]:
                        if p["subsequence"] == subseq:
                            already = True
                            break
                    if not already:
                        output["bytecode_summary"]["patterns"].append(pattern)

    # Write output
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(f"\n[*] Opcode map written to {args.output}")

    # ---------- summary ----------
    print(f"\n{'='*72}")
    print(f"BYTECODE STREAM FOR start_service (_x) -- {len(stream)} dispatches")
    print(f"{'='*72}")
    print(f"{'Cycle':>5} {'TblIdx':>6} {'Slot':>4} {'Handler':>10} {'InsnCnt':>8}  Hint")
    print(f"{'-'*5:>5} {'-'*6:>6} {'-'*4:>4} {'-'*10:>10} {'-'*8:>8}  {'-'*30}")
    for s in stream:
        idx = s["table_index"]
        hint = opcode_map.get(idx, {}).get("semantic_hint", "")[:30]
        print(f"{s['cycle']:5d} {idx:6d} {s['table_slot']:4d} "
              f"{s['handler']:#10x} {s['insn_count']:8d}  {hint}")

    # Pattern summary
    if output["bytecode_summary"]["patterns"]:
        print(f"\nRepeating patterns detected:")
        for p in output["bytecode_summary"]["patterns"][:5]:
            print(f"  {p['subsequence']} x{p['occurrences']} (first at cycle {p['first_at']})")

    print(f"\nHandler frequency:")
    freq = Counter(c["table_index"] for c in cycles)
    for idx, count in freq.most_common():
        h = opcode_map.get(idx, {})
        print(f"  idx={idx:3d}  count={count:2d}  "
              f"handler={h.get('handler_addr','?')!s:>10s}  "
              f"avg_insn={h.get('avg_insn_count',0):6d}  "
              f"{h.get('semantic_hint','')[:40]}")


if __name__ == "__main__":
    main()
