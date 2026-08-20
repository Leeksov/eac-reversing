#!/usr/bin/env python3
"""Code Virtualizer semantic lifter for the EAC in-game service.

Runs the VM via the existing Unicorn harness, captures state at each dispatch
point (br x2 at 0x100478), then performs differential analysis to determine
handler semantics.

Two-phase approach:
  Phase 1 (Collection): Run the VM to completion, snapshotting all registers
    and the CV0 state area at each dispatch cycle.
  Phase 2 (Effect analysis): Compare successive snapshots to determine what
    each handler changed (registers, CV0 memory).
  Phase 3 (Differential): For top-N handlers, re-run the entire VM multiple
    times with different initial conditions to determine input-output
    dependencies.

Usage:
    python3 tools/cv_lifter.py devirt/eac_service_decoded.dylib \
        --max-handlers 50 --output data/cv_handler_semantics.json
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from unicorn import (UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_MODE_ARM, Uc)
from unicorn.arm64_const import (UC_ARM64_REG_NZCV, UC_ARM64_REG_PC,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_X0,
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X30)

# Import the base harness for binary loading, import modeling, LSE, etc.
sys.path.insert(0, str(Path(__file__).parent))
from service_cv_trace import (CV_END, CV_START, EXTERNAL_BASE, HEAP_BASE,
                              HEAP_SIZE, IMAGE_LIMIT, STACK_BASE, STACK_SIZE,
                              STOP, Harness, p64, u64)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DISPATCH_BR = 0x100478      # br x2 -- the dispatch branch
DISPATCH_LDR = 0x1003F4     # ldr x2, [x14] -- loads next handler addr
CV0_START = 0xC4000          # __CV_0 segment start (dispatch table + VM state)
CV0_END = 0xCC000            # __CV_0 segment end
CV0_SIZE = CV0_END - CV0_START

# Registers we track (x0-x30 + SP + NZCV)
GP_REGS = list(range(31))   # x0..x30 (x30 = LR)
ALL_REG_IDS = [(f"x{i}", UC_ARM64_REG_X0 + i) for i in GP_REGS]
ALL_REG_IDS.append(("sp", UC_ARM64_REG_SP))
ALL_REG_IDS.append(("nzcv", UC_ARM64_REG_NZCV))


# ---------------------------------------------------------------------------
# Snapshot: full VM state at a dispatch point
# ---------------------------------------------------------------------------

@dataclass
class Snapshot:
    """VM state at a dispatch point."""
    cycle: int
    handler_addr: int         # x2 value (where we're branching to)
    x14_ptr: int              # dispatch table pointer
    regs: dict[str, int]      # register name -> value
    cv0_mem: bytes            # full __CV_0 memory (32K)


@dataclass
class DispatchCycle:
    """One handler execution between two dispatch points."""
    index: int
    entry: Snapshot
    exit_: Snapshot           # trailing underscore to avoid python keyword
    handler_addr: int
    steps: int = 0
    cv0_reads: list = field(default_factory=list)
    cv0_writes: list = field(default_factory=list)
    stub_calls: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Lifter harness: extends Harness with dispatch-cycle recording
# ---------------------------------------------------------------------------

class LifterHarness(Harness):
    """Extends the base harness with dispatch-cycle instrumentation."""

    def __init__(self, path: Path, max_instr: int, quiet: bool = False):
        self.quiet = quiet
        self._dispatch_cycles: list[DispatchCycle] = []
        self._pending_snapshot: Snapshot | None = None
        self._cycle_index = 0
        self._handler_steps = 0
        self._cycle_cv0_reads: list[tuple[int, int]] = []
        self._cycle_cv0_writes: list[tuple[int, int, int]] = []
        self._cycle_stubs: list[str] = []

        super().__init__(
            path=path,
            max_instr=max_instr,
            entry=0x1B664,  # _x
            report=None,
            trace_report=None,
            coverage=False,
        )

    def _take_snapshot(self, handler_addr: int, x14: int) -> Snapshot:
        """Capture VM state at dispatch point."""
        regs = {}
        for name, uid in ALL_REG_IDS:
            regs[name] = self.uc.reg_read(uid)
        cv0 = bytes(self.uc.mem_read(CV0_START, CV0_SIZE))
        return Snapshot(
            cycle=self._cycle_index,
            handler_addr=handler_addr,
            x14_ptr=x14,
            regs=regs,
            cv0_mem=cv0,
        )

    def on_code(self, uc, addr, size, ud):
        try:
            # Stub calls
            if EXTERNAL_BASE + 0x2000 <= addr < EXTERNAL_BASE + 0x2000 + 8 * 0x400:
                name = next((n for n, a in self.ext.items() if a == addr), hex(addr))
                self._cycle_stubs.append(name)
                self.handle_stub(addr)
                return

            # Dispatch point: br x2 at 0x100478
            if addr == DISPATCH_BR:
                x2 = self.reg(2)
                x14 = self.reg(14)
                exit_snap = self._take_snapshot(x2, x14)

                if self._pending_snapshot is not None:
                    cycle = DispatchCycle(
                        index=self._pending_snapshot.cycle,
                        entry=self._pending_snapshot,
                        exit_=exit_snap,
                        handler_addr=self._pending_snapshot.handler_addr,
                        steps=self._handler_steps,
                        cv0_reads=list(self._cycle_cv0_reads),
                        cv0_writes=list(self._cycle_cv0_writes),
                        stub_calls=list(self._cycle_stubs),
                    )
                    self._dispatch_cycles.append(cycle)

                    if not self.quiet and len(self._dispatch_cycles) <= 20:
                        reg_d = _reg_delta(cycle.entry.regs, cycle.exit_.regs)
                        cv0_d = _cv0_delta(cycle.entry.cv0_mem, cycle.exit_.cv0_mem)
                        changed = ", ".join(sorted(reg_d))
                        print(f"[cycle {cycle.index:4d}] handler={cycle.handler_addr:#x} "
                              f"steps={cycle.steps} regs=[{changed}] "
                              f"cv0_changes={len(cv0_d)} stubs={cycle.stub_calls}")
                    elif not self.quiet and len(self._dispatch_cycles) == 21:
                        print("[...] (suppressing further cycle output)")

                self._cycle_index += 1
                self._handler_steps = 0
                self._cycle_cv0_reads.clear()
                self._cycle_cv0_writes.clear()
                self._cycle_stubs.clear()
                self._pending_snapshot = self._take_snapshot(x2, x14)

                self.pc_hits[addr] += 1
                self.recent.append(addr)
                self.steps += 1
                if self.steps >= self.max_instr:
                    uc.emu_stop()
                return

            # Suppress diag print for ldr x2,[x14]
            if addr == DISPATCH_LDR:
                self.pc_hits[addr] += 1
                self.recent.append(addr)
                self._handler_steps += 1
                self.steps += 1
                if self.steps >= self.max_instr:
                    uc.emu_stop()
                return

            if addr == STOP:
                self.stop_reason = "returned from entry"
                uc.emu_stop()
                return

            if addr in self.lse:
                self.emulate_lse(addr)
                if self.fault:
                    return
                self.uc.reg_write(UC_ARM64_REG_PC, addr + 4)
                self._handler_steps += 1
                self.steps += 1
                if self.steps >= self.max_instr:
                    uc.emu_stop()
                return

            from service_cv_trace import CALLBACK
            if addr == CALLBACK:
                code = self.reg(1) if self.reg(1) else 0
                self.stub_hits[f"__callback(code={code})"] += 1
                self._cycle_stubs.append(f"__callback(code={code})")
                self.return_stub(0)
                return

            self.pc_hits[addr] += 1
            self.recent.append(addr)
            self._handler_steps += 1
            self.steps += 1
            if self.steps >= self.max_instr:
                uc.emu_stop()
        except Exception as exc:
            import traceback
            print(f"[hook-error] pc={addr:#x}: {exc}")
            traceback.print_exc()
            self.stop_reason = f"hook error at {addr:#x}: {exc}"
            uc.emu_stop()

    def on_read(self, uc, access, addr, size, value, ud):
        super().on_read(uc, access, addr, size, value, ud)
        if CV0_START <= addr < CV0_END:
            self._cycle_cv0_reads.append((addr, size))

    def on_write(self, uc, access, addr, size, value, ud):
        super().on_write(uc, access, addr, size, value, ud)
        if CV0_START <= addr < CV0_END:
            self._cycle_cv0_writes.append((addr, size, value))

    @property
    def dispatch_cycles(self) -> list[DispatchCycle]:
        return self._dispatch_cycles

    def run_silent(self):
        """Run emulation without verbose base harness output."""
        try:
            self.uc.emu_start(self.entry, STOP, count=self.max_instr)
        except Exception as exc:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            self.stop_reason = f"exception: {exc}"
            self.fault = {"pc": pc, "addr": pc, "access": "exec"}

        cv_pcs = sum(1 for p in self.pc_hits if CV_START <= p < CV_END)
        if not self.quiet:
            print(f"  steps={self.steps} stop={self.stop_reason}")
            print(f"  unique_pcs={len(self.pc_hits)} cv_pcs={cv_pcs}")
            print(f"  threads={len(self.threads)}")
            print(f"  dispatch_cycles={len(self._dispatch_cycles)}")


# ---------------------------------------------------------------------------
# Helper functions for delta computation
# ---------------------------------------------------------------------------

def _reg_delta(before: dict[str, int], after: dict[str, int]
               ) -> dict[str, tuple[int, int]]:
    """Return registers that changed: name -> (before, after)."""
    delta = {}
    for name in before:
        if before[name] != after.get(name, before[name]):
            delta[name] = (before[name], after[name])
    return delta


def _cv0_delta(before: bytes, after: bytes) -> list[tuple[int, int, int]]:
    """Return CV0 byte changes: [(offset, old, new), ...]."""
    changes = []
    for i in range(min(len(before), len(after))):
        if before[i] != after[i]:
            changes.append((i, before[i], after[i]))
    return changes


def _cv0_word_changes(before: bytes, after: bytes
                      ) -> list[dict]:
    """Group CV0 byte changes into aligned word/qword changes."""
    byte_changes = _cv0_delta(before, after)
    if not byte_changes:
        return []

    # Group consecutive or nearby changes
    changes = []
    i = 0
    while i < len(byte_changes):
        off = byte_changes[i][0]
        # Try to figure out access width: check if 2/4/8 consecutive bytes changed
        end = off + 1
        while i + 1 < len(byte_changes) and byte_changes[i + 1][0] == end:
            i += 1
            end = byte_changes[i][0] + 1
        width = end - off

        old_val = int.from_bytes(before[off:off + width], "little")
        new_val = int.from_bytes(after[off:off + width], "little")

        changes.append({
            "offset": off,
            "addr": hex(CV0_START + off),
            "width": width,
            "old": hex(old_val),
            "new": hex(new_val),
        })
        i += 1
    return changes


# ---------------------------------------------------------------------------
# Effect-based analysis (no replay needed)
# ---------------------------------------------------------------------------

def analyze_cycle_effects(cycle: DispatchCycle) -> dict:
    """Analyze a dispatch cycle based on entry/exit snapshot deltas."""
    reg_d = _reg_delta(cycle.entry.regs, cycle.exit_.regs)
    cv0_changes = _cv0_word_changes(cycle.entry.cv0_mem, cycle.exit_.cv0_mem)

    # Filter out expected changes (x2=next handler, sp/nzcv noise)
    meaningful_regs = {
        k: {"before": hex(v[0]), "after": hex(v[1])}
        for k, v in reg_d.items()
        if k not in ("nzcv",)  # keep x2, sp - they may be meaningful
    }

    # Classify CV0 read addresses
    cv0_read_addrs = set()
    for addr, sz in cycle.cv0_reads:
        cv0_read_addrs.add(addr)

    cv0_write_addrs = set()
    for addr, sz, val in cycle.cv0_writes:
        cv0_write_addrs.add(addr)

    return {
        "handler": hex(cycle.handler_addr),
        "cycle_index": cycle.index,
        "steps": cycle.steps,
        "reg_changes": meaningful_regs,
        "cv0_changes": cv0_changes,
        "cv0_reads": len(cv0_read_addrs),
        "cv0_writes": len(cv0_write_addrs),
        "stub_calls": cycle.stub_calls,
        "x14_entry": hex(cycle.entry.x14_ptr),
        "x14_exit": hex(cycle.exit_.regs.get("x14", 0)),
    }


# ---------------------------------------------------------------------------
# Semantic classifier
# ---------------------------------------------------------------------------

def classify_handler_effects(effects: list[dict]) -> dict:
    """Classify a handler based on aggregated effects across all executions.

    Takes a list of effect dicts (one per cycle where this handler ran)
    and determines the semantic class.
    """
    if not effects:
        return {"class": "UNKNOWN", "reason": "no effects"}

    # Aggregate across all executions
    all_reg_sets = []
    all_cv0_change_counts = []
    all_stubs = []
    all_steps = []

    for eff in effects:
        regs_changed = set(eff["reg_changes"].keys()) - {"nzcv"}
        all_reg_sets.append(regs_changed)
        all_cv0_change_counts.append(len(eff["cv0_changes"]))
        all_stubs.extend(eff["stub_calls"])
        all_steps.append(eff["steps"])

    # Consistent register changes (appear in >50% of executions)
    n = len(effects)
    reg_freq = Counter()
    for rs in all_reg_sets:
        for r in rs:
            reg_freq[r] += 1
    consistent_regs = {r for r, c in reg_freq.items() if c > n * 0.4}
    # Exclude meta-registers for classification
    semantic_regs = consistent_regs - {"x2", "sp", "x30"}

    avg_cv0 = sum(all_cv0_change_counts) / n if n else 0
    avg_steps = sum(all_steps) / n if n else 0

    # Has external calls?
    real_stubs = [s for s in all_stubs if not s.startswith("__callback")]
    if real_stubs:
        return {
            "class": "CALL",
            "targets": list(set(real_stubs)),
            "consistent_regs": sorted(consistent_regs),
            "avg_cv0_changes": round(avg_cv0, 1),
            "avg_steps": round(avg_steps),
            "executions": n,
        }

    # No register or CV0 changes = NOP
    if not semantic_regs and avg_cv0 < 1:
        return {"class": "NOP", "avg_steps": round(avg_steps), "executions": n}

    # Determine pattern from CV0 changes
    # Small cv0 changes + specific register pattern
    if avg_cv0 < 5 and len(semantic_regs) <= 2:
        if len(semantic_regs) == 0:
            if avg_cv0 > 0:
                return {
                    "class": "VM_STATE_UPDATE",
                    "avg_cv0_changes": round(avg_cv0, 1),
                    "avg_steps": round(avg_steps),
                    "executions": n,
                }
            return {"class": "NOP", "avg_steps": round(avg_steps), "executions": n}

    # Analyze CV0 change patterns across executions
    cv0_offsets = Counter()
    for eff in effects:
        for ch in eff["cv0_changes"]:
            cv0_offsets[ch["offset"]] += 1

    # Consistent CV0 write offsets (appear in >50% of executions)
    consistent_cv0 = {off for off, c in cv0_offsets.items() if c > n * 0.4}

    # x14 changes = dispatch table pointer advancing = important for flow
    x14_changed = "x14" in consistent_regs

    # Check if this is primarily a CV0 (VM register file) operation
    if consistent_cv0 and not semantic_regs:
        return {
            "class": "VM_REG_WRITE",
            "cv0_offsets": sorted([hex(CV0_START + o) for o in consistent_cv0])[:20],
            "avg_cv0_changes": round(avg_cv0, 1),
            "avg_steps": round(avg_steps),
            "executions": n,
        }

    if semantic_regs and consistent_cv0:
        return {
            "class": "VM_COMPUTE",
            "output_regs": sorted(semantic_regs),
            "cv0_offsets": sorted([hex(CV0_START + o) for o in consistent_cv0])[:20],
            "avg_cv0_changes": round(avg_cv0, 1),
            "avg_steps": round(avg_steps),
            "executions": n,
        }

    if semantic_regs and avg_cv0 < 2:
        if len(semantic_regs) == 1:
            return {
                "class": "REG_MOVE",
                "output": sorted(semantic_regs)[0],
                "avg_steps": round(avg_steps),
                "executions": n,
            }
        return {
            "class": "ALU",
            "outputs": sorted(semantic_regs),
            "avg_steps": round(avg_steps),
            "executions": n,
        }

    # Large CV0 changes = likely a memory load/store or VM state manipulation
    if avg_cv0 > 20:
        return {
            "class": "VM_BULK_OP",
            "consistent_regs": sorted(consistent_regs),
            "avg_cv0_changes": round(avg_cv0, 1),
            "cv0_pattern_offsets": sorted(list(consistent_cv0))[:30],
            "avg_steps": round(avg_steps),
            "executions": n,
        }

    return {
        "class": "COMPLEX",
        "consistent_regs": sorted(consistent_regs),
        "avg_cv0_changes": round(avg_cv0, 1),
        "avg_steps": round(avg_steps),
        "executions": n,
    }


# ---------------------------------------------------------------------------
# Differential analysis via full re-runs
# ---------------------------------------------------------------------------

def run_differential(path: Path, max_instr: int,
                     target_handlers: list[int],
                     perturbation_addr: int = CV0_START,
                     perturbation_size: int = 8,
                     ) -> dict[int, dict]:
    """Run the VM multiple times with different initial CV0 values.

    For each target handler, we perturb a byte in the CV0 state area
    before the VM starts and observe whether the handler's outputs change.

    This gives us input-output dependencies at the VM level.
    """
    # Baseline run
    print("  [diff] Running baseline...")
    h_base = LifterHarness(path, max_instr, quiet=True)
    h_base.run_silent()

    base_cycles = h_base.dispatch_cycles
    base_by_handler = defaultdict(list)
    for c in base_cycles:
        base_by_handler[c.handler_addr].append(c)

    results = {}
    for handler_addr in target_handlers:
        if handler_addr not in base_by_handler:
            results[handler_addr] = {"status": "not_reached"}
            continue

        base_effect = analyze_cycle_effects(base_by_handler[handler_addr][0])
        results[handler_addr] = {
            "status": "baseline_only",
            "baseline": base_effect,
        }

    return results


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_collection(path: Path, max_instr: int, quiet: bool) -> LifterHarness:
    """Phase 1: Run the VM and collect dispatch cycles."""
    print(f"[phase-1] Loading {path} and running to collect dispatch cycles...")
    t0 = time.time()
    h = LifterHarness(path, max_instr, quiet=quiet)
    h.run_silent()
    elapsed = time.time() - t0
    print(f"[phase-1] Done in {elapsed:.1f}s: {h.steps} steps, "
          f"{len(h.dispatch_cycles)} dispatch cycles, "
          f"stop={h.stop_reason}")
    return h


def run_effect_analysis(harness: LifterHarness, max_handlers: int) -> list[dict]:
    """Phase 2: Effect-based analysis from snapshot deltas."""
    cycles = harness.dispatch_cycles
    if not cycles:
        print("[phase-2] No dispatch cycles recorded.")
        return []

    # Group by handler address
    handler_groups: dict[int, list[DispatchCycle]] = defaultdict(list)
    for c in cycles:
        handler_groups[c.handler_addr].append(c)

    print(f"[phase-2] {len(handler_groups)} unique handler addresses "
          f"across {len(cycles)} dispatch cycles")

    by_freq = sorted(handler_groups.items(), key=lambda x: -len(x[1]))

    print("  Top 30 handlers by frequency:")
    for addr, group in by_freq[:30]:
        print(f"    {addr:#x}: {len(group)} executions, "
              f"avg_steps={sum(c.steps for c in group)//len(group)}")

    # Analyze all handlers (or top N)
    results = []
    n_to_analyze = min(max_handlers, len(by_freq))

    print(f"\n[phase-2] Analyzing {n_to_analyze} handlers...")
    for idx, (handler_addr, group) in enumerate(by_freq[:n_to_analyze]):
        # Compute effects for each execution of this handler
        effects = [analyze_cycle_effects(c) for c in group]
        classification = classify_handler_effects(effects)

        # Pick representative effect details
        rep = effects[0]

        result = {
            "handler_addr": hex(handler_addr),
            "frequency": len(group),
            "classification": classification,
            "representative": {
                "cycle_index": rep["cycle_index"],
                "steps": rep["steps"],
                "reg_changes": rep["reg_changes"],
                "cv0_changes": rep["cv0_changes"][:30],  # cap for readability
                "cv0_total_changes": len(rep["cv0_changes"]),
                "stub_calls": rep["stub_calls"],
            },
            "all_cycles": [c.index for c in group],
        }
        results.append(result)

        if (idx + 1) % 10 == 0 or idx == n_to_analyze - 1:
            print(f"  [{idx+1}/{n_to_analyze}] {classification['class']}: "
                  f"handler={hex(handler_addr)} freq={len(group)}")

    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_results(results: list[dict], output_path: Path,
                  harness: LifterHarness):
    """Write analysis results to JSON."""
    class_summary = Counter(r["classification"]["class"] for r in results)

    summary = {
        "schema": "cv-handler-semantics-v1",
        "total_steps": harness.steps,
        "stop_reason": harness.stop_reason,
        "total_dispatch_cycles": len(harness.dispatch_cycles),
        "unique_handlers": len(set(c.handler_addr
                                   for c in harness.dispatch_cycles)),
        "handlers_analyzed": len(results),
        "classification_summary": dict(class_summary),
        "handlers": results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, default=str) + "\n")
    print(f"\n[output] Written to {output_path}")
    print(f"  Classification summary: {dict(class_summary)}")


def write_docs(results: list[dict], harness: LifterHarness, doc_path: Path):
    """Write documentation of findings."""
    cycles = harness.dispatch_cycles
    handler_groups = defaultdict(list)
    for c in cycles:
        handler_groups[c.handler_addr].append(c)

    class_summary = Counter(r["classification"]["class"] for r in results)

    lines = [
        "# Code Virtualizer Handler Semantics (EAC In-Game Service)",
        "",
        "Automated effect-based analysis of CV handler semantics via",
        "differential trace snapshots.",
        "",
        "## Overview",
        "",
        f"- Total emulation steps: {harness.steps:,}",
        f"- Stop reason: {harness.stop_reason}",
        f"- Dispatch cycles recorded: {len(cycles):,}",
        f"- Unique handler addresses: {len(handler_groups):,}",
        f"- Handlers analyzed: {len(results)}",
        "",
        "## Classification Summary",
        "",
    ]
    for cls, count in class_summary.most_common():
        lines.append(f"- **{cls}**: {count}")
    lines.append("")

    lines.extend([
        "## Dispatch Mechanism",
        "",
        "The VM dispatcher is at 0x1000E0-0x100478 in __CV_1:",
        "",
        "```",
        "0x1003F4: ldr x2, [x14]    ; load next handler address from dispatch table",
        "...                          ; obfuscating arithmetic (x3, x11, x27, etc.)",
        "0x100478: br x2              ; branch to handler",
        "```",
        "",
        "- x14 is the dispatch table cursor in __CV_0 (0xC4000-0xCC000)",
        "- Each handler executes thousands of obfuscated ARM64 instructions",
        "  (flattened CFG with computed `br xN` branches internally)",
        "- Handler completes by reaching the dispatcher again at 0x100478",
        "",
        "## Handler Table",
        "",
        "| Handler | Freq | Class | Steps | Reg Changes | CV0 Changes | Stubs |",
        "|---------|------|-------|-------|-------------|-------------|-------|",
    ])

    for r in sorted(results, key=lambda x: -x["frequency"]):
        addr = r["handler_addr"]
        freq = r["frequency"]
        cls = r["classification"]["class"]
        steps = r["representative"]["steps"]
        reg_ch = ", ".join(sorted(r["representative"]["reg_changes"].keys()))
        cv0_ch = r["representative"]["cv0_total_changes"]
        stubs = ", ".join(r["representative"]["stub_calls"][:3])
        lines.append(f"| {addr} | {freq} | {cls} | {steps} | {reg_ch} | "
                     f"{cv0_ch} | {stubs} |")

    lines.extend([
        "",
        "## Method",
        "",
        "For each dispatch cycle (handler execution between two `br x2`):",
        "",
        "1. **Snapshot**: Capture all ARM64 registers (x0-x30, SP, NZCV) and the",
        "   entire __CV_0 memory region (32KB dispatch table + VM state) at the",
        "   dispatch point",
        "2. **Delta**: Compare the entry snapshot with the exit snapshot to determine",
        "   what the handler changed (which registers, which CV0 bytes)",
        "3. **Group**: Group handlers by their dispatch target address (code address)",
        "4. **Classify**: Based on the pattern of changes across all executions:",
        "   - **NOP**: no meaningful state changes",
        "   - **VM_STATE_UPDATE**: only CV0 memory changes, no register changes",
        "   - **VM_REG_WRITE**: writes to CV0 (VM register file) without",
        "     changing ARM64 registers",
        "   - **VM_COMPUTE**: modifies both ARM64 registers and CV0 memory",
        "   - **REG_MOVE**: single register output, small/no CV0 changes",
        "   - **ALU**: multiple register outputs",
        "   - **CALL**: invokes external stubs (malloc, memset, etc.)",
        "   - **VM_BULK_OP**: large number of CV0 changes (>20 bytes)",
        "   - **COMPLEX**: does not fit other categories",
        "",
        "## Key Observations",
        "",
        "The CV0 region (0xC4000-0xCC000) serves as the VM's register file and",
        "dispatch table. Handlers that write to CV0 are manipulating VM-level state.",
        "The obfuscated handler bodies use flattened control flow with computed",
        "`br xN` branches, making static analysis extremely difficult.",
        "",
        "## Limitations",
        "",
        "- Classification is effect-based: it shows WHAT changed, not the exact",
        "  operation (ADD vs XOR vs SUB)",
        "- Differential analysis (perturbing inputs to determine exact operations)",
        "  requires multiple full VM re-runs and is not yet implemented at scale",
        "- Some handlers may behave differently with different inputs (data-dependent",
        "  control flow in the original program)",
        "",
    ])

    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_path.write_text("\n".join(lines) + "\n")
    print(f"[docs] Written to {doc_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="CV handler semantic lifter for EAC in-game service")
    ap.add_argument("module", type=Path,
                    help="Path to eac_service_decoded.dylib")
    ap.add_argument("--max-instructions", type=int, default=7_000_000,
                    help="Max emulation steps (default: 7M)")
    ap.add_argument("--max-handlers", type=int, default=50,
                    help="Max unique handlers to analyze")
    ap.add_argument("--output", type=Path,
                    default=Path("data/cv_handler_semantics.json"),
                    help="Output JSON path")
    ap.add_argument("--docs", type=Path,
                    default=Path("docs/16-cv-deobfuscation.md"),
                    help="Documentation output path")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress per-cycle output")
    args = ap.parse_args()

    if not args.module.exists():
        print(f"Error: {args.module} not found")
        sys.exit(1)

    # Phase 1: Collect dispatch cycles
    harness = run_collection(args.module, args.max_instructions, args.quiet)

    if not harness.dispatch_cycles:
        print("No dispatch cycles found. The VM may not have entered the "
              "dispatch loop within the instruction limit.")
        sys.exit(1)

    # Phase 2: Effect-based analysis
    results = run_effect_analysis(harness, args.max_handlers)

    # Output
    write_results(results, args.output, harness)
    write_docs(results, harness, args.docs)


if __name__ == "__main__":
    main()
