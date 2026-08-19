#!/usr/bin/env python3
"""Extract likely Code Virtualizer opcode fetches from an offline trace.

The protected dispatcher is flattened and uses different native fetch sites.
An opcode fetch is recognized dynamically: an LDRB from the CV bytecode area
is followed by two or more comparisons of the loaded byte against dispatcher
constants.  This intentionally excludes CV key/table reads such as 0x6d0200.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs


CV_BYTECODE_START = 0x8B0000
CV_BYTECODE_END = 0x920000


def parse_immediate(text: str) -> int | None:
    try:
        return int(text.lstrip("#"), 0)
    except ValueError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("effects", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--window", type=int, default=48)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    image = args.module.read_bytes()
    effects = json.loads(args.effects.read_text())
    pcs = json.loads(args.trace.read_text())["pcs"]
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    decoded: dict[int, tuple[str, str]] = {}

    def disasm(pc: int) -> tuple[str, str]:
        if pc not in decoded:
            insn = next(cs.disasm(image[pc : pc + 4], pc), None)
            decoded[pc] = (insn.mnemonic, insn.op_str) if insn else ("", "")
        return decoded[pc]

    results: list[dict[str, object]] = []
    for read in effects.get("cv_byte_reads", []):
        address = int(read["address"])
        if not CV_BYTECODE_START <= address < CV_BYTECODE_END:
            continue
        step = int(read["step"])
        trace_index = step - 1
        if not 0 <= trace_index < len(pcs):
            continue
        pc = int(read["pc"])
        mnemonic, operands = disasm(pc)
        match = re.fullmatch(r"ldrb\s+w(\d+),\s*\[.*\]", f"{mnemonic} {operands}")
        if not match:
            continue
        loaded_reg = f"w{match.group(1)}"
        constants: dict[str, int] = {}
        comparisons: list[dict[str, object]] = []
        dynamic: list[dict[str, object]] = []
        branch_count = 0
        for dynamic_pc in pcs[trace_index + 1 : trace_index + 1 + args.window]:
            dynamic_pc = int(dynamic_pc)
            dyn_mnemonic, dyn_operands = disasm(dynamic_pc)
            dynamic.append(
                {"pc": dynamic_pc, "mnemonic": dyn_mnemonic, "operands": dyn_operands}
            )
            parts = [part.strip() for part in dyn_operands.split(",")]
            if dyn_mnemonic == "mov" and len(parts) == 2 and parts[0].startswith("w"):
                immediate = parse_immediate(parts[1])
                if immediate is not None:
                    constants[parts[0]] = immediate & 0xFF
            elif dyn_mnemonic == "movk" and parts:
                constants.pop(parts[0], None)
            if dyn_mnemonic == "cmp" and len(parts) == 2 and parts[0] == loaded_reg:
                compare_value = parse_immediate(parts[1])
                if compare_value is None:
                    compare_value = constants.get(parts[1])
                comparisons.append(
                    {
                        "pc": dynamic_pc,
                        "rhs": parts[1],
                        "value": compare_value,
                    }
                )
            if dyn_mnemonic.startswith("b."):
                branch_count += 1
        if len(comparisons) < 2 or branch_count < 2:
            continue
        results.append(
            {
                "step": step,
                "fetch_pc": pc,
                "bytecode_address": address,
                "opcode": int(read["value"]),
                "loaded_register": loaded_reg,
                "comparisons": comparisons,
                "dynamic_window": dynamic,
            }
        )

    report = {
        "schema": "cv-opcode-trace-v1",
        "module": str(args.module),
        "effects": str(args.effects),
        "trace": str(args.trace),
        "candidate_count": len(results),
        "events": results,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"candidate_count={len(results)}")
    for event in results:
        compares = ",".join(
            "?" if item["value"] is None else f"{item['value']:#04x}"
            for item in event["comparisons"]
        )
        print(
            f"step={event['step']:6} fetch={event['fetch_pc']:#x} "
            f"vip={event['bytecode_address']:#x} opcode={event['opcode']:#04x} "
            f"chain=[{compares}]"
        )


if __name__ == "__main__":
    main()
