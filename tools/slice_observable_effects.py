#!/usr/bin/env python3
"""Build local register-dependency slices for observable VM writes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("effects", type=Path, nargs="+")
    args = parser.parse_args()

    raw = args.module.read_bytes()
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    output_runs = []
    markdown = [
        "# Observable-effect local slices",
        "",
        "These are dynamic, path-specific backward register slices over the 256 instructions preceding each first non-VM/non-stack write. They remove instructions that do not feed the sink's register operands; VM-memory dependencies remain explicit loads/stores and require the CFG package for wider analysis.",
        "",
    ]

    for path in args.effects:
        package = json.loads(path.read_text())
        run_name = path.stem.replace(".effects", "")
        run_slices = []
        markdown.extend([f"## {run_name}", ""])
        for context in package.get("observable_write_contexts", []):
            decoded = []
            for pc in context["recent_pcs"]:
                if not (0 <= pc <= len(raw) - 4):
                    continue
                insn = next(cs.disasm(raw[pc : pc + 4], pc), None)
                if insn is not None:
                    decoded.append(insn)
            if not decoded:
                continue
            # The last instruction is the memory-write sink. Seed liveness
            # with all of its explicit/implicit register reads.
            sink = decoded[-1]
            try:
                sink_reads, _ = sink.regs_access()
            except Exception:
                sink_reads = []
            needed = set(sink_reads)
            selected = [sink]
            for insn in reversed(decoded[:-1]):
                try:
                    reads, writes = insn.regs_access()
                except Exception:
                    continue
                write_set = set(writes)
                if not (write_set & needed):
                    continue
                selected.append(insn)
                needed.difference_update(write_set)
                needed.update(reads)
            selected.reverse()
            item = {
                "pc": context["pc"],
                "region": context["region"],
                "address": context["address"],
                "size": context["size"],
                "first_value": context["first_value"],
                "registers": context["registers"],
                "slice": [
                    {"address": insn.address, "text": f"{insn.mnemonic} {insn.op_str}".rstrip()}
                    for insn in selected
                ],
            }
            run_slices.append(item)
            markdown.append(
                f"### `{context['pc']:#x}` → `{context['region']}+{context['address']:#x}` "
                f"({context['size']} bytes, first `{context['first_value']:#x}`)"
            )
            markdown.extend(["", "```asm"])
            markdown.extend(f"{insn.address:08x}  {insn.mnemonic} {insn.op_str}".rstrip() for insn in selected)
            markdown.extend(["```", ""])
        output_runs.append(
            {
                "run": run_name,
                "entry": package["entry"],
                "stop_reason": package["stop_reason"],
                "boundary_states": package.get("boundary_states", []),
                "slices": run_slices,
            }
        )

    output = {"schema": "cv-observable-slices-v1", "module": str(args.module), "runs": output_runs}
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(output, indent=2) + "\n")
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text("\n".join(markdown) + "\n")
    print(f"runs={len(output_runs)} slices={sum(len(run['slices']) for run in output_runs)}")


if __name__ == "__main__":
    main()
