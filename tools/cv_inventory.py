#!/usr/bin/env python3
"""Inventory native wrappers that transfer control into Code Virtualizer.

The output is intentionally IDA-friendly JSON.  A later IDAPython pass adds
the containing function bounds and names from the existing IDB without having
to rediscover functions from the stripped Mach-O.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_IMM


CV_DATA_START = 0x6D0000
CV_EXEC_START = 0x6D8000
CV_END = 0x920000


def parse_segments(data: bytes) -> list[dict[str, int | str]]:
    _, _, _, _, command_count, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    offset = 32
    segments: list[dict[str, int | str]] = []
    for _ in range(command_count):
        command, command_size = struct.unpack_from("<II", data, offset)
        if command == 0x19:  # LC_SEGMENT_64
            name = data[offset + 8 : offset + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, offset + 24
            )
            segments.append(
                {
                    "name": name,
                    "vmaddr": vmaddr,
                    "vmsize": vmsize,
                    "fileoff": fileoff,
                    "filesize": filesize,
                }
            )
        offset += command_size
    return segments


def scan(module: Path) -> dict[str, object]:
    data = module.read_bytes()
    segments = parse_segments(data)
    text = next(segment for segment in segments if segment["name"] == "__TEXT")
    text_start = int(text["vmaddr"])
    text_end = text_start + int(text["filesize"])

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    transitions: list[dict[str, object]] = []
    for address in range(text_start, text_end - 3, 4):
        instruction = next(md.disasm(data[address : address + 4], address), None)
        if not instruction or instruction.mnemonic not in {"b", "bl"}:
            continue
        if not instruction.operands or instruction.operands[0].type != ARM64_OP_IMM:
            continue
        target = instruction.operands[0].imm
        if not CV_EXEC_START <= target < CV_END:
            continue
        transitions.append(
            {
                "source": address,
                "source_hex": f"0x{address:x}",
                "target": target,
                "target_hex": f"0x{target:x}",
                "kind": instruction.mnemonic,
                "wrapper": None,
            }
        )

    target_counts = Counter(item["target"] for item in transitions)
    return {
        "schema": "cv-inventory-v1",
        "module": str(module),
        "segments": segments,
        "cv": {
            "data_start": CV_DATA_START,
            "exec_start": CV_EXEC_START,
            "end": CV_END,
        },
        "statistics": {
            "transition_count": len(transitions),
            "unique_entry_count": len(target_counts),
            "tail_entries": sum(item["kind"] == "b" for item in transitions),
            "call_entries": sum(item["kind"] == "bl" for item in transitions),
            "duplicate_targets": sum(count > 1 for count in target_counts.values()),
        },
        "transitions": transitions,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = scan(args.module)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps(inventory["statistics"], indent=2))
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
