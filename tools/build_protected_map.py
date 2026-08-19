#!/usr/bin/env python3
"""Join the raw CV transition inventory with IDA function ownership."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--ida-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text())
    ida_map = json.loads(args.ida_map.read_text())
    transition_by_source = {
        item["source_hex"].lower(): item for item in inventory["transitions"]
    }
    groups: dict[str, dict[str, object]] = {}
    missing: list[str] = []
    for owner in ida_map["sources"]:
        if owner["fn"] is None:
            continue
        source = owner["source"].lower()
        transition = transition_by_source.get(source)
        if transition is None:
            missing.append(source)
            continue
        function = owner["fn"]
        start = function["start"].lower()
        group = groups.setdefault(
            start,
            {
                "start": int(start, 16),
                "start_hex": start,
                "name": function["name"],
                "size": int(function["size"], 16),
                "entries": [],
            },
        )
        group["entries"].append(
            {
                "source": transition["source"],
                "source_hex": transition["source_hex"],
                "target": transition["target"],
                "target_hex": transition["target_hex"],
                "kind": transition["kind"],
            }
        )

    functions = sorted(groups.values(), key=lambda item: item["start"])
    output = {
        "schema": "cv-protected-map-v1",
        "module": inventory["module"],
        "statistics": {
            "function_count": len(functions),
            "entry_count": sum(len(item["entries"]) for item in functions),
            "multi_entry_functions": sum(len(item["entries"]) > 1 for item in functions),
            "unjoined_sources": len(missing),
        },
        "functions": functions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output["statistics"], indent=2))
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
