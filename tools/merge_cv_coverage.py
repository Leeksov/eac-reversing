#!/usr/bin/env python3
"""Build a protected-function coverage matrix from Unicorn run packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("runs", type=Path, nargs="+")
    args = parser.parse_args()

    protected = json.loads(args.map.read_text())
    run_data = [(path.stem.replace(".coverage", ""), json.loads(path.read_text())) for path in args.runs]
    rows = []
    for function in protected["functions"]:
        row = {
            "name": function["name"],
            "wrapper": function["start"],
            "wrapper_hex": function["start_hex"],
            "entries": function["entries"],
            "runs": {},
        }
        for run_name, run in run_data:
            hits = sum(
                hit["count"]
                for hit in run["protected_entry_hits"]
                if hit["wrapper"] == function["start"]
            )
            row["runs"][run_name] = hits
        row["covered"] = any(row["runs"].values())
        rows.append(row)

    output = {
        "schema": "cv-coverage-matrix-v1",
        "runs": [
            {
                "name": name,
                "steps": run["steps"],
                "stop_reason": run["stop_reason"],
                "nodes": len(run["nodes"]),
                "edges": len(run["edges"]),
            }
            for name, run in run_data
        ],
        "statistics": {
            "function_count": len(rows),
            "covered_functions": sum(row["covered"] for row in rows),
            "uncovered_functions": sum(not row["covered"] for row in rows),
        },
        "functions": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output["statistics"], indent=2))
    print("uncovered:")
    for row in rows:
        if not row["covered"]:
            print(f"  {row['wrapper_hex']} {row['name']}")


if __name__ == "__main__":
    main()
