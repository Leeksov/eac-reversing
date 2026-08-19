#!/usr/bin/env python3
"""Summarize observable effects for every protected wrapper/run pair."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


CV_EXEC_START = 0x6D8000
CV_END = 0x920000


def stub_symbols(path: Path) -> dict[int, str]:
    text = subprocess.run(["otool", "-Iv", str(path)], check=True, text=True, capture_output=True).stdout
    result: dict[int, str] = {}
    enabled = False
    for line in text.splitlines():
        if line.startswith("Indirect symbols for "):
            enabled = "(__TEXT,__stubs)" in line
            continue
        if enabled and (match := re.match(r"0x([0-9a-fA-F]+)\s+\d+\s+(\S+)", line.strip())):
            result[int(match.group(1), 16)] = match.group(2)
    return result


def preferred(address: int, slide: int) -> int:
    return address - slide if slide <= address < slide + 0x940000 else address


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("runs", type=Path, nargs="+")
    args = parser.parse_args()

    protected = json.loads(args.map.read_text())
    stubs = stub_symbols(args.module)
    loaded = []
    for path in args.runs:
        run = json.loads(path.read_text())
        name = path.stem.replace(".coverage", "")
        hit_wrappers = Counter(hit["wrapper"] for hit in run["protected_entry_hits"] for _ in range(hit["count"]))
        loaded.append((name, run, hit_wrappers))

    rows = []
    for function in protected["functions"]:
        observations = []
        for run_name, run, hit_wrappers in loaded:
            if not hit_wrappers[function["start"]]:
                continue
            slide = run["slide"]
            vm_nodes = {
                preferred(item["pc"], slide)
                for item in run["nodes"]
                if CV_EXEC_START <= preferred(item["pc"], slide) < CV_END
            }
            vm_edges = 0
            exits: Counter[int] = Counter()
            for edge in run["edges"]:
                source = preferred(edge["source"], slide)
                target = preferred(edge["target"], slide)
                if CV_EXEC_START <= source < CV_END:
                    vm_edges += 1
                    if not (CV_EXEC_START <= target < CV_END):
                        exits[target] += edge["count"]
            regions: Counter[str] = Counter()
            for site in run.get("write_sites", []):
                pc = preferred(site["pc"], slide)
                if CV_EXEC_START <= pc < CV_END:
                    regions[site["region"]] += site["count"]
            observations.append(
                {
                    "run": run_name,
                    "entry": run["entry"],
                    "steps": run["steps"],
                    "stop_reason": run["stop_reason"],
                    "vm_nodes": len(vm_nodes),
                    "vm_edges": vm_edges,
                    "writes": dict(regions),
                    "imports": run.get("imports", {}),
                    "callbacks": len(run.get("callbacks", [])),
                    "exec_events": len(run.get("exec_events", [])),
                    "native_exits": [
                        {"target": target, "symbol": stubs.get(target), "count": count}
                        for target, count in exits.most_common()
                    ],
                    "evidence": "real-flow" if run_name.startswith(("activation_", "export_e_")) else "synthetic-entry",
                }
            )
        rows.append({**function, "observations": observations})

    output = {
        "schema": "cv-effect-summary-v1",
        "module": str(args.module),
        "functions": rows,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(output, indent=2) + "\n")

    lines = [
        "# Code Virtualizer effect index",
        "",
        "`real-flow` means the wrapper was reached through export `a`/`e`; `synthetic-entry` means its VM entry was invoked offline with writable synthetic arguments. The latter proves and maps the dispatcher path, but does not prove a production input branch.",
        "",
        "| wrapper | VM entry | evidence | VM instructions | termination | observable effects |",
        "|---|---:|---|---:|---|---|",
    ]
    for function in rows:
        entries = ", ".join(item["target_hex"] for item in function["entries"])
        for index, observation in enumerate(function["observations"]):
            effects = []
            if observation["imports"]:
                effects.append("imports: " + ", ".join(sorted(observation["imports"])))
            if observation["writes"]:
                effects.append("writes: " + ", ".join(f"{key}={value}" for key, value in sorted(observation["writes"].items())))
            if observation["callbacks"]:
                effects.append(f"callbacks={observation['callbacks']}")
            if observation["exec_events"]:
                effects.append(f"exec_events={observation['exec_events']}")
            lines.append(
                "| "
                + (f"`{function['name']}` `{function['start_hex']}`" if index == 0 else "↳")
                + f" | `{entries}` | {observation['evidence']} `{observation['run']}` | {observation['vm_nodes']} | "
                + observation["stop_reason"].replace("|", "\\|")
                + " | "
                + ("; ".join(effects) or "none observed")
                + " |"
            )
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text("\n".join(lines) + "\n")
    print(f"functions={len(rows)} observations={sum(len(row['observations']) for row in rows)}")


if __name__ == "__main__":
    main()
