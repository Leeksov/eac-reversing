#!/usr/bin/env python3
"""Merge offline Unicorn coverage into an IDA-oriented dynamic CV graph."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


CV_EXEC_START = 0x6D8000
CV_END = 0x920000


def preferred(address: int, slide: int) -> int:
    return address - slide if slide <= address < slide + 0x940000 else address


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("runs", type=Path, nargs="+")
    args = parser.parse_args()

    protected = json.loads(args.map.read_text())
    run_packages = [(path.stem.replace(".coverage", ""), json.loads(path.read_text())) for path in args.runs]
    node_hits: Counter[int] = Counter()
    edge_hits: Counter[tuple[int, int]] = Counter()
    edge_runs: dict[tuple[int, int], set[str]] = defaultdict(set)
    node_runs: dict[int, set[str]] = defaultdict(set)
    write_sites: Counter[tuple[int, str, int]] = Counter()

    for run_name, run in run_packages:
        slide = run["slide"]
        for item in run["nodes"]:
            pc = preferred(item["pc"], slide)
            if CV_EXEC_START <= pc < CV_END:
                node_hits[pc] += item["count"]
                node_runs[pc].add(run_name)
        for item in run["edges"]:
            source = preferred(item["source"], slide)
            target = preferred(item["target"], slide)
            if CV_EXEC_START <= source < CV_END:
                edge_hits[(source, target)] += item["count"]
                edge_runs[(source, target)].add(run_name)
        for item in run.get("write_sites", []):
            pc = preferred(item["pc"], slide)
            if CV_EXEC_START <= pc < CV_END:
                write_sites[(pc, item["region"], item["size"])] += item["count"]

    nodes = set(node_hits)
    outgoing: dict[int, set[int]] = defaultdict(set)
    incoming: dict[int, set[int]] = defaultdict(set)
    for source, target in edge_hits:
        outgoing[source].add(target)
        if target in nodes:
            incoming[target].add(source)

    entry_targets = {
        entry["target"]
        for function in protected["functions"]
        for entry in function["entries"]
    }
    leaders = {pc for pc in entry_targets if pc in nodes}
    for pc in nodes:
        predecessors = incoming.get(pc, set())
        if len(predecessors) != 1 or any(source + 4 != pc for source in predecessors):
            leaders.add(pc)
        for target in outgoing.get(pc, set()):
            if target in nodes and (target != pc + 4 or len(outgoing[pc]) != 1):
                leaders.add(target)

    # Cover disconnected sequential islands too.
    for pc in sorted(nodes):
        if pc - 4 not in nodes:
            leaders.add(pc)

    block_for_pc: dict[int, int] = {}
    block_nodes: dict[int, list[int]] = {}
    for leader in sorted(leaders):
        if leader in block_for_pc or leader not in nodes:
            continue
        members = []
        pc = leader
        while pc in nodes and pc not in block_for_pc:
            members.append(pc)
            block_for_pc[pc] = leader
            successors = outgoing.get(pc, set())
            if len(successors) != 1:
                break
            successor = next(iter(successors))
            if successor != pc + 4 or successor in leaders:
                break
            pc = successor
        block_nodes[leader] = members
    for pc in sorted(nodes):
        if pc not in block_for_pc:
            block_for_pc[pc] = pc
            block_nodes[pc] = [pc]

    raw = args.module.read_bytes()
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    blocks = []
    for start, members in sorted(block_nodes.items()):
        instructions = []
        for pc in members:
            word = raw[pc : pc + 4]
            decoded = next(cs.disasm(word, pc), None)
            instructions.append(
                {
                    "address": pc,
                    "bytes": word.hex(),
                    "text": f"{decoded.mnemonic} {decoded.op_str}".rstrip() if decoded else ".word 0x" + word[::-1].hex(),
                    "count": node_hits[pc],
                }
            )
        blocks.append(
            {
                "start": start,
                "end": members[-1] + 4,
                "instruction_count": len(members),
                "execution_count": sum(node_hits[pc] for pc in members),
                "runs": sorted(set().union(*(node_runs[pc] for pc in members))),
                "instructions": instructions,
            }
        )

    block_edges: Counter[tuple[int, int | None, int]] = Counter()
    block_edge_runs: dict[tuple[int, int | None, int], set[str]] = defaultdict(set)
    for (source, target), count in edge_hits.items():
        source_block = block_for_pc[source]
        target_block = block_for_pc.get(target)
        # Keep the exact external target as the third tuple element.
        key = (source_block, target_block, target)
        if target_block != source_block:
            block_edges[key] += count
            block_edge_runs[key].update(edge_runs[(source, target)])

    entries = []
    for function in protected["functions"]:
        for item in function["entries"]:
            entries.append(
                {
                    "name": function["name"],
                    "wrapper": function["start"],
                    "source": item["source"],
                    "target": item["target"],
                    "block": block_for_pc.get(item["target"]),
                    "covered": item["target"] in nodes,
                }
            )

    output = {
        "schema": "cv-dynamic-cfg-v1",
        "module": str(args.module),
        "cv_range": {"start": CV_EXEC_START, "end": CV_END},
        "statistics": {
            "runs": len(run_packages),
            "entries": len(entries),
            "covered_entries": sum(item["covered"] for item in entries),
            "instructions": len(nodes),
            "blocks": len(blocks),
            "edges": len(block_edges),
        },
        "runs": [
            {
                "name": name,
                "entry": run["entry"],
                "steps": run["steps"],
                "stop_reason": run["stop_reason"],
            }
            for name, run in run_packages
        ],
        "entries": entries,
        "blocks": blocks,
        "edges": [
            {
                "source_block": source_block,
                "target_block": target_block,
                "target": target,
                "count": count,
                "runs": sorted(block_edge_runs[(source_block, target_block, target)]),
            }
            for (source_block, target_block, target), count in sorted(block_edges.items())
        ],
        "write_sites": [
            {"pc": pc, "region": region, "size": size, "count": count}
            for (pc, region, size), count in sorted(write_sites.items())
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output) + "\n")
    print(json.dumps(output["statistics"], indent=2))


if __name__ == "__main__":
    main()
