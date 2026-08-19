#!/usr/bin/env python3
"""Consolidate CFG, coverage, effects and slices into a compact DEVIRT IR."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--cfg", type=Path, required=True)
    parser.add_argument("--slices", type=Path, required=True)
    parser.add_argument("--effects-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--readme", type=Path, required=True)
    args = parser.parse_args()

    protected = json.loads(args.map.read_text())
    coverage = json.loads(args.coverage.read_text())
    cfg = json.loads(args.cfg.read_text())
    slices = json.loads(args.slices.read_text())
    coverage_by_wrapper = {row["wrapper"]: row for row in coverage["functions"]}
    cfg_blocks = {block["start"]: block for block in cfg["blocks"]}
    slices_by_run = {run["run"]: run for run in slices["runs"]}
    effects = {}
    for path in args.effects_dir.glob("*.effects.json"):
        effects[path.stem.replace(".effects", "")] = json.loads(path.read_text())

    functions = []
    for function in protected["functions"]:
        row = coverage_by_wrapper[function["start"]]
        evidence_runs = [name for name, count in row["runs"].items() if count]
        block_ids = sorted(
            block["start"]
            for block in cfg["blocks"]
            if set(block["runs"]) & set(evidence_runs)
        )
        relevant_effects = []
        for run_name, package in effects.items():
            direct_match = run_name == f"direct_{function['start_hex']}"
            chunk_match = function["name"] == "sub_3CFC" and run_name == "direct_0x3c44"
            first_43ec = function["name"] == "sub_43EC" and run_name == "direct_0x435c"
            export_e = function["name"] == "sub_4A04" and run_name == "export_e"
            shared_real = run_name == "activation_parent" and any(name.startswith("activation_parent") for name in evidence_runs)
            if direct_match or chunk_match or first_43ec or export_e or shared_real:
                slice_run = slices_by_run.get(run_name, {})
                relevant_effects.append(
                    {
                        "run": run_name,
                        "evidence": "real-flow" if run_name in {"activation_parent", "export_e"} else "synthetic-entry",
                        "stop_reason": package["stop_reason"],
                        "final_x0": package["final_x0"],
                        "reads": len(package["reads"]),
                        "writes": len(package["writes"]),
                        "boundary_states": len(package["boundary_states"]),
                        "observable_slices": len(slice_run.get("slices", [])),
                    }
                )
        functions.append(
            {
                "name": function["name"],
                "wrapper": function["start"],
                "entries": function["entries"],
                "evidence_runs": evidence_runs,
                "dynamic_block_ids": block_ids,
                "effects": relevant_effects,
            }
        )

    output = {
        "schema": "cv-devirt-ir-v1",
        "module": protected["module"],
        "statistics": {
            "functions": len(functions),
            "entries": sum(len(function["entries"]) for function in functions),
            "covered_entries": cfg["statistics"]["covered_entries"],
            "shared_blocks": len(cfg_blocks),
            "dynamic_edges": cfg["statistics"]["edges"],
            "effect_runs": len(effects),
            "observable_slices": sum(len(run.get("slices", [])) for run in slices["runs"]),
        },
        "artifacts": {
            "protected_map": str(args.map.resolve()),
            "coverage_matrix": str(args.coverage.resolve()),
            "dynamic_cfg": str(args.cfg.resolve()),
            "observable_slices": str(args.slices.resolve()),
            "effects_directory": str(args.effects_dir.resolve()),
        },
        "functions": functions,
    }
    if output["statistics"]["covered_entries"] != output["statistics"]["entries"]:
        raise RuntimeError("DEVIRT package has uncovered VM entries")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")

    lines = [
        "# Offline DEVIRT package for mac_arm64.decoded",
        "",
        "Пакет построен полностью офлайн: Mach-O не загружается в процесс, Rust/EAC не запускаются. В IDB добавлены только аналитические имена, комментарии, цвета и xref.",
        "",
        "## Покрытие",
        "",
        f"- защищённых обёрток: {output['statistics']['functions']}",
        f"- VM-входов: {output['statistics']['covered_entries']}/{output['statistics']['entries']}",
        f"- исполненных ARM64-инструкций VM: {cfg['statistics']['instructions']}",
        f"- динамических блоков: {cfg['statistics']['blocks']}",
        f"- динамических переходов: {cfg['statistics']['edges']}",
        f"- профилей memory effects: {output['statistics']['effect_runs']}",
        f"- локальных backward-slice: {output['statistics']['observable_slices']}",
        "",
        "## Артефакты",
        "",
        "- `devirt_ir.json` — индекс функций, входов, evidence-runs и ссылок на блоки/эффекты.",
        "- `cv_dynamic_cfg.json` — полный объединённый динамический CFG с дизассемблированными инструкциями.",
        "- `cv_observable_slices.json` / `.md` — path-specific slice для записей вне VM/стека.",
        "- `cv_effects.json` / `.md` — сводка наблюдаемых импортов и записей.",
        "- `effects/*.effects.json` — точные чтения, записи и регистры на границах VM.",
        "- `tools/ida_import_devirt.py` — повторяемый импорт в IDA.",
        "",
        "## Как читать IDA",
        "",
        "- `cv_devirt_*` — подтверждённые VM-entry.",
        "- зелёный код — достигнут через activation/export `e`.",
        "- голубой код — достигнут прямым синтетическим вызовом entry.",
        "- розовый код — sink наблюдаемой записи; в комментарии находится локальный backward-slice.",
        "",
        "## Граница достоверности",
        "",
        "Динамический CFG покрывает каждый известный VM-entry, но это не доказательство покрытия всех возможных ветвей для всех значений входных структур. `synthetic-entry` служит для восстановления диспетчерного пути и ABI; production-семантика подтверждается только для `real-flow`. Полного статического удаления opaque predicates без рантайма этот пакет не заявляет.",
    ]
    args.readme.write_text("\n".join(lines) + "\n")
    print(json.dumps(output["statistics"], indent=2))


if __name__ == "__main__":
    main()
