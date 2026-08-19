"""Import cv_dynamic_cfg.json into the currently open mac_arm64 IDB.

Run with File -> Script file... in IDA.  Set CV_DEVIRT_CFG to avoid the file
picker.  This script annotates the IDB only; it never patches the input file.
"""

from __future__ import annotations

import json
import os

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_ua
import ida_xref
import idaapi
import idc


DEFAULT_CFG = "/Users/leeksov/Documents/ChatGPT/rustreverse/devirt/cv_dynamic_cfg.json"
DEFAULT_SLICES = "/Users/leeksov/Documents/ChatGPT/rustreverse/devirt/cv_observable_slices.json"


def _append_comment(ea: int, text: str) -> None:
    previous = ida_bytes.get_cmt(ea, False) or ""
    if text in previous:
        return
    ida_bytes.set_cmt(ea, (previous + "\n" + text).strip(), False)


def _safe_name(ea: int, name: str) -> None:
    ida_name.set_name(
        ea,
        name.replace("sub_", "").replace("-", "_")[:100],
        ida_name.SN_NOCHECK | ida_name.SN_NOWARN,
    )


def main() -> None:
    path = os.environ.get("CV_DEVIRT_CFG")
    if not path and os.path.isfile(DEFAULT_CFG):
        path = DEFAULT_CFG
    if not path:
        path = ida_kernwin.ask_file(False, "*.json", "Select cv_dynamic_cfg.json")
    if not path:
        return
    package = json.load(open(path, "r", encoding="utf-8"))
    if package.get("schema") != "cv-dynamic-cfg-v1":
        raise RuntimeError("unsupported DEVIRT CFG schema")

    blocks = {block["start"]: block for block in package["blocks"]}
    real_prefixes = ("activation_parent", "activation_child", "export_e_")
    made_code = 0
    for index, block in enumerate(package["blocks"]):
        real_observed = any(run.startswith(real_prefixes) for run in block["runs"])
        color = 0xD8F5D0 if real_observed else 0xD9E9FF
        for instruction in block["instructions"]:
            ea = instruction["address"]
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                made_code += bool(ida_ua.create_insn(ea))
            idc.set_color(ea, idc.CIC_ITEM, color)
        _append_comment(
            block["start"],
            "[DEVIRT dynamic block] "
            f"insns={block['instruction_count']} executions={block['execution_count']} "
            f"evidence={'real-flow' if real_observed else 'synthetic-entry'} "
            f"runs={','.join(block['runs'])}",
        )
        if index % 250 == 0:
            ida_kernwin.replace_wait_box(
                f"Importing DEVIRT blocks: {index}/{len(package['blocks'])}"
            )

    dynamic_xrefs = 0
    for edge in package["edges"]:
        target_block = edge["target_block"]
        source = blocks[edge["source_block"]]["instructions"][-1]["address"]
        target = target_block if target_block in blocks else edge["target"]
        # Synthetic callback/heap sentinels are outside the Mach-O. Keep them
        # in JSON, but do not create dangling IDB xrefs.
        if not ida_bytes.is_mapped(target):
            continue
        if target == source + 4:
            continue
        if ida_xref.add_cref(source, target, ida_xref.fl_JN):
            dynamic_xrefs += 1
        _append_comment(
            source,
            f"[DEVIRT edge] -> {target:#x} count={edge['count']} "
            f"runs={','.join(edge['runs'])}",
        )

    for entry in package["entries"]:
        suffix = f"{entry['target']:x}"
        _safe_name(entry["target"], f"cv_devirt_{entry['name']}_{suffix}")
        _append_comment(
            entry["source"],
            f"[DEVIRT protected transition] {entry['name']} -> {entry['target']:#x}",
        )
        _append_comment(
            entry["target"],
            f"[DEVIRT VM entry] wrapper={entry['wrapper']:#x} source={entry['source']:#x}",
        )
        function = ida_funcs.get_func(entry["wrapper"])
        if function:
            old = ida_funcs.get_func_cmt(function, False) or ""
            note = f"[DEVIRT] dynamic VM entry {entry['target']:#x}; see cv_dynamic_cfg.json"
            if note not in old:
                ida_funcs.set_func_cmt(function, (old + "\n" + note).strip(), False)

    slice_count = 0
    if os.path.isfile(DEFAULT_SLICES):
        slices = json.load(open(DEFAULT_SLICES, "r", encoding="utf-8"))
        for run in slices.get("runs", []):
            for item in run.get("slices", []):
                lines = [
                    f"[DEVIRT observable write] run={run['run']} "
                    f"target={item['region']}+{item['address']:#x} size={item['size']} "
                    f"first_value={item['first_value']:#x}",
                    "[DEVIRT local backward slice]",
                ]
                lines.extend(
                    f"  {insn['address']:#x}: {insn['text']}" for insn in item["slice"][-24:]
                )
                _append_comment(item["pc"], "\n".join(lines))
                idc.set_color(item["pc"], idc.CIC_ITEM, 0xFFD6F0)
                if item["region"] == "image" and ida_bytes.is_mapped(item["address"]):
                    ida_xref.add_dref(item["pc"], item["address"], ida_xref.dr_W)
                    _append_comment(
                        item["address"],
                        f"[DEVIRT effect target] written at {item['pc']:#x} in {run['run']}",
                    )
                slice_count += 1

    # Do not block on the whole database's auto-analysis queue here. IDA will
    # process the new code/xrefs asynchronously after the script returns.
    ida_kernwin.hide_wait_box()
    ida_kernwin.info(
        "DEVIRT import complete\n\n"
        f"Blocks: {len(package['blocks'])}\n"
        f"Dynamic edges: {dynamic_xrefs}\n"
        f"Observable effect slices: {slice_count}\n"
        f"Newly decoded instructions: {made_code}\n"
        "Green = observed through activation/export e; blue = synthetic entry."
    )


ida_kernwin.show_wait_box("Importing DEVIRT CFG...")
try:
    main()
finally:
    ida_kernwin.hide_wait_box()
