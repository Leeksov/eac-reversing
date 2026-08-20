#!/usr/bin/env python3
"""IR-to-C decompiler backend for Code Virtualizer bytecode.

Takes handler semantics JSON (opcode -> operation mapping) and a bytecode
stream JSON, then produces readable C code with basic block detection,
control flow structuring, and virtual register tracking.

Usage:
    python3 ir_to_c.py handlers.json bytecode.json -o output.c
    python3 ir_to_c.py handlers.json bytecode.json --cfg cfg.dot
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# IR node types
# ---------------------------------------------------------------------------

class IRKind(Enum):
    """Intermediate representation node categories."""
    NOP        = auto()
    MOV        = auto()   # vreg = vreg | imm
    LOAD       = auto()   # vreg = *(type*)addr
    STORE      = auto()   # *(type*)addr = vreg
    ADD        = auto()
    SUB        = auto()
    MUL        = auto()
    DIV        = auto()
    AND        = auto()
    OR         = auto()
    XOR        = auto()
    NOT        = auto()
    SHL        = auto()
    SHR        = auto()
    SAR        = auto()   # arithmetic shift right
    ROL        = auto()
    ROR        = auto()
    CMP        = auto()   # sets flags
    TEST       = auto()   # AND-based flag set
    BRANCH     = auto()   # conditional branch
    JUMP       = auto()   # unconditional jump
    CALL       = auto()   # native call (import/wrapper)
    RET        = auto()
    FLAG_SET   = auto()   # direct flag manipulation
    FLAG_CLEAR = auto()
    PREDICATE  = auto()   # conditional execution gate
    UNKNOWN    = auto()


@dataclass
class IRNode:
    """Single IR instruction derived from one VM bytecode opcode."""
    kind: IRKind
    dst: str | None = None        # destination operand (vreg name, flag, etc.)
    src: list[str] = field(default_factory=list)  # source operands
    width: int = 4                # access width in bytes (1/2/4/8)
    flags_read: list[str] = field(default_factory=list)
    flags_written: list[str] = field(default_factory=list)
    condition: str | None = None  # for branches: "Z", "!Z", "C", etc.
    target_offset: int | None = None  # branch target as bytecode offset
    comment: str = ""             # original opcode info
    raw_operation: str = ""       # from handler semantics
    opcode: str = ""              # hex opcode string
    bytecode_offset: int = 0      # position in bytecode stream

    @property
    def is_terminator(self) -> bool:
        return self.kind in (IRKind.BRANCH, IRKind.JUMP, IRKind.RET)


# ---------------------------------------------------------------------------
# Category -> IRKind mapping
# ---------------------------------------------------------------------------

CATEGORY_MAP: dict[str, IRKind] = {
    "ADD":         IRKind.ADD,
    "SUB":         IRKind.SUB,
    "MUL":         IRKind.MUL,
    "DIV":         IRKind.DIV,
    "AND":         IRKind.AND,
    "OR":          IRKind.OR,
    "XOR":         IRKind.XOR,
    "NOT":         IRKind.NOT,
    "SHL":         IRKind.SHL,
    "SHR":         IRKind.SHR,
    "LSR":         IRKind.SHR,
    "SAR":         IRKind.SAR,
    "ASR":         IRKind.SAR,
    "ROL":         IRKind.ROL,
    "ROR":         IRKind.ROR,
    "MOV":         IRKind.MOV,
    "LOAD":        IRKind.LOAD,
    "STORE":       IRKind.STORE,
    "CMP":         IRKind.CMP,
    "TEST":        IRKind.TEST,
    "BRANCH":      IRKind.BRANCH,
    "JUMP":        IRKind.JUMP,
    "CALL":        IRKind.CALL,
    "NATIVE_CALL": IRKind.CALL,
    "RET":         IRKind.RET,
    "RETURN":      IRKind.RET,
    "NOP":         IRKind.NOP,
    "FLAG_SET":    IRKind.FLAG_SET,
    "FLAG_CLEAR":  IRKind.FLAG_CLEAR,
    "PREDICATE":   IRKind.PREDICATE,
}


# ---------------------------------------------------------------------------
# Handler semantics -> IR lowering
# ---------------------------------------------------------------------------

def parse_vreg(token: str) -> str | None:
    """Extract a normalized vreg name from tokens like 'vreg[3]'."""
    m = re.match(r"vreg\[(\d+)\]", token.strip())
    if m:
        return f"r{m.group(1)}"
    return None


def parse_flag(token: str) -> str | None:
    """Extract flag name from tokens like 'flag_Z'."""
    m = re.match(r"flag_(\w+)", token.strip())
    if m:
        return m.group(1)
    return None


def detect_width_from_operation(operation: str) -> int:
    """Infer access width from cast expressions in the operation string."""
    if "uint8_t" in operation or "int8_t" in operation:
        return 1
    if "uint16_t" in operation or "int16_t" in operation:
        return 2
    if "uint64_t" in operation or "int64_t" in operation:
        return 8
    return 4  # default uint32_t


def detect_condition(handler: dict[str, Any]) -> str | None:
    """Extract branch condition from handler inputs/operation."""
    for inp in handler.get("inputs", []):
        flag = parse_flag(inp)
        if flag:
            return flag
    # Try parsing from operation string
    op = handler.get("operation", "")
    m = re.match(r"if\s*\((!?)flag_(\w+)\)", op)
    if m:
        negate = m.group(1)
        flag = m.group(2)
        return f"!{flag}" if negate else flag
    return None


def lower_handler(handler: dict[str, Any], opcode: str,
                  bytecode_offset: int) -> IRNode:
    """Convert a single handler semantics entry to an IR node."""
    category = handler.get("category", "UNKNOWN").upper()
    kind = CATEGORY_MAP.get(category, IRKind.UNKNOWN)
    operation = handler.get("operation", "")
    inputs = handler.get("inputs", [])
    outputs = handler.get("outputs", [])
    flags = handler.get("flags_affected", [])

    # Destination
    dst = None
    if outputs:
        dst = parse_vreg(outputs[0])
        if dst is None and outputs[0] == "vpc":
            dst = "vpc"
        if dst is None:
            dst = outputs[0]

    # Sources
    src = []
    for inp in inputs:
        v = parse_vreg(inp)
        if v:
            src.append(v)
        elif parse_flag(inp):
            src.append(inp)
        else:
            src.append(inp)

    width = detect_width_from_operation(operation)
    condition = detect_condition(handler) if kind == IRKind.BRANCH else None

    return IRNode(
        kind=kind,
        dst=dst,
        src=src,
        width=width,
        flags_read=[parse_flag(i) or i for i in inputs if parse_flag(i)],
        flags_written=flags,
        condition=condition,
        raw_operation=operation,
        opcode=opcode,
        bytecode_offset=bytecode_offset,
        comment=f"opcode {opcode} ({category})",
    )


# ---------------------------------------------------------------------------
# Bytecode stream -> IR program
# ---------------------------------------------------------------------------

def lift_program(handlers: dict[str, dict[str, Any]],
                 bytecode: list[dict[str, Any]]) -> list[IRNode]:
    """Lift an entire bytecode stream to IR using handler semantics."""
    # Build opcode -> handler lookup (normalize opcode keys)
    handler_by_opcode: dict[str, dict[str, Any]] = {}
    for addr, h in handlers.items():
        opc = h.get("opcode", "")
        if isinstance(opc, str):
            opc = opc.lower()
        else:
            opc = f"0x{opc:02x}"
        handler_by_opcode[opc] = h

    program: list[IRNode] = []
    for insn in bytecode:
        opc = insn.get("opcode", "")
        if isinstance(opc, str):
            opc_norm = opc.lower()
        else:
            opc_norm = f"0x{opc:02x}"

        offset = insn.get("offset", len(program))
        operands = insn.get("operands", [])

        if opc_norm in handler_by_opcode:
            h = handler_by_opcode[opc_norm]
            node = lower_handler(h, opc, offset)
            # Override vreg indices from bytecode operands if present
            node = _patch_operands(node, operands, h)
            program.append(node)
        else:
            program.append(IRNode(
                kind=IRKind.UNKNOWN,
                opcode=opc,
                bytecode_offset=offset,
                comment=f"UNKNOWN opcode {opc}",
                raw_operation=f"/* UNKNOWN opcode {opc} */",
            ))

    return program


def _patch_operands(node: IRNode, operands: list[Any],
                    handler: dict[str, Any]) -> IRNode:
    """Substitute concrete register indices from bytecode operands.

    The bytecode operands list provides the *actual* register indices for
    this instruction.  The handler semantics use abstract indices (e.g.
    vreg[3], vreg[7]) that are placeholders.  We collect the unique abstract
    vregs in definition order (outputs first, then inputs, deduped) and map
    each to the corresponding bytecode operand.
    """
    if not operands:
        return node

    inputs = handler.get("inputs", [])
    outputs = handler.get("outputs", [])

    # Collect unique abstract vreg names in definition order
    seen: set[str] = set()
    ordered_abstract: list[str] = []
    for token in outputs + inputs:
        m = re.match(r"vreg\[(\d+)\]", token)
        if m:
            name = f"r{m.group(1)}"
            if name not in seen:
                seen.add(name)
                ordered_abstract.append(name)

    # Map each abstract name to the concrete operand at the same position
    vreg_map: dict[str, str] = {}
    for i, abstract in enumerate(ordered_abstract):
        if i < len(operands):
            vreg_map[abstract] = f"r{operands[i]}"

    if not vreg_map:
        return node

    if node.dst and node.dst in vreg_map:
        node.dst = vreg_map[node.dst]
    node.src = [vreg_map.get(s, s) for s in node.src]

    # Rebuild raw_operation with substituted registers
    op = node.raw_operation
    for abstract, concrete in vreg_map.items():
        op = op.replace(abstract.replace("r", "vreg[") + "]",
                        concrete.replace("r", "vreg[") + "]")
    node.raw_operation = op

    return node


# ---------------------------------------------------------------------------
# Basic block detection and CFG construction
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    """A maximal sequence of non-branching IR nodes."""
    id: int
    label: str
    nodes: list[IRNode]
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)

    @property
    def start_offset(self) -> int:
        return self.nodes[0].bytecode_offset if self.nodes else -1

    @property
    def is_empty(self) -> bool:
        return len(self.nodes) == 0


def build_cfg(program: list[IRNode]) -> list[BasicBlock]:
    """Split IR program into basic blocks and link them."""
    if not program:
        return []

    # Find block leaders: index 0, targets of branches, instructions after branches
    leaders: set[int] = {0}
    branch_targets: dict[int, int] = {}  # bytecode offset -> program index

    # Build offset -> index map
    offset_to_idx: dict[int, int] = {}
    for i, node in enumerate(program):
        offset_to_idx[node.bytecode_offset] = i

    for i, node in enumerate(program):
        if node.is_terminator:
            if i + 1 < len(program):
                leaders.add(i + 1)
            if node.target_offset is not None and node.target_offset in offset_to_idx:
                target_idx = offset_to_idx[node.target_offset]
                leaders.add(target_idx)
                branch_targets[node.bytecode_offset] = target_idx

    # Build blocks
    sorted_leaders = sorted(leaders)
    blocks: list[BasicBlock] = []
    leader_to_block: dict[int, int] = {}

    for block_id, leader_idx in enumerate(sorted_leaders):
        end_idx = sorted_leaders[block_id + 1] if block_id + 1 < len(sorted_leaders) else len(program)
        nodes = program[leader_idx:end_idx]
        label = f"block_{block_id}"
        bb = BasicBlock(id=block_id, label=label, nodes=nodes)
        blocks.append(bb)
        leader_to_block[leader_idx] = block_id

    # Link successors
    for block_id, bb in enumerate(blocks):
        if not bb.nodes:
            continue
        last = bb.nodes[-1]

        if last.kind == IRKind.JUMP:
            if last.target_offset is not None and last.bytecode_offset in branch_targets:
                target_block = leader_to_block.get(branch_targets[last.bytecode_offset])
                if target_block is not None:
                    bb.successors.append(target_block)
        elif last.kind == IRKind.BRANCH:
            # Fall-through
            if block_id + 1 < len(blocks):
                bb.successors.append(block_id + 1)
            # Taken
            if last.target_offset is not None and last.bytecode_offset in branch_targets:
                target_block = leader_to_block.get(branch_targets[last.bytecode_offset])
                if target_block is not None and target_block not in bb.successors:
                    bb.successors.append(target_block)
        elif last.kind == IRKind.RET:
            pass  # no successors
        else:
            # Fall through to next block
            if block_id + 1 < len(blocks):
                bb.successors.append(block_id + 1)

    # Fill predecessors
    for bb in blocks:
        for succ_id in bb.successors:
            blocks[succ_id].predecessors.append(bb.id)

    return blocks


# ---------------------------------------------------------------------------
# C code emitter
# ---------------------------------------------------------------------------

# Width -> C type
WIDTH_TYPE = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}

# Known native call stubs (from cv-wrappers classification)
NATIVE_STUBS: dict[str, str] = {
    "0x20": "native_mutex_init",
    "0x21": "native_mutex_lock",
    "0x22": "native_mutex_unlock",
    "0x23": "native_cond_init",
    "0x24": "native_cond_signal",
    "0x25": "native_cond_wait",
    "0x30": "native_malloc",
    "0x31": "native_free",
    "0x40": "native_memcpy",
    "0x41": "native_memset",
    "0x50": "native_open",
    "0x51": "native_read",
    "0x52": "native_write",
    "0x53": "native_close",
}


def _vreg_name(reg: str) -> str:
    """Convert internal reg name to C variable."""
    if reg.startswith("r"):
        return f"vm->r{reg[1:]}"
    if reg.startswith("flag_"):
        return f"vm->{reg}"
    if reg == "vpc":
        return "vm->vpc"
    return reg


def _emit_load(node: IRNode) -> str:
    ctype = WIDTH_TYPE.get(node.width, "uint32_t")
    dst = _vreg_name(node.dst) if node.dst else "/* ??? */"
    if node.src:
        addr = _vreg_name(node.src[0])
        return f"{dst} = *({ctype}*)({addr});"
    return f"{dst} = /* LOAD: no source */;"


def _emit_store(node: IRNode) -> str:
    ctype = WIDTH_TYPE.get(node.width, "uint32_t")
    if len(node.src) >= 2:
        val = _vreg_name(node.src[0])
        addr = _vreg_name(node.src[1])
        return f"*({ctype}*)({addr}) = {val};"
    return f"/* STORE: incomplete operands */;"


def _emit_binop(node: IRNode, operator: str) -> str:
    dst = _vreg_name(node.dst) if node.dst else "/* ??? */"
    if len(node.src) >= 2:
        lhs = _vreg_name(node.src[0])
        rhs = _vreg_name(node.src[1])
        return f"{dst} = {lhs} {operator} {rhs};"
    elif len(node.src) == 1:
        src = _vreg_name(node.src[0])
        return f"{dst} = {dst} {operator} {src};"
    return f"{dst} = /* {operator}: missing operands */;"


def _emit_unop(node: IRNode, operator: str) -> str:
    dst = _vreg_name(node.dst) if node.dst else "/* ??? */"
    if node.src:
        src = _vreg_name(node.src[0])
        return f"{dst} = {operator}{src};"
    return f"{dst} = {operator}{dst};"


OP_MAP = {
    IRKind.ADD: "+",
    IRKind.SUB: "-",
    IRKind.MUL: "*",
    IRKind.DIV: "/",
    IRKind.AND: "&",
    IRKind.OR:  "|",
    IRKind.XOR: "^",
    IRKind.SHL: "<<",
    IRKind.SHR: ">>",
    IRKind.SAR: ">>",  # C arithmetic shift when operand is signed
    IRKind.ROL: "<<<",  # pseudo-operator, will use macro
    IRKind.ROR: ">>>",
}


def emit_node(node: IRNode) -> str:
    """Emit a single IR node as a C statement."""
    if node.kind == IRKind.NOP:
        return f"/* nop */  // {node.comment}"

    if node.kind == IRKind.UNKNOWN:
        return f"/* UNKNOWN opcode {node.opcode} */"

    if node.kind == IRKind.MOV:
        dst = _vreg_name(node.dst) if node.dst else "/* ??? */"
        if node.src:
            src = _vreg_name(node.src[0])
            return f"{dst} = {src};"
        return f"/* MOV: no source */;"

    if node.kind == IRKind.LOAD:
        return _emit_load(node)

    if node.kind == IRKind.STORE:
        return _emit_store(node)

    if node.kind in OP_MAP:
        op = OP_MAP[node.kind]
        if node.kind in (IRKind.ROL, IRKind.ROR):
            # Use helper macro
            func = "ROL" if node.kind == IRKind.ROL else "ROR"
            dst = _vreg_name(node.dst) if node.dst else "/* ??? */"
            args = ", ".join(_vreg_name(s) for s in node.src)
            return f"{dst} = {func}({args});"
        return _emit_binop(node, op)

    if node.kind == IRKind.NOT:
        return _emit_unop(node, "~")

    if node.kind == IRKind.CMP:
        if len(node.src) >= 2:
            lhs = _vreg_name(node.src[0])
            rhs = _vreg_name(node.src[1])
            flags = ", ".join(node.flags_written) if node.flags_written else "NZCV"
            return f"/* CMP: sets {flags} */  __cmp({lhs}, {rhs});"
        return f"/* CMP: incomplete */;"

    if node.kind == IRKind.TEST:
        if len(node.src) >= 2:
            lhs = _vreg_name(node.src[0])
            rhs = _vreg_name(node.src[1])
            return f"/* TEST: sets flags */  __test({lhs}, {rhs});"
        return f"/* TEST: incomplete */;"

    if node.kind == IRKind.BRANCH:
        cond = node.condition or "??"
        target = f"label_{node.target_offset}" if node.target_offset is not None else "/* ?? */"
        flag_ref = f"vm->flag_{cond.lstrip('!')}"
        if cond.startswith("!"):
            return f"if (!{flag_ref}) goto {target};"
        return f"if ({flag_ref}) goto {target};"

    if node.kind == IRKind.JUMP:
        target = f"label_{node.target_offset}" if node.target_offset is not None else "/* ?? */"
        return f"goto {target};"

    if node.kind == IRKind.RET:
        return "return;"

    if node.kind == IRKind.CALL:
        func_name = NATIVE_STUBS.get(node.opcode, f"native_{node.opcode}")
        args = ", ".join(_vreg_name(s) for s in node.src)
        if node.dst:
            dst = _vreg_name(node.dst)
            return f"{dst} = {func_name}({args});"
        return f"{func_name}({args});"

    if node.kind == IRKind.FLAG_SET:
        if node.dst:
            return f"vm->flag_{node.dst} = 1;"
        return "/* FLAG_SET: no target */;"

    if node.kind == IRKind.FLAG_CLEAR:
        if node.dst:
            return f"vm->flag_{node.dst} = 0;"
        return "/* FLAG_CLEAR: no target */;"

    if node.kind == IRKind.PREDICATE:
        cond = node.condition or "??"
        flag_ref = f"vm->flag_{cond.lstrip('!')}"
        body = f"/* predicated: {node.raw_operation} */"
        if cond.startswith("!"):
            return f"if (!{flag_ref}) {{ {body} }}"
        return f"if ({flag_ref}) {{ {body} }}"

    # Fallback: use raw operation from handler
    if node.raw_operation:
        sanitized = node.raw_operation.replace("vreg[", "vm->r").replace("]", "")
        return f"{sanitized};  // {node.comment}"

    return f"/* unhandled IR kind: {node.kind.name} */  // {node.comment}"


# ---------------------------------------------------------------------------
# Control flow structuring (simple patterns)
# ---------------------------------------------------------------------------

@dataclass
class StructuredBlock:
    """Structured control flow region."""
    kind: str  # "sequence", "if_then", "if_then_else", "loop", "block"
    blocks: list[int] = field(default_factory=list)
    condition: str = ""
    then_body: list[int] = field(default_factory=list)
    else_body: list[int] = field(default_factory=list)


def detect_if_then(blocks: list[BasicBlock], block_id: int) -> StructuredBlock | None:
    """Detect if-then pattern: block branches to block+2, falls through to block+1."""
    bb = blocks[block_id]
    if not bb.nodes or bb.nodes[-1].kind != IRKind.BRANCH:
        return None
    if len(bb.successors) != 2:
        return None

    fall = bb.successors[0]
    taken = bb.successors[1]

    # if-then: taken skips over fall-through (fall+1 == taken)
    if taken == fall + 1 and taken < len(blocks):
        return StructuredBlock(
            kind="if_then",
            blocks=[block_id],
            condition=bb.nodes[-1].condition or "",
            then_body=[fall],
        )

    # if-then-else: both converge at the same point
    if fall < len(blocks) and taken < len(blocks):
        fall_succs = set(blocks[fall].successors)
        taken_succs = set(blocks[taken].successors)
        common = fall_succs & taken_succs
        if common:
            return StructuredBlock(
                kind="if_then_else",
                blocks=[block_id],
                condition=bb.nodes[-1].condition or "",
                then_body=[taken],
                else_body=[fall],
            )

    return None


# ---------------------------------------------------------------------------
# Full C code generation
# ---------------------------------------------------------------------------

def detect_used_registers(program: list[IRNode]) -> set[str]:
    """Collect all virtual registers referenced in the program."""
    regs: set[str] = set()
    for node in program:
        if node.dst and node.dst.startswith("r"):
            regs.add(node.dst)
        for s in node.src:
            if s.startswith("r"):
                regs.add(s)
    return regs


def detect_used_flags(program: list[IRNode]) -> set[str]:
    """Collect all flag names referenced in the program."""
    flags: set[str] = set()
    for node in program:
        for f in node.flags_written:
            flags.add(f)
        for f in node.flags_read:
            flags.add(f)
        if node.condition:
            flags.add(node.condition.lstrip("!"))
    return flags


def generate_c(blocks: list[BasicBlock], program: list[IRNode],
               function_name: str = "vm_program",
               emit_struct: bool = True) -> str:
    """Generate complete C source from basic blocks."""
    lines: list[str] = []
    regs = detect_used_registers(program)
    flags = detect_used_flags(program)
    max_reg = 0
    for r in regs:
        m = re.match(r"r(\d+)", r)
        if m:
            max_reg = max(max_reg, int(m.group(1)))

    # Header
    lines.append("/* ================================================================")
    lines.append(f" * Decompiled VM program: {function_name}")
    lines.append(f" * Registers used: {sorted(regs)}")
    lines.append(f" * Flags used: {sorted(flags)}")
    lines.append(f" * Basic blocks: {len(blocks)}")
    lines.append(f" * Instructions: {len(program)}")
    lines.append(" * Generated by ir_to_c.py (Code Virtualizer decompiler)")
    lines.append(" * ================================================================ */")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <stddef.h>")
    lines.append("")

    # Rotate macros
    has_rotate = any(n.kind in (IRKind.ROL, IRKind.ROR) for n in program)
    if has_rotate:
        lines.append("#define ROL(val, n) (((val) << (n)) | ((val) >> (32 - (n))))")
        lines.append("#define ROR(val, n) (((val) >> (n)) | ((val) << (32 - (n))))")
        lines.append("")

    # VM state struct
    if emit_struct:
        lines.append("typedef struct {")
        for i in range(max_reg + 1):
            lines.append(f"    uint64_t r{i};")
        lines.append("")
        for f in sorted(flags):
            lines.append(f"    uint8_t flag_{f};")
        lines.append("")
        lines.append("    uint64_t vpc;       /* virtual program counter */")
        lines.append("} vm_state_t;")
        lines.append("")

    # CMP/TEST helper stubs
    has_cmp = any(n.kind == IRKind.CMP for n in program)
    has_test = any(n.kind == IRKind.TEST for n in program)
    if has_cmp or has_test:
        lines.append("/* Flag-setting helpers (platform-specific in real impl) */")
        if has_cmp:
            lines.append("static inline void __cmp(uint64_t a, uint64_t b) {")
            lines.append("    /* sets Z, N, C, V based on a - b */")
            lines.append("}")
            lines.append("")
        if has_test:
            lines.append("static inline void __test(uint64_t a, uint64_t b) {")
            lines.append("    /* sets Z, N based on a & b */")
            lines.append("}")
            lines.append("")

    # Function body
    lines.append(f"void {function_name}(vm_state_t *vm)")
    lines.append("{")

    # Detect structured patterns
    structured: dict[int, StructuredBlock] = {}
    skip_blocks: set[int] = set()
    for bb in blocks:
        if bb.id in skip_blocks:
            continue
        pattern = detect_if_then(blocks, bb.id)
        if pattern:
            structured[bb.id] = pattern
            skip_blocks.update(pattern.then_body)
            skip_blocks.update(pattern.else_body)

    for bb in blocks:
        # Label (skip for block 0 if it's the entry)
        if bb.id > 0 or bb.predecessors:
            lines.append(f"")
            lines.append(f"{bb.label}:  /* offset {bb.start_offset} */")

        if bb.id in structured:
            pattern = structured[bb.id]
            # Emit non-terminator nodes
            for node in bb.nodes:
                if not node.is_terminator:
                    lines.append(f"    {emit_node(node)}")

            last = bb.nodes[-1] if bb.nodes else None
            cond = last.condition if last else ""
            flag_ref = f"vm->flag_{cond.lstrip('!')}" if cond else "/* ?? */"
            negate = cond.startswith("!")

            if pattern.kind == "if_then":
                cond_expr = f"!{flag_ref}" if negate else flag_ref
                lines.append(f"    if ({cond_expr}) {{")
                for then_id in pattern.then_body:
                    for node in blocks[then_id].nodes:
                        lines.append(f"        {emit_node(node)}")
                lines.append(f"    }}")

            elif pattern.kind == "if_then_else":
                cond_expr = f"!{flag_ref}" if negate else flag_ref
                lines.append(f"    if ({cond_expr}) {{")
                for then_id in pattern.then_body:
                    for node in blocks[then_id].nodes:
                        lines.append(f"        {emit_node(node)}")
                lines.append(f"    }} else {{")
                for else_id in pattern.else_body:
                    for node in blocks[else_id].nodes:
                        lines.append(f"        {emit_node(node)}")
                lines.append(f"    }}")

        elif bb.id not in skip_blocks:
            for node in bb.nodes:
                lines.append(f"    {emit_node(node)}")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DOT graph export
# ---------------------------------------------------------------------------

def export_cfg_dot(blocks: list[BasicBlock]) -> str:
    """Export the CFG as a Graphviz DOT graph."""
    lines = ["digraph CFG {", "    rankdir=TB;", "    node [shape=box, fontname=monospace, fontsize=10];"]
    for bb in blocks:
        node_summary = []
        for node in bb.nodes[:5]:  # first 5 instructions
            stmt = emit_node(node).replace('"', '\\"')
            if len(stmt) > 60:
                stmt = stmt[:57] + "..."
            node_summary.append(stmt)
        if len(bb.nodes) > 5:
            node_summary.append(f"... +{len(bb.nodes) - 5} more")
        label = f"{bb.label}\\n" + "\\l".join(node_summary) + "\\l"
        lines.append(f'    {bb.label} [label="{label}"];')

    for bb in blocks:
        for succ_id in bb.successors:
            style = ""
            if len(bb.successors) == 2:
                style = ' [label="T"]' if succ_id != bb.id + 1 else ' [label="F"]'
            lines.append(f"    {bb.label} -> {blocks[succ_id].label}{style};")

    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON statistics
# ---------------------------------------------------------------------------

def emit_stats(program: list[IRNode], blocks: list[BasicBlock]) -> dict[str, Any]:
    """Produce a summary of the decompiled program."""
    kind_counts: dict[str, int] = {}
    for node in program:
        kind_counts[node.kind.name] = kind_counts.get(node.kind.name, 0) + 1

    unknown = sum(1 for n in program if n.kind == IRKind.UNKNOWN)
    return {
        "total_instructions": len(program),
        "basic_blocks": len(blocks),
        "instruction_kinds": kind_counts,
        "unknown_opcodes": unknown,
        "known_opcodes": len(program) - unknown,
        "coverage_pct": round((len(program) - unknown) / max(len(program), 1) * 100, 1),
        "registers_used": sorted(detect_used_registers(program)),
        "flags_used": sorted(detect_used_flags(program)),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IR-to-C decompiler for Code Virtualizer bytecode",
    )
    parser.add_argument("handlers", type=Path,
                        help="Handler semantics JSON (opcode -> operation mapping)")
    parser.add_argument("bytecode", type=Path,
                        help="Bytecode stream JSON (instruction sequence)")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output C file (default: stdout)")
    parser.add_argument("--cfg", type=Path, default=None,
                        help="Export CFG as DOT graph")
    parser.add_argument("--stats", type=Path, default=None,
                        help="Export decompilation statistics as JSON")
    parser.add_argument("--name", type=str, default="vm_program",
                        help="Function name in output (default: vm_program)")
    parser.add_argument("--no-struct", action="store_true",
                        help="Omit the vm_state_t struct definition")
    args = parser.parse_args()

    handler_data = json.loads(args.handlers.read_text())
    bytecode_data = json.loads(args.bytecode.read_text())

    # Accept both {"handlers": {...}} and flat dict
    if "handlers" in handler_data and isinstance(handler_data["handlers"], dict):
        handlers = handler_data["handlers"]
    else:
        handlers = handler_data

    # Accept both {"program": [...]} and flat list
    if "program" in bytecode_data and isinstance(bytecode_data["program"], list):
        bytecode = bytecode_data["program"]
    else:
        bytecode = bytecode_data

    # Lift
    program = lift_program(handlers, bytecode)
    blocks = build_cfg(program)

    # Generate C
    c_code = generate_c(blocks, program, function_name=args.name,
                        emit_struct=not args.no_struct)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(c_code)
        print(f"wrote {args.output} ({len(c_code)} bytes, {len(program)} instructions)")
    else:
        print(c_code)

    # CFG
    if args.cfg:
        dot = export_cfg_dot(blocks)
        args.cfg.parent.mkdir(parents=True, exist_ok=True)
        args.cfg.write_text(dot)
        print(f"wrote CFG: {args.cfg}")

    # Stats
    stats = emit_stats(program, blocks)
    if args.stats:
        args.stats.parent.mkdir(parents=True, exist_ok=True)
        args.stats.write_text(json.dumps(stats, indent=2) + "\n")
        print(f"wrote stats: {args.stats}")
    else:
        print(json.dumps(stats, indent=2), file=sys.stderr)


if __name__ == "__main__":
    main()
