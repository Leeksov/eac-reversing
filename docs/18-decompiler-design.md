# IR-to-C Decompiler Backend

Design document for the Code Virtualizer bytecode-to-C translation layer.

---

## Pipeline Position

```
trace ─► cv_lifter.py ─► handler semantics JSON
                              │
bytecode ─► extract_svc_bytecode.py ─► bytecode stream JSON
                              │
                         ir_to_c.py  ◄── THIS TOOL
                              │
                         readable C output
```

The decompiler sits at position 4 in the pipeline. It consumes two JSON inputs produced by earlier stages and emits human-readable C code.

---

## Intermediate Representation

### IR Node Types

Each VM bytecode instruction is lowered to exactly one IR node. The IR is a flat list of typed operations, not a tree or SSA form -- simplicity is preferred over optimization capability since the goal is readability.

| Category | IR Kinds | Notes |
|----------|----------|-------|
| Data movement | `MOV`, `LOAD`, `STORE` | Width-annotated (1/2/4/8 bytes) |
| Arithmetic | `ADD`, `SUB`, `MUL`, `DIV` | Binary operations on vregs |
| Bitwise | `AND`, `OR`, `XOR`, `NOT` | |
| Shifts/rotates | `SHL`, `SHR`, `SAR`, `ROL`, `ROR` | SAR = arithmetic shift right |
| Comparison | `CMP`, `TEST` | Set flags, no visible output |
| Control flow | `BRANCH`, `JUMP`, `RET` | Branch is conditional, jump is unconditional |
| Calls | `CALL` | Native function call through import stub |
| Flags | `FLAG_SET`, `FLAG_CLEAR`, `PREDICATE` | Direct flag manipulation |
| Other | `NOP`, `UNKNOWN` | Unknown = unlifted opcode |

### IR Node Structure

```
IRNode:
    kind:           IRKind enum
    dst:            destination register or flag (nullable)
    src:            list of source operands
    width:          access width in bytes (1/2/4/8)
    flags_read:     flags consumed by this operation
    flags_written:  flags produced by this operation
    condition:      branch condition (e.g. "Z", "!Z")
    target_offset:  branch target as bytecode offset
    raw_operation:  original handler semantics string
    opcode:         hex opcode from bytecode
    bytecode_offset: position in the bytecode stream
```

### Operand Naming

Virtual registers from the VM register file are named `r0` through `rN`. The handler semantics use abstract names like `vreg[3]`; the bytecode stream provides concrete register indices as operands. The lowering step maps abstract to concrete.

Flags follow the ARM NZCV convention: `flag_Z`, `flag_N`, `flag_C`, `flag_V`.

---

## Translation Strategy

### Phase 1: Lowering (handler semantics + bytecode -> IR)

For each bytecode instruction:

1. Look up the opcode in the handler semantics table.
2. Map the handler's `category` field to an `IRKind`.
3. Extract destination, sources, width, and flags from the handler.
4. Substitute abstract register indices with concrete operand values from the bytecode.
5. If the opcode is not in the handler table, emit `UNKNOWN`.

The operand substitution deserves explanation. The handler semantics describe operations using placeholder register indices (e.g., `vreg[3] = vreg[3] + vreg[7]`). The bytecode stream provides the actual register indices per instruction (e.g., operands `[3, 7]`). The lowering collects unique abstract vregs in definition order (outputs first, then inputs, deduplicated) and maps each to the corresponding bytecode operand positionally.

### Phase 2: Basic Block Detection

The IR program is split into basic blocks using standard leader identification:

- Index 0 is always a leader.
- Any instruction that is the target of a branch is a leader.
- Any instruction immediately following a terminator (BRANCH, JUMP, RET) is a leader.

### Phase 3: CFG Construction

Successors are linked based on terminator type:

- **BRANCH** (conditional): fall-through + taken target.
- **JUMP** (unconditional): single target.
- **RET**: no successors.
- **Non-terminator at block end**: fall-through to next block.

### Phase 4: Control Flow Structuring

Simple pattern matching recovers structured constructs:

- **if-then**: Block branches over exactly one block (taken target = fall-through + 1).
- **if-then-else**: Block branches to two blocks that converge at a common successor.
- **Linear sequence**: Default; emitted as labeled blocks with goto.

Loop detection is not currently implemented. The EAC service's `start_service` VM program is observed to be linear (no loops in the trace), so goto-based output is sufficient for the primary target.

### Phase 5: C Emission

Each IR node maps to a single C statement:

| IR Kind | C Output |
|---------|----------|
| `LOAD` | `vm->rN = *(uint32_t*)(vm->rM);` |
| `STORE` | `*(uint32_t*)(vm->rM) = vm->rN;` |
| `ADD` | `vm->rN = vm->rA + vm->rB;` |
| `BRANCH` | `if (vm->flag_Z) goto label_X;` |
| `CALL` | `vm->rN = native_func(vm->rA);` |
| `UNKNOWN` | `/* UNKNOWN opcode 0xXX */` |

The emitter generates:
1. A `vm_state_t` struct with all used registers and flags.
2. Helper stubs for `__cmp` and `__test` (flag-setting operations).
3. The function body with labeled blocks.
4. Inline comments with opcode information.

---

## Input Formats

### Handler Semantics JSON

```json
{
  "handlers": {
    "<handler_address>": {
      "opcode": "0xHH",
      "category": "ADD|LOAD|STORE|BRANCH|...",
      "inputs": ["vreg[N]", "flag_Z", ...],
      "outputs": ["vreg[M]", "vpc", ...],
      "operation": "vreg[M] = vreg[N] + vreg[K]",
      "flags_affected": ["Z", "N", "C", "V"]
    }
  }
}
```

Also accepts a flat dict (without the `"handlers"` wrapper).

### Bytecode Stream JSON

```json
{
  "program": [
    {"offset": 0, "opcode": "0xHH", "operands": [3, 7]},
    ...
  ]
}
```

Also accepts a flat list (without the `"program"` wrapper).

---

## Output

### C Code

Complete compilable C with:
- `vm_state_t` struct definition (suppressible via `--no-struct`)
- Helper function stubs
- Labeled basic blocks
- Inline comments

### CFG (optional, `--cfg`)

Graphviz DOT format for visualization. Each node shows the first 5 instructions of the block; edges are labeled T/F for conditional branches.

### Statistics (optional, `--stats`)

JSON with instruction counts by kind, register/flag usage, unknown opcode count, and coverage percentage.

---

## Limitations

1. **Partial coverage**: The lifter may not identify all 247 service VM handlers. Unknown opcodes are emitted as comments, not errors.

2. **No SSA/optimization**: The IR is a flat statement list. No dead code elimination, constant propagation, or register coalescing is performed. This is intentional -- the goal is faithful translation, not optimized output.

3. **Operand mapping heuristic**: The abstract-to-concrete register mapping is positional. If a handler's semantics use three distinct vregs but the bytecode provides two operands, the third vreg keeps its abstract index. This can produce incorrect register references for complex handlers.

4. **No loop detection**: Back-edges in the CFG are not identified. All control flow is expressed as if/goto. For the primary target (start_service), this is acceptable since no loops were observed.

5. **Width inference**: Access widths are inferred from C type casts in the handler's `operation` string. If the string doesn't contain a cast, the default is 32-bit.

6. **Native call stubs**: The `NATIVE_STUBS` table is a placeholder. Real import mappings should come from the CV wrapper classification (doc 11).

7. **Per-build opcodes**: The opcode-to-handler mapping is build-specific. The handler semantics JSON must be regenerated for each service binary version.

---

## Usage

```bash
# Basic: stdout
python3 tools/ir_to_c.py handlers.json bytecode.json --name vm_start_service

# Full: C file + CFG + stats
python3 tools/ir_to_c.py handlers.json bytecode.json \
    -o output/start_service.c \
    --cfg output/start_service.dot \
    --stats output/start_service_stats.json \
    --name vm_start_service
```
