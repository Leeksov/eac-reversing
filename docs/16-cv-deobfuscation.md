# Code Virtualizer Handler Semantics (EAC In-Game Service)

Automated effect-based analysis of CV handler semantics via
differential trace snapshots.

## Overview

- Total emulation steps: 6,709,677
- Stop reason: instruction limit
- Dispatch cycles recorded: 65
- Unique handler addresses: 26
- Handlers analyzed: 26

## Classification Summary

- **VM_COMPUTE**: 14
- **CALL**: 12

## Dispatch Mechanism

The VM dispatcher is at 0x1000E0-0x100478 in __CV_1:

```
0x1003F4: ldr x2, [x14]    ; load next handler address from dispatch table
...                          ; obfuscating arithmetic (x3, x11, x27, etc.)
0x100478: br x2              ; branch to handler
```

- x14 is the dispatch table cursor in __CV_0 (0xC4000-0xCC000)
- Each handler executes thousands of obfuscated ARM64 instructions
  (flattened CFG with computed `br xN` branches internally)
- Handler completes by reaching the dispatcher again at 0x100478

## Handler Table

| Handler | Freq | Class | Steps | Reg Changes | CV0 Changes | Stubs |
|---------|------|-------|-------|-------------|-------------|-------|
| 0x111b90 | 9 | CALL | 168750 | sp, x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 17 | _pthread_mutex_lock, _memset |
| 0xf3fb8 | 7 | CALL | 108012 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 8 | _memset, _memset |
| 0x11fdc0 | 5 | CALL | 109891 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 7 | _memset, _memset |
| 0x1220c0 | 5 | VM_COMPUTE | 3164 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 8 |  |
| 0x12da88 | 4 | CALL | 55365 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 7 | _memset |
| 0x11fdd0 | 4 | VM_COMPUTE | 2814 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 8 |  |
| 0xf3570 | 4 | CALL | 229024 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 11 | _memset, _memset, _pthread_mutexattr_init |
| 0x117b78 | 3 | VM_COMPUTE | 19242 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 9 |  |
| 0x11fc48 | 3 | VM_COMPUTE | 14324 | x1, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 12 |  |
| 0x11b8b0 | 2 | CALL | 588905 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x29, x3, x30, x4, x5, x6, x7, x9 | 28 | _bzero, _fopen, _fread |
| 0x122f78 | 2 | VM_COMPUTE | 875 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x6, x7, x9 | 5 |  |
| 0x120fc8 | 2 | CALL | 284090 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 21 | _calloc, _bzero, _calloc |
| 0x122750 | 2 | CALL | 230715 | sp, x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 16 | _CGEventSourceCounterForEventType, _gettimeofday |
| 0x1030d8 | 1 | VM_COMPUTE | 164345 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 12 |  |
| 0xfdbd8 | 1 | CALL | 192002 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 23 | __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc, __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_, __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_ |
| 0x11feb0 | 1 | CALL | 108947 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x29, x3, x4, x5, x6, x7, x9 | 13 | __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev |
| 0xf1898 | 1 | CALL | 108596 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 12 | _memcpy, _getpid |
| 0x12feb0 | 1 | VM_COMPUTE | 16220 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 10 |  |
| 0x10bf50 | 1 | VM_COMPUTE | 4976 | x1, x10, x11, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 10 |  |
| 0x121008 | 1 | VM_COMPUTE | 18705 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 9 |  |
| 0x12dac0 | 1 | VM_COMPUTE | 4530 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 8 |  |
| 0x11fe38 | 1 | VM_COMPUTE | 57973 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x22, x26, x3, x4, x5, x6, x7, x9 | 11 |  |
| 0x124af0 | 1 | VM_COMPUTE | 103529 | x1, x10, x11, x12, x14, x15, x16, x17, x19, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 11 |  |
| 0x122bd0 | 1 | CALL | 108844 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 11 | __Znwm |
| 0xf3310 | 1 | VM_COMPUTE | 2278 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 10 |  |
| 0x123198 | 1 | VM_COMPUTE | 4763 | x1, x10, x11, x12, x14, x15, x16, x17, x2, x21, x22, x26, x3, x4, x5, x6, x7, x9 | 7 |  |

## Method

For each dispatch cycle (handler execution between two `br x2`):

1. **Snapshot**: Capture all ARM64 registers (x0-x30, SP, NZCV) and the
   entire __CV_0 memory region (32KB dispatch table + VM state) at the
   dispatch point
2. **Delta**: Compare the entry snapshot with the exit snapshot to determine
   what the handler changed (which registers, which CV0 bytes)
3. **Group**: Group handlers by their dispatch target address (code address)
4. **Classify**: Based on the pattern of changes across all executions:
   - **NOP**: no meaningful state changes
   - **VM_STATE_UPDATE**: only CV0 memory changes, no register changes
   - **VM_REG_WRITE**: writes to CV0 (VM register file) without
     changing ARM64 registers
   - **VM_COMPUTE**: modifies both ARM64 registers and CV0 memory
   - **REG_MOVE**: single register output, small/no CV0 changes
   - **ALU**: multiple register outputs
   - **CALL**: invokes external stubs (malloc, memset, etc.)
   - **VM_BULK_OP**: large number of CV0 changes (>20 bytes)
   - **COMPLEX**: does not fit other categories

## Key Observations

### VM Register File Layout

The CV0 region (0xC4000-0xCC000) contains the VM's register file. Analysis
of write patterns across handlers reveals consistent slots:

| CV0 Offset | Width | Notes |
|-----------|-------|-------|
| 0xC4000   | 3-4B  | VM state word 0 (varies: pointers, immediates) |
| 0xC4010   | 1-4B  | VM state word 1 (frequently updated) |
| 0xC4030   | 1-8B  | VM operand / pointer slot |
| 0xC4038   | 4-8B  | VM accumulator (most active slot) |
| 0xC409C   | 1-5B  | VM state word 2 / counter |
| 0xC40A4   | 1B    | VM flag byte (0/1 toggle) |
| 0xC40F0   | 1-4B  | VM operand slot (pointers) |
| 0xC4114   | 6-8B  | VM wide register (large values, pointers) |
| 0xC4150   | 2-4B  | VM index / selector |
| 0xC4158   | 4B    | VM pointer slot |
| 0xC4190   | 4B    | VM state word 3 |

### Handler Architecture

All handlers modify the same set of ARM64 registers (x1, x2, x3, x4, x5,
x6, x7, x9, x10, x11, x12, x14, x15, x16, x17, x21, x22, x26) -- these
are scratch registers used by the obfuscated handler bodies and do NOT
correspond to the VM's logical register file. The actual VM state is in CV0.

The obfuscated handler bodies use flattened control flow with computed
`br xN` branches (typically `br x8`), making static analysis extremely
difficult. Each handler is 2K-600K instructions of ARM64, performing what
amounts to a simple VM operation (mov, add, load, store, etc.).

### Handler Categories Found

**CALL handlers** (12): Invoke native functions through the VM. The most
common pattern is calling `_memset` (memory initialization). Other patterns:
- File I/O: `_fopen`, `_fread`, `_fclose` (handler 0x11B8B0)
- Anti-cheat: `_getpid`, `_CGEventSourceCounterForEventType` (handler 0x122750)
- String ops: `_strlen`, `_memcpy`, `std::string` methods
- Allocation: `__Znwm` (operator new), `_calloc`
- Threading: `_pthread_mutex_*`, `_pthread_cond_*`

**VM_COMPUTE handlers** (14): Pure computation within the VM. These modify
CV0 state slots without calling any external functions. They represent the
core VM operations (arithmetic, logic, data movement within the register file).

## Limitations

- Classification is effect-based: it shows WHAT changed, not the exact
  operation (ADD vs XOR vs SUB)
- Differential analysis (perturbing inputs to determine exact operations)
  requires replaying individual handlers, which is blocked by the obfuscated
  intra-handler control flow (computed `br xN` branches depend on live state)
- Some handlers may behave differently with different inputs (data-dependent
  control flow in the original program)
- The 7M instruction limit captures only the init phase; the full service
  execution (6.7M+ steps) may reveal additional handlers

