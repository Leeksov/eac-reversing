# 17 -- Bytecode Extraction & Opcode-Handler Mapping (Service VM)

Status: **partial** -- dispatch table decoded, bytecode stream extracted,
opcode-byte-to-index mapping still requires instrumented harness run.

## Dispatch Table

Location: `__CV_0` at vmaddr `0xC42D0`, file offset `0xC02D0`.

| Property | Value |
|---|---|
| Entry count | 247 |
| Entry size | 16 bytes (two 8-byte pointers) |
| Format | `(handler_slot0_ptr, handler_slot1_ptr)` |
| Each pointer | Branch instruction (`B target`) to the actual handler |
| Used in trace | 26 entries (out of 247) |

Each 16-byte entry encodes **two** branch trampolines.  The dispatcher
selects both the entry index (0..246) and which slot (0 or 1) to use,
giving a theoretical address space of 494 handlers.  Only 26 unique
`(index, slot)` combinations are exercised during `start_service`.

### Observed Entries

| Index | Slot | Trampoline | Handler | Avg InsnCnt | Freq |
|------:|-----:|-----------:|--------:|------------:|-----:|
|     5 |    0 | 0x0F3310   | 0x173DE0 |       2,048 |    1 |
|     7 |    0 | 0x0F3570   | 0x1728A8 |     180,540 |    4 |
|     8 |    0 | 0x11FDC0   | 0x12BBDC |     100,085 |    5 |
|    10 |    1 | 0x0FDBD8   | 0x0DF58C |     191,783 |    1 |
|    43 |    0 | 0x12DAC0   | 0x1B2C7C |       4,300 |    1 |
|    49 |    1 | 0x121008   | 0x0F4AAC |      18,475 |    1 |
|    54 |    1 | 0x0F3FB8   | 0x127C60 |      66,775 |    7 |
|    56 |    1 | 0x12DA88   | 0x0F08DC |      55,135 |    4 |
|    65 |    0 | 0x122750   | 0x10F59C |     156,148 |    2 |
|    69 |    1 | 0x0F1898   | 0x100758 |     108,366 |    1 |
|    79 |    1 | 0x1030D8   | 0x1975FC |     164,115 |    1 |
|    93 |    0 | 0x11FDD0   | 0x10C828 |       2,584 |    4 |
|   109 |    1 | 0x120FC8   | 0x0DFB58 |     286,019 |    2 |
|   130 |    0 | 0x111B90   | 0x0EE0D4 |     169,605 |    9 |
|   134 |    1 | 0x11FC48   | 0x0FC0DC |      14,294 |    3 |
|   136 |    0 | 0x122BD0   | 0x0FADC0 |      90,512 |    2 |
|   151 |    0 | 0x11FEB0   | 0x1A6DAC |     108,717 |    1 |
|   169 |    0 | 0x124AF0   | 0x161048 |     103,299 |    1 |
|   185 |    1 | 0x11FE38   | 0x14DDE4 |      57,743 |    1 |
|   192 |    1 | 0x122F78   | 0x151508 |         645 |    2 |
|   200 |    0 | 0x1220C0   | 0x0E457C |      10,536 |    5 |
|   207 |    0 | 0x10BF50   | 0x18E4C4 |       4,746 |    1 |
|   227 |    1 | 0x117B78   | 0x1C5D80 |      19,012 |    3 |
|   237 |    0 | 0x12FEB0   | 0x142000 |      15,990 |    1 |
|   239 |    1 | 0x123198   | 0x12F9CC |       4,533 |    1 |
|   241 |    0 | 0x11B8B0   | 0x1D2C08 |     574,849 |    2 |

## Dispatch Handler

The dispatcher at `0x1000E0`--`0x100478` (230 instructions, 920 bytes) is
a single obfuscated block that:

1. Reads two encrypted halfwords from the VM bytecode stream:
   - `0x100168: ldrh w27, [x16]` (via pointer at `[x29+0x150]`)
   - `0x1002E8: ldrh w27, [x9]`  (via derived pointer)
2. Applies obfuscated arithmetic (ADD/XOR with keys from `[x29+0x114]`
   and `[x29+0x118]`) to compute a dispatch table pointer in `x14`.
3. Loads the handler address: `0x1003F4: ldr x2, [x14]`.
4. Advances the virtual program counter: `0x100474: str x26, [x8]`
   where `x8 = x29 + 0x150`.
5. Dispatches: `0x100478: br x2`.

The handler returns to the dispatcher via `0x11E850: b #0x1000E0`.

### VM State Layout (from dispatcher)

| Offset from x29 | Width | Purpose |
|:---|:---|:---|
| `+0x9C`  | 8 | Scratch / computed value |
| `+0x114` | 4 | Decryption key 1 (for halfword transform) |
| `+0x118` | 4 | Decryption key 2 (XOR key for halfword) |
| `+0x150` | 8 | Bytecode pointer (VPC) |
| `+0x168` | 1 | Commit/retire flag (written by handlers) |
| `+0x190` | 8 | Scratch / flag word |
| `+0x1D0` | 8 | Pointer loaded during dispatch |

## Opcode Byte Values

26 opcode byte constants found by static scan of `__CV_1` (UXTB + CMP +
B.eq/B.ne pattern):

    02  03  07  0C  0D  11  20  2C  2E  33
    44  6E  83  85  8F  93  A3  B5  BC  BE
    C4  D7  E1  EE  FA  FE

These are the **raw opcode values** before the per-build scramble.  The
dispatcher transforms each value through obfuscated arithmetic to compute
a dispatch-table index.

### Opcode-to-Index Mapping (unknown)

The bijection between the 26 opcode bytes and the 26 table indices has not
yet been recovered.  The dispatch computation is intentionally obfuscated
to prevent static analysis.

**To resolve:**  Instrument `service_cv_trace.py` to capture the halfword
value read at `0x100168` and the resulting `x14` at `0x1003F4` for each
dispatch cycle.  The pre-transform halfword, once decoded through the
key at `[x29+0x118]`, gives the raw opcode byte.

### Width Sub-dispatch

Some handlers contain a secondary dispatch chain comparing the loaded
byte against `0xA3` (16-bit), `0xE1` (64-bit), `0xB5` (32-bit), and
`0x44` (8-bit).  This is the width selection for the load/store family,
observed at `0x14C248`--`0x14C2E0` and `0x18C078`--`0x18C528`.

## Bytecode Stream for `start_service`

66 dispatch cycles extracted from the Unicorn trace of `_x` with 6.7M PCs.
The complete stream is in `data/svc_opcode_map.json` under `bytecode_stream`.

### Sequence (table indices)

```
54 56  8 93  7   | block A (x4)
54 56  8 93  7   |
130              | separator
54 56  8 93  7   |
54 56  8 93  7   |
130              |
241 192 200 109  | block B (x2)
130              |
241 192 200 109  |
79               | unique
130 10 151 69 65 237 65 207  | init sequence
130 49 43        | setup
227 54 227 54 227 54  | alternating pair (x3)
185              |
130  8           |
130 200 134 200 134 200 134  | triple pair
169 136          |
130  5           |
130 239          |
130 136          |
```

### Structural Observations

- **Block A** `[54, 56, 8, 93, 7]` repeats 4 times with handler `130`
  separating groups of two repetitions.  This is a loop body executing
  twice per iteration, with `130` as the loop-back / condition check.

- **Block B** `[241, 192, 200, 109]` repeats twice.  Handler `241` is the
  heaviest (~575K instructions), likely a native-call sequence (malloc,
  mutex_init, memset chains observed in stub_hits).

- **Alternating pair** `[227, 54]` repeats 3 times -- likely a
  paired load/store or copy operation.

- **Triple pair** `[200, 134]` repeats 3 times -- handler `200`
  (avg 10K insns) followed by `134` (avg 14K insns), possibly
  register-to-memory store with flag update.

- Handler `192` (avg 645 instructions) is the lightest -- likely a NOP,
  VPC advance, or simple flag set.

- Handler `130` appears 9 times, often between structural blocks --
  functions as a control-flow separator (conditional branch, loop check,
  or VPC recalculation).

## Bytecode Region

The bytecode is **not** stored in `__CV_0` (which only contains the
dispatch table and one pointer at `0xC41D0`).  It resides within the
`__CV_1` code region (`0xCC000`--`0x644000`), accessed as data by the
dispatcher via the VPC pointer at `[x29+0x150]`.

The exact bytecode base address requires capturing the VPC value during
the first dispatch cycle.  The dispatcher reads encrypted halfwords from
this region and transforms them to produce table indices.

## Tool

Extraction script: `tools/extract_svc_bytecode.py`

```bash
python3 tools/extract_svc_bytecode.py devirt/eac_service_decoded.dylib \
    --trace /tmp/svc_trace_full.json \
    --output data/svc_opcode_map.json
```

## Next Steps

1. **Instrument the harness** to capture the raw halfword and decryption
   keys at each dispatch.  Add logging at `0x100168` and `0x10022C` in
   `service_cv_trace.py` to record:
   - The halfword value (`w27` after `ldrh`)
   - The XOR key from `[x29+0x118]`
   - The ADD key from `[x29+0x114]`
   - The final computed `x14` value

2. **Locate the bytecode base** by capturing the VPC (`x16` at `0x100168`)
   during the first dispatch.

3. **Build the definitive opcode mapping** once the raw bytes are captured,
   completing the bijection between the 26 opcode values and 26 table
   indices.

4. **Lift handler semantics** using the sub-dispatch patterns (width
   selection at `0x14C248` etc.) and the handler effect traces.
