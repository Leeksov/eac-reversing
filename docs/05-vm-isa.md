# VM Instruction Set Architecture

EAC uses two distinct virtual machines: a bootstrapper VM embedded in the EOS SDK framework, and a service VM inside the dynamically loaded dylib. Each VM has its own opcode encoding and dispatch table. The bootstrapper's opcode table is NOT transferable to the service -- encodings are per-build.

---

## Bootstrapper VM

- **27 opcodes**
- **Location:** `__CV` segment, address range `0x6D8000` -- `0x920000`
- **412 comparison sites** identified in the dispatch logic

### Opcode Families

#### Load/Store by Width

| Opcode | Width |
|--------|-------|
| `0x5E` | u8    |
| `0xA3` | u16   |
| `0xB9` | u32   |
| `0xFD` | u64   |

#### NZCV-Flag Predicated Operations

These opcodes execute conditionally based on the current state of the NZCV flag word in the VM state.

`0x35`, `0x47`, `0x48`, `0x52`, `0x53`, `0x6D`, `0x9B`, `0xD6`, `0xDE`

#### Flag Set/Clear

Manipulate individual bits in the flag word.

| Opcodes | Target bits |
|---------|-------------|
| `0x24`, `0x34` | `0x200` |
| `0x99`, `0xBA`, `0xFB` | `0x400` |

#### Bitwise NOT

`0xAC` -- performs bitwise inversion on the operand.

#### Logical Shift Right by 11

`0x71`, `0x7B` -- both perform `LSR #11` on the operand.

#### Conditional Branch

`0x7D`, `0xDA` -- branch to a target offset if the flag condition is met.

#### VM-State Register Fetch

`0x02` -- reads a value from the VM state register file.

### VM State Layout

| Field | Location |
|-------|----------|
| Commit slot | `[x29 + 0x168]` |
| Register file | Adjacent to commit slot |
| Flag word | Bitfield checked by predicated opcodes |

---

## Service VM

- **26 opcodes**
- **Location:** `__CV` segment, address range `0xCC000` -- `0x644000`
- **423 call sites** identified across the service binary

### Opcode Table

```
02 03 07 0C 0D 11 20 2C 2E 33 44 6E 83 85 8F 93
A3 B5 BC BE C4 D7 E1 EE FA FE
```

### Dispatch Table

The dispatch table resides in segment `__CV_0` at address range `0xC4000` -- `0xCC000`. It contains **247 paired entries**. Each pair maps an opcode to its handler address.

### Handler Structure

Every handler follows a consistent pattern:

1. **Save all registers** -- full context preservation on entry.
2. **Obfuscated compute** -- the actual operation, buried under layers of arithmetic obfuscation. Each handler contains approximately **100K obfuscated ARM64 instructions**.
3. **Load next handler** -- reads the next handler address from the dispatch table.
4. **Indirect branch** -- `br xN` to the next handler (threaded dispatch).

### Per-Build Encoding

The opcode-to-handler mapping is unique to each build of the service binary. A table extracted from one build cannot be reused for another. This is a deliberate anti-analysis measure that forces re-extraction of the dispatch table for every new version.
