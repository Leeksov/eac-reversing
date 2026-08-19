# Container Codec

## Overview

A byte-level obfuscation codec used by EAC for both `runtime.conf` and the embedded service image. The codec was independently confirmed by locating it in **unobfuscated form** inside the EOS SDK (`sub_563D5C`), with three independent byte-level matches proving identity.

## Container Format

```
+--------+-------------------+--------+--------+---------------------+
| u64 0  | u32 magic         | u32 l1 | u32 l2 | obfuscated(l1)      |
| 8 bytes| 0xE6ACC57F        | 4 bytes| 4 bytes| l1 bytes            |
+--------+-------------------+--------+--------+---------------------+
```

| Field           | Type  | Value / Description                        |
|----------------|-------|--------------------------------------------|
| Reserved       | u64   | Always `0`                                 |
| Magic          | u32   | `0xE6ACC57F`                               |
| len1           | u32   | Length of the obfuscated payload            |
| len2           | u32   | Length of the deobfuscated output (verified: `1108`/`1108` for runtime.conf) |
| Payload        | bytes | `len1` bytes of obfuscated data            |

## Deobfuscation Algorithm

From the EOS SDK (`sub_563D5C`), verified against bootstrapper behavior:

```python
def deobfuscate(c: bytes) -> bytes:
    b = bytearray(c); n = len(c)
    v = (b[n-1] - 3*(n-1)) & 0xFF
    b[n-1] = v
    for i in range(n-2, 0, -1):
        v = (b[i] - v - 3*i) & 0xFF
        b[i] = v
    b[0] = (b[0] - b[1]) & 0xFF
    return bytes(b)
```

The algorithm processes bytes in reverse order. Each output byte depends on its own ciphertext value, the previously decoded byte, and a position-dependent constant (`3*i`).

## VM Decoder in the Bootstrapper

The bootstrapper implements the same codec as a per-byte virtual machine:

- **Cost**: 27,388 VM instructions per input byte
- **Behavioral law**: `t[j] = F(t[j+1], c[j+1], t[j+2])` -- each output byte is a function of adjacent decoded bytes and ciphertext
- **Proven differentially**: 0 ambiguities across 524 observed states
- **Equivalence**: the VM decoder produces identical output to the closed-form Python formula above

## Usage

The same codec is applied to two distinct payloads:

| Payload             | Container Location         | Decoded Size |
|--------------------|----------------------------|-------------|
| `runtime.conf`     | External file              | 1108 bytes  |
| Embedded service   | Bootstrapper binary body   | Mach-O dylib, 6.6 MB |

## Offline Oracle

An offline decoder is available at `tools/decoder_oracle.py` for decoding containers outside the bootstrapper.

## Discovery

The codec was identified by finding the same logic in the **unobfuscated** EOS SDK binary. Three independent byte-level comparisons confirmed that the EOS SDK function `sub_563D5C` implements an identical transformation to the bootstrapper's VM decoder.
