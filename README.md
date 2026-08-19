# EAC Reverse Engineering (macOS arm64)

Complete reverse engineering of Easy Anti-Cheat on macOS ARM64, covering the bootstrapper, container codec, in-game service, EOS SDK API, and the Code Virtualizer protection layer.

## Summary of Findings

| Component | Status | Key Result |
|-----------|--------|------------|
| **Bootstrapper** | Fully reversed | Anti-debug, runtime.conf (size-only check), PE-gate, shm handoff |
| **Container codec** | Cracked | Deobfuscation formula recovered, verified 1108/1108 bytes |
| **Embedded image** | Decoded | Valid Mach-O arm64 dylib (EAC in-game service) |
| **EOS SDK API** | 54 exports mapped | Dispatch architecture, engine load point identified |
| **In-game service** | Decompiled | DH key exchange, system fingerprinting, 10 worker threads |
| **VM protection** | Analyzed | 27 opcodes (bootstrapper), 26 opcodes (service), 247 handlers |

## Architecture

```
Steam ─→ EAC Bootstrapper ─→ shm handoff ─→ Game Process
              │                                    │
              │ anti-debug, size check,             │ EOS SDK loads service:
              │ decode embedded image               │ dlopen(eac.ingame.tmp)
              │                                    │
              └── Code Virtualizer (27 opcodes)     └── In-Game Service
                                                        │
                                                        ├── DH key exchange (RFC 3526)
                                                        ├── /dev/urandom CSPRNG
                                                        ├── CGEventSource input monitoring
                                                        ├── Process introspection
                                                        ├── Hash catalogue
                                                        ├── X.509 certificate validation
                                                        └── Code Virtualizer (26 opcodes)
```

## Project Structure

```
docs/
  architecture.md        High-level component diagram
  01-bootstrapper.md     Bootstrapper activation flow and runtime.conf
  02-container-codec.md  Container obfuscation codec
  03-ingame-service.md   In-game service binary analysis
  04-eos-api.md          EOS AntiCheat SDK (54 exports)
  05-vm-isa.md           VM instruction set (both VMs)
  06-start-service.md    Decompiled start_service logic

src/
  codec.py               Standalone container codec (encode/decode)
  recovered_semantics.c  Bootstrapper: 28 recovered C functions
  start_service_decompiled.c  Service: effect-level C decompilation

tools/
  service_cv_trace.py    Unicorn harness for in-game service (CV tracing)
  offline_cv_trace.py    Unicorn harness for bootstrapper
  decoder_oracle.py      Offline codec oracle (Unicorn-based probing)
  build_dynamic_cfg.py   Build dynamic CFG from trace data
  extract_cv_opcodes.py  Extract CV opcodes from binary
  build_protected_map.py Map protected functions
  cv_inventory.py        CV inventory builder
  merge_cv_coverage.py   Merge CV coverage data
  build_effect_summary.py  Summarize effects
  slice_observable_effects.py  Slice observable effects
  build_devirt_package.py  Assemble devirt package
  ida_import_devirt.py   Import devirt results into IDA

data/
  vm_opcode_table.json   Bootstrapper 27-opcode table
  svc_cv_wrappers.json   Service 116 CV wrapper catalog
  semantic_manifest.json 28 recovered function signatures
  protected_functions.json  Protected function map
  ida_wrappers.json      IDA wrapper analysis data
```

## Key Discoveries

### Container Codec (universal)
All EAC payloads use a simple reverse-pass obfuscation, recovered from an unobfuscated parser in the EOS SDK:

```python
def deobfuscate(c: bytes) -> bytes:
    b = bytearray(c); n = len(c)
    v = (b[n-1] - 3*(n-1)) & 0xFF;  b[n-1] = v
    for i in range(n-2, 0, -1):
        v = (b[i] - v - 3*i) & 0xFF;  b[i] = v
    b[0] = (b[0] - b[1]) & 0xFF
    return bytes(b)
```

### runtime.conf Validation
The **sole** launcher predicate is `file_size >= 1108`. Content is decoded but never validated. A random file of the correct size produces byte-identical execution traces.

### Service Initialization (start_service / _x)
Decompiled from a 6.7M-instruction Unicorn trace (353 import calls):
1. Validate args, atomic one-shot guard
2. Allocate 11KB service context (52 mutexes, 14 cond vars)
3. Seed CSPRNG from `/dev/urandom` (128 bytes)
4. DH key exchange using RFC 3526 Group 14 (2048-bit MODP)
5. Initialize 10 worker thread queues
6. Fingerprint system: PID, HID input event count, timestamps
7. Check environment variables

## Requirements

- Python 3.9+
- [Unicorn Engine](https://www.unicorn-engine.org/) (`pip install unicorn`)
- [Capstone](https://www.capstone-engine.org/) (`pip install capstone`)
- Target binaries (not included in repo — see docs for paths)

## Reproduction

```bash
# Decode a container file
python3 src/codec.py <container_file> <output_file>

# Trace the in-game service (requires eac_service_decoded.dylib)
python3 tools/service_cv_trace.py eac_service_decoded.dylib \
    --max-instructions 10000000 \
    --report /tmp/report.json

# Trace the bootstrapper (requires mac_arm64.decoded)
python3 tools/offline_cv_trace.py mac_arm64.decoded \
    --max-instructions 50000000 \
    --report /tmp/boot_report.json
```

## Disclaimer

This research is conducted for educational and security research purposes. All analysis is performed on legitimately obtained software through static and dynamic analysis techniques.
