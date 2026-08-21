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

## Target Binaries

Binaries are not included in the repository. Here is how to obtain them:

### mac_arm64.decoded (EAC Bootstrapper)

The EAC bootstrapper for macOS arm64. Located inside the game's app bundle:

```
<Steam>/steamapps/common/Rust/rust.app/Contents/MacOS/start_protected_game
```

This is a Mach-O universal binary (`com.epicgames.easyanticheat`, v1.9.4). Extract the arm64 slice:

```bash
lipo start_protected_game -thin arm64 -output mac_arm64.decoded
```

The same binary is also at `rust.app/Contents/MacOS/rust` — they are identical.

### eac_service_decoded.dylib (In-Game Service)

The EAC in-game service dylib, embedded inside the bootstrapper binary as an obfuscated container. To extract:

1. Run the bootstrapper through the Unicorn harness to dump the shm handoff, or locate the embedded image at file offset `0x57CE4` (size `0x657AEC` bytes including the 20-byte container header).

2. Decode the container using `src/codec.py`:

```bash
# Extract raw container from the bootstrapper binary
python3 -c "
data = open('mac_arm64.decoded', 'rb').read()
open('eac_embedded_image.bin', 'wb').write(data[0x57CE4:0x57CE4+0x657AEC])
"

# Decode the container (strips header, deobfuscates payload)
python3 src/codec.py eac_embedded_image.bin eac_service_decoded.dylib
```

The result is a valid Mach-O arm64 dylib (6.6 MB) with install name `../Bin/easyanticheat_mac_arm64.eac.ingame.tmp`. The game writes this to a temp path and loads it via `dlopen`.

**Container format**: `{u64 0, u32 magic 0xE6ACC57F, u32 payload_len, u32 header_len, obfuscated_payload}`. See [docs/02-container-codec.md](docs/02-container-codec.md) for the deobfuscation formula.

### Other binaries (optional)

| Binary | Location | Purpose |
|--------|----------|---------|
| `libEOSSDK-Mac-Shipping.dylib` | `RustClient.app/Contents/PlugIns/` | EOS SDK (fat: x86_64+arm64), contains the unobfuscated handoff parser |
| `GameAssembly.dylib` | `RustClient.app/Contents/Frameworks/` | Unity IL2CPP game code |
| `Settings.json` | `EasyAntiCheat/` | Product/sandbox/deployment GUIDs |

## Requirements

- Python 3.9+
- [Unicorn Engine](https://www.unicorn-engine.org/) (`pip install unicorn`)
- [Capstone](https://www.capstone-engine.org/) (`pip install capstone`)
- Target binaries (see above)

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

## About This Project

This repository serves as a demonstration of what **GLM 5.3 Max** is capable of. The entire research — from initial binary triage to full decompilation, deobfuscation pipeline, and runtime scenario harnesses — was conducted as a test of the model's reasoning, reverse engineering, and code generation abilities.

**54 files, 27,000+ lines of code and documentation, 22 analysis documents, 19 tools** — produced by the model through iterative exploration of a real-world, heavily obfuscated anti-cheat system protected by Code Virtualizer.

## Disclaimer

This research is conducted for educational and security research purposes. All analysis is performed on legitimately obtained software through static and dynamic analysis techniques.
