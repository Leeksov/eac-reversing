# Changelog

## Phase 7 — Service Decompilation (2026-08-20)

- Unicorn harness stabilized: fixed `scan_lse()` and `patch_ldaprb()` vmaddr/file-offset mapping bug, modeled `___cxa_guard_acquire`, `dyld_stub_binder`, `fopen`/`fread` for `/dev/urandom`, Mach clock APIs
- Full `start_service` trace: 6.7M instructions, 101K unique PCs, 97K in CV region, 353 import calls
- Effect-level decompilation of `_x` export: DH key exchange, CSPRNG seeding, system fingerprinting, worker thread initialization
- Dispatch table extracted: 247 paired handler entries in `__CV_0`

## Phase 6 — Service VM Tracing (2026-08-17)

- Ported Unicorn harness for `eac_service_decoded.dylib` (`tools/service_cv_trace.py`)
- 317 import bindings modeled (malloc, pthread, mem*, CF*, IO*, mach*)
- LSE atomics emulation (casal, ldaddal, swp, etc.) in code hook
- VM entered CV region, reached 97K steps before first fault

## Phase 5 — EOS AntiCheat API (2026-08-17)

- 54 exports decompiled from `libEOSSDK-Mac-Shipping.dylib`
- Dispatch architecture: thunk → vtable → engine (`this+728`)
- Client vtable decoded from chained fixups (DYLD_CHAINED_PTR_64)
- Engine load point identified: `AddNotifyClientIntegrityViolated` → `sub_563D5C`

## Phase 4 — In-Game Service Analysis (2026-08-17)

- Embedded image decoded to valid Mach-O arm64 dylib (6.6 MB)
- Service ABI: `_x` (init/start), `_y` (stop)
- Context struct 0x2B20 mapped: vtable, 5 worker queues, callback list
- 116 CV wrappers catalogued, 26-opcode service VM table identified

## Phase 3 — Container Codec (2026-08-16)

- Deobfuscation formula recovered from unobfuscated EOS SDK parser (`sub_563D5C`)
- Verified against ground truth: 1108/1108 byte-identical matches
- Container format: `{u64 0, u32 magic 0xE6ACC57F, u32 len1, u32 len2, payload}`

## Phase 2 — VM ISA Extraction (2026-08-16)

- Bootstrapper VM: 27 distinct opcodes extracted from 412 comparison sites
- Opcode families classified: load/store, NZCV-flag predicated, flag set/clear, bitwise, branch
- VM state layout documented: commit slot, register file, flag word

## Phase 1 — Bootstrapper Devirtualization (2026-08-16)

- 28 protected functions recovered to C semantics
- Activation flow fully traced (40.4M instructions to `execv`)
- runtime.conf: sole predicate is file size >= 1108 bytes (content never checked)
- Anti-debug: `sysctl(P_TRACED)` → callback 502
- PE-gate: Windows PE targets → `_exit(1)`
- shm handoff: header + 0x657AE0-byte embedded image with product/sandbox/deployment GUIDs
