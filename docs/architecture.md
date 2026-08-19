# Architecture Overview

## EAC Component Map (macOS arm64)

```
 Steam launches rust.app
         |
         v
 ┌─────────────────────────────────────────────────────────────┐
 │  EAC Bootstrapper (mac_arm64.decoded)                       │
 │  com.epicgames.easyanticheat v1.9.4                         │
 │                                                             │
 │  1. Anti-debug: sysctl(P_TRACED) → callback 502             │
 │  2. Validate runtime.conf (size >= 1108 only, content blind)│
 │  3. PE-gate: reject I386/AMD64 targets                      │
 │  4. Decode embedded image (6.6 MB, container codec)         │
 │  5. Write to shm: {magic, GUIDs, decoded image}             │
 │  6. execv(RustClient.app) → launches game                   │
 └───────────────────────┬─────────────────────────────────────┘
                         │ shm handoff
                         v
 ┌─────────────────────────────────────────────────────────────┐
 │  Game Process (RustClient.app)                              │
 │                                                             │
 │  ┌───────────────────────────────────────────────────────┐  │
 │  │ libEOSSDK-Mac-Shipping.dylib (EOS SDK)                │  │
 │  │                                                       │  │
 │  │ 54 exports (Client + Server AntiCheat API)            │  │
 │  │ Dispatch: thunk → vtable → engine (this+728)          │  │
 │  │                                                       │  │
 │  │ AddNotifyClientIntegrityViolated (0x5630E4):          │  │
 │  │   → sub_563D5C: scan ~/Library/Caches/eac/           │  │
 │  │   → parse container (magic 0xE6ACC57F)                │  │
 │  │   → deobfuscate → write .tmp dylib → dlopen          │  │
 │  └───────────────────┬───────────────────────────────────┘  │
 │                      │ dlopen                               │
 │                      v                                      │
 │  ┌───────────────────────────────────────────────────────┐  │
 │  │ eac_service (easyanticheat_mac_arm64.eac.ingame.tmp)  │  │
 │  │                                                       │  │
 │  │ Exports: _x (init/start), _y (stop)                   │  │
 │  │ Context: 0x2B20 bytes, singleton @ qword_C1278        │  │
 │  │                                                       │  │
 │  │ Protected by Code Virtualizer:                        │  │
 │  │   __CV segments: 0xC4000 (8KB) + 0xCC000 (5.5MB)     │  │
 │  │   247 handler entries, 26-opcode ISA (per-build)      │  │
 │  │   ~100K obfuscated instructions per handler           │  │
 │  │                                                       │  │
 │  │ Capabilities:                                         │  │
 │  │   ├── DH key exchange (RFC 3526 Group 14, 2048-bit)   │  │
 │  │   ├── VM detection (IOKit, DiskArbitration)           │  │
 │  │   ├── Hash catalogue (integrity checking)             │  │
 │  │   ├── X.509 "Anti-Cheat Integrity CA"                 │  │
 │  │   ├── Input monitoring (CGEventSource)                │  │
 │  │   ├── Process introspection (task_for_pid, csops)     │  │
 │  │   ├── SIP check (csr_get_active_config)               │  │
 │  │   └── Socket channel (network protocol to backend)    │  │
 │  └───────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────┘
```

## Container Codec

All EAC payloads (runtime.conf, embedded images) use the same obfuscation:

```
Container: [u64 reserved=0] [u32 magic=0xE6ACC57F] [u32 len1] [u32 len2] [obfuscated(len1)]

Deobfuscation (reverse pass):
  v = (c[n-1] - 3*(n-1)) & 0xFF;  c[n-1] = v;
  for i in n-2..1:  v = (c[i] - v - 3*i) & 0xFF;  c[i] = v;
  c[0] = (c[0] - c[1]) & 0xFF;
```

## Shared Memory Handoff Layout

```
Offset  Size  Content
0x00    4     u32 version = 2
0x04    4     u32 image_offset = 0x328
0x08    8     u64 flags = 1
0x10    4     u32 channel_a = 0
0x14    4     u32 channel_b = 2
0x18    4     u32 mode = 0x0C
0x1C    64    product GUID (UTF-8)
0x5C    64    sandbox GUID (UTF-8)
0x9C    64    deployment GUID (UTF-8)
0x328   ...   decoded Mach-O image (0x657AE0 bytes)
```

## VM Architecture (Code Virtualizer)

Both the bootstrapper and service use Code Virtualizer but with **independent, per-build opcode tables**.

| Property | Bootstrapper | In-Game Service |
|----------|-------------|-----------------|
| CV region | 0x6D8000-0x920000 | 0xCC000-0x644000 |
| Opcodes | 27 | 26 |
| Handler pattern | save regs → compute → br xN | same |
| Opcode encoding | fixed per build | fixed per build |
| ISA family | load/store, NZCV, branch, NOT | TBD (partially overlapping) |
