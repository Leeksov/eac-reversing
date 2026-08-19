# CV Wrapper Classification -- EAC In-Game Service

116 Code Virtualizer wrappers in `eac_service_decoded.dylib`.
Each wrapper is a native function whose body is a single `b` (branch) instruction
into the CV region (0xCC000-0x644000). The VM calls these addresses; native code
calls the containing function (a thin frame that saves callee-saved registers,
then falls through to the branch).

## Statistics by Category

| Category              | Count | Description                                           |
|-----------------------|------:|-------------------------------------------------------|
| connection_protocol   |    19 | Backend connection object vtable methods               |
| event_callback        |    13 | Event dispatch, callback invocation, state transitions |
| network_send_recv     |    12 | Send/recv data paths, network I/O                      |
| detection             |    12 | Anti-debug, VM detection, environment checks           |
| threading_worker      |    12 | Worker queues, pthread sync, job dispatch               |
| integrity_scan        |    10 | Hash catalogue, process scanning, cert validation      |
| service_context       |     9 | Main service context (0x2B20) vtable methods           |
| io_file               |     8 | File I/O, dylib loading, temp file operations          |
| crypto_tls            |     7 | TLS handshake, cipher ops, certificate processing      |
| initialization        |     6 | Service init, config validation, early setup           |
| vm_introspection      |     4 | vm_region, process enumeration, late introspection     |
| service_lifecycle     |     2 | start_service / shutdown_drain                         |
| memory_management     |     2 | Small allocation/utility helpers                       |
| **Total**             | **116** |                                                     |

## Key Wrappers Identified

### Service Lifecycle (entry points from _x / _y)

| Wrapper   | CV Target    | Containing Func | Role                          |
|-----------|-------------|-----------------|-------------------------------|
| 0x10A40   | 0x18AE18    | sub_10A08       | `start_service` -- called from `_x`, orchestrates full service startup |
| 0x127A8   | 0x14BC50    | sub_12770       | `shutdown_drain` -- called from `_y`, service shutdown |

### Connection Protocol (vtable at off_B4F48+, dual-interface pattern)

7 wrappers appear in **two** vtables (B4F9x and B503x), indicating a dual-interface
dispatch pattern (likely TLS vs plaintext or versioned protocol):

| Wrapper   | CV Target    | Vtable 1 | Vtable 2 | Notes            |
|-----------|-------------|----------|----------|------------------|
| 0x40BAC   | 0x136224    | B4F98    | B5038    | Protocol method  |
| 0x40D70   | 0x14AA9C    | B4FA0    | B5040    | Protocol method  |
| 0x40EA0   | 0x112A08    | B4FA8    | B5048    | Protocol method  |
| 0x41068   | 0x1CEA1C    | B4FB0    | B5050    | Protocol method  |
| 0x41554   | 0x0EE078    | B4FB8    | B5058    | Protocol method  |
| 0x4180C   | 0x15D1CC    | B4FC0    | B5060    | Protocol method  |

Related strings: `"OnConnect"`, `"Connection"`, `"CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n"`,
`"NoConnectionResetV2A"`.."E"`, `"game_error.error_corrupted_network"`.

### Crypto/TLS (near Mbed TLS 2.4.1)

| Wrapper   | CV Target    | Notes                                     |
|-----------|-------------|-------------------------------------------|
| 0x0D680   | 0x1AC21C    | Called from two sites, core crypto op      |
| 0x0E70C   | 0x0FD0D8    | TLS/cipher operation                       |
| 0x0ECF8   | 0x10E678    | Crypto object vtable method (data @0xE900) |
| 0x0F1DC   | 0x10CED8    | Cipher vtable method (data @0xE9E8), smallest wrapper (12 bytes) |

Related strings: embedded PEM certificates (PolarSSL Test CA), encrypted EC/RSA private keys,
`"client hello, add ciphersuite"`, `"server hello, chosen ciphersuite"`.

### Integrity Scanning

| Wrapper   | CV Target    | Notes                                         |
|-----------|-------------|-----------------------------------------------|
| 0x139B0   | 0x15712C    | Vtable B4348 method, integrity check           |
| 0x13ABC   | 0x118EC4    | Vtable B4350 method, integrity check           |
| 0x14554   | 0x12D808    | Data refs at 0x156E8/EC, catalogue dispatch    |
| 0x10540   | 0x123070    | Called from 0x1538C, scan/check operation      |

Related strings: `"Easy Anti-Cheat Hash Catalogue not found"`,
`"Corrupt Easy Anti-Cheat Hash Catalogue"`, `"EAC index certificate revoked"`,
`"Could not locate game executable entry in the catalogue."`.

### Detection/Monitoring

| Wrapper   | CV Target    | Notes                                     |
|-----------|-------------|-------------------------------------------|
| 0x15F94   | 0x0CC864    | Detection check, called from 0x16E80      |
| 0x44864   | 0x0DB23C    | Vtable B5228 method, detection object      |
| 0x44AA0   | 0x11C2C0    | Vtable B5270 method, detection object      |

Related strings: `"Cannot run under Virtual Machine."`, `"game_error.error_virtual"`,
imports for IOKit registry, DiskArbitration, CGEventSourceCounterForEventType.

## Full Wrapper Table

### Initialization (6)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 1 | 0x3AAC | 0x16524C | 0x3A7C | 0x34 | Called from 4 sites in init range (0x390C..0x3A68), early setup/config |
| 2 | 0x3C6C | 0x0D9204 | 0x3C3C | 0x34 | Init-range wrapper, VM-only entry |
| 3 | 0x3FA8 | 0x0D7D14 | 0x3F74 | 0x210 | Conditional (a2!=0), large containing func, config/validation branch |
| 4 | 0x41AC | 0x1B7A9C | 0x418C | 0x24 | Init-range small wrapper |
| 5 | 0x44FC | 0x115DD4 | 0x44D4 | 0x2C | Init-range wrapper |
| 6 | 0x4BEC | 0x16A8A0 | 0x4BD0 | 0x20 | Init-range wrapper |

### Service Lifecycle (2)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 7 | 0x10A40 | 0x18AE18 | 0x10A08 | 0x3C | start_service, called from _x |
| 8 | 0x127A8 | 0x14BC50 | 0x12770 | 0x3C | shutdown_drain, called from _y |

### Network Send/Recv (12)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 9 | 0x6280 | 0x15B500 | 0x6264 | 0x20 | Timeout/reconnect path in sub_5EEC |
| 10 | 0x68F0 | 0x177184 | 0x68D8 | 0x1C | Vtable ref at 0x6530, network object method |
| 11 | 0x6C14 | 0x0F3B6C | 0x6BEC | 0x2C | Send/recv helper |
| 12 | 0x6E2C | 0x1031A4 | 0x6E08 | 0x28 | Network data processing |
| 13 | 0x6EFC | 0x0E4934 | 0x6EE4 | 0x1C | Network I/O handler |
| 14 | 0x7130 | 0x165188 | 0x7118 | 0x1C | Data transfer callback |
| 15 | 0x7594 | 0x0D9E4C | 0x7560 | 0x38 | Network data wrapper |
| 16 | 0x799C | 0x132838 | 0x7984 | 0x1C | Network state handler |
| 17 | 0x7A4C | 0x1985CC | 0x7A34 | 0x1C | Network state handler |
| 18 | 0x7BF8 | 0x1AC158 | 0x7BE0 | 0x1C | Network state handler |
| 19 | 0x7C98 | 0x0E2574 | 0x7C7C | 0x20 | Network buffer handler |
| 20 | 0x7D74 | 0x1127D0 | 0x7D50 | 0x28 | Network buffer handler |

### Crypto/TLS (7)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 21 | 0xD680 | 0x1AC21C | 0xD654 | 0x30 | Crypto op, called from 2 sites |
| 22 | 0xE70C | 0x0FD0D8 | 0xE6EC | 0x24 | TLS/cipher operation |
| 23 | 0xECF8 | 0x10E678 | 0xECE0 | 0x1C | Crypto vtable method (data @0xE900) |
| 24 | 0xF1DC | 0x10CED8 | 0xF1D4 | 0x0C | Cipher vtable method (data @0xE9E8) |
| 25 | 0xF500 | 0x137F50 | 0xF4E0 | 0x24 | Crypto helper near mbedtls |
| 26 | 0xF808 | 0x23BEA8 | 0xF7E4 | 0x28 | Near mbedtls_cipher area |
| 27 | 0xFAEC | 0x1712E4 | 0xFAD0 | 0x20 | Crypto state handler |

### Service Context (9)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 28 | 0x11668 | 0x1FCAFC | 0x1164C | 0x20 | Context operation |
| 29 | 0x117B0 | 0x11E5BC | 0x11780 | 0x34 | Context operation |
| 30 | 0x11958 | 0x15FCE0 | 0x1192C | 0x30 | Vtable B42C0 method |
| 31 | 0x11BD4 | 0x0F9724 | 0x11BA0 | 0x38 | Vtable B4328 method |
| 32 | 0x11E20 | 0x0DB0B4 | 0x11DD0 | 0x54 | Large prologue context op |
| 33 | 0x12484 | 0x19BECC | 0x12454 | 0x34 | Context operation |
| 34 | 0x12550 | 0x591098 | 0x12550 | 0x00 | VM-only entry, far CV target |
| 35 | 0x1287C | 0x144D70 | 0x1283C | 0x44 | Called from 0x14D0C, dispatch |
| 36 | 0x12F44 | 0x47C6F8 | 0x12F44 | 0x00 | VM-only entry, far CV target |

### Integrity Scan (10)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 37 | 0x10540 | 0x123070 | 0x10514 | 0x30 | Scan/check, called from 0x1538C |
| 38 | 0x139B0 | 0x15712C | 0x13980 | 0x34 | Vtable B4348 method |
| 39 | 0x13ABC | 0x118EC4 | 0x13A9C | 0x24 | Vtable B4350 method |
| 40 | 0x13B2C | 0x179634 | 0x13B0C | 0x24 | Scan/verify, called from 0x15418 |
| 41 | 0x13FD8 | 0x0F7854 | 0x13FB4 | 0x28 | Hash operation |
| 42 | 0x140C8 | 0x0F8084 | 0x140A0 | 0x2C | Hash operation |
| 43 | 0x141D4 | 0x155254 | 0x14198 | 0x40 | Hash operation, large prologue |
| 44 | 0x14494 | 0x13C21C | 0x1447C | 0x1C | Integrity check |
| 45 | 0x14554 | 0x12D808 | 0x1451C | 0x3C | Catalogue dispatch (data 0x156E8/EC) |
| 46 | 0x147AC | 0x216B8C | 0x147AC | 0x00 | VM-only integrity entry |

### Detection/Monitoring (12)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 47 | 0x15F94 | 0x0CC864 | 0x15F54 | 0x44 | Detection check |
| 48 | 0x16654 | 0x2BF614 | 0x16654 | 0x00 | VM-only detection entry |
| 49 | 0x1711C | 0x182E88 | 0x170E4 | 0x3C | Monitoring operation |
| 50 | 0x17794 | 0x2420C8 | 0x1775C | 0x3C | Near vtable B5478 |
| 51 | 0x17DF4 | 0x169478 | 0x17DE0 | 0x18 | Detection trigger |
| 52 | 0x1811C | 0x23C02C | 0x180E4 | 0x3C | Detection operation |
| 53 | 0x187B8 | 0x159048 | 0x18780 | 0x3C | Detection operation |
| 54 | 0x18E08 | 0x15FF6C | 0x18DD0 | 0x3C | Detection scan |
| 55 | 0x19748 | 0x1849FC | 0x19710 | 0x3C | Detection scan |
| 56 | 0x1980C | 0x38D9D8 | 0x1980C | 0x00 | VM-only detection entry |
| 57 | 0x44864 | 0x0DB23C | 0x4484C | 0x1C | Vtable B5228 method |
| 58 | 0x44AA0 | 0x11C2C0 | 0x44A88 | 0x1C | Vtable B5270 method |

### Event/Callback (13)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 59 | 0x1AA24 | 0x0F3170 | 0x1A9F4 | 0x34 | Event/state handler |
| 60 | 0x1AB74 | 0x118F44 | 0x1AB40 | 0x38 | Event/state handler |
| 61 | 0x1AF4C | 0x1D2A9C | 0x1AF28 | 0x28 | Calls sub_1AFD0 natively, then CV |
| 62 | 0x1B060 | 0x19A874 | 0x1B034 | 0x30 | Event/state handler |
| 63 | 0x1B22C | 0x149264 | 0x1B210 | 0x20 | Event dispatch |
| 64 | 0x1B7DC | 0x1BD000 | 0x1B7B0 | 0x30 | State transition handler |
| 65 | 0x1BF4C | 0x47B3C8 | 0x1BF4C | 0x00 | VM-only event entry |
| 66 | 0x1C380 | 0x161938 | 0x1C354 | 0x30 | State handler |
| 67 | 0x1CE2C | 0x1B0980 | 0x1CE14 | 0x1C | Event notification |
| 68 | 0x1D2F0 | 0x105F4C | 0x1D2D8 | 0x1C | Event/report handler |
| 69 | 0x1D7C4 | 0x170A10 | 0x1D79C | 0x2C | Event processing |
| 70 | 0x1DB08 | 0x150C28 | 0x1DACC | 0x40 | Event/result handler |
| 71 | 0x1E094 | 0x0F6D64 | 0x1E068 | 0x30 | Event completion |

### Connection Protocol (19)

| # | Wrapper PC | CV Target  | Func Start | Size | Vtable(s) |
|---|-----------|------------|------------|------|-----------|
| 72 | 0x3BE4C | 0x0F8194 | 0x3BE38 | 0x18 | B4F48 |
| 73 | 0x402AC | 0x11EBF4 | 0x40290 | 0x20 | (code callers) |
| 74 | 0x404A0 | 0x1064D8 | 0x40484 | 0x20 | B4F70 |
| 75 | 0x40608 | 0x2102A8 | 0x405D8 | 0x34 | B4F88 |
| 76 | 0x4081C | 0x0E1610 | 0x407F4 | 0x2C | B4F90 |
| 77 | 0x409E4 | 0x284990 | 0x409B4 | 0x34 | -- |
| 78 | 0x40BAC | 0x136224 | 0x40B88 | 0x28 | B4F98 / B5038 |
| 79 | 0x40D70 | 0x14AA9C | 0x40D3C | 0x38 | B4FA0 / B5040 |
| 80 | 0x40EA0 | 0x112A08 | 0x40E78 | 0x2C | B4FA8 / B5048 |
| 81 | 0x41068 | 0x1CEA1C | 0x41040 | 0x2C | B4FB0 / B5050 |
| 82 | 0x4129C | 0x22D55C | 0x41258 | 0x48 | B4F78 |
| 83 | 0x41554 | 0x0EE078 | 0x41520 | 0x38 | B4FB8 / B5058 |
| 84 | 0x4180C | 0x15D1CC | 0x417D4 | 0x3C | B4FC0 / B5060 |
| 85 | 0x41C5C | 0x170B54 | 0x41C18 | 0x48 | B5018 |
| 86 | 0x41F44 | 0x13EF74 | 0x41F0C | 0x3C | B5028 |
| 87 | 0x42300 | 0x15AE18 | 0x422D4 | 0x30 | B5030 |
| 88 | 0x42344 | 0x304B1C | 0x42344 | 0x00 | -- |
| 89 | 0x42504 | 0x1BDB3C | 0x424E4 | 0x24 | B5070 |
| 90 | 0x42B0C | 0x0F60F8 | 0x42AE4 | 0x2C | B5078 |

### Threading/Worker (12)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 91 | 0x1B178 | 0x0CE48C | 0x1B14C | 0x30 | Mutex-related, calls sub_4C93C |
| 92 | 0x48DB8 | 0x0EE3D8 | 0x48D74 | 0x48 | Vtable B5478 method, worker |
| 93 | 0x49F0C | 0x0F617C | 0x49EF0 | 0x20 | Worker task |
| 94 | 0x4A1B4 | 0x2D8224 | 0x4A188 | 0x30 | Worker task |
| 95 | 0x4A430 | 0x181BFC | 0x4A3F8 | 0x3C | Worker task |
| 96 | 0x4A718 | 0x15BFC8 | 0x4A6E4 | 0x38 | Worker task |
| 97 | 0x4AFF8 | 0x110C40 | 0x4AFD8 | 0x24 | Worker task |
| 98 | 0x4BD74 | 0x131938 | 0x4BD5C | 0x1C | Worker dispatch |
| 99 | 0x4CF4C | 0x0E7260 | 0x4CF30 | 0x20 | Task operation |
| 100 | 0x4D3FC | 0x14B588 | 0x4D3EC | 0x14 | Task operation (smallest: 20 bytes) |
| 101 | 0x4D498 | 0x178DF0 | 0x4D470 | 0x2C | Task operation |
| 102 | 0x4D808 | 0x0CF77C | 0x4D7E0 | 0x2C | Task operation |

### I/O & File (8)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 103 | 0x4E1E4 | 0x0F7D90 | 0x4E1CC | 0x1C | I/O operation |
| 104 | 0x4E390 | 0x0D9100 | 0x4E374 | 0x20 | I/O or dylib operation |
| 105 | 0x4E6D8 | 0x11E578 | 0x4E6B4 | 0x28 | Calls sub_4E88C natively, then CV |
| 106 | 0x4EBE4 | 0x166ADC | 0x4EBC0 | 0x28 | I/O handler |
| 107 | 0x4EE68 | 0x12682C | 0x4EE4C | 0x20 | I/O operation |
| 108 | 0x4EEA4 | 0x28C688 | 0x4EEA4 | 0x00 | VM-only I/O entry |
| 109 | 0x4F1D0 | 0x10B35C | 0x4F1A0 | 0x34 | I/O / memory operation |
| 110 | 0x4F608 | 0x0FEE30 | 0x4F5D8 | 0x34 | I/O handler |

### Memory Management (2)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 111 | 0x288E0 | 0x0F53A0 | 0x288D4 | 0x10 | Small utility (16 bytes) |
| 112 | 0x28980 | 0x1795B4 | 0x28978 | 0x0C | Smallest utility (12 bytes) |

### VM Introspection (4)

| # | Wrapper PC | CV Target  | Func Start | Size | Description |
|---|-----------|------------|------------|------|-------------|
| 113 | 0x9E400 | 0x5A3048 | 0x9E400 | 0x00 | Near end of __text, bare branch |
| 114 | 0x9FC34 | 0x36C170 | 0x9FC34 | 0x00 | Near end of __text, bare branch |
| 115 | 0xA0528 | 0x36CA64 | 0xA0528 | 0x00 | Near end of __text, bare branch |
| 116 | 0xB3A54 | 0x29A5E4 | 0xB3A54 | 0x00 | At very end of __text, bare branch |

## Structural Observations

### Wrapper Anatomy

All 116 wrappers are **fully virtualized** -- every wrapper's native body is a single
ARM64 `b` instruction into the CV region. There is zero native prologue (no register
saves, no BL calls, no stack frame). The containing function (identified by IDA)
wraps this branch in a small frame (12-84 bytes) that saves callee-saved registers
and passes arguments, then falls through to the `b` instruction.

Only 3 wrappers perform any native work before entering CV:
- **0x1AF4C** (event_callback): calls `sub_1AFD0` to prepare event data
- **0x1B178** (threading): calls `sub_4C93C` to lock a pthread mutex
- **0x4E6D8** (io_file): calls `sub_4E88C` for I/O pre-processing

### Vtable Mapping

27 wrappers are referenced from vtable data structures:

| Vtable Base | Object Type               | Wrapper Count |
|-------------|---------------------------|---------------|
| B42A8       | Service context (0x2B20)  | 2             |
| B4328       | Service subsystem         | 1             |
| B4348/B4350 | Integrity checker         | 2             |
| B4F48-B5078 | Connection protocol       | 17            |
| B5228/B5270 | Detection objects         | 2             |
| B5478       | Worker object             | 1             |
| Other       | Local data refs           | 2             |

### Connection Protocol Dual-Interface

The connection_protocol cluster (0x40000-0x42B0C) has a distinctive dual-vtable
pattern: 7 methods appear in both vtable B4F9x and B503x. This likely represents
two protocol implementations sharing the same method signatures (e.g. TLS-wrapped
vs direct socket, or protocol version A vs B). This matches the string evidence:
`"NoConnectionResetV2A"` through `"NoConnectionResetV2E"` suggests multiple
connection reset strategies, and `"CONNECT %s:%d HTTP/1.1"` indicates HTTP CONNECT
proxy tunneling.

### Address Range Clusters

| Range          | Dominant Category     | Count |
|----------------|----------------------|-------|
| 0x3800-0x4C00  | Initialization       | 6     |
| 0x6200-0x7D80  | Network send/recv    | 12    |
| 0xD600-0xFB00  | Crypto/TLS           | 7     |
| 0x10500-0x12F50 | Service context      | 11    |
| 0x13900-0x14800 | Integrity scan       | 10    |
| 0x15F00-0x19900 | Detection            | 10    |
| 0x1AA00-0x1E100 | Event/callback       | 13    |
| 0x3BE00-0x42B10 | Connection protocol  | 19    |
| 0x44800-0x4F700 | Threading + I/O      | 22    |
| 0x9E400-0xB3A60 | VM introspection     | 4     |

### CV Target Distribution

CV targets range from 0xCC864 to 0x5A3048 within the CV region (0xCC000-0x644000).
Two wrappers have notably distant targets (0x591098, 0x5A3048), suggesting large
or complex VM programs. The median CV target is around 0x150000.
