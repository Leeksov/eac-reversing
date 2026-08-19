# EAC In-Game Service

## Overview

The in-game service is decoded from the embedded image inside the bootstrapper using the container codec. It is a valid Mach-O arm64 dynamic library, 6.6 MB in size.

**Install name**: `../Bin/easyanticheat_mac_arm64.eac.ingame.tmp`

## Exports

| Symbol | Address    | Purpose                                   |
|--------|-----------|-------------------------------------------|
| `_x`   | `0x1B664` | Init/start entry point (v1 argument block)|
| `_y`   | `0x1B744` | Stop/shutdown                             |

## Context Struct

The service maintains a singleton context structure:

| Property        | Value / Location          |
|----------------|---------------------------|
| Size           | `0x2B20` bytes (11,040)   |
| Vtable         | `off_B42A8`               |
| Singleton      | `qword_C1278`             |
| Magic          | `0x43F6DDBA0E9721AF`      |

## Worker Queues

Five worker queues are embedded within the context struct, all sharing vtable `off_B54A8`:

| Queue | Context Offset |
|-------|---------------|
| 1     | `0x1C78`       |
| 2     | `0x1E90`       |
| 3     | `0x2090`       |
| 4     | `0x22A8`       |
| 5     | `0x26A8`       |

Callback list is located at context offset `0x26B0`.

## CV Wrappers

116 CV (Code Virtualization) wrappers are catalogued in `svc_cv_wrappers.json`.

## VM Table

The service has its own 26-opcode virtual machine with a per-build encoded dispatch table:

```
02 03 07 0C 0D 11 20 2C 2E 33 44 6E 83 85 8F 93
A3 B5 BC BE C4 D7 E1 EE FA FE
```

## __CV Segments

Two custom segments carry the virtualized code:

| Segment  | Address    | Size   | Purpose                                |
|----------|-----------|--------|----------------------------------------|
| `__CV_0` | `0xC4000` | 8 KB   | Dispatch table: 247 paired entries     |
| `__CV_1` | `0xCC000` | 5.5 MB | Handler bytecode referenced by `__CV_0`|

The dispatch table in `__CV_0` contains 247 paired entries, each pointing to a handler in `__CV_1`.

## Threading Model

| Function       | Role                    |
|---------------|-------------------------|
| `sub_4CA44`   | Job loop                |
| `sub_4CBBC`   | Thread start routine    |
| `sub_4408`    | Starter (called from VM)|
| `sub_5DE4`    | Starter (called from VM)|
| `sub_43928`   | Starter (called from VM)|
| `sub_4F860`   | Starter (called from VM)|

## Arsenal

The service employs the following detection and integrity mechanisms:

### System Introspection
- `task_for_pid` -- process task port acquisition
- `proc_*` -- process information queries
- `vm_region_64` -- virtual memory region inspection
- `csops` -- code signing status checks
- `csr_get_active_config` -- SIP (System Integrity Protection) status

### Integrity
- X.509 certificate chain with subject **"Anti-Cheat Integrity CA"**
- Encrypted RSA PEM key material
- Hash catalogue for known-good validation

### Detection
- VM detection (hypervisor/virtualization checks)
- `CGEventSourceCounterForEventType` -- input event monitoring

### Communication
- Socket-based channel for client-server communication
