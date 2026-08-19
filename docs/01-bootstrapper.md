# EAC Bootstrapper (macOS arm64)

## Overview

Binary: `mac_arm64.decoded`
Entry export: `a` at `0x35E0`
Full activation path: 40.4 million instructions to `execv(RustClient)`

The bootstrapper validates its environment, decodes configuration and an embedded service image, then hands off to the Rust client via `execv`. The entire activation sequence is trivially bypassable.

## Anti-Debug

- `sysctl` check for `P_TRACED` flag
- On detection: callback **502** with message `"Launch Error: {0}"`
- `ptrace(PT_DENY_ATTACH)` called to prevent future attachment
- `DYLD_INSERT_LIBRARIES` environment variable cleared

## runtime.conf Validation

The **sole predicate** for runtime.conf acceptance is file size >= 1108 bytes (`0x454`). The file content is never checked at the validation gate.

| Size Range   | Result                    |
|-------------|---------------------------|
| 0 -- 510     | Callback **510**, abort   |
| 511 -- 1107  | Callback **510**, abort   |
| >= 1108      | Success                   |

A random file of the correct size produces byte-identical execution traces through the launcher.

### runtime.conf Format

- **File size**: 1108 bytes (`0x454`)
- **Decoder**: per-byte VM, 27,388 instructions per byte, backward diffusion chain

Decoded plaintext layout:

| Offset  | Size       | Content                          |
|---------|-----------|----------------------------------|
| `0x000` | 4 bytes   | Magic `"EAC\0"`                  |
| `0x004` | 254 bytes | Key blob                         |
| --      | 4 bytes   | Counter `0x02AB1EDA`             |
| --      | `0x300`   | Zero-filled padding (768 bytes)  |
| --      | 4 bytes   | Flag u32 = 1                     |
| --      | 4 bytes   | Flag u32 = 1                     |

### Diffusion Properties

- Mutating `in[i]` affects `out[0..i]` (backward diffusion)
- Alternating sign pattern across the diffusion chain
- The VM decoder is behaviorally equivalent to the container codec (see `02-container-codec.md`)

## base.cer

Parsed but **non-fatal** -- failure to load or parse does not block the launch sequence.

## Mbed TLS GCM

Mbed TLS AES-GCM code is present in the binary but **never executes** during the launcher flow.

## PE Gate

The bootstrapper contains a platform gate on the decoded image:

| Target Arch  | Action            |
|-------------|-------------------|
| I386         | `_exit(1)`        |
| AMD64        | `_exit(1)`        |
| Non-PE       | `execv` with args |

On macOS arm64, the decoded image is a Mach-O, so the non-PE path is taken.

## Shared Memory Handoff

The bootstrapper sets up a shared memory region for communication with the launched client.

**Header structure:**

```c
struct shm_header {
    uint32_t version;    // 2
    uint32_t offset;     // 0x328
    // GUIDs follow
};
```

Embedded image size: `0x657AE0` bytes, written into the shared memory region after the header.

## Environment Setup

- `EAC_LAUNCHERDIR` environment variable set to the launcher directory
- `DYLD_INSERT_LIBRARIES` cleared
- `ptrace(PT_DENY_ATTACH)` invoked

### Path Format

Mixed path separators: forward-slash base path with backslash suffix (Windows-style convention carried over to macOS).

## Callback Codes

| Code | Meaning          |
|------|------------------|
| 502  | Anti-debug trip  |
| 510  | Config failure   |
| 1002 | Progress update  |
