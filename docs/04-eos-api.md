# EOS AntiCheat SDK API

## Overview

54 exports decompiled across the Client and Server interfaces. The SDK uses a layered dispatch architecture to route API calls into the EAC engine.

## Dispatch Architecture

All public API functions follow the same dispatch chain:

```
thunk --> null-guard --> interface vtable --> EAC engine (this+728)
                                         \-> fallback fn-ptrs (this+512..704)
```

When the engine pointer at `this+728` is null (i.e., EAC has not been loaded yet), calls fall through to a bank of function pointers stored at offsets `this+512` through `this+704`. These fallbacks return error code **16**, indicating the engine is not available.

## Client VTable Resolution

The client vtable lives at `0x15D9E00`. IDA cannot resolve it automatically because the binary uses chained fixups (`DYLD_CHAINED_PTR_64`). The correct resolution formula is:

```
target = raw & 0xFFFFFFFFF    (when bit63 == 0)
```

Without applying this fixup logic, IDA shows garbage pointers for all vtable entries.

## Engine Load Point

The key function that triggers EAC service loading is `AddNotifyClientIntegrityViolated` at address `0x5630E4`.

### Load sequence

1. Calls `sub_563D5C` (handoff parser).
2. Scans `~/Library/Caches/com.epicgames.easyanticheat/` for the service container.
3. Parses the container file (magic `0xE6ACC57F`).
4. Deobfuscates the payload using the codec formula.
5. Writes the result to a `.tmp` dylib on disk.
6. Loads the dylib via `dlopen`.

After `dlopen` succeeds, the engine pointer at `this+728` is populated and all subsequent API calls route through the real engine vtable.

## Client Interface Entries

24 client interface entries have been decoded. Each entry consists of three addresses:

| # | Role | Description |
|---|------|-------------|
| 1 | Thunk | Public symbol exported from the framework |
| 2 | VTable slot | Pointer in the client vtable at `0x15D9E00` |
| 3 | Implementation | Actual logic inside the EAC engine or fallback |

All 24 entries follow the same null-guard dispatch pattern described above.
