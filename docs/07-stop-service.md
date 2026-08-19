# stop_service Decompilation

Annotated decompilation of the `_y` export, the service shutdown entry point. This function tears down the EAC service runtime initialized by `_x`. The effect trace covers **0 import calls** across **60,073 ARM64 instructions** -- the entire shutdown sequence is Code Virtualizer-protected.

---

## Native Wrapper

`_y` is a 5-instruction native trampoline at `0x1B744`:

```c
void y(void) {
    void *ctx = get_singleton();   // sub_109FC -> reads qword_C1278
    shutdown_service(ctx);          // sub_12770 -> enters CV at 0x14BC50
}
```

### sub_109FC -- Singleton Accessor

Returns the global context pointer stored at `qword_C1278`. This is the same 0x2B20-byte allocation created by `_x` during Phase 2 of startup. Called from 12 sites across the binary -- every service method reads the singleton through this accessor.

### sub_12770 -- Shutdown Entry

Loads two CV dispatch keys into callee-saved registers and tail-branches into the Code Virtualizer region:

| Register | Value | Purpose |
|----------|-------|---------|
| X19 | `0x9D7F1CD976F4ECD1` | CV handler key A |
| X20 | `0x179DCD43013BD3DF` | CV handler key B |

Target: `B 0x14BC50` (inside `__CV_hidden` segment).

---

## Emulation Strategy

The shutdown function requires a live context from `_x`. A two-phase approach was used:

1. **Phase 1**: Run `_x` for 5M instructions to initialize the context. After this budget, `qword_C1278` holds `0x20010400` (heap-allocated context with vtable at `off_B42A8` and 3 sub-structure pointers initialized). `_x` does not fully return within 5M steps, but context construction completes early.

2. **Phase 2**: Run `_y` from `0x1B744`. The emulator needs one CAS spin-loop bypass (see below), after which `_y` returns cleanly in 60K steps.

### CAS Spin at 0xC414C

The virtualized code performs a `compare_exchange_strong` on a CV-internal atomic flag at address `0xC414C`:

```
ldaxr   w12, [x9]          ; load current value from 0xC414C
cmp     w12, w8             ; compare with expected (0)
b.ne    retry               ; if != 0, spin
stlxr   w11, w3, [x9]      ; store new value (1)
cbz     w11, done           ; if store succeeded, continue
b       retry
```

| Field | Value |
|-------|-------|
| Address | `0xC414C` (in `__CV` data segment) |
| Expected | `0x0` (service running) |
| New value | `0x1` (shutting down) |
| Current at trace time | `0x1` (set during `_x` init, never cleared because `_x` did not complete) |

In a live process, the flag would be `0` after `_x` finishes initialization, and `_y` would CAS it to `1` on the first attempt. In the emulator, `_x`'s partial execution left the flag at `1`, creating an infinite spin. Forcing the CAS after 5 attempts allows `_y` to proceed.

---

## Trace Results

| Metric | Value |
|--------|-------|
| Total instructions | 60,073 |
| Unique PCs executed | 26,665 |
| Native (non-CV) PCs | 35 |
| CV-region PCs | 26,630 |
| Import/stub calls | **0** |
| Threads spawned | 0 |
| Memory allocated | 0 bytes |
| Memory freed | 0 bytes |
| Stop reason | Returned from entry |

---

## Behavioral Analysis

### What _y Does

1. **Reads the singleton** context pointer from `qword_C1278`.
2. **Enters CV** at `0x14BC50` with the context pointer in X0.
3. **Atomically sets** the shutdown flag at `0xC414C` from 0 to 1.
4. **Executes 26,630 unique CV-region addresses** -- the virtualized shutdown logic.
5. **Returns** to the caller.

### What _y Does NOT Do

- Does not call `free()` or `operator delete` -- no heap deallocation.
- Does not call `pthread_join()` or `pthread_cancel()` -- no thread teardown.
- Does not call `pthread_mutex_destroy()` or `pthread_cond_destroy()`.
- Does not call `close()` or `fclose()` -- no file descriptor cleanup.
- Does not call `munmap()` or `vm_deallocate()`.
- Does not zero or modify the context structure at `0x20010400`.
- Does not clear the singleton pointer at `qword_C1278`.
- Does not reset the init-once guard at `byte_BEC54`.

### Interpretation

The shutdown is **flag-based, not resource-based**. `_y` sets a "shutting down" flag and performs virtualized state transitions (26K unique PCs worth of CV logic), but delegates all actual resource cleanup to process exit. This is consistent with the anti-cheat use case:

- The EAC service runs for the lifetime of the game process.
- When the game exits, the OS reclaims all memory, threads, and file descriptors.
- The only purpose of `_y` is to signal the service to stop its internal state machine so that no further anti-cheat checks are dispatched.
- The entire shutdown path is CV-virtualized to prevent reverse engineers from understanding the state machine transitions.

---

## Contrast with _x (start_service)

| Aspect | `_x` (start) | `_y` (stop) |
|--------|--------------|-------------|
| Native code | ~224 bytes | 20 bytes |
| Import calls | 353 | 0 |
| Instructions traced | ~6.7M (incomplete) | 60K (complete) |
| Unique PCs | 84,430 | 26,665 |
| Memory allocated | 0x2B20 + sub-allocs | None |
| Threads created | 10 work queues | None |
| Mutexes initialized | 52 | None destroyed |
| Files opened | 2 (`/dev/urandom`) | None |
| Crypto operations | DH key exchange x2 | None |
| Returns within budget | No (5M limit) | Yes (60K steps) |

---

## Key Addresses

| Symbol | Address | Description |
|--------|---------|-------------|
| `_y` entry | `0x1B744` | Export: stop_service |
| `sub_109FC` | `0x109FC` | Singleton accessor (returns `qword_C1278`) |
| `sub_12770` | `0x12770` | Shutdown CV wrapper |
| CV entry | `0x14BC50` | Virtualized shutdown handler |
| `qword_C1278` | `0xC1278` | Singleton context pointer (global) |
| Shutdown flag | `0xC414C` | Atomic CAS target in `__CV` segment |
| CV key A | `0x9D7F1CD976F4ECD1` | Loaded into X19 by sub_12770 |
| CV key B | `0x179DCD43013BD3DF` | Loaded into X20 by sub_12770 |

---

## Harness

The two-phase trace harness is at `tools/trace_y_twophase.py`. Usage:

```bash
python3 tools/trace_y_twophase.py devirt/eac_service_decoded.dylib \
    --max-x 5000000 --max-y 5000000
```

Report output: `/tmp/svc_y_twophase_report.json`
