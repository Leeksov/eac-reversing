# 12 - Runtime Behavior (Extended Trace Analysis)

## Summary

Extended Unicorn emulation of the EAC in-game service (`eac_service_decoded.dylib`)
reveals that the service uses a **cooperative single-threaded model** with no worker
threads. The game engine drives the service by calling two exports:

| Export | Address  | Role |
|--------|----------|------|
| `_x`   | 0x1B664  | One-time initialization |
| `_y`   | 0x1B744  | Tick/poll (called each game frame) |

## Thread Creation

**No threads are created.** Neither `_x` nor `_y` calls `pthread_create`. The binary
imports `pthread_create` and `pthread_join` but they are never invoked during:

- Full `_x` initialization (~6.7M instructions)
- Any subsequent `_y` tick call (~138K instructions each)
- Repeated `_y` invocations (tested 5 consecutive calls)

The 52 mutexes and 14 condition variables initialized during `_x` exist to
protect shared state in a model where the game engine might call vtable methods
from different threads -- but the service itself never spawns threads.

## _x Initialization (Complete Trace)

The `_x` function runs to completion after ~6.7M emulated instructions. Prior
reports of an "instruction limit" stop were a harness artifact: Unicorn's
`until` address parameter causes `emu_start` to return silently when the
function's `ret` instruction sets PC to the STOP sentinel, without the code
hook firing to update the stop reason.

### Init Sequence

1. **Guard check** -- Atomic CAS at 0xbec54 prevents re-initialization
2. **Allocate context** -- `operator new(0x2B20)` = 11,040 bytes
3. **Constructor** (0x10850 -> 0x106e0) -- Sets vtable, initializes sub-objects:
   - 52 recursive mutexes (`pthread_mutexattr_settype(RECURSIVE)`)
   - 14 condition variables
   - Sub-objects at offsets +0x1C38, +0x1E90, +0x2090, +0x22A8, +0x24A8,
     +0x26B0, +0x27B8, +0x29D0, +0x29E0, +0x2AE0
4. **Store globals** -- Context pointer saved to 0xbec58 and 0xc1278
5. **Read entropy** -- Two `fopen`/`fread` calls fill 128-byte crypto seeds
   at context offsets +0x0228 and +0x0C00
6. **Configure DTLS** -- 312-byte session structures at +0x0618 and +0x0FF0
   contain mbedTLS handshake parameters (buffer size 0x2710 = 10000, 14
   cipher suites, 48-byte session state)
7. **Register metadata** -- Copies 5 GUIDs from the init block, stores PID
   (via `getpid`), reads `CGEventSourceCounterForEventType(1, 5)` for
   keystroke count, snapshots `gettimeofday`
8. **Return 0** -- Writes status to `[adrp(0xbe000) + 0xC50]`, returns success

### Return Value

`_x` returns `w0 = 0` (loaded from `[0xbec50]`). The value at this address
is the service status code, initialized to 0 by the `str wzr` at the function
prologue.

## _y Tick Function

`_y` is a lightweight poll function:

```
_y:
    stp x29, x30, [sp, #-0x10]!
    bl  0x109fc          ; load context ptr from 0xc1278
    ldp x29, x30, [sp], #0x10
    b   0x12770          ; tail-call into main dispatch
```

### 0x109fc -- Context Loader

A two-instruction function (`nop; ldr x0, #0xc1278; ret`) that returns the
global context pointer in x0.

### 0x12770 -- Main Dispatch (CV-Protected)

```
0x12770: sub sp, sp, #0x60
         ...
         mov x19, #0xecd1        ; obfuscation key A
         movk x19, #0x76f4, lsl #16
         movk x19, #0x1cd9, lsl #32
         movk x19, #0x9d7f, lsl #48
         mov x20, #0xd3df        ; obfuscation key B
         movk x20, #0x13b, lsl #16
         movk x20, #0xcd43, lsl #32
         movk x20, #0x179d, lsl #48
         stur wzr, [x29, #-0x24] ; clear status
         b 0x14bc50              ; enter CV region
```

The function enters the Code Virtualizer region at 0x14bc50 with two 64-bit
obfuscation keys. Inside the VM, it runs a state machine that:

1. Checks connection state (at context +0x26A8)
2. Calls `_dladdr(0xe6ec, ...)` -- integrity check on a code address
3. Polls for pending network data (none in emulation)
4. Returns with `stur wzr, [x29, #-0x24]` (status = 0)

Each tick is deterministic: exactly 138,030 instructions, producing one
`_dladdr` stub call and no other external calls.

### Repeated Tick Behavior

Five consecutive `_y` calls produce identical results:

```
_y[0]: steps=138030, threads=0, stubs=[_dladdr:1]
_y[1]: steps=138030, threads=0, stubs=[_dladdr:1]
_y[2]: steps=138030, threads=0, stubs=[_dladdr:1]
_y[3]: steps=138030, threads=0, stubs=[_dladdr:1]
_y[4]: steps=138030, threads=0, stubs=[_dladdr:1]
```

Without network I/O, the tick function is a no-op polling loop.

## Post-Init Context State

The 0x2B20-byte context at heap address 0x20010400:

| Offset | Size | Content |
|--------|------|---------|
| +0x0000 | 8 | Vtable pointer (0xb42a8) -- 20 methods |
| +0x0008 | 8 | Sub-vtable (0xb4178) |
| +0x0070 | 1 | Init-complete flag (0x01) |
| +0x0218 | 1 | Config flags (0x40) |
| +0x0228 | 128 | Crypto seed A (from fread) |
| +0x02F0 | 32 | Ring buffer header A |
| +0x0618 | 312 | DTLS session state A (mbedTLS config) |
| +0x0760 | 16 | Session ID A |
| +0x0778 | 52 | Cipher suite config A |
| +0x0C00 | 128 | Crypto seed B (from fread) |
| +0x0CC8 | 32 | Ring buffer header B |
| +0x0FF0 | 312 | DTLS session state B (mbedTLS config) |
| +0x1138 | 16 | Session ID B |
| +0x1150 | 52 | Cipher suite config B |
| +0x1420 | 4 | Stack canary fragment |
| +0x1538 | 28 | Timer/scheduler state |
| +0x15CA | 10 | Network config (float 0x3F80 = 1.0f) |
| +0x1E90 | 8 | Queue vtable (0xb54a8) -- 6 methods |
| +0x2090 | 8 | Queue vtable (0xb54a8) |
| +0x22A8 | 8 | Queue vtable (0xb54a8) |
| +0x24A8 | 8 | Queue vtable (0xb54a8) |
| +0x26A8 | 4 | **Connection state: 0x05 (idle)** |
| +0x26B0 | 8 | Self-pointer (0x20010400) |
| +0x27B8 | 8 | Task manager vtable (0xb49e0) -- 2 methods |
| +0x2A28 | 6 | Mode string: "local" |
| +0x2A3F | 1 | GUID count: 5 |

### Dual DTLS Sessions

The context contains two parallel session structures (A at +0x0618, B at
+0x0FF0) with identical configurations but different crypto seeds. This
maps to the EAC dual-channel architecture:

- **Channel A**: Client-to-server anti-cheat reports
- **Channel B**: Server-to-client challenge/response

Both use the same parameters: buffer size 10000, 14 cipher suites, DTLS 1.2.

## Vtable at 0xb42a8 (20 Methods)

| Index | Address | Signature / Role |
|-------|---------|------------------|
| 0  | 0x109e4 | Destructor helper (jumps to 0x10854) |
| 1  | 0x109e8 | Full destructor (dtor + free) |
| 2  | 0xc4f0  | `process_message(ctx, data, callback)` -- parses incoming message |
| 3  | 0x1192c | State machine entry (-> CV at 0x15fce0) |
| 4  | 0x13680 | `is_connected()` -- returns `(state & 0xDF) == 0x11` |
| 5  | 0xd818  | `get_network_ctx()` -- returns `ctx + 0x1AC0` |
| 6  | 0xc6cc  | `format_message(ctx, str, out)` -- string encode |
| 7  | 0x13694 | Connection management |
| 8  | 0xd828  | Data accessor |
| 9  | 0x1395c | Status query |
| 10 | 0x149c4 | Session management |
| 11 | 0x11cb8 | Event handler |
| 12 | 0x149cc | Timer/scheduler |
| 13 | 0x11cb0 | Notification handler |
| 14 | 0xd848  | No-op (ret) |
| 15 | 0xd84c  | No-op (ret) |
| 16 | 0x11ba0 | `send_receive(ctx, cmd, data)` (-> CV at 0xf9724) |
| 17 | 0x13954 | Query method |
| 18 | 0xd858  | `get_version()` -- returns 2 |
| 19 | 0x13838 | Cleanup/reset |

### Connection State Machine

Vtable method [4] at 0x13680 reveals the connection state encoding:

```arm64
ldr   w8, [x0, #0x26a8]     ; load state
and   w8, w8, #0xffffffdf    ; clear bit 5
cmp   w8, #0x11              ; compare to 0x11 (connected)
cset  w0, eq                 ; return 1 if connected
```

Current state = 0x05 (idle). Connected state = 0x11 or 0x31 (bit 5 is a
"secure" flag). State transitions would occur during DTLS handshake.

## Requirements for Runtime Loop Activation

For the service to progress beyond idle polling, these conditions must be met:

### 1. Network Socket Creation
The binary imports `_socket`, `_connect`, `_send`, `_recv`, `_poll` but none
are called. The DTLS handshake initiation is gated on a trigger from the
game engine (likely via vtable[2] `process_message` or vtable[7]).

### 2. Server Endpoint
The service needs an EAC backend endpoint. The game provides this via the
callback function (registered at init block +0x0C). The callback is invoked
with event codes; one of these presumably provides the server address.

### 3. Session Token
The 5 GUIDs passed during `_x` init (game ID, session tokens) must be valid
for the backend to accept the DTLS handshake.

### 4. Game-Driven State Transition
The service is entirely game-driven. The game must:
1. Call `_x` to initialize
2. Feed connection parameters via the callback or vtable[2]
3. Call `_y` repeatedly -- the tick function handles DTLS handshake progression
4. Once connected (state 0x11/0x31), `_y` processes anti-cheat challenges

### 5. Harness Requirements for Extended Emulation
To emulate the runtime loop, the harness would need:
- A model for `_socket`/`_connect` that simulates a network peer
- A DTLS server stub that completes the mbedTLS handshake
- Simulated callback invocations with connection parameters
- A model for `_recv` that provides anti-cheat challenge data

## Anti-Tamper Observations

The `_y` tick calls `dladdr(0xe6ec, ...)` on every invocation. Address
0xe6ec is inside the binary's `__TEXT` segment. This is an integrity
verification: `dladdr` returns the Dl_info struct with the module's base
address and loaded path, allowing the service to verify it hasn't been
detached or remapped.

The `CGEventSourceCounterForEventType(kCGEventSourceStateCombinedSessionState,
kCGEventKeyUp)` call during init captures the current keystroke count, likely
used as an activity baseline for input monitoring.

## Harness Bug Fix

The original trace reports showed `stop_reason: "instruction limit"` even
though `_x` completed normally. Root cause: Unicorn's `emu_start(entry, STOP,
count=N)` stops emulation when PC reaches the `until` address (STOP) **without
executing the instruction there**. The on_code hook never fires for STOP, so
`stop_reason` is never updated from its default. The `_x` function in fact
returns successfully after ~6.7M instructions with return value 0.
