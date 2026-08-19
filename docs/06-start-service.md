# start_service Decompilation

Annotated decompilation of the `_x` export, the service entry point. This function initializes the entire EAC service runtime. The effect trace covers **353 import calls** across **6.7 million ARM64 instructions**.

---

## Phase 1: Argument Validation

The function receives a configuration struct and validates it before proceeding.

- `size >= 0x14` -- rejects undersized input structs.
- `version <= 2` -- only protocol versions 0, 1, and 2 are accepted.
- `flags == 1` -- exactly one flag bit must be set.
- **Atomic one-shot guard:** a `casalb` (compare-and-swap with acquire-release semantics) ensures the function can only be called once per process lifetime. If the guard byte is already set, the function returns immediately.

## Phase 2: Context Allocation

Allocates the main service context: **0x2B20 bytes**.

Initialization includes:
- Writing the vtable pointer at the base of the context.
- Constructing sub-objects at known offsets within the allocation.
- Zeroing out state fields.

## Phase 3: Channel A Initialization

Sets up the first encrypted communication channel.

1. Clear all channel state to zero.
2. Seed from `/dev/urandom` -- reads **128 bytes** of entropy.
3. Diffie-Hellman key exchange using **RFC 3526 Group 14** (2048-bit MODP):
   - Prime: `FFFFFFFF...C90FDAA2...` (full 2048-bit value from the RFC).
   - Generator: `02`.
4. Assemble the session key from the random seed combined with timestamps.

## Phase 4: Channel B Initialization

Identical to Channel A. A second independent encrypted channel is established using the same DH parameters but fresh random material.

## Phase 5: Timing Subsystem

- Protected by its own guard (prevents re-initialization).
- Calls `steady_clock::now()` to capture the baseline timestamp for all subsequent timing operations.

## Phase 6: Worker Threads

Creates **10 work queues**, each provisioned with:

- 3 mutexes
- 1 condition variable

Additionally, shared synchronization primitives are allocated. Totals across the entire worker pool:

| Resource | Count |
|----------|-------|
| Mutexes | 52 |
| Condition variables | 14 |

## Phase 7: GUID Storage

Copies three GUIDs from the input arguments into global storage:

- **Product GUID**
- **Sandbox GUID**
- **Deployment GUID**

These are used in all subsequent communications with the EAC backend.

## Phase 8: Client ID Formatting

Formats a client identification string using `vsnprintf`. The resulting string is exactly **37 characters** long (standard UUID format).

## Phase 9: System Fingerprint

Collects host-specific data for anti-cheat telemetry:

- `getpid()` -- current process ID.
- `CGEventSourceCounterForEventType(1, 5)` -- HID input event count (measures whether user input devices are present and active).
- `gettimeofday()` -- wall clock timestamp.

## Phase 10: Telemetry Buffer

Assembles a telemetry payload from the fingerprint data:

- Process ID
- Input event count
- Timestamps (both steady clock and wall clock)
- Nonce values derived from the DH exchange

## Phase 11: Environment Check

Calls `getenv()` to inspect environment variables. The specific variables checked are used to detect debugging or instrumentation tools.

## Phase 12: Return

Returns a status code indicating success or the specific validation/initialization step that failed.
