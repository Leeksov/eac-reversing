# 14 - Self-Protection and Environment Hardening

Analysis of the anti-debug, code integrity, and environment hardening mechanisms
in `eac_service_decoded.dylib`. This document covers the self-protection layer
that wraps the detection capabilities documented in `09-detection-capabilities.md`.

---

## 1. Anti-Debug Mechanisms

### ptrace Import -- Dead or Runtime-Resolved

The binary imports `_ptrace` (stub at `0x9cd88`, GOT at `0x644580`), but static
analysis reveals **zero call sites**. No function in the binary issues a BL to the
ptrace stub, and no `SVC #0x80` instructions exist for direct syscall invocation.

All eight MOV #0x1F (PT_DENY_ATTACH = 31) occurrences were analyzed and confirmed
as false positives:

| Address | Function | Actual Purpose |
|---------|----------|----------------|
| 0x27a18, 0x27a78 | sub_279A8 | LZW compression -- 0x1F is a stream byte |
| 0x2b708 | sub_2B6A0 | mbedtls error code mapper -- 31 is an error category |
| 0x3ba8c | sub_3ABB4 | String decryption table -- 0x1F is an opcode parameter |
| 0x54cc8 | sub_54C2C | mbedtls debug bignum printer -- bit iteration counter |
| 0x7ff04 | sub_7FDB4 | mbedtls RSA key generation -- 31-iteration loop |
| 0x82bd8 | sub_82B58 | mbedtls RSA key generation -- 31-iteration loop |
| 0x85adc | sub_85A5C | mbedtls bignum operation -- shift amount |

The ptrace import likely serves one of two purposes:

1. **Runtime-resolved via dlsym**: The binary imports `dlsym` and could resolve
   `ptrace` dynamically, bypassing static analysis. This is a common anti-analysis
   technique -- the import table entry acts as a decoy while the real call goes
   through `dlsym(RTLD_DEFAULT, "ptrace")` inside virtualized code.

2. **Dead import from linked library**: The import may originate from the mbedtls
   or another statically-linked library and is simply never called.

### Virtualized API Dispatch

The most significant anti-debug finding is architectural: **all security-sensitive
API calls are routed through the Code Virtualizer VM**. No import stub in the
binary has direct callers from application code. The GOT pointers at `0xbc000`-
`0xbd000` are only referenced by their corresponding PLT stubs, which themselves
have no callers.

This means:
- Breakpoints on import stubs will never fire through normal execution
- Call-graph analysis cannot link security APIs to their consuming functions
- Static analysis of the anti-debug flow requires full devirtualization

The VM dispatch mechanism was confirmed through exhaustive scanning: iterating
all 3,244 functions and all code references from every instruction produced zero
BL instructions targeting any import stub address.

### signal / alarm -- mbedtls Timing, Not Anti-Debug

The `_signal` and `_alarm` imports are used exclusively by the embedded mbedtls
timing self-test subsystem:

```
sub_970C4: signal(SIGALRM=14, handler); alarm(seconds);
sub_970FC: SIGALRM handler -- sets flag, re-registers itself
sub_971F8: mbedtls timing self-test ("TIMING test #1...")
```

These functions have **zero callers** in IDA's analysis, meaning they are either
dead code from the mbedtls library or invoked through virtualized dispatch only
during initialization. They are not a watchdog timer or crash handler for
anti-debug purposes.

---

## 2. Code Integrity Verification

### dladdr Per-Tick Integrity Check

The runtime behavior analysis (doc 12) confirms that every `_y` tick call invokes
`dladdr(0xe6ec, ...)` from within the VM. This is a **function pointer integrity
check**: by calling `dladdr` on a known code address, EAC verifies that:

1. The address still maps to the expected module (eac_service_decoded.dylib)
2. No hook/trampoline has redirected the function to a different image
3. The memory region is still backed by the legitimate binary

The consistency of this check -- exactly one `dladdr` call per tick across all
five measured ticks (138,030 instructions each) -- indicates it is a mandatory
polling operation, not conditional on any state.

### csops Code Signing Validation

The `_csops` import (stub at `0x9c9ec`) provides access to the macOS code signing
syscall. Through virtualized dispatch, EAC can:

- Query `CS_OPS_STATUS` to verify the process has valid code signing
- Retrieve `CS_OPS_CDHASH` for the code directory hash
- Detect if the binary has been modified post-signing (invalid signature)
- Check entitlement flags

The X.509 key usage parser at `sub_8A774` recognizes the `id-kp-codeSigning` OID,
confirming that the certificate infrastructure validates code-signing certificates
as well as TLS server certificates.

### Memory Protection Operations

Three memory protection imports exist, all called through virtualized dispatch:

| Import | Wrapper | Direct Callers | Purpose |
|--------|---------|----------------|---------|
| `_mprotect` | sub_4E580 (0x4E580) | Zero | Page-aligned mprotect with old-prot output |
| `_vm_protect` | stub at 0x9cf38 | Zero | Mach VM protection changes |
| `_vm_region_64` | stub at 0x9cf44 | Zero | Memory region attribute queries |

**sub_4E580** is the only analyzable wrapper. It:
1. Aligns the target address down to the 4KB page boundary
2. Rounds the size up to the page boundary
3. Calls `mprotect(aligned_addr, aligned_size, protection)`
4. Optionally outputs the previous protection flags
5. Runs a pre-hook (`sub_4E1CC`) that jumps into the VM at `0xF7D90` for validation

The pre-hook into the VM before every mprotect call suggests EAC validates that
protection changes are authorized before applying them.

**sub_4E920** acquires its own task port via `task_for_pid(mach_task_self(), getpid(), &port)`.
This port is likely passed to `vm_protect` and `vm_region_64` inside the VM,
enabling Mach-level memory inspection that cannot be intercepted by POSIX-layer
hooks.

---

## 3. Thread Priority Hardening

### SCHED_FIFO Real-Time Elevation

EAC elevates its threads to **SCHED_FIFO (real-time FIFO)** scheduling with three
internal priority tiers:

| Level | Priority Value | Meaning |
|-------|---------------|---------|
| 0 | `sched_get_priority_min(SCHED_FIFO) + 12` | Normal |
| 1 | `sched_get_priority_min(SCHED_FIFO) + 16` | Medium |
| 2 | `sched_get_priority_max(SCHED_FIFO)` | Maximum |

Three setter functions implement this:

- **sub_4CD14** (0x4CD14): Sets priority for the current thread (`pthread_self()`)
- **sub_4CD7C** (0x4CD7C): Binary choice (level 0 or 1) for the current thread
- **sub_4CDD8** (0x4CDD8): Sets priority for an explicit `pthread_t` handle

All three call `pthread_setschedparam(thread, SCHED_FIFO, &param)`. SCHED_FIFO
is the only policy used -- SCHED_RR and SCHED_OTHER are never passed.

SCHED_FIFO real-time scheduling provides:
- **Preemption resistance**: Anti-cheat threads cannot be starved by a cheat tool
  flooding the scheduler with normal-priority threads
- **Deterministic timing**: Detection checks run with predictable latency, making
  timing-based evasion unreliable
- **Priority inversion prevention**: Critical anti-cheat operations complete
  before lower-priority game or cheat threads can run

### Thread Creation and Priority Assignment

**sub_4408** (0x4408) creates two threads via `sub_4CBBC` (pthread_create wrapper
with entry point `sub_4CA44`), then immediately sets both to priority level 0
(normal FIFO). The priority setters themselves have zero direct callers in IDA,
indicating they are also invoked from within the VM for dynamic priority adjustment.

---

## 4. Mach Semaphore Work Queue

### Custom Spin-Wait Hybrid

EAC implements a bounded work queue (capacity 8) using Mach semaphores with a
Preshing-style spin-then-block pattern:

**Constructor** (sub_28384, 0x28384):
```
semaphore_create(mach_task_self(), &sem, policy=0, value=0)
```
Initializes 8 mutex-protected work slots.

**Wait/Acquire** (sub_28890, 0x28890):
1. Spins for 10,000 iterations attempting atomic CAS decrement
2. On spin exhaustion: performs atomic decrement, then blocks via
   `semaphore_wait(sem)` if count <= 0

**Submit** (sub_284B0, 0x284B0):
Acquires all 8 semaphore slots, copies work data under mutex, signals via
`semaphore_signal`. Called from sub_3CEB8 and sub_3D21C.

**Release** (sub_286F8, 0x286F8):
Unlocks mutex, increments counter, calls `semaphore_signal` if waiters
(flagged by MSB 0x80000000) are present.

This architecture provides high-performance task dispatch with minimal kernel
transitions for the common case (spin succeeds), falling back to Mach
semaphores only under contention.

---

## 5. User Identity Collection

### Home Directory Resolution

**sub_34444** (0x34444, 312 bytes) resolves the user's home directory:

```
1. getuid() -> check if running as root (uid 0)
2. If non-root: getenv("HOME")
3. If root AND issetugid() returns 0:
   - Try getenv("SUDO_UID") -> atoi -> use that uid
   - Try getenv("PKEXEC_UID") -> atoi -> use that uid
4. If HOME is still empty: getpwuid(uid) -> pw_dir
5. Ensure path ends with '/'
```

This function handles the case where EAC runs with elevated privileges (via sudo
or pkexec) by resolving the *original* user's home directory rather than root's.
The home directory is needed for:

- Locating the `EasyAntiCheat/` data directory
- Finding the hash catalogue and certificate store
- Writing per-user configuration or state

### issetugid Safety Check

The `issetugid()` call prevents reading `SUDO_UID`/`PKEXEC_UID` environment
variables when the binary was launched via a setuid mechanism (which could allow
environment variable injection attacks).

### Launcher Directory Resolution

**sub_C6CC** (0xC6CC) resolves the launcher directory by reading the
`EAC_LAUNCHERDIR` environment variable. This is used to locate game files and
the hash catalogue relative to the launcher's installation path.

---

## 6. Connection Resilience Strategies

### NoConnectionResetV2A through V2E

Five connection reset strategy strings exist at sequential addresses:

| Address | String | Strategy |
|---------|--------|----------|
| 0xab141 | `NoConnectionResetV2A` | Strategy A |
| 0xab156 | `NoConnectionResetV2B` | Strategy B |
| 0xab16b | `NoConnectionResetV2C` | Strategy C |
| 0xab180 | `NoConnectionResetV2D` | Strategy D |
| 0xab195 | `NoConnectionResetV2E` | Strategy E |

These strings have **no direct xrefs** from any analyzed code. They reside in
`__cstring` immediately after the actively-referenced protocol error strings,
and are physically contiguous with them. The most likely explanation is that
they are referenced from within the `__CV_hidden` RX segment (0xcc000-0x644000,
~5.6 MB of Code Virtualizer protected code) which cannot be statically analyzed.
They may represent connection state machine states that exist only inside the VM.

The strings appear in a sequential block alongside protocol error types:

```
0xab0e0: MMCorruptedData
0xab0f0: MessageTooSmallA
0xab101: MessageTooLarge
0xab111: MessageTooSmallB
0xab122: CorruptedData
0xab130: MessageTooSmallC
0xab141: NoConnectionResetV2A
...
0xab195: NoConnectionResetV2E
0xab1aa: OnConnect
```

The naming convention (V2 + letter suffix A-E) suggests five progressive
escalation tiers for connection recovery, likely involving:

- **V2A**: Immediate retry with exponential backoff
- **V2B**: Retry with server re-selection
- **V2C**: DNS re-resolution (via the `host -4 %s` fallback)
- **V2D**: Full connection teardown and re-establishment
- **V2E**: Terminal failure / report to game

### Connection Error Dispatch

**sub_6664** (0x6664) handles connection errors by:
1. Storing the error string (e.g., "MMCorruptedData") in the context at offset +5224
2. Calling `sub_7ED8` to evaluate connection state
3. Building a structured message with parameters "N1", "N2", "N3"
4. Encoding the message through the **string decryption table** (sub_3ABB4,
   opcode 17) for transmission
5. Dispatching via `sub_3A70C` with error code 2

### Protocol Message Validation

**sub_6300** (0x6300) validates incoming protocol messages with the following checks:

| Check | Error String | Error Code |
|-------|-------------|------------|
| Message < 12 bytes | MessageTooSmallA | 3 |
| Payload > 1MB (0x100000) | MessageTooLarge | 2 |
| Payload length > buffer | MessageTooSmallB | 4 |
| Payload < 8 bytes after header | MessageTooSmallC | 5 |
| CRC/integrity check fails | CorruptedData | 1 |
| Leading 0 in payload array | MMCorruptedData | 6 |

Failed integrity checks dispatch through `sub_6664` which constructs the
"Corrupted packet flow" error with the specific failure mode appended in
parentheses (e.g., `"Corrupted packet flow (MessageTooSmallA)"`).

### DNS Fallback via popen

**sub_47D44** (0x47D44) implements DNS resolution via shell command execution:

```c
snprintf(cmd, 256, "host -4 %s", hostname);
FILE *f = popen(cmd, "r");
// Reads output, parses last space-separated token as IP
// Calls sub_4FF1C to validate IP format
pclose(f);
```

This is the only `popen` usage in the binary. It serves as a fallback DNS resolver
when the primary `getaddrinfo`-based resolution (sub_47C58) fails. The `-4` flag
forces IPv4-only resolution.

The connection establishment function **sub_47E84** (0x47E84):
1. Tries `getaddrinfo`-based resolution first
2. Falls back to `popen("host -4 %s")` on failure
3. Creates TCP sockets (AF_INET, SOCK_STREAM, IPPROTO_TCP)
4. Sets `SO_NOSIGPIPE` via setsockopt
5. Attempts connection via sub_47A70

---

## 7. Self-Location and Path Verification

### Executable Path Resolution

The `_NSGetExecutablePath` import (stub at `0x9c650`) allows the binary to
determine its own file path at runtime. This serves:

- **Self-integrity checking**: Re-reading the binary from disk to verify it has
  not been modified since loading
- **Path validation**: Ensuring the binary is running from the expected location
  (`../Bin/easyanticheat_mac_arm64.eac.ingame.tmp`)
- **Catalogue location**: The certificate store path is built relative to the
  executable location via the `EasyAntiCheat/Certificates/` directory
  (sub_2BF3C at 0x2BF3C)

### Certificate Path Construction

**sub_2BF3C** (0x2BF3C) builds certificate file paths:
1. Copies the base directory path
2. Appends `"EasyAntiCheat/Certificates/"` (from 0x9f408)
3. Appends additional path components and filename
4. Calls `sub_34044` to verify the constructed path exists

This function is called from **sub_2BB24** (0x2BB24) as part of the certificate
chain loading during initialization.

---

## 8. System Information Collection

### OS Version Fingerprinting

**sub_39F80** (0x39F80) collects OS version information:
```c
os_name = sub_4B42C();     // e.g., "macOS"
os_version = sub_4B620();  // e.g., "14.2"
kernel = sub_4B794();      // e.g., "23.2.0"
snprintf(buf, 64, "%s %s (Kernel %s)", os_name, os_version, kernel);
```

**sub_4B42C** (0x4B42C) uses `sysctl({CTL_HW=6, HW_MACHINE=1})` to determine
the architecture (x86_64 vs arm64) and returns a bitness classification.

### System Metadata Builder

**sub_38DD0** (0x38DD0, 4032 bytes, complexity 61) is a large JSON-like structure
builder that collects comprehensive system metadata. It constructs key-value pairs
using `","` and `":"` separators, building a JSON object with fields including:
- OS version string (from sub_39F80)
- Architecture information
- Hardware identifiers
- Configuration state

This metadata is sent to EAC backend servers during the handshake for server-side
environment validation and analytics.

### SIP Status Check

The `_csr_get_active_config` import queries the System Integrity Protection (SIP)
configuration bitmask. While routed through virtualized dispatch (zero direct
callers), a disabled SIP configuration combined with other environment indicators
triggers the "Forbidden system configuration" error (code 14 in sub_C9F4).

---

## 9. String Obfuscation Table

### sub_3ABB4 -- Runtime String Decryptor

**sub_3ABB4** (0x3ABB4, 4056 bytes, 133 basic blocks, complexity 68) is a
**string decryption table** with 22+ switch cases. Each case:

1. Reads encrypted bytes from data sections (e.g., `byte_A0E68`, `unk_A0E01`)
2. Applies XOR decryption using PRNG sequences (xorshift, LCG, or MADD-based)
3. Constructs a `std::string` via `sub_39D90`
4. Zeroes the plaintext buffer via `memset` (security wipe)

Known callers and their opcodes:

| Caller | Address | Opcode | Context |
|--------|---------|--------|---------|
| sub_6664 | 0x679c | 17 | Connection error messages (N1/N2/N3 parameters) |
| sub_D0A8 | 0xd1d4 | 5 | Protocol messages (N1/S1 parameters) |
| sub_D384 | 0xd4a8 | 6 | One-shot initialization (guarded by `byte_BCCB0`) |

The security wipe after use ensures that decrypted strings have minimal lifetime
in memory, making memory scanning for cleartext strings more difficult.

---

## 10. Error Code Taxonomy

### sub_C9F4 -- Central Violation Dispatch

**sub_C9F4** (0xC9F4, 1244 bytes) maps integer error codes to localized error
strings. The function uses `a2` as a switch value:

| Code | Error Key | Display Message |
|------|-----------|-----------------|
| 0 | (custom string from caller) | (custom) |
| 1 | `game_error.error_catalogue_not_found` | Easy Anti-Cheat Hash Catalogue not found |
| 2 | `game_error.error_catalogue_corrupted` | Corrupt Easy Anti-Cheat Hash Catalogue |
| 3 | `game_error.error_certificate_revoked` | EAC index certificate revoked |
| 4 | `game_error.error_file_version` | Unknown file version |
| 5 | `game_error.error_file_not_found` | Missing required file |
| 6 | `game_error.error_file_forbidden` | Unknown game file |
| 7 | `game_error.error_system_version` | Untrusted system file |
| 8 | `game_error.error_module_forbidden` | Forbidden module |
| 9 | `game_error.error_corrupted_memory` | Corrupted memory |
| 10 | `game_error.error_tool_forbidden` | Forbidden tool |
| 11 | `game_error.error_violation` | Internal anti-cheat error |
| 12 | `game_error.error_corrupted_network` | Corrupted packet flow |
| 13 | `game_error.error_virtual` | Cannot run under Virtual Machine. |
| 14 | `game_error.error_system_configuration` | Forbidden system configuration |
| 15 | `game_error.executable_not_hashed` | Could not locate game executable entry in the catalogue. |

For code 0 (fallback), the function constructs a string using XOR decryption
with seed 789515133 and PRNG multiplier -1140671485, decrypting data from
`unk_9DDEC` to produce "Internal anti-cheat error" as the final fallback.

The error dispatch chain: `sub_C848` -> `sub_C9F4` -> callback to game engine.

---

## 11. Summary of Self-Protection Architecture

### Layered Defense Model

```
Layer 1: VM Dispatch
  All security-sensitive API calls routed through Code Virtualizer
  -> Defeats static analysis, breakpoints on import stubs

Layer 2: Anti-Debug
  ptrace import present but unused statically
  -> Likely called via dlsym inside VM
  -> csops validates code signing integrity

Layer 3: Runtime Integrity
  dladdr called every tick to verify function pointer integrity
  mprotect/vm_protect for memory page protection
  vm_region_64 for memory layout inspection
  All routed through VM dispatch

Layer 4: Thread Hardening
  SCHED_FIFO real-time priority for anti-cheat threads
  Mach semaphore work queue (spin-then-block)
  -> Prevents thread starvation attacks

Layer 5: String Protection
  22-case decryption table (sub_3ABB4)
  XOR + PRNG decryption per string
  Security wipe after use

Layer 6: Environment Validation
  SIP status check (csr_get_active_config)
  VM detection (error code 13)
  System configuration validation (error code 14)
  User identity resolution for path validation

Layer 7: Connection Resilience
  5-tier NoConnectionReset strategy (V2A-V2E)
  DNS fallback via popen("host -4")
  Protocol message integrity (6 validation checks)
  Dual DTLS channels with embedded PKI
```

### Key Functions

| Function | Address | Size | Role |
|----------|---------|------|------|
| sub_C9F4 | 0xC9F4 | 1244 | Error code dispatch |
| sub_C848 | 0xC848 | 428 | Error queue processor |
| sub_3ABB4 | 0x3ABB4 | 4056 | String decryption table (22+ cases) |
| sub_6300 | 0x6300 | 868 | Protocol message validator |
| sub_6664 | 0x6664 | 540 | Connection error handler |
| sub_69F0 | 0x69F0 | 432 | Error callback dispatcher |
| sub_34444 | 0x34444 | 312 | Home directory resolver |
| sub_47D44 | 0x47D44 | 320 | DNS fallback (popen "host -4") |
| sub_4CD14 | 0x4CD14 | 104 | Thread priority setter (self) |
| sub_4CDD8 | 0x4CDD8 | 104 | Thread priority setter (explicit thread) |
| sub_4E580 | 0x4E580 | 164 | mprotect wrapper (page-aligned) |
| sub_4E920 | 0x4E920 | 48 | task_for_pid self-port acquisition |
| sub_28384 | 0x28384 | 1172 | Semaphore work queue constructor |
| sub_28890 | 0x28890 | 112 | Semaphore spin-wait acquire |
| sub_970C4 | 0x970C4 | 56 | mbedtls alarm setup (not anti-debug) |
| sub_39F80 | 0x39F80 | 272 | OS version string builder |
| sub_38DD0 | 0x38DD0 | 4032 | System metadata JSON builder |
| sub_2BF3C | 0x2BF3C | 776 | Certificate path builder |
| sub_8A774 | 0x8A774 | 280 | X.509 key usage OID parser |
