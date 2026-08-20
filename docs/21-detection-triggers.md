# 21 - Detection Trigger Harness

Analysis of EAC's detection mechanisms via controlled simulation. The harness
(`tools/trace_detection.py`) extends the two-phase emulation framework to inject
suspicious conditions into stub responses and observe whether the callback fires
with a detection error code.

---

## 1. Harness Design

### Architecture

```
DetectionHarness(TwoPhaseHarness)
    |
    +-- handle_stub() override
    |     |-- scenario-specific interceptors
    |     +-- default passthrough (base behavior)
    |
    +-- on_code() override
    |     +-- CALLBACK interception with error code logging
    |
    +-- run_scenario()
          +-- Phase 1: _x init (0x1B664)
          +-- Phase 2: N x _y ticks (0x1B744)
          +-- Collect: callbacks, detection stubs, per-tick results
```

### Usage

```bash
# Run all scenarios
python3 tools/trace_detection.py path/to/eac_service_decoded.dylib

# Run a specific scenario
python3 tools/trace_detection.py path/to/eac_service_decoded.dylib --scenario vm_detected

# Increase tick count for delayed detections
python3 tools/trace_detection.py path/to/eac_service_decoded.dylib --ticks 10

# Adjust instruction limits
python3 tools/trace_detection.py path/to/eac_service_decoded.dylib --max-x 10000000 --max-y 1000000
```

### Output

The harness produces:
- Console output with per-tick stub calls and callback events
- JSON report at `--output` (default: `/tmp/detection_trace_report.json`)
- Summary table mapping scenarios to triggered error codes

---

## 2. Scenarios

### Scenario 0: Baseline (Clean Run)

No injected conditions. Establishes the expected stub call pattern and confirms
no false-positive callbacks fire during normal _x + _y execution.

Expected: zero callbacks, one `_dladdr(0xe6ec)` per tick.

### Scenario 1: Debugger Attached (`debugger_attached`)

**Trigger**: `_sysctl` with MIB `{CTL_KERN=1, KERN_PROC=14}` returns a
`kinfo_proc` struct with `p_flag | P_TRACED` (0x800) set.

**Mechanism**: The VM-dispatched sysctl call checks the process flags for the
`P_TRACED` bit, which the kernel sets when a debugger is attached via ptrace.

| Field | Value |
|-------|-------|
| Stub | `_sysctl` |
| MIB | `{1, 14}` (CTL_KERN / KERN_PROC) |
| Injected | `kp_proc.p_flag = 0x4804` (P_TRACED set) |
| Expected code | 11 (`game_error.error_violation`) |
| Expected message | Internal anti-cheat error |

### Scenario 2: VM Detected (`vm_detected`)

**Trigger**: Multiple complementary checks:
- `_IORegistryEntrySearchCFProperty` returns "VMware Virtual Platform"
- `_IORegistryEntryCreateCFProperty` returns VM hardware strings
- `_IOServiceGetMatchingService` returns a valid service handle
- `_DADiskCopyDescription` returns "VBOX HARDDISK" as media model
- `_sysctlbyname("kern.hv_vmm_present")` returns 1
- `_sysctlbyname("hw.model")` returns "VMware7,1"

**Mechanism**: IOKit registry queries walk the device tree for hardware model
identifiers. DiskArbitration checks disk controller model strings.
`kern.hv_vmm_present` is a kernel-level hypervisor indicator.

| Field | Value |
|-------|-------|
| Stubs | `_IORegistryEntrySearchCFProperty`, `_sysctlbyname`, `_DADiskCopyDescription` |
| Injected | VM hardware identifiers at multiple levels |
| Expected code | 13 (`game_error.error_virtual`) |
| Expected message | Cannot run under Virtual Machine. |

### Scenario 3: SIP Disabled (`sip_disabled`)

**Trigger**: `_csr_get_active_config` writes `0x27` to the output pointer,
indicating multiple SIP protections are disabled.

**Mechanism**: The CSR config bitmask is queried via the undocumented
`csr_get_active_config` syscall. Non-zero values indicate SIP protections
are disabled -- a common research/analysis environment fingerprint.

| Field | Value |
|-------|-------|
| Stub | `_csr_get_active_config` |
| Injected | CSR flags 0x27 (UNTRUSTED_KEXTS \| UNRESTRICTED_FS \| TASK_FOR_PID \| UNRESTRICTED_DTRACE) |
| Expected code | 14 (`game_error.error_system_configuration`) |
| Expected message | Forbidden system configuration |

### Scenario 4: Suspicious Process (`suspicious_process`)

**Trigger**: `_proc_listpids` returns 5 PIDs; `_proc_pidpath` maps them to
known analysis/cheat tool paths.

**Mechanism**: The service enumerates all running processes and checks each
executable path against an internal blacklist of known tools.

| PID | Injected Path |
|-----|---------------|
| 1001 | `/usr/local/bin/cheatengine` |
| 1002 | `/Applications/GameGuardian.app/Contents/MacOS/GameGuardian` |
| 1003 | `/usr/bin/frida-server` |
| 1004 | `/usr/local/bin/lldb` |
| 1005 | `/Applications/IDA Pro.app/Contents/MacOS/ida64` |

| Field | Value |
|-------|-------|
| Stubs | `_proc_listpids`, `_proc_pidpath`, `_proc_pidinfo` |
| Expected code | 10 (`game_error.error_tool_forbidden`) |
| Expected message | Forbidden tool |

### Scenario 5: Input Automation (`input_automation`)

**Trigger**: `_CGEventSourceCounterForEventType` returns mismatched counts:
- HID (state 2): 50 events
- Combined (state 1): 500 events
- Ratio: 10:1 combined-to-HID indicates 90% synthetic input

**Mechanism**: The service periodically compares hardware-sourced event counts
(kCGEventSourceStateHIDSystem) against combined counts (which include
software-generated events). A large discrepancy indicates macro/aimbot software
injecting synthetic input.

| Field | Value |
|-------|-------|
| Stub | `_CGEventSourceCounterForEventType` |
| Injected | HID=50, Combined=500 |
| Expected code | 11 (`game_error.error_violation`) or deferred server-side |
| Note | Input automation may be reported asynchronously rather than via immediate callback |

### Scenario 6: Integrity Violation (`integrity_dladdr`)

**Trigger**: `_dladdr(0xe6ec)` returns `Dl_info` pointing to
`/usr/lib/libevil.dylib` with base address `0xDEAD0000` -- indicating the
function has been relocated to a foreign module.

**Mechanism**: Every `_y` tick calls `dladdr(0xe6ec)` and verifies the returned
module name and base address match the expected EAC service binary. A mismatch
indicates the function has been hooked or the binary has been remapped.

| Field | Value |
|-------|-------|
| Stub | `_dladdr` |
| Queried address | 0xe6ec |
| Injected dli_fname | `/usr/lib/libevil.dylib` |
| Injected dli_fbase | `0xDEAD0000` |
| Expected code | 9 (`game_error.error_corrupted_memory`) or 11 (`game_error.error_violation`) |
| Expected message | Corrupted memory / Internal anti-cheat error |

### Scenario 7: Hook Detected (`hook_detected`)

**Trigger**: `_dladdr(0xe6ec)` returns the correct module name but with a wrong
base address (`0xBAAD0000`) and the symbol address in a foreign image range.

**Mechanism**: Even if the module name matches, a base address mismatch
indicates the function pointer has been detoured through a hook trampoline.
The symbol address being outside the legitimate image range confirms the hook.

| Field | Value |
|-------|-------|
| Stub | `_dladdr` |
| Queried address | 0xe6ec |
| Injected dli_fbase | `0xBAAD0000` (wrong base) |
| Injected dli_saddr | `0xBAADE6EC` (foreign image) |
| Expected code | 9 (`game_error.error_corrupted_memory`) or 11 (`game_error.error_violation`) |

---

## 3. Error Code Reference

Complete error dispatch table from `sub_C9F4` (0xC9F4, 1244 bytes):

| Code | game_error.* | Display Message | Detection Category |
|------|-------------|-----------------|-------------------|
| 0 | (custom/fallback) | Internal anti-cheat error | Generic |
| 1 | error_catalogue_not_found | Easy Anti-Cheat Hash Catalogue not found | File integrity |
| 2 | error_catalogue_corrupted | Corrupt Easy Anti-Cheat Hash Catalogue | File integrity |
| 3 | error_certificate_revoked | EAC index certificate revoked | PKI |
| 4 | error_file_version | Unknown file version | File integrity |
| 5 | error_file_not_found | Missing required file | File integrity |
| 6 | error_file_forbidden | Unknown game file | Module scanning |
| 7 | error_system_version | Untrusted system file | Environment |
| 8 | error_module_forbidden | Forbidden module | Module scanning |
| 9 | error_corrupted_memory | Corrupted memory | Memory integrity |
| 10 | error_tool_forbidden | Forbidden tool | Process scanning |
| 11 | error_violation | Internal anti-cheat error | Generic violation |
| 12 | error_corrupted_network | Corrupted packet flow | Network integrity |
| 13 | error_virtual | Cannot run under Virtual Machine. | VM detection |
| 14 | error_system_configuration | Forbidden system configuration | Environment |
| 15 | executable_not_hashed | Could not locate game executable entry in the catalogue. | Hash catalogue |

---

## 4. Detection Architecture

### Stub Call Flow

All detection-relevant API calls are routed through the Code Virtualizer VM.
The call chain is:

```
_y tick (0x1B744)
  -> 0x12770 (main dispatch)
    -> enters CV region at 0x14BC50
      -> VM-internal state machine
        -> exits to PLT stub (e.g., _dladdr, _sysctl)
          -> GOT -> external function (our intercepted stub)
        -> evaluates result inside VM
        -> if detection triggered:
          -> sub_C848 (error queue processor)
            -> sub_C9F4 (error code dispatch)
              -> callback(ctx, error_code)
```

### Timing

Detection checks are distributed across init and tick phases:

| Check | Phase | Frequency |
|-------|-------|-----------|
| IOKit/DA/sysctl VM queries | _x init | Once |
| csr_get_active_config | _x init | Once |
| CGEventSourceCounterForEventType | _x init + periodic | Baseline at init, periodic re-check |
| dladdr integrity | Every _y tick | Once per tick (confirmed: 138K insn/tick) |
| proc_listpids/pidpath | Periodic _y tick | Interval-based (not every tick) |
| sysctl P_TRACED | Periodic _y tick | Interval-based |

### Deferred vs Immediate Detection

Some detections trigger an immediate callback (VM detection is a hard block);
others may accumulate evidence and report asynchronously to the EAC backend.
The harness captures both immediate callbacks and the pattern of stub calls
to identify deferred detection paths.

---

## 5. Limitations

1. **CV opaqueness**: Detection logic runs inside the Code Virtualizer region
   (0xCC000-0x644000). The harness observes inputs (stub arguments) and outputs
   (callback error codes) but cannot trace the decision logic within the VM.

2. **Network-gated detections**: Some checks may only trigger after the service
   establishes a connection (state 0x11/0x31). Without a DTLS server stub, these
   remain dormant.

3. **Timing dependencies**: Interval-based checks (process scanning, periodic
   integrity) may require many more ticks than the default 3 to trigger.

4. **Blacklist completeness**: The process scanning scenario uses guessed tool
   names. The actual blacklist is encrypted inside the VM and cannot be extracted
   without full devirtualization.

5. **Multi-signal correlation**: EAC may require multiple weak signals (SIP
   disabled + suspicious memory layout + unusual process list) to trigger a
   detection, rather than any single signal in isolation.
