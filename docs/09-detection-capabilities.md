# EAC In-Game Service: Detection Capabilities

Analysis of `eac_service_decoded.dylib` -- the decoded (devirtualized) EAC in-game
service for macOS. This document catalogs the VM detection, process integrity,
input automation detection, hash catalogue, certificate infrastructure, and
environment checking systems identifiable through string analysis and import
table inspection.

---

## 1. Virtual Machine Detection

### Error Surface

The binary contains an explicit VM-rejection path:

```
Cannot run under Virtual Machine.
game_error.error_virtual
```

This is a hard block -- the game will not proceed when a VM is detected.

### IOKit Hardware Interrogation

The primary VM detection mechanism uses the IOKit framework to query hardware
registry properties. The following IOKit imports are present:

| Import | Purpose |
|--------|---------|
| `IOServiceMatching` | Build matching dictionaries for IOKit service lookups |
| `IOServiceGetMatchingService` | Find a single matching IOKit service |
| `IOServiceGetMatchingServices` | Enumerate all matching IOKit services |
| `IORegistryEntryCreateCFProperty` | Read a single property from a registry entry |
| `IORegistryEntrySearchCFProperty` | Search the registry tree for a property |
| `IORegistryEntryGetParentEntry` | Walk the IOKit device tree upward |
| `IOIteratorNext` / `IOObjectRelease` | Iterate and release IOKit objects |
| `kIOMasterPortDefault` | Default Mach port for IOKit communication |

The string `IOService` is present as a matching class name. The IOKit device
tree on macOS exposes hardware model information, PCI/USB vendor IDs, and SMBIOS
data. Hypervisors like VMware, Parallels, and VirtualBox create IOKit entries
with identifiable vendor strings, device model names, and ACPI table markers.
Querying `IORegistryEntrySearchCFProperty` with recursive search can locate
these artifacts anywhere in the tree.

### DiskArbitration Framework

The binary imports DiskArbitration functions for disk/volume inspection:

| Import | Purpose |
|--------|---------|
| `DASessionCreate` | Create a Disk Arbitration session |
| `DADiskCreateFromVolumePath` | Get a disk reference from a mount path |
| `DADiskCopyDescription` | Get disk metadata dictionary (model, vendor, bus protocol, etc.) |
| `DADiskCopyIOMedia` | Get the underlying IOKit media object |

VM disk controllers expose identifiable model strings (e.g., "VBOX HARDDISK",
"VMware Virtual", "QEMU HARDDISK"). `DADiskCopyDescription` returns a
dictionary containing keys like `DAMediaModel`, `DADeviceVendor`, and
`DADeviceProtocol` that reveal virtualization.

### sysctl Hardware Queries

Two sysctl imports are present:

- `sysctl` -- query kernel state by MIB array
- `sysctlbyname` -- query kernel state by name string

These can query `hw.model`, `machdep.cpu.brand_string`,
`kern.hv_vmm_present` (returns 1 when a hypervisor is active on the host),
and `hw.memsize` (VMs often have suspiciously round memory sizes). The
`kern.hv_vmm_present` sysctl is the single most reliable VM detection check
on macOS -- it is set by the kernel itself when running under a hypervisor.

### SIP / CSR Status

The binary imports `csr_get_active_config` from libSystem. This queries the
System Integrity Protection (SIP) configuration bitmask. While SIP is not
directly a VM indicator, disabled SIP on a VM is a common research/analysis
environment fingerprint. Combined with VM hardware indicators, a disabled CSR
config strengthens the detection signal.

---

## 2. Process Integrity Checks

### Anti-Debug (ptrace)

The binary imports `ptrace`. On macOS, `ptrace(PT_DENY_ATTACH, 0, 0, 0)` is
the canonical anti-debug technique -- it causes any debugger attachment to the
process to fail with EBUSY, and kills the process if a debugger is already
attached.

### Code Signing Validation (csops)

The `csops` import provides access to the code-signing operations syscall.
This can:

- Query the code signing status of a process (`CS_OPS_STATUS`)
- Retrieve the code directory hash (`CS_OPS_CDHASH`)
- Check entitlements and flags
- Detect if a binary has been modified after signing (invalid signature)

### Process Enumeration

Full process introspection is available through:

| Import | Purpose |
|--------|---------|
| `proc_listpids` | List all PIDs on the system by type |
| `proc_pidinfo` | Get detailed info for a specific PID (path, flags, status) |
| `proc_pidpath` | Get the executable path for a PID |
| `proc_regionfilename` | Get the file backing a memory region in a process |

These enable scanning for known cheat tools, debuggers, injection frameworks,
and other forbidden processes. The corresponding error strings confirm this:

```
Forbidden tool
game_error.error_tool_forbidden
Forbidden module
game_error.error_module_forbidden
```

### Memory Inspection

| Import | Purpose |
|--------|---------|
| `vm_region_64` | Query memory region attributes (protection, sharing, file backing) |
| `vm_protect` | Change memory protection (verify writability of code pages) |
| `mprotect` | POSIX memory protection control |
| `task_for_pid` | Get the Mach task port for another process |
| `mach_task_self_` | Get the current process's task port |

`vm_region_64` can detect injected shared libraries by finding memory regions
with file-backed mappings that don't correspond to expected loaded images.
`task_for_pid` against the EAC process itself can verify whether another process
has obtained its task port (indicating a debugger or injector).

### Dynamic Linker Inspection

| Import | Purpose |
|--------|---------|
| `dlopen` | Load a shared library |
| `dlsym` | Resolve a symbol from a loaded library |
| `dladdr` | Reverse-resolve an address to its containing library and symbol |
| `dlclose` | Unload a shared library |
| `_NSGetExecutablePath` | Get the path of the main executable |
| `getenv` | Read environment variables |
| `issetugid` | Check if the process was launched setuid/setgid |

`dladdr` is particularly important for hook detection: by calling it on known
function pointers, EAC can verify that functions resolve to the expected library
(e.g., libSystem) rather than an interposed/hooked replacement. `getenv` can
check for `DYLD_INSERT_LIBRARIES` or other injection environment variables.

### Mach-O Binary Parsing

The import of `swap_fat_arch` indicates the binary parses Mach-O fat (universal)
headers directly. This is used to read and hash game binaries and loaded modules
from disk for catalogue verification, and potentially to detect in-memory
modifications by comparing against on-disk versions.

---

## 3. Input Automation Detection

### CGEventSource Counter

The binary imports:

```
CoreGraphics/_CGEventSourceCounterForEventType
```

`CGEventSourceCounterForEventType` returns a running count of events generated
from a specific source. By comparing counters for `kCGEventSourceStateHIDSystem`
(physical hardware events) vs `kCGEventSourceStateCombinedSessionState` (all
events including synthetic), EAC can detect software-generated mouse/keyboard
input. A discrepancy between the two counters indicates automation tools, macro
software, or aimbots injecting synthetic input events.

This is a passive detection method -- it requires no hooking or injection, just
periodic polling of the event counters.

---

## 4. Hash Catalogue System

The "Easy Anti-Cheat Hash Catalogue" is a signed manifest of expected file
hashes for game binaries and modules.

### Error Codes

```
Easy Anti-Cheat Hash Catalogue not found
game_error.error_catalogue_not_found

Corrupt Easy Anti-Cheat Hash Catalogue
game_error.error_catalogue_corrupted

Could not locate game executable entry in the catalogue.
game_error.executable_not_hashed
```

### Verification Flow

1. The catalogue file is loaded and its integrity verified (likely via the
   embedded certificate chain -- see section 5)
2. The game executable and loaded modules are hashed
3. Hashes are compared against catalogue entries
4. Missing entries (`executable_not_hashed`) or mismatched hashes trigger
   violations

### Related Error Codes

```
Forbidden module              -- loaded DLL/dylib is blacklisted
game_error.error_module_forbidden

Untrusted system file         -- system file fails trust check
game_error.error_file_forbidden
game_error.error_file_not_found
game_error.error_file_version  -- wrong version of a required file
```

### Hashing Algorithms Available

The embedded mbedTLS library provides:

- MD5 (legacy, likely for backwards compatibility)
- SHA-1
- SHA-224, SHA-256, SHA-384, SHA-512
- RIPEMD-160

SHA-256 is the most likely algorithm used for catalogue hashing given its
presence in the TLS handshake and certificate verification paths.

---

## 5. Certificate and Signing Infrastructure

### Certificate Chain (Custom PKI)

EAC operates its own PKI hierarchy embedded in the binary:

```
Anti-Cheat Integrity CA11                    -- Root CA
Anti-Cheat Integrity Intermediate CA1        -- Intermediate CA (1)
Anti-Cheat Integrity Intermediate CA10       -- Intermediate CA (10)
```

This three-tier chain (Root -> Intermediate -> Leaf) is used to sign and verify:
- The hash catalogue
- Communication with EAC backend servers
- Potentially the EAC service binary itself

### Certificate Revocation

```
EAC index certificate revoked
game_error.error_certificate_revoked
```

EAC can revoke certificates, which would invalidate signed catalogues and
force clients to obtain updated ones. This provides a mechanism to invalidate
old catalogue versions that may have been tampered with.

### Embedded TLS Stack (mbedTLS)

The binary embeds a full mbedTLS library (source path visible:
`/Users/arttumarttinen/Desktop/workspace/Git/External/mbedtls/library/`).

Supported features:
- Full X.509 certificate parsing and validation
- RSA, ECDSA, ECDH key operations
- TLS 1.0/1.1/1.2 with extensive cipher suite support
- DTLS support (UDP-based TLS, used for game traffic)
- Certificate chain verification with custom CA roots
- Pre-shared key (PSK) cipher suites

The TLS stack handles secure communication with EAC backend servers for:
- Reporting detection results
- Downloading updated catalogues and configurations
- Heartbeat/keepalive connections (NoConnectionResetV2A-E strings suggest
  multiple reconnection strategies)

### Code Signing References

The string `id-kp-codeSigning` (X.509 Extended Key Usage OID) indicates the
certificate infrastructure may also validate code-signing certificates, tying
into the `csops` code-signing status checks.

---

## 6. Environment and System Configuration Checks

### System Configuration Validation

```
Forbidden system configuration
game_error.error_system_configuration

game_error.error_system_version
```

EAC checks the OS version and system configuration. Unsupported or suspicious
system configurations (e.g., a version known to have exploitable bugs, or a
system with security features disabled) trigger a block.

### Network Proxy Detection

The binary imports CFNetwork proxy settings functions:

| Import | Purpose |
|--------|---------|
| `CFNetworkCopySystemProxySettings` | Get system proxy configuration |
| `kCFNetworkProxiesHTTPEnable/Port/Proxy` | HTTP proxy settings |
| `kCFNetworkProxiesHTTPSEnable/Port/Proxy` | HTTPS proxy settings |
| `kCFNetworkProxiesSOCKSEnable/Port/Proxy` | SOCKS proxy settings |
| `kCFNetworkProxiesProxyAutoConfigEnable` | PAC auto-config detection |
| `kCFNetworkProxiesProxyAutoConfigURLString` | PAC URL |

This serves dual purposes:
1. Route EAC backend connections through the system proxy when legitimate
2. Detect interception proxies (e.g., mitmproxy, Charles, Fiddler) that could
   be used to tamper with EAC-server communication

The `CONNECT %s:%d HTTP/1.1` string confirms HTTP CONNECT tunnel support for
proxied TLS connections.

### Memory Integrity

```
Corrupted memory
game_error.error_corrupted_memory
```

Runtime memory integrity checks detect in-memory patching of game code or
EAC service code. This likely combines:
- Periodic re-hashing of code sections
- Guard pages and canary values
- `vm_region_64` to detect unexpected memory protection changes

### Network Integrity

```
Corrupted packet flow
game_error.error_corrupted_network
```

Network packet validation detects tampered or replayed game traffic.

---

## 7. Summary of Detection Error Taxonomy

| Error Code | Category | Severity |
|------------|----------|----------|
| `error_virtual` | VM Detection | Hard block |
| `error_tool_forbidden` | Process scanning | Kick/ban |
| `error_module_forbidden` | Module scanning | Kick/ban |
| `error_file_forbidden` | File trust | Kick/ban |
| `error_file_not_found` | File integrity | Error |
| `error_file_version` | Version check | Error |
| `error_catalogue_not_found` | Hash catalogue | Error |
| `error_catalogue_corrupted` | Hash catalogue integrity | Error |
| `executable_not_hashed` | Hash catalogue | Error |
| `error_certificate_revoked` | PKI revocation | Error |
| `error_corrupted_memory` | Memory integrity | Kick/ban |
| `error_corrupted_network` | Network integrity | Kick/ban |
| `error_system_configuration` | Environment | Hard block |
| `error_system_version` | Environment | Hard block |
| `error_violation` | Generic violation | Kick/ban |

---

## 8. Import Summary by Detection Category

### VM / Hardware Detection
- IOKit: `IOServiceMatching`, `IOServiceGetMatchingService(s)`, `IORegistryEntryCreateCFProperty`, `IORegistryEntrySearchCFProperty`, `IORegistryEntryGetParentEntry`
- DiskArbitration: `DASessionCreate`, `DADiskCreateFromVolumePath`, `DADiskCopyDescription`, `DADiskCopyIOMedia`
- libSystem: `sysctl`, `sysctlbyname`, `csr_get_active_config`

### Process / Code Integrity
- libSystem: `ptrace`, `csops`, `proc_listpids`, `proc_pidinfo`, `proc_pidpath`, `proc_regionfilename`, `vm_region_64`, `vm_protect`, `mprotect`, `task_for_pid`, `mach_task_self_`

### Dynamic Loading / Hook Detection
- libSystem: `dlopen`, `dlsym`, `dladdr`, `dlclose`, `_NSGetExecutablePath`, `getenv`, `issetugid`

### Input Automation
- CoreGraphics: `CGEventSourceCounterForEventType`

### Network / Proxy
- CFNetwork: `CFNetworkCopySystemProxySettings`, proxy setting keys (HTTP/HTTPS/SOCKS/PAC)

### File System
- libSystem: `stat`, `open`, `read`, `fopen`, `fread`, `mmap`, `glob`, `opendir`, `readdir`, `realpath`, `swap_fat_arch`
