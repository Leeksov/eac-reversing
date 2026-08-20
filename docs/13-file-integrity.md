# 13 - File Integrity and Hash Catalogue System

## Overview

The EAC in-game service implements a comprehensive file integrity verification
system that scans game directories, parses Mach-O binaries, and validates files
against a signed hash catalogue. Files are classified into categories (game files,
system files, modules, tools) and checked for tampering, version mismatches, or
outright prohibition.

---

## Hash Catalogue

### Structure and Loading

The hash catalogue is a binary file located under the `EasyAntiCheat/Certificates/`
directory relative to the game installation. It begins with a 4-byte magic number:

```
0x00434145 = "EAC\0" (little-endian)
```

The catalogue loading function (`sub_2CE38` at `0x2CE38`) reads the file via
`sub_347F0` (a generic file reader using `fopen`/`fread`/`fclose`), then validates:

1. File size >= 0x40C bytes (minimum catalogue size)
2. Magic number == `0x00434145`
3. Second DWORD = catalogue version number (returned to caller)

Two catalogue format versions are supported, distinguished by the version field:
- **Version 4**: allocates 0x38 bytes, uses `sub_2CDA0` for parsing
- **Version 5**: allocates 0x7B0 bytes (1968 bytes), uses `sub_30380` for parsing

The larger v5 structure suggests it holds significantly more hash entries or
additional metadata compared to v4.

### Certificate Verification

The catalogue's integrity is verified using embedded ECC (ECDSA) certificates
based on mbedTLS. The binary contains multiple PEM-encoded test certificates
from PolarSSL/mbedTLS. The string `"EAC index certificate revoked"` (error code 3)
indicates the catalogue itself is signed with a certificate chain that can be
revoked server-side.

The certificate directory path is constructed as:
```
<game_install_path>/EasyAntiCheat/Certificates/
```

### Catalogue Lookup Flow

The main catalogue lookup function is `sub_2BB24` at `0x2BB24`. Its flow:

1. Call `sub_2BF3C` to resolve the catalogue path by appending
   `EasyAntiCheat/Certificates/` plus a wildcard pattern to the game directory
2. Call `sub_34B40` to glob for matching files (using POSIX `glob()` with
   flag 32 = `GLOB_TILDE`)
3. For each glob result, call `basename()` to extract the filename
4. Search for a matching entry in the catalogue using wide string comparison
5. If found, call `sub_2B8D0` to perform the actual hash verification
6. Return error code 7 (system error) or 8 (not found) on failure

---

## Game Directory Scanning

### Executable Resolution (`sub_34DF0` at `0x34DF0`)

The service locates the game executable through:

1. `_NSGetExecutablePath()` to get the current process path
2. `realpath()` to resolve symlinks to the canonical path
3. `strlen()` + resize to trim the buffer

This resolved path serves as the root for all subsequent file lookups.

### Directory Enumeration (`sub_353C4` at `0x353C4`)

The main directory scanner uses POSIX directory APIs:

```
opendir(path)
  while (entry = readdir(dir)):
    construct full path = base_path + "/" + entry->d_name
    stat(full_path) -> check file attributes
    compute hash of file contents
    insert into hash map (key = hash, value = path + attributes)
  closedir(dir)
```

The function builds an in-memory hash map (unordered_map) of all files found.
Each entry stores:
- The wide-string filename
- The wide-string relative path
- A hash value computed via `sub_35EC8`

The hash map uses a standard open-addressing scheme with load-factor-based
rehashing (threshold stored at object offset +56 as a float).

When a file already exists in the map (hash collision with matching key),
the function calls `sub_35CB4` to construct an error path string, indicating
a duplicate or conflicting file was found.

### Recursive Directory Walking (`sub_6A270` at `0x6A270`)

A separate recursive directory walker is used for deeper scans:

```c
int scan_directory(int context, char *path) {
    DIR *dir = opendir(path);
    while ((entry = readdir(dir)) != NULL) {
        snprintf(fullpath, 512, "%s/%s", path, entry->d_name);
        if (stat(fullpath) fails) return ERROR;
        if (S_ISREG(st_mode)) {  // Regular file check: (mode & 0xF000) == 0x8000
            read_file(fullpath, &data, &size);
            result = check_file(context, data);
            // Secure wipe: zero out file data after checking
            memset(data, 0, size);
            free(data);
            total += result;
        }
    }
    closedir(dir);
    return total;
}
```

Notable: after reading and checking each file, the contents are securely wiped
(byte-by-byte zeroing loop) before freeing the buffer, preventing file data
from lingering in memory.

### Glob-Based File Discovery (`sub_34B40` at `0x34B40`)

The glob function uses POSIX `glob()` with flag 32 (`GLOB_TILDE`) to expand
shell-style patterns. For each match:

1. Call `basename()` to extract the filename component
2. Call `sub_34D58` to normalize the name (likely lowercasing or encoding)
3. Construct a wide string and append to a dynamic vector

Results are collected into a `std::vector<std::wstring>` that the caller
iterates to find matching catalogue entries.

---

## Mach-O Binary Parsing

### Fat Binary Detection (`sub_4DF6C` at `0x4DF6C`)

EAC parses Mach-O binaries to determine their architecture. The function handles
both fat (universal) and thin binaries:

**Recognized magic numbers:**
| Magic | Hex | Type |
|-------|-----|------|
| `FAT_MAGIC` | `0xBEBAFECA` | Fat binary (32-bit arch entries) |
| `FAT_MAGIC_64` | `0xBFBAFECA` | Fat binary (64-bit arch entries) |
| `FAT_CIGAM` / `FAT_CIGAM_64` | byte-swapped variants | Big-endian fat headers |
| `MH_MAGIC` | `0xFEEDFACE` | Thin Mach-O 32-bit |
| `MH_CIGAM` | `0xCEFAEDFE` | Thin Mach-O 32-bit (swapped) |
| `MH_MAGIC_64` | `0xCFFAEDFE` | Thin Mach-O 64-bit (swapped) |

**Architecture detection in fat binaries:**

When a fat binary is detected, the function:
1. Byte-swaps the `nfat_arch` count using `bswap32()` if needed
2. Calls `swap_fat_arch()` (imported from libSystem) to fix endianness of all
   `fat_arch` entries
3. Iterates through each architecture entry checking the `cputype` field:
   - `CPU_TYPE_X86_64` (0x01000007) -> sets flag bit 0 (value 1)
   - `CPU_TYPE_ARM64` (0x0100000C) -> sets flag bit 1 (value 2)

The output `a2` accumulates a bitmask: `1` = contains x86_64, `2` = contains
arm64, `3` = contains both (universal binary).

### Thin Binary Detection (`sub_4E054` at `0x4E054`)

For non-fat binaries, the function checks the Mach-O header directly:

1. Reads the magic number and validates it matches a known Mach-O magic
2. If big-endian (`MH_CIGAM` variants), byte-swaps the first 7 DWORDs of the header
   (magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags)
3. Checks `cputype` (second DWORD):
   - `CPU_TYPE_X86_64` -> returns flag 1
   - `CPU_TYPE_ARM64` -> returns flag 2

### File Reading for Parsing (`sub_347F0` at `0x347F0`)

The generic file reader opens files in `"rb"` mode:

1. `fopen(path, "rb")`
2. `fseek(fp, 0, SEEK_END)` + `ftell()` to determine file size
3. Caps read size to `min(file_size, max_allowed_size)`
4. `rewind()` + `fread()` to read the entire file
5. Validates that `fread` returned the expected byte count

The `max_allowed_size` parameter prevents excessive memory allocation for
extremely large files.

---

## FortniteGame Hardcoded Path

At `0x1395C`, a function checks whether the game ID equals 217:

```c
if (*(game_context + 9896) == 217) {
    path_prefix = "FortniteGame/Binaries/Mac/";
} else {
    path_prefix = "";  // empty string at 0xAB1EB
}
```

Game ID 217 corresponds to Fortnite. This hardcoded path prefix is used during
catalogue lookups, meaning EAC has special-case logic for Fortnite's directory
structure on macOS. The path is prepended to filenames when searching for entries
in the hash catalogue, compensating for Fortnite's non-standard binary location
within its application bundle.

This function is called from a vtable (referenced at `0xB42F0`), suggesting
it is part of a game-specific adapter interface.

---

## File Classification and Error Taxonomy

### Error Dispatch System (`sub_C9F4` at `0xC9F4`)

The central error dispatch function `sub_C9F4` takes a numeric error code (parameter
`a2`) and maps it to both a machine-readable error string and a human-readable
message. It uses a nested binary decision tree (if-else chain) for efficient
dispatch.

### Complete Error Code Table

| Code | Machine Error Code | Human Message | Category |
|------|-------------------|---------------|----------|
| 0 | *(special: uses `__s` param directly)* | *(custom message)* | Generic |
| 1 | `game_error.error_catalogue_not_found` | Easy Anti-Cheat Hash Catalogue not found | Catalogue |
| 2 | `game_error.error_catalogue_corrupted` | Corrupt Easy Anti-Cheat Hash Catalogue | Catalogue |
| 3 | `game_error.error_certificate_revoked` | EAC index certificate revoked | Catalogue |
| 4 | `game_error.error_file_version` | Unknown file version | File Integrity |
| 5 | `game_error.error_file_not_found` | Missing required file | File Integrity |
| 6 | `game_error.error_file_forbidden` | Unknown game file | File Integrity |
| 7 | `game_error.error_system_version` | Untrusted system file | System Integrity |
| 8 | `game_error.error_module_forbidden` | Forbidden module | Module Detection |
| 9 | `game_error.error_corrupted_memory` | Corrupted memory | Runtime Integrity |
| 10 | `game_error.error_tool_forbidden` | Forbidden tool | Tool Detection |
| 11 | `game_error.error_violation` | Internal anti-cheat error | Runtime Violation |
| 12 | `game_error.error_corrupted_network` | Corrupted packet flow | Network Integrity |
| 13 | `game_error.error_virtual` | Cannot run under Virtual Machine. | Environment |
| 14 | `game_error.error_system_configuration` | Forbidden system configuration | Environment |
| 15 | `game_error.executable_not_hashed` | Could not locate game executable entry in the catalogue. | Catalogue |
| 16+ | *(XOR-obfuscated)* | Internal anti-cheat error | Fallback |

### Error Categories Explained

**Catalogue Errors (1-3, 15):**
- Code 1: The hash catalogue file itself was not found on disk
- Code 2: The catalogue file exists but failed integrity/format validation
  (bad magic, truncated, etc.)
- Code 3: The signing certificate for the catalogue has been revoked
- Code 15: The game executable's hash is not present in the catalogue; the
  executable may have been modified or the catalogue is outdated

**File Integrity Errors (4-6):**
- Code 4 ("Unknown file version"): A game file exists but its hash does not
  match any known version in the catalogue
- Code 5 ("Missing required file"): A file that the catalogue lists as required
  was not found on disk
- Code 6 ("Unknown game file"): A file was found in the game directory that has
  no entry at all in the catalogue -- potentially injected

**System Integrity Errors (7):**
- Code 7 ("Untrusted system file"): A system library or framework loaded by the
  game does not match known-good system file hashes. This catches modified system
  libraries used for injection.

**Module/Tool Detection (8, 10):**
- Code 8 ("Forbidden module"): A loaded dynamic library (dylib/framework) is on
  EAC's blacklist. Cheat injectors, function hooking libraries, etc.
- Code 10 ("Forbidden tool"): A running process or tool has been identified as
  a cheat tool (debuggers, memory editors, etc.)

**Runtime Integrity (9, 11, 12):**
- Code 9 ("Corrupted memory"): In-memory integrity checks failed, suggesting
  code or data has been tampered with after loading
- Code 11 ("Internal anti-cheat error"): A generic violation was detected
  (catch-all for signatures that don't fit other categories)
- Code 12 ("Corrupted packet flow"): Network packet integrity checks failed,
  suggesting packet manipulation or replay attacks

**Environment Checks (13, 14):**
- Code 13 ("Cannot run under Virtual Machine"): VM detection triggered (VMware,
  Parallels, QEMU, etc.)
- Code 14 ("Forbidden system configuration"): System configuration deemed
  incompatible or suspicious (e.g., SIP disabled, kernel extensions loaded)

**Fallback (code >= 16):**
When the error code is unrecognized and the filename string (`__s`) is NULL,
the function constructs an XOR-obfuscated 10-byte error identifier using a
linear congruential generator (seed `789515133`, multiplier `-1140671485`,
increment `-12820164`). This is likely a unique session/detection identifier
that is sent to the server. The human-readable message defaults to
"Internal anti-cheat error".

### Error Reporting Flow

The error queue system works as follows:

1. Detection functions push `(error_code, filename)` tuples into a thread-safe
   queue (protected by `pthread_mutex` at context+6576)
2. `sub_C968` dequeues entries one at a time, extracting the code and associated
   string
3. `sub_C848` iterates the queue, calling `sub_C9F4` for each entry to format
   the error, then invokes a callback (`a2`) with the formatted result
4. The callback can return 0 to stop processing (e.g., first fatal error) or
   1 to continue
5. After all queue entries are processed, `sub_69E4` handles the final
   accumulated result

The error formatting function `sub_378F8` constructs the final error message
by combining the machine error code with optional file path context. If a
separate verification function at offset +152 in the context object exists,
it is called to further validate the error before reporting.

---

## Initialization Flow (`sub_113DC` at `0x113DC`)

The main file integrity initialization ties everything together:

1. **Resolve executable path**: Call `sub_34DF0` which uses
   `_NSGetExecutablePath()` + `realpath()` to find the game binary
2. **Extract directory**: Call `sub_342D4` to get the parent directory
3. **Open catalogue**: Call `sub_2CD28` to locate and parse the hash catalogue
4. **Verify executable**: Call `sub_2C3AC` which:
   - Resolves the executable path via `realpath()`
   - On iOS/platform builds, uses alternate path resolution via `sub_11338`
   - Opens and reads the file
   - Looks up its hash in the catalogue
   - Uses `pthread_mutex` for thread-safe catalogue access
5. **Handle failures**:
   - If catalogue lookup returns 0, calls error handler with code **15**
     (`executable_not_hashed`)
   - If hash verification returns non-zero, calls error handler with code **4**
     (`error_file_version`)

The error handler is dispatched through a vtable call at `*(vtable + 128)`,
passing `(context, error_code, filename)`.

---

## Key Function Reference

| Address | Name | Purpose |
|---------|------|---------|
| `0x113DC` | `sub_113DC` | Main initialization: resolve exe, load catalogue, verify |
| `0x1395C` | `sub_1395C` | FortniteGame path prefix selection (game ID 217) |
| `0x2BB24` | `sub_2BB24` | Catalogue entry lookup with glob-based file discovery |
| `0x2B8D0` | `sub_2B8D0` | Hash verification against catalogue entry |
| `0x2BF3C` | `sub_2BF3C` | Catalogue path resolution (Certificates directory) |
| `0x2C3AC` | `sub_2C3AC` | Full catalogue verification pipeline |
| `0x2CE38` | `sub_2CE38` | Read and validate catalogue header (magic + version) |
| `0x2CECC` | `sub_2CECC` | Catalogue format factory (v4 vs v5) |
| `0x34018` | `sub_34018` | Simple `stat()` existence check |
| `0x347F0` | `sub_347F0` | Generic file reader (fopen/fseek/fread/fclose) |
| `0x348D8` | `sub_348D8` | File reader with path construction |
| `0x34B40` | `sub_34B40` | Glob-based file enumeration with basename extraction |
| `0x34DF0` | `sub_34DF0` | Executable path resolution (NSGetExecutablePath + realpath) |
| `0x353C4` | `sub_353C4` | Directory scanning with hash map construction |
| `0x35338` | `sub_35338` | Directory scan entry point (validates + normalizes path) |
| `0x37E0C` | `sub_37E0C` | File verification with error path construction |
| `0x378F8` | `sub_378F8` | Error message formatting (machine code + human message) |
| `0x4DEC8` | `sub_4DEC8` | Mach-O architecture detection orchestrator |
| `0x4DF6C` | `sub_4DF6C` | Fat Mach-O parser (swap_fat_arch, CPU type extraction) |
| `0x4E054` | `sub_4E054` | Thin Mach-O parser (header byte-swap, CPU type check) |
| `0x6A270` | `sub_6A270` | Recursive directory walker with secure file wiping |
| `0xC848`  | `sub_C848`  | Error queue iterator (dequeue + callback dispatch) |
| `0xC968`  | `sub_C968`  | Error queue dequeue (mutex-protected) |
| `0xC9F4`  | `sub_C9F4`  | Error code to message mapper (16 error codes) |

---

## Key Imports Used

| Import | Usage |
|--------|-------|
| `_glob` / `_globfree` | Enumerate files matching catalogue patterns |
| `_opendir` / `_readdir` / `_closedir` | Walk game directories recursively |
| `_stat` | Check file existence and type (regular file vs directory) |
| `_realpath` | Resolve symlinks to canonical paths |
| `_open` / `_read` / `_close` | Low-level file I/O for binary reading |
| `_swap_fat_arch` | Byte-swap fat Mach-O architecture headers |
| `__NSGetExecutablePath` | Get path of the running executable |
| `_basename` | Extract filename from full path |
| `_proc_regionfilename` | Get filename for a memory-mapped region (imported but xref not found in current analysis) |
