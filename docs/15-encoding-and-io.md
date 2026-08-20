# 15 - Encoding, Internationalization, and I/O Subsystem

## Overview

The EAC in-game service implements a multi-layer character encoding system built around `iconv`, wide strings (`wchar_t`/`std::wstring`), and C++ locale facets. The binary maintains dual string representations -- narrow `std::string` (UTF-8) for external communication and wide `std::wstring` (UTF-32LE on macOS/arm64) for internal processing -- and provides conversion functions between them. The time subsystem uses UTC exclusively, and a structured logging system formats messages with timestamps, severity levels, and source tags.

---

## Character Encoding System

### Supported Encodings

Three encoding names appear as string literals used with `iconv_open`:

| Encoding    | Role |
|-------------|------|
| `UTF-8`     | External / narrow string representation |
| `UTF-32LE`  | Internal wide string representation (`wchar_t` on macOS arm64 is 4 bytes) |
| `UTF-16LE`  | Wire/interchange format (Windows compatibility, game engine interop) |

### Conversion Functions

Four core conversion functions handle all encoding transformations via `iconv`:

#### `sub_51664` -- Wide-to-UTF8 (`wchar_t[]` -> `char[]`)

- **Direction**: UTF-32LE -> UTF-8
- **Error sentinel**: On failure, returns the literal string `"W2U8_ERROR"`
- **Pattern**: Allocates `4 * input_length` bytes for the output buffer, calls `iconv_open("UTF-8", "UTF-32LE")`, performs the conversion, then constructs an `std::string` from the result
- **Call sites**: 29 xrefs -- the most heavily used conversion. Called whenever internal wide strings must be serialized for logging, network transmission, or file I/O

#### `sub_51990` -- UTF8-to-Wide (`char[]` -> `wchar_t[]`)

- **Direction**: UTF-8 -> UTF-32LE
- **Pattern**: Mirror of `sub_51664`. Allocates `4 * input_length` bytes, calls `iconv_open("UTF-32LE", "UTF-8")`, constructs an `std::wstring`
- **Call sites**: 19 xrefs -- used when ingesting external strings (file paths, configuration values, network data) into the internal wide representation

#### `sub_51BD8` -- UTF16-to-Wide (`char16_t[]` -> `wchar_t[]`)

- **Direction**: UTF-16LE -> UTF-32LE
- **Error handling**: On `iconv_open` failure, calls `strerror(errno)` and prepends `"utf16_to_wchar iconv_open ERROR "`. On conversion failure, prepends `"utf16_to_wchar iconv ERROR "`
- **Note**: Input byte count is `2 * char_count`, output is `4 * char_count`
- **Call sites**: 4 xrefs -- used in the network/game-engine interop layer where UTF-16LE data arrives from Windows-native game clients or the EOS SDK

#### `sub_51FA4` -- Wide-to-UTF16 (`wchar_t[]` -> `char16_t[]`)

- **Direction**: UTF-32LE -> UTF-16LE
- **Call sites**: Not directly referenced (likely called through vtable dispatch or inlined)

### Why Three Encodings?

- **UTF-32LE** is the native `wchar_t` on macOS/arm64 (4 bytes per character). All internal string processing uses this for O(1) character indexing
- **UTF-8** is the standard for logging, file paths, and most external interfaces
- **UTF-16LE** exists for Windows interoperability. EAC is cross-platform and the Windows client uses `wchar_t` = 2 bytes (UTF-16LE). The UTF-16 conversion layer bridges the platform gap when processing data originating from Windows game clients or the Epic Online Services (EOS) SDK

### Error String: `W2U8_ERROR`

When wide-to-UTF8 conversion fails (e.g., `iconv_open` returns `-1` or `iconv` returns `-1`), the function returns the literal string `"W2U8_ERROR"` instead of the converted result. This sentinel value can appear in logs and error messages, providing a diagnostic indicator of encoding failures.

---

## Wide String Usage Pattern

The binary makes extensive use of `std::wstring` (`basic_string<wchar_t>`) alongside `std::string`. The import table reveals parallel operations for both types:

### Narrow String (`std::string`) Operations
- `find`, `rfind`, `compare`, `erase`, `append`, `assign`, `insert`, `replace`, `resize`, `reserve`, `push_back`, copy constructor, destructor, `operator=`, `operator+`

### Wide String (`std::wstring`) Operations
- `rfind`, `compare`, `erase`, `append`, `assign`, `insert`, `replace`, `push_back`, copy constructor, destructor, `operator=`
- Low-level: `wcslen`, `wmemchr`, `wmemcmp`, `wmemcpy`, `vswprintf`

### Dual-Representation Architecture

The service maintains a **dual string representation** throughout its codebase:

1. **Internal processing** uses `std::wstring` (UTF-32LE) for file path manipulation, string matching, and anti-cheat logic
2. **External interfaces** use `std::string` (UTF-8) for logging output, network protocol messages, and system API calls
3. **Conversion boundaries** occur at well-defined points: when reading external data (UTF-8/UTF-16 -> wstring) and when producing output (wstring -> UTF-8)

### Platform String Functions

Additional multibyte/wide conversion via POSIX:
- `mbstowcs` / `wcstombs` -- used as fallback or for locale-aware conversions outside the iconv path

---

## Time and Date Handling

### Time Functions Used

| Import | Purpose |
|--------|---------|
| `time()` | Get current Unix timestamp |
| `gmtime_r()` | Thread-safe conversion to UTC `struct tm` |
| `strftime()` | Format narrow timestamp strings |
| `wcsftime()` | Format wide timestamp strings |
| `difftime()` | Compute time differences (timeout/expiry checks) |
| `gmtime()` | Non-reentrant UTC conversion (legacy code path) |

### Timestamp Format Strings

Three distinct timestamp formats exist, each with a dedicated function:

#### `sub_53DA0` -- Time-only (narrow)
```
Format: "%H:%M:%S"
Fallback: "00:00:00"
Output: std::string
```

#### `sub_53E3C` -- Time-only (wide)
```
Format: L"%H:%M:%S" (via wcsftime)
Fallback: L"00:00:00"
Output: std::wstring
```

#### `sub_53F7C` -- ISO 8601 datetime (narrow)
```
Format: "%Y-%m-%d %H:%M:%SZ"
Fallback: "0000-00-00 00:00:00Z"
Output: std::string
```

All three:
1. Call `time(NULL)` to get the current timestamp
2. Convert to UTC via `gmtime_r()` (thread-safe)
3. Format with `strftime`/`wcsftime` into a stack buffer (128 chars)
4. Return a fallback string if formatting fails

**Key detail**: All timestamps use `gmtime_r`, never `localtime`. The service operates exclusively in UTC, ensuring consistent time references regardless of the client machine's timezone.

### Certificate Date Formatting

The mbedTLS layer (embedded TLS library) uses additional date formats for X.509 certificate display:
```
%04d-%02d-%02d %02d:%02d:%02d   (for issued/expires/revocation dates)
```

---

## Logging and Debug Output System

### Log Message Formatter: `sub_4F894`

This function constructs structured log messages with the following format:

```
[EAC <timestamp>] [<source>] <severity>: <message>
```

#### Components

| Field | Values | Description |
|-------|--------|-------------|
| Prefix | `[EAC ` | Fixed EAC identifier prefix |
| Timestamp | `HH:MM:SS` or `YYYY-MM-DD HH:MM:SSZ` | UTC timestamp |
| Source | `InGame` | Module identifier (in-game service) |
| Severity | `Verb`, `Info`, `Warn`, `Err!` | Log level |
| Invalid | `<invalid>` | Fallback for unknown severity |

The function:
1. Constructs the timestamp via the time formatting functions
2. Concatenates `[EAC `, timestamp, `] `, `[`, source, `] `, severity, `: `
3. Appends the actual log message
4. Uses `vsnprintf` (via wrapper `sub_503B4`) for parameterized messages

### Severity Levels

```
0 -> "Verb"     (Verbose/Debug)
1 -> "Info"     (Informational)
2 -> "Warn"     (Warning)
3 -> "Err!"     (Error)
_ -> "<invalid>"
```

### Output Functions

| Import | Usage |
|--------|-------|
| `printf` | Direct console output |
| `puts` / `putchar` | Simple string/character output |
| `snprintf` / `vsnprintf` | Formatted string construction (primary logging path) |
| `vswprintf` | Wide-string formatted output |

### `sub_503B4` -- vsnprintf Wrapper

A thin wrapper around `vsnprintf` that accepts variadic arguments:
```c
int sub_503B4(char *buf, size_t size, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    return vsnprintf(buf, size, fmt, va);
}
```

Used throughout the codebase for safe formatted string construction with bounded buffers.

---

## Game Error Reporting System

### Error Code Mapping: `sub_C9F4`

A dispatch function maps integer error codes to structured error identifiers using a `<section>.<key>` naming convention:

| Code | Identifier | User-Facing Message |
|------|-----------|---------------------|
| 0 | *(no identifier)* | *(passthrough)* |
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
| 13 | `game_error.error_virtual` | Cannot run under Virtual Machine |
| 14 | `game_error.error_system_configuration` | Forbidden system configuration |
| 15 | `game_error.executable_not_hashed` | Could not locate game executable entry in the catalogue |

The identifiers follow the pattern `game_error.<key>`, matching the INI-style `<section>.<key>` configuration system. Error messages are dispatched via `sub_378F8` which looks up the key in an internal configuration store (at object offset +6688).

For unknown/fallback error codes (>15), the function constructs a format string using XOR-decoded data and outputs via `vsnprintf` with the message "Internal anti-cheat error".

---

## Configuration / INI Parser

### Key-Value Lookup: `sub_38198`

The service uses a `<section>.<key>` configuration system:

1. Splits the identifier string on `"."` (via `sub_382F4` / `sub_50DF4`)
2. Validates exactly 2 parts (section + key); otherwise returns `"Identifier syntax error: expected \"<section>.<key>\""`
3. Looks up the section in a dictionary (`sub_388A8`); fails with `"Section not found '<id>'"`
4. Looks up the key within that section (`sub_38A40`); fails with `"Key not found '<id>'"`
5. Returns the value string on success

This is the mechanism behind the `game_error.*` identifiers -- they reference entries in an internal configuration/localization table.

---

## Stream I/O Subsystem

### C++ iostream Usage

The binary implements a custom `streambuf` subclass for binary data parsing:

#### Custom Streambuf Constructor: `sub_32490`

- Inherits from `std::basic_streambuf<char>`
- Sets up a vtable at `off_B4D40`
- Initializes ~300 bytes of internal state (zeroed)
- Queries the locale for the `codecvt<char, char, __mbstate_t>` facet via `locale::has_facet` / `locale::use_facet`
- Stores the facet pointer at offset +128 and queries its `always_noconv()` method (stored at offset +402)
- Calls a virtual method at vtable+24 with a 4096-byte buffer size

#### Stream Operations

| Import | Usage |
|--------|-------|
| `basic_istream::read()` | Read binary data chunks |
| `basic_istream::seekg()` | Seek within stream (absolute and relative) |
| `basic_streambuf::xsgetn()` | Get sequence of characters from input |
| `basic_streambuf::xsputn()` | Put sequence of characters to output |
| `basic_streambuf::uflow()` | Single character extraction |
| `basic_streambuf::showmanyc()` | Check available characters |

#### File/Data Reading Pattern: `sub_315E0`

The stream reading function implements a loop-until-complete pattern:
1. Checks if a buffer is allocated (offset +608) and reading is enabled (offset +648)
2. Determines read size as `min(remaining_to_read, total_available)` (offsets +616, +632)
3. Calls `istream::read()` in a loop until the target byte count is reached
4. Updates position tracking: current position (+624) and remaining bytes (+632)
5. Records bytes actually read at offset +640

This is used for reading file catalogue entries, hash data, and other binary payloads from the EAC data files.

#### Stream Seek Pattern: `sub_314DC` / `sub_316B0`

Two seek helpers:
- **Absolute seek** (`sub_314DC`): Clears error state, seeks to a stored position (offset +78*8), checks for ios errors
- **Relative seek** (`sub_316B0`): Seeks backward by a negative offset (offset +80*8), updates position bookkeeping

These support random access into binary catalogue files for hash verification.

---

## Locale System

### Locale Facet Usage

The binary uses the C++ locale system minimally:

- **`std::locale::has_facet`** / **`std::locale::use_facet`**: Used in the custom streambuf to obtain `codecvt<char, char, __mbstate_t>` -- the identity codec (char-to-char). This is standard C++ streambuf initialization and does not perform actual encoding conversion
- **`std::codecvt<char, char, __mbstate_t>::id`**: Referenced for locale facet lookup

### macOS Rune Functions

| Import | Purpose |
|--------|---------|
| `___maskrune` | Character classification (isalpha, isdigit, etc.) via macOS locale tables |
| `___tolower` | Case conversion using locale-aware rules |
| `__DefaultRuneLocale` | Default locale character classification table |

These are used for case-insensitive string comparisons and character validation in the anti-cheat logic.

### Locale Configuration Files

The binary contains references to locale-specific `.cfg` files, likely from a bundled C++ standard library or ICU component:

```
ast.cfg, ast_es.cfg     (Asturian)
ca.cfg, ca_es.cfg        (Catalan, Spain)
es_gq.cfg                (Spanish, Equatorial Guinea)
eu.cfg, eu_es.cfg        (Basque, Spain)
gl.cfg, gl_es.cfg        (Galician, Spain)
zh_hk.cfg, zh_tw.cfg     (Chinese, Hong Kong/Taiwan)
```

These appear to be locale data files for the `mbstowcs`/`wcstombs` functions or the C++ locale system, providing character encoding tables for specific regional locales.

### I18N.dll Reference

The string `"I18N.dll"` appears in the binary but has no xrefs -- it is likely a vestigial string from a shared library or build artifact (possibly from Mono/.NET interop used by game engines like Unity).

---

## OS Information Collection

### Platform Identification

Two parallel functions return the platform name:

- **`sub_54038`** (narrow): Returns `"MacOS"` as `std::string`
- **`sub_54048`** (wide): Returns `L"MacOS"` as `std::wstring`

### OS Version String: `sub_39F80`

Constructs a system identification string:
```
Format: "%s %s (Kernel %s)"
Example: "MacOS 14.0 (Kernel 23.0.0)"
```

Built by calling three helper functions:
- `sub_4B42C` -- Gets kernel/OS version string
- `sub_4B620` -- Gets OS release string
- `sub_4B794` -- Gets OS name string

### Platform Version with Architecture: `sub_54058` / `sub_5412C`

Extended version strings for narrow and wide representations:
- Narrow: Concatenates `"MacOS"` + `" "` + `"Unrecognized"` (fallback for unrecognized sub-versions)
- Wide: Concatenates `L"MacOS"` + `L" "` + (wide version data from `dword_A18D0`)

---

## Summary of Data Flow

```
External Data (UTF-8 / UTF-16LE)
        |
        v
   [iconv conversion]
        |
        v
 Internal Processing (std::wstring / UTF-32LE)
        |
        v
   [iconv conversion]
        |
        v
  Output (UTF-8 std::string)
        |
        +---> Logging:  "[EAC HH:MM:SS] [InGame] Info: ..."
        +---> Network:  Protocol messages
        +---> Errors:   "game_error.<key>" -> user message
        +---> Files:    Binary catalogue I/O via custom streambuf
```

The encoding subsystem is a bridge layer necessitated by EAC's cross-platform nature: Windows uses UTF-16LE `wchar_t`, macOS uses UTF-32LE `wchar_t`, and external protocols use UTF-8. The iconv-based conversion functions at `0x51664`, `0x51990`, `0x51BD8`, and `0x51FA4` form the translation layer between these representations.
