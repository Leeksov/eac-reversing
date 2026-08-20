# 20 - Hash Catalogue Trace Results

Findings from tracing EAC's file integrity system using `tools/trace_catalogue.py`,
a Unicorn-based harness that feeds synthetic catalogue files to the binary and
records all import calls, file accesses, and parsing decisions.

---

## Harness Overview

The harness (`tools/trace_catalogue.py`) extends the core emulation framework with:

- **Filesystem model**: fopen/fread/fseek/ftell/rewind/fclose serve synthetic files
  based on path matching (.bin = catalogue, .cer = certificate, Mach-O for exe paths)
- **Path resolution**: `_NSGetExecutablePath` returns a fake game executable path,
  `realpath` echoes it back
- **Charset conversion**: iconv stubs perform real UTF-8 <-> UTF-32LE conversion
  (the binary uses wide strings internally for all path operations)
- **C++ string operations**: Full std::string and std::wstring method models for
  14 imported libc++ functions (append, assign, insert, rfind, copy ctor, etc.)
- **Runtime globals**: Initializes `dword_C1288 = 0x10004` (normally set by
  `InitFunc_2` at 0x302B8) -- required for version field validation

Three trace modes:
- `--mode init`: Traces `sub_113DC` (exe verification against catalogue tree)
- `--mode load`: Traces `sub_2B8D0` (catalogue file loading + certificate parsing)
- `--mode full`: Traces `_x` (full service entry point)

---

## Catalogue Binary Format (v4)

Determined by tracing through `sub_2F73C` (catalogue validator) and `sub_2FF30`
(certificate verifier). The format has a fixed 0x41C (1052) byte header followed
by variable-length data sections:

```
Offset  Size    Field                   Description
------  ------  ----------------------  ------------------------------------------
0x000   4       magic                   0x00434145 ("EAC\0" LE)
0x004   2       version_low             4 for format v4
0x006   2       version_high            Controls parsing mode (1 = decrypt/clear)
0x008   0x400   cert_key_area           1024 bytes of certificate/key data
0x408   4       cert_data_length        Length of cert data (must be > 0)
0x40C   4       signed_data_size        Size of hash entry block after header
0x410   4       signature_size          Size of ECDSA signature block
0x414   4       entry_table_size        Size used for entry table allocation
0x418   4       (reserved)              Padding to 0x41C alignment
0x41C   var     signed_data             Hash entries (signed_data_size bytes)
0x41C+S var     signature               ECDSA signature (signature_size bytes)
```

**Size constraint**: `total_file_size - 1052 == signed_data_size + signature_size`

**Version high field** (offset 0x006):
- When `version_high == 1` (matches `HIWORD(dword_C1288)`):
  - The catalogue data is copied to a temporary buffer
  - `cert_data_length` at offset 0x408 is cleared to 0 in the copy
  - The cert_key_area (offsets 0x008-0x408) is zeroed in the copy
  - The full copy is used for subsequent parsing
  - This path appears to handle encrypted/obfuscated catalogue data
- When `version_high != 1`:
  - Raw data starting at offset 0x41C is used directly
  - No decryption or clearing occurs

---

## Companion Certificate File

The v4 parser (`sub_2F518`) constructs a companion certificate path by:

1. `rfind('.')` on the catalogue file path to find the extension
2. Truncating at the dot position
3. Appending `.cer` (wide string at `0x9F490`)

So `game_429c2212.bin` has a companion `game_429c2212.cer`.

The certificate file is a DER-encoded X.509 certificate used for ECDSA signature
verification of the catalogue data. The binary uses mbedTLS internally.

---

## Trace Results: Init Mode (sub_113DC)

Entry: `sub_113DC` -- main file integrity initialization.

**Execution**: 940 steps, 567 unique PCs, 0 CV instructions.

**Call sequence**:
1. `sub_34DF0` -- resolves game executable path:
   - `_NSGetExecutablePath(buf, &bufsize)` -- returns the process path
   - `realpath(path, resolved)` -- canonicalizes the path
   - `strlen` + `string::resize` -- trims the buffer
2. `sub_342D4` -- extracts basename from exe path (pure computation, no imports)
3. `sub_2CD28` -- computes CRC32 identifier for catalogue lookup:
   - `sub_2CDA0` -- copies basename to std::string
   - `sub_51990` -- converts UTF-8 to UTF-32LE via `iconv_open("UTF-32LE","UTF-8")` + `iconv`
   - `sub_2CBF0` -- computes CRC32 of the wide-string basename:
     - `sub_34304` -- wide-string basename (scans for `/` or `\`)
     - `sub_501AC` -- `wcslen` (counts wide chars)
     - `sub_2919C` -- CRC32 over `4 * wcslen` bytes using table at `0x9EF80`
4. `sub_2C3AC` -- searches the catalogue tree (empty -> returns NULL):
   - `realpath()` on the exe path
   - `pthread_mutex_lock` on the catalogue mutex
   - `sub_2DF24` -- tree lookup by CRC32 key
   - `pthread_mutex_unlock`
5. **Error dispatch**: vtable call at `*(vtable+128)` with error code **15**
   ("Could not locate game executable entry in the catalogue")

**CRC32 input**: 8 bytes of the wide-string exe basename data.

**Import calls**: 21 unique stubs hit (see stub_hits in report).

---

## Trace Results: Load Mode (sub_2B8D0)

Entry: `sub_2B8D0` -- catalogue file loading and parsing.

**Execution**: 15,421 steps, 1,311 unique PCs, 0 CV instructions.

**File access pattern** (3 files opened):

| # | Path | Size Read | Purpose |
|---|------|-----------|---------|
| 1 | `.../Certificates/game_429c2212.bin` | 1436 | Header validation (sub_2CE38) |
| 2 | `.../Certificates/game_429c2212.bin` | 1436 | Full data for parsing (sub_2F518) |
| 3 | `.../Certificates/game_429c2212.cer` | 1024 | Certificate for signature verification |

**Call sequence**:
1. `sub_2CE38` -- validates catalogue header:
   - Converts wstring path to narrow via iconv (UTF-32LE -> UTF-8)
   - `sub_348D8` -> `sub_347F0` -- opens and reads the .bin file
   - Checks: `size >= 0x40C`, `magic == 0x00434145`
   - Returns version number from DWORD[1] (0x0004 for v4)
2. `sub_CFF4` -- extracts certificate chain from context
3. `sub_2CECC` -- format factory:
   - Version 4: allocates 0x38-byte handler, sets vtable to `off_B4B78`
   - Version 5: allocates 0x7B0-byte handler, calls `sub_30380`
4. Handler vtable[2] = `sub_2F518` -- main v4 parsing:
   - Copies 6 context strings (string copy ctor x6)
   - Copies wstring path, `rfind('.')` for extension
   - Constructs `.cer` path by appending `".cer"` from `0x9F490`
   - Re-reads the .bin file via `sub_348D8`
5. `sub_2F73C` -- catalogue data validation:
   - Re-validates: size >= 0x41C, magic, version field matches `dword_C1288`
   - Size consistency: `total - 1052 == signed_data_size + signature_size`
   - Copies catalogue data for processing
6. `sub_2FF30` -- certificate verification:
   - Opens and reads the `.cer` file
   - `sub_2FC4C` -- certificate chain validation (mbedTLS)
   - `sub_95F00` -- hash computation over signed data
   - `sub_8C234` -- ECDSA signature verification
   - Returns error 11 with our synthetic data (signature mismatch)

**Return value**: 11 (Internal anti-cheat error -- ECDSA signature verification failed
on our synthetic certificate data).

---

## Key Addresses for Catalogue System

| Address | Function | Role |
|---------|----------|------|
| `0x113DC` | `sub_113DC` | Entry: exe verification init |
| `0x2B8D0` | `sub_2B8D0` | Entry: catalogue load + parse |
| `0x2BB24` | `sub_2BB24` | Glob-based catalogue file discovery |
| `0x2BF3C` | `sub_2BF3C` | Catalogue directory path construction |
| `0x2C3AC` | `sub_2C3AC` | CRC32-based tree lookup |
| `0x2CBF0` | `sub_2CBF0` | Wide-string basename CRC32 |
| `0x2CD28` | `sub_2CD28` | Path -> CRC32 pipeline |
| `0x2CE38` | `sub_2CE38` | Header validation (magic + version) |
| `0x2CECC` | `sub_2CECC` | Format factory (v4/v5 dispatch) |
| `0x2F518` | `sub_2F518` | V4 handler: parse + cert path construction |
| `0x2F73C` | `sub_2F73C` | Catalogue body validation + size checks |
| `0x2FF30` | `sub_2FF30` | Certificate verification entry |
| `0x2FC4C` | `sub_2FC4C` | Certificate chain validation |
| `0x2919C` | `sub_2919C` | CRC32 computation (table at `0x9EF80`) |
| `0x302B8` | `InitFunc_2` | Runtime init: sets `dword_C1288 = 0x10004` |
| `0x347F0` | `sub_347F0` | Generic file reader (fopen/fseek/fread/fclose) |
| `0x348D8` | `sub_348D8` | File reader with wstring->narrow path conversion |
| `0x34DF0` | `sub_34DF0` | Executable path resolution |
| `0x342D4` | `sub_342D4` | Narrow-string basename extraction |
| `0x34304` | `sub_34304` | Wide-string basename extraction |
| `0x51664` | `sub_51664` | UTF-32LE -> UTF-8 conversion (iconv) |
| `0x51990` | `sub_51990` | UTF-8 -> UTF-32LE conversion (iconv) |
| `0x501AC` | `sub_501AC` | Wide-string length (wcslen equivalent) |
| `0x50C68` | `sub_50C68` | Wide-string to-lowercase (A-Z |= 0x20) |

---

## Runtime Globals

| Address | Value | Set By | Purpose |
|---------|-------|--------|---------|
| `0xC1288` | `0x00010004` | `InitFunc_2` | Version validation: low16=4, high16=1 |
| `0xBEC60` | 0/1 | `sub_4F538` guard | Platform flag (0=macOS, 1=iOS/other) |
| `0xBEC68` | guard | `__cxa_guard` | One-time init guard for BEC60 |
| `0xBEC70` | 0/1 | `sub_4F538` guard | Platform flag (duplicate for CRC path) |
| `0xBEC78` | guard | `__cxa_guard` | One-time init guard for BEC70 |
| `0xC1390` | 0/1 | `sub_4F538` | Set to 1 if exe path ends in ".exe" |

---

## Wide String Data Constants

| Address | Wide String Content | Used In |
|---------|--------------------|---------| 
| `0x9F3E0` | `".bin"` | Catalogue file extension |
| `0x9F3F4` | `"base"` | Base filename component |
| `0x9F408` | `"EasyAntiCheat/Certificates/"` | Certificate directory suffix |
| `0x9F490` | `".cer"` | Certificate file extension |

---

## Error Flow Summary

The catalogue verification produces these error paths:

1. **Catalogue not loaded** (tree empty) -> sub_113DC dispatches error **15**
   ("Could not locate game executable entry in the catalogue")
2. **Header invalid** (bad magic/size) -> sub_2B8D0 returns **8**
   ("Not found" -- catalogue format unrecognized)
3. **Format creation fails** -> sub_2B8D0 returns **7**
   ("System error" -- handler allocation failed)
4. **Body validation fails** (size mismatch, version mismatch) -> parser returns **9**
   ("Corrupted memory" -- catalogue structure invalid)
5. **Certificate missing** (cer path not found) -> sub_2FF30 returns **27**
   (Extended error -- parameter validation failed)
6. **Certificate/signature invalid** -> sub_2FF30 returns **11**
   ("Internal anti-cheat error" -- ECDSA verification failed)
7. **Hash mismatch** -> sub_113DC dispatches error **4**
   ("Unknown file version" -- exe hash not in catalogue)
