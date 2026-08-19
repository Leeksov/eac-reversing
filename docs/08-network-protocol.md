# 08 - EAC In-Game Service Network Protocol

## Overview

The EAC in-game service (`eac_service_decoded.dylib`) implements a custom binary
protocol layered over TLS 1.0-1.2, transported on TCP sockets. The TLS
implementation is a statically linked copy of **mbedTLS** (compiled from
`/Users/arttumarttinen/Desktop/workspace/Git/External/mbedtls/library/`). The
service also supports both TLS and DTLS (v1.0/v1.2), with the DTLS path
providing UDP-based transport with its own fragment reassembly logic. An HTTP
layer is present for proxy tunnelling (CONNECT) and for the initial EAC backend
handshake (GET/POST over HTTP/1.1).

Build timestamp found in binary: `Jun 11 2026 05:20:13`.

---

## 1. Networking API Imports

### BSD Socket Layer (from libSystem)

| Import              | GOT Address  | Purpose                              |
|---------------------|--------------|--------------------------------------|
| `_socket`           | `0x644628`   | Create TCP socket (AF_INET, SOCK_STREAM) |
| `_connect`          | `0x644330`   | Non-blocking connect with retry      |
| `_send`             | `0x644608`   | Send data (MSG_NOSIGNAL=0x80000)     |
| `_recv`             | `0x6445c0`   | Receive data (blocking + peek modes) |
| `_select`           | `0x6445e0`   | Wait for socket writability (connect timeout) |
| `_getaddrinfo`      | `0x6443e8`   | DNS resolution (AF_INET, SOCK_STREAM) |
| `_freeaddrinfo`     | `0x6443d8`   | Free DNS results                     |
| `_setsockopt`       | `0x644610`   | SO_RCVTIMEO (4102) / SO_SNDTIMEO (4101) |
| `_getsockopt`       | `0x644408`   | SO_ERROR check after non-blocking connect |
| `_fcntl`            | `0x644378`   | F_GETFL/F_SETFL for O_NONBLOCK       |
| `_close`            | `0x644320`   | Close socket fd                      |
| `_ioctl`            | `0x644480`   | Socket I/O control                   |
| `_read`             | `0x6445a0`   | Raw fd read (used by mbedTLS bio)    |

### Proxy Detection (from CFNetwork)

| Import                                    | GOT Address  | Purpose              |
|-------------------------------------------|--------------|----------------------|
| `_CFNetworkCopySystemProxySettings`       | `0x6447f0`   | Read macOS system proxy config |
| `_kCFNetworkProxiesHTTPProxy`             | `0x6447a8`   | HTTP proxy host key  |
| `_kCFNetworkProxiesHTTPSProxy`            | `0x6447c0`   | HTTPS proxy host key |
| `_kCFNetworkProxiesSOCKSProxy`            | `0x6447e8`   | SOCKS proxy host key |
| `_kCFNetworkProxiesProxyAutoConfigEnable` | `0x6447c8`   | PAC auto-config flag |
| `_kCFNetworkProxiesProxyAutoConfigURLString` | `0x6447d0` | PAC URL             |

### DNS Fallback

The service has a fallback DNS resolver at `sub_47D44` that shells out to:
```
host -4 <hostname>
```
via `popen()`, parsing the output to extract IPv4 addresses. This is invoked
when `getaddrinfo()` does not return results.

---

## 2. Transport Protocols

### Primary: TCP + TLS (mbedTLS)

The binary statically links mbedTLS with full TLS 1.0/1.1/1.2 and DTLS 1.0/1.2
support compiled in. Source file paths embedded in debug strings:

- `ssl_cli.c` -- TLS client handshake
- `ssl_srv.c` -- TLS server handshake (for self-test / DTLS cookie)
- `ssl_tls.c` -- Core TLS record layer

**Supported TLS versions** (from strings):
- SSLv3.0, TLSv1.0, TLSv1.1, TLSv1.2
- DTLSv1.0, DTLSv1.2

**Cipher suites**: The full mbedTLS suite table is compiled in (140+ suites).
Key families present:
- `TLS-ECDHE-RSA-WITH-AES-{128,256}-{CBC,GCM}-SHA{256,384}` (modern)
- `TLS-ECDHE-ECDSA-WITH-AES-*` (EC server certs)
- `TLS-DHE-RSA-WITH-AES-*`
- `TLS-RSA-WITH-AES-*` (fallback, no PFS)
- `TLS-*-PSK-*` (pre-shared key families)
- RC4, 3DES, Camellia, Blowfish variants also compiled in

**Elliptic curves**: secp256r1, secp384r1, secp521r1, secp192/224 variants,
brainpoolP256r1/384r1/512r1, secp256k1.

**Embedded certificates**: Multiple PEM-encoded test/production certificates
from "PolarSSL" (mbedTLS predecessor) CA hierarchy are embedded in the binary.
The `EAC index certificate` validation uses X.509 certificate chain verification
with revocation checking (`EAC index certificate revoked`).

### HTTP Layer

HTTP/1.1 is used for two purposes:

1. **Proxy CONNECT tunnelling** (`sub_46A20`):
   ```
   CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n
   ```
   Used when a system HTTP/HTTPS proxy is detected via CFNetwork.

2. **Backend API requests** (`sub_4576C` / `sub_459C8`):
   - `GET <path> HTTP/1.1\r\n` -- with custom headers
   - `POST <path> HTTP/1.1\r\n` -- with `Content-Length` header and body

   The HTTP response parser (`sub_45B68`) processes `\r\n\r\n` header
   termination, extracts `HTTP/` version, status code, and parses
   `content-length` for body framing.

### DTLS (UDP) Path

DTLS support is compiled in but appears secondary. Strings indicate:
- Fragment reassembly (`adding fragment, offset = %d, length = %d`)
- Epoch management (`DTLS epoch would wrap`)
- HelloVerifyRequest / cookie exchange
- Out-of-sequence message handling
- Timer-based retransmission (`mbedtls_ssl_resend`)

---

## 3. Socket Wrapper Class

The networking layer is encapsulated in a C++ class with a vtable at `0xB5400`.
Key methods and their offsets within the object (stored at `this+184` = socket
fd, `this+240/242/244` = timeout config):

| Vtable Slot | Function     | Address      | Purpose                           |
|-------------|-------------|--------------|-----------------------------------|
| 0           | IsAlive     | `sub_477E0`  | `recv(fd, buf, 4, MSG_PEEK\|MSG_DONTWAIT)` liveness check |
| 1           | HasData     | `sub_47784`  | Check if readable data pending    |
| 2           | SetRecvTimeout | `sub_478DC` | `setsockopt(SO_RCVTIMEO)` in ms  |
| 3           | SetSendTimeout | `sub_47960` | `setsockopt(SO_SNDTIMEO)` in ms  |
| 4           | SetConnTimeout | `sub_479E4` | Store connect timeout at +240    |
| 5           | (unused)    |              |                                    |
| 6           | Connect     | `sub_47E84`  | Full connection: DNS resolve + socket + connect |
| 7           | Send        | `sub_4807C`  | `send(fd, buf, len, MSG_NOSIGNAL)` |
| 8           | Recv        | `sub_4810C`  | `recv(fd, buf, len, 0)` with EINTR/EAGAIN handling |
| 9           | Disconnect  | `sub_481CC`  | `close(fd)` + reset state         |

### Connection Flow (`sub_47E84` -- Connect)

1. Lock mutex at `this+8`
2. Disconnect any existing socket (vtable slot 11, offset +120)
3. Extract hostname and port from connection parameters
4. **DNS Resolution** (`sub_47C58`):
   - Call `getaddrinfo(hostname, port_str, {AF_INET, SOCK_STREAM}, &results)`
   - Iterate results, store each resolved address via `sub_48580`
5. **DNS Fallback** (`sub_47D44`):
   - If getaddrinfo fails, run `popen("host -4 <hostname>")` and parse output
6. For each resolved address:
   - Create socket: `socket(AF_INET, SOCK_STREAM, 0)`
   - Set `SO_RCVTIMEO` / `SO_SNDTIMEO` from stored timeouts
   - **Non-blocking connect** (`sub_47A70`):
     - `fcntl(fd, F_SETFL, flags | O_NONBLOCK)`
     - `connect(fd, addr, 16)` -- accepts EINPROGRESS/EWOULDBLOCK/EAGAIN
     - `select(fd+1, NULL, &wset, NULL, &timeout)` to wait for writability
     - `getsockopt(fd, SOL_SOCKET, SO_ERROR)` to verify connection succeeded
     - Restore blocking mode: `fcntl(fd, F_SETFL, original_flags)`
   - On first successful connect, break

### Send (`sub_4807C`)

- Mutex-protected
- Single `send(fd, buf, len, MSG_NOSIGNAL)` call
- Returns success only if all bytes sent; otherwise calls disconnect handler
  (`sub_44450`)

### Recv (`sub_4810C`)

- Mutex-protected
- `recv(fd, buf, len, 0)` with EINTR (4) and EAGAIN (35) retry
- Returns 0 and disconnects on recv returning 0 (peer closed)

---

## 4. Application-Layer Protocol (EAC Binary Protocol)

### Message Framing

The protocol uses a 12-byte message header followed by variable-length payload.
Analysis of the message processing function `sub_6300`:

```
Offset  Size   Field
0x00    4      total_length    (uint32, includes header, max 0x100000 = 1MB)
0x04    8      session_id      (uint64, validated against local state at obj+40)
0x02    2      flags           (uint16, bit 2 = special processing mode)
0x08    4      checksum        (CRC32 over entire message with this field zeroed)
```

**Integrity check** (`sub_6888`): The message checksum at offset +8 is validated
using CRC32 (`sub_2919C`) -- a standard CRC32 with lookup table at `0x9EF80`.
The algorithm zeroes the checksum field, computes CRC32 over `total_length`
bytes, and compares against the stored checksum.

### Message Processing (`sub_6300`)

The receive loop processes incoming data through a framing layer (`sub_3DF64`):

1. **Frame extraction**: `sub_3DF64` reads from the encrypted stream, validates
   the 24-byte framing header (session ID match at offset +4 vs local state),
   and handles acknowledgment/sequence logic.

2. **Size validation**:
   - Minimum message size: 12 bytes (`MessageTooSmallA`)
   - Maximum message size: 0x100000 / 1MB (`MessageTooLarge`)
   - Payload must be >= 8 bytes after header (`MessageTooSmallC`)

3. **Integrity check**: CRC32 validation (`sub_6888`)

4. **Payload extraction**: `total_length - 12` bytes of payload are copied and
   dispatched to a message queue (`sub_8998` -> `sub_4BA18`) for asynchronous
   processing.

5. **Error codes**: Failed messages generate named error events:
   - `MessageTooSmallA/B/C` -- undersized messages (severity 3/4/5)
   - `MessageTooLarge` -- oversized message (severity 2)
   - `CorruptedData` -- CRC32 mismatch (severity 1)
   - `MMCorruptedData` -- memory corruption detected (severity 6)

### Connection Errors

The service reports network errors via the game error callback system:

| Error Code | Error Key                              | Message                          |
|------------|----------------------------------------|----------------------------------|
| 12         | `game_error.error_corrupted_network`   | "Corrupted packet flow"          |
| 8          | `game_error.error_module_forbidden`    | "Forbidden module"               |
| 9          | `game_error.error_corrupted_memory`    | "Corrupted memory"               |
| 10         | `game_error.error_tool_forbidden`      | "Forbidden tool"                 |
| 11         | `game_error.error_violation`           | "Internal anti-cheat error"      |
| 13         | `game_error.error_virtual`             | "Cannot run under Virtual Machine" |
| 14         | `game_error.error_system_configuration`| "Forbidden system configuration" |
| 15         | `game_error.error_file_version`        | (file version error)             |

Error 12 ("Corrupted packet flow") specifically indicates a network protocol
integrity failure and is dispatched with the connection identifier appended.

### Connection Reset Handling

Five distinct connection reset variants are defined as named strings:
- `NoConnectionResetV2A` through `NoConnectionResetV2E`

These appear to represent different categories of connection loss/reset that
the client can distinguish for telemetry and retry logic.

---

## 5. Backend Communication Architecture

### Connection Sequence

```
Game Process
    |
    v
EAC Service (this dylib)
    |
    +-- [1] DNS Resolution (getaddrinfo / "host -4" fallback)
    |
    +-- [2] System Proxy Detection (CFNetworkCopySystemProxySettings)
    |        |
    |        +-- HTTP proxy  -> CONNECT tunnel (sub_46A20)
    |        +-- HTTPS proxy -> CONNECT tunnel
    |        +-- SOCKS proxy -> direct SOCKS connect
    |        +-- PAC URL     -> auto-config
    |
    +-- [3] TCP Connect (non-blocking with select timeout)
    |
    +-- [4] TLS Handshake (mbedTLS, mutual certificate validation)
    |        |
    |        +-- Server certificate chain verification
    |        +-- EAC index certificate revocation check
    |        +-- SNI extension (client hello, adding server name)
    |
    +-- [5] HTTP Request/Response (GET/POST over TLS)
    |        |
    |        +-- Initial handshake: GET <path> HTTP/1.1
    |        +-- Data upload: POST <path> HTTP/1.1 + Content-Length
    |        +-- Response parsing (sub_45B68)
    |
    +-- [6] Binary Protocol (framed messages over TLS stream)
             |
             +-- 12-byte header (length + session_id + CRC32)
             +-- Payload (detection results, heartbeats, etc.)
             +-- Bidirectional messaging via message queue
```

### Proxy Support

The service reads macOS system proxy settings via `CFNetworkCopySystemProxySettings`
and supports:
- **HTTP/HTTPS proxy**: Uses HTTP CONNECT method to tunnel through the proxy
- **SOCKS proxy**: Direct SOCKS connection
- **PAC (Proxy Auto-Configuration)**: Reads PAC URL for automatic proxy selection

### No Hardcoded Endpoints

The binary contains **no hardcoded server URLs, IP addresses, or port numbers**.
All connection parameters (hostname, port, paths) are passed to the service at
runtime through the EOS (Epic Online Services) SDK interface. The only
network-related format strings are:
- `CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n` (proxy tunnel)
- `GET ` / `POST ` (HTTP requests)
- `host -4 %s` (DNS fallback)
- `%i` (port number formatting for getaddrinfo)

---

## 6. Harness Trace Observations

From the `/tmp/svc_report.json` trace (initialization only, no network
activity):

- **No socket-related stubs were hit** during service initialization, confirming
  that the network subsystem is dormant until a game session is actively
  connected and the EAC backend triggers communication.
- The initialization phase only exercises: mutex/condvar setup (52 mutex inits),
  memory allocation (5 `new`, 8 `calloc`, 32 `memset`), time queries (4
  `gettimeofday`, 3 `clock_get_time`), and file I/O (2 `fopen`/`fread`/`fclose`
  -- likely reading local configuration or certificate stores).

---

## 7. Security Observations

1. **MSG_NOSIGNAL (0x80000)**: Used on `send()` to prevent SIGPIPE on broken
   connections -- standard robust networking practice.

2. **CRC32 for integrity**: The application-layer message checksum uses CRC32,
   which is not cryptographically secure. However, since messages travel inside
   a TLS tunnel, the CRC32 serves as a structural integrity check rather than a
   security mechanism.

3. **Certificate pinning**: The embedded PolarSSL/mbedTLS test certificates and
   the `EAC index certificate revoked` error suggest the service performs
   certificate pinning or at minimum validates against a known CA chain specific
   to EAC infrastructure.

4. **No plaintext secrets**: Connection endpoints and credentials are not
   embedded in the binary -- they are provided at runtime through the EOS SDK
   layer.

5. **Renegotiation controls**: The TLS stack has renegotiation handling with
   explicit controls (`refusing renegotiation, sending alert`, `legacy
   renegotiation, breaking off handshake`), indicating awareness of TLS
   renegotiation attacks.
