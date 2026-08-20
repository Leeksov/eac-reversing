# 19 - Network Handshake Tracing

## Overview

This document describes the `trace_network.py` harness for capturing the EAC
in-game service's network handshake sequence. The harness extends the two-phase
emulation approach (_x init then _y tick) with synthetic network peer stubs
that intercept all socket operations and log the binary data exchanged.

## Harness Design

### Architecture

```
trace_network.py (NetworkTraceHarness)
    |
    +-- Phase 1: _x initialization (inherits from Harness)
    |     - Allocates 0x2B20-byte context
    |     - Initializes DTLS sessions, mutexes, crypto seeds
    |     - Stores context at 0xC1278
    |
    +-- Phase 2: Network trigger + _y tick loop
          |
          +-- Trigger Strategy (configurable):
          |     - "state": Manipulate ctx+0x26A8 connection state
          |     - "vtable2": Call process_message (vtable[2] at 0xC4F0)
          |     - "vtable7": Call connection management (vtable[7] at 0x13694)
          |     - "all": Try each strategy sequentially
          |
          +-- _y tick loop (0x1B744) with network stubs
                - socket() -> fake fd 42
                - connect() -> success, logs sockaddr_in
                - getaddrinfo() -> fake addrinfo for 127.0.0.1
                - send() -> logs data, queues synthetic response
                - recv() -> returns queued response data
                - select() -> marks fd ready
                - All calls logged with full binary data
```

### Network Stub Models

| Stub | Behavior | Purpose |
|------|----------|---------|
| `_socket(AF_INET, SOCK_STREAM, 0)` | Returns fd=42 | Fake TCP socket |
| `_connect(fd, sockaddr, len)` | Returns 0, logs addr | Captures target endpoint |
| `_getaddrinfo(host, port, hints, res)` | Builds fake addrinfo -> 127.0.0.1 | DNS interception |
| `_freeaddrinfo(ai)` | No-op | Cleanup |
| `_send(fd, buf, len, flags)` | Logs data, queues response | **Captures handshake bytes** |
| `_recv(fd, buf, len, flags)` | Returns queued response | Synthetic server |
| `_select(nfds, r, w, e, timeout)` | Returns 1, marks fd ready | Unblocks I/O waits |
| `_setsockopt` / `_getsockopt` | Returns 0 | Socket config |
| `_fcntl(fd, F_GETFL/F_SETFL)` | Returns 0 / accepts flags | Non-blocking mode |
| `_close(fd)` | Resets socket state | Socket teardown |
| `_popen("host -4 ...")` | Returns fake FILE, logs cmd | DNS fallback |
| `_poll(fds, nfds, timeout)` | Returns 1 (ready) | I/O readiness |

### Synthetic Server Responses

The harness auto-detects the protocol of sent data and generates matching
responses:

1. **HTTP requests** (GET/POST/CONNECT): Returns `HTTP/1.1 200 OK` with a
   minimal JSON body.

2. **TLS ClientHello** (record type 0x16): Returns a minimal TLS 1.2
   ServerHello stub.

3. **EAC binary protocol** (12-byte header with valid total_length): Returns
   a server hello message echoing the session ID with a computed CRC32 checksum.

4. **Unknown**: Returns 4 zero bytes as a minimal ack.

## Trigger Strategies

The service enters an idle state (connection state = 0x05) after _x
initialization. The _y tick function checks this state at ctx+0x26A8 and
does nothing when idle. Three strategies are available to activate the
network stack:

### Strategy 1: State Manipulation (`--trigger state`)

Writes various values to the connection state field and ticks _y:

| State | Label | Rationale |
|-------|-------|-----------|
| 0x01 | connecting | Lowest state that might trigger socket creation |
| 0x10 | pre-connect | One bit below the connected threshold (0x11) |
| 0x02 | handshake-start | Early handshake state |
| 0x04 | awaiting-connection | Pre-idle state |
| 0x00 | reset | Force full re-init |
| 0x08 | network-init | Network subsystem flag |
| 0x20 | secure-flag | The "secure" bit from is_connected() |

### Strategy 2: vtable[2] Process Message (`--trigger vtable2`)

Calls the `process_message` method (at 0xC4F0) directly with a synthetic
message containing a server hostname and port. This is the mechanism the
game engine uses to feed connection parameters.

### Strategy 3: vtable[7] Connection Management (`--trigger vtable7`)

Calls the connection management method (at 0x13694) directly. This may
initiate connection setup internally.

### Combined (`--trigger all`, default)

Tries all strategies sequentially, stopping when network activity is detected.

## Connection State Machine

From docs/12-runtime-behavior.md, the connection state encoding:

```
state = ctx[+0x26A8]
is_connected = (state & 0xDF) == 0x11
```

- `0x05` = idle (post-init default)
- `0x11` = connected (standard)
- `0x31` = connected + secure (bit 5 = TLS established)
- State transitions during DTLS handshake are driven by the tick loop

## Protocol Framing Reference

From docs/08-network-protocol.md, the EAC binary protocol header:

```
Offset  Size  Field
0x00    4     total_length (uint32, includes header, max 1MB)
0x04    8     session_id (uint64, validated against local state)
0x02    2     flags (uint16, bit 2 = special processing)
0x08    4     checksum (CRC32 with this field zeroed for computation)
```

The connection sequence is: DNS -> TCP connect -> TLS handshake -> HTTP
request/response -> binary protocol framing.

## Usage

```bash
# Default: try all trigger strategies, 10 ticks
python3 tools/trace_network.py path/to/eac_service_decoded.dylib

# Specific trigger with more ticks
python3 tools/trace_network.py path/to/eac_service_decoded.dylib \
    --trigger state --ticks 20 --max-y 10000000

# Focus on vtable-based triggering
python3 tools/trace_network.py path/to/eac_service_decoded.dylib \
    --trigger vtable2

# Increase init budget for complex initialization paths
python3 tools/trace_network.py path/to/eac_service_decoded.dylib \
    --max-x 15000000 --max-y 8000000 --ticks 30
```

### Output

- Console: Real-time logging of all network calls with hex data
- `/tmp/svc_network_trace.json`: Full structured report with:
  - All network events with timestamps and binary data
  - DNS queries and resolved addresses
  - Connection targets (IP:port)
  - Complete hex dumps of all sent/received data
  - SSL/TLS events
  - Callback invocations from the service
  - popen DNS fallback commands
  - Stub hit counts

## Expected Observations

### If network activity triggers:

1. **DNS resolution**: `getaddrinfo("eac-cdn.epicgames.com", "443")` or similar
   hostname provided by the game via callback/vtable[2].

2. **TCP connect**: `connect(42, 127.0.0.1:443)` to the resolved address.

3. **TLS handshake**: The first `send()` should contain a TLS ClientHello
   record (content type 0x16) with mbedTLS-generated parameters including
   the configured cipher suites and SNI extension.

4. **HTTP request**: After TLS, an HTTP GET or POST to the EAC backend
   for the initial handshake.

5. **Binary protocol**: After HTTP, the 12-byte framed binary protocol
   for anti-cheat communication.

### If no network activity:

The service is entirely game-driven. Without proper initialization
parameters from the EOS SDK (server hostname, session tokens, game ID),
the tick function remains in idle polling mode. The harness logs which
trigger strategies were attempted and their outcomes for further analysis.

## Key Addresses

| Address | Role |
|---------|------|
| 0x1B664 | `_x` entry (init) |
| 0x1B744 | `_y` entry (tick) |
| 0xC1278 | Global context pointer |
| 0xB42A8 | Main vtable (20 methods) |
| 0xC4F0  | vtable[2] process_message |
| 0x13694 | vtable[7] connection management |
| 0x13680 | vtable[4] is_connected |
| 0x47E84 | Socket wrapper Connect method |
| 0x47C58 | DNS resolution (getaddrinfo path) |
| 0x47D44 | DNS fallback (popen "host -4") |
| 0x4807C | Socket wrapper Send method |
| 0x4810C | Socket wrapper Recv method |
| 0xB5400 | Socket wrapper vtable |

## Dual DTLS Channels

The context contains two parallel DTLS session structures:

- **Channel A** (ctx+0x0618): Client-to-server anti-cheat reports
- **Channel B** (ctx+0x0FF0): Server-to-client challenge/response

Both are configured with: buffer size 10000, 14 cipher suites, DTLS 1.2.
The handshake trace should reveal which channel initiates first and whether
they use the same or different server endpoints.
