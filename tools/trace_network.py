#!/usr/bin/env python3
"""Network handshake tracer for the EAC in-game service.

Extends the two-phase harness (_x init -> _y tick loop) with synthetic
network peer stubs.  After _x completes, manipulates connection state
to trigger the network stack, then logs every socket/connect/send/recv
call with full binary data to understand the handshake protocol.

Usage:
    python3 trace_network.py path/to/eac_service_decoded.dylib [options]
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time as _time
from collections import Counter, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from service_cv_trace import (Harness, STOP, STACK_BASE, STACK_SIZE,
                               CV_START, CV_END, EXTERNAL_BASE, RET, u64, p64,
                               HEAP_BASE, CALLBACK)
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X30)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


# CAS spin-loop addresses (from trace_y_twophase.py)
CAS_LDAXR_ADDRS = {
    0x1CD6F4, 0x1D80C8, 0x1D9F5C, 0x1DB984, 0x1DD9E4, 0x1DFBD8,
    0x1E27D0, 0x1E4B88, 0x1E6394, 0x1E8F24, 0x1EA640, 0x1EC4CC,
    0x1EF3BC, 0x1F4C24, 0x22278C, 0x22644C,
}
CAS_THRESHOLD = 5

# Fake socket fd
FAKE_FD = 42

# Context offsets (from docs/12-runtime-behavior.md)
CTX_PTR_ADDR = 0xC1278       # global pointer to context
CTX_CONN_STATE_OFF = 0x26A8  # connection state field
CTX_VTABLE_OFF = 0x0         # vtable pointer
CTX_CALLBACK_OFF = 0x0C      # callback in init block (not in ctx)

# Connection states
STATE_IDLE = 0x05
STATE_CONNECTING = 0x01
STATE_CONNECTED = 0x11

# GOT addresses for network imports (from docs/08-network-protocol.md)
GOT_SOCKET       = 0x644628
GOT_CONNECT      = 0x644330
GOT_SEND         = 0x644608
GOT_RECV         = 0x6445C0
GOT_SELECT       = 0x6445E0
GOT_GETADDRINFO  = 0x6443E8
GOT_FREEADDRINFO = 0x6443D8
GOT_SETSOCKOPT   = 0x644610
GOT_GETSOCKOPT   = 0x644408
GOT_FCNTL        = 0x644378
GOT_CLOSE        = 0x644320
GOT_IOCTL        = 0x644480
GOT_READ         = 0x6445A0
GOT_POPEN        = None  # resolved dynamically

# Synthetic server response templates
# The EAC protocol uses 12-byte binary framing:
#   total_length (u32) | session_id (u64) | flags (u16) | checksum (CRC32)
FAKE_SESSION_ID = 0xDEADBEEF13370001


def crc32_eac(data: bytes) -> int:
    """CRC32 matching the EAC implementation (standard CRC32)."""
    import binascii
    return binascii.crc32(data) & 0xFFFFFFFF


def build_server_hello(session_id: int = FAKE_SESSION_ID) -> bytes:
    """Build a minimal EAC server hello response.

    12-byte header + minimal payload.
    """
    payload = b"\x01\x00\x00\x00"  # server hello type = 1
    payload += struct.pack("<Q", session_id)  # echo session
    payload += b"\x00" * 16  # padding/challenge nonce
    total_len = 12 + len(payload)
    # Build header: length, then session_id at +4, flags at +2, checksum at +8
    # Per docs: Offset 0x00=total_length(u32), 0x04=session_id(u64),
    #           0x02=flags(u16), 0x08=checksum(CRC32)
    # This is a bit ambiguous -- let's use the framing from sub_6300:
    # Actually re-reading: total_length(4) | session_id(8) = 12 bytes header
    # flags and checksum are within/overlapping -- let's just build raw
    msg = struct.pack("<I", total_len)
    msg += struct.pack("<Q", session_id)
    # checksum placeholder
    msg += b"\x00" * (total_len - len(msg))
    # compute CRC32 with checksum field zeroed (at offset 8, 4 bytes)
    msg_arr = bytearray(msg)
    msg_arr[8:12] = b"\x00\x00\x00\x00"
    crc = crc32_eac(bytes(msg_arr))
    struct.pack_into("<I", msg_arr, 8, crc)
    return bytes(msg_arr) + payload


class NetworkEvent:
    """A single network I/O event for logging."""
    __slots__ = ("tick", "call", "args", "data", "result", "timestamp")

    def __init__(self, tick: int, call: str, args: dict, data: bytes | None = None,
                 result: int = 0):
        self.tick = tick
        self.call = call
        self.args = args
        self.data = data
        self.result = result
        self.timestamp = _time.monotonic()

    def to_dict(self) -> dict:
        d = {"tick": self.tick, "call": self.call, "args": self.args,
             "result": self.result}
        if self.data is not None:
            d["data_hex"] = self.data.hex()
            d["data_len"] = len(self.data)
            # Try to decode as ASCII if printable
            try:
                text = self.data.decode("ascii")
                if all(32 <= c < 127 or c in (10, 13, 9) for c in self.data):
                    d["data_ascii"] = text
            except Exception:
                pass
        return d


class NetworkTraceHarness(Harness):
    """Harness that traces the EAC network handshake.

    After _x initialization, manipulates connection state and ticks _y
    repeatedly while stubbing all socket operations to simulate a server.
    """

    def __init__(self, path: Path, max_x: int, max_y_per_tick: int,
                 num_ticks: int, trigger_mode: str = "state"):
        self.max_y_per_tick = max_y_per_tick
        self.num_ticks = num_ticks
        self.trigger_mode = trigger_mode  # "state", "vtable2", "vtable7"

        # Network state
        self.net_events: list[NetworkEvent] = []
        self.current_tick = 0
        self.socket_created = False
        self.connected = False
        self.send_log: list[bytes] = []
        self.recv_queue: list[bytes] = []  # synthetic server responses
        self.recv_buffer = bytearray()
        self.dns_queries: list[str] = []
        self.connect_addrs: list[dict] = []
        self.callback_events: list[dict] = []
        self.ssl_events: list[dict] = []
        self.popen_cmds: list[str] = []

        # Fake addrinfo allocation
        self._addrinfo_ptr = 0

        # CAS handling
        self.cas_spins = Counter()
        self.cas_forces = []
        self.phase = 1
        self._cas_log_limit = 50

        # Track which connection states we've tried
        self._state_attempts = []

        super().__init__(path, max_x, entry=0x1B664, report=None,
                         trace_report=None, coverage=False)

    # ----------------------------------------------------------------
    # Network stub handlers
    # ----------------------------------------------------------------
    def _log_net(self, call: str, args: dict, data: bytes | None = None,
                 result: int = 0) -> NetworkEvent:
        ev = NetworkEvent(self.current_tick, call, args, data, result)
        self.net_events.append(ev)
        return ev

    def handle_socket(self) -> int:
        """_socket(domain, type, protocol) -> fd"""
        domain = self.reg(0)
        typ = self.reg(1)
        proto = self.reg(2)
        self.socket_created = True
        self._log_net("socket", {"domain": domain, "type": typ, "protocol": proto},
                      result=FAKE_FD)
        print(f"  [NET] socket(domain={domain}, type={typ}, proto={proto}) -> {FAKE_FD}")
        return FAKE_FD

    def handle_connect(self) -> int:
        """_connect(fd, addr, addrlen) -> 0"""
        fd = self.reg(0)
        addr_ptr = self.reg(1)
        addrlen = self.reg(2)
        # Read sockaddr_in: sa_family(2) + port(2) + addr(4)
        addr_data = bytes(self.uc.mem_read(addr_ptr, min(addrlen, 16)))
        info = {"fd": fd, "addrlen": addrlen}
        if len(addr_data) >= 8:
            sa_family = struct.unpack_from("<H", addr_data, 0)[0]
            port = struct.unpack_from(">H", addr_data, 2)[0]  # network byte order
            ip_bytes = addr_data[4:8]
            ip_str = ".".join(str(b) for b in ip_bytes)
            info.update({"family": sa_family, "port": port, "ip": ip_str})
            self.connect_addrs.append({"ip": ip_str, "port": port, "family": sa_family})
            print(f"  [NET] connect(fd={fd}, {ip_str}:{port}, family={sa_family}) -> 0")
        else:
            print(f"  [NET] connect(fd={fd}, addrlen={addrlen}, data={addr_data.hex()}) -> 0")
        self.connected = True
        # Return EINPROGRESS (-36) for non-blocking, or 0 for blocking
        # The code handles EINPROGRESS, so let's return 0 for simplicity
        self._log_net("connect", info, addr_data, result=0)
        return 0

    def handle_getaddrinfo(self) -> int:
        """_getaddrinfo(hostname, service, hints, result) -> 0"""
        hostname_ptr = self.reg(0)
        service_ptr = self.reg(1)
        hints_ptr = self.reg(2)
        result_ptr = self.reg(3)

        hostname = self.cstr(hostname_ptr).decode("utf-8", errors="replace") if hostname_ptr else ""
        service = self.cstr(service_ptr).decode("utf-8", errors="replace") if service_ptr else ""
        self.dns_queries.append(f"{hostname}:{service}")
        print(f"  [NET] getaddrinfo(host=\"{hostname}\", service=\"{service}\") -> 0")

        # Build a fake addrinfo struct pointing to 127.0.0.1
        # struct addrinfo {
        #   int ai_flags;        // 0
        #   int ai_family;       // AF_INET = 2
        #   int ai_socktype;     // SOCK_STREAM = 1
        #   int ai_protocol;     // 0
        #   socklen_t ai_addrlen;// 16
        #   char *ai_canonname;  // NULL
        #   struct sockaddr *ai_addr;  // ptr to sockaddr_in
        #   struct addrinfo *ai_next;  // NULL
        # }
        # On arm64 macOS, this is 48 bytes (with padding)
        ai = self.alloc(128)  # addrinfo + sockaddr_in
        sockaddr_off = 64

        # sockaddr_in: sa_len(1) + sa_family(1) + sin_port(2) + sin_addr(4) + zero(8)
        port_num = int(service) if service.isdigit() else 443
        sockaddr = struct.pack("BB", 16, 2)  # sa_len=16, sa_family=AF_INET
        sockaddr += struct.pack(">H", port_num)  # port in network byte order
        sockaddr += bytes([127, 0, 0, 1])  # 127.0.0.1
        sockaddr += b"\x00" * 8  # sin_zero
        self.uc.mem_write(ai + sockaddr_off, sockaddr)

        # addrinfo struct
        ai_data = struct.pack("<i", 0)          # ai_flags
        ai_data += struct.pack("<i", 2)          # ai_family = AF_INET
        ai_data += struct.pack("<i", 1)          # ai_socktype = SOCK_STREAM
        ai_data += struct.pack("<i", 0)          # ai_protocol
        ai_data += struct.pack("<I", 16)         # ai_addrlen (u32 on arm64)
        ai_data += b"\x00" * 4                   # padding
        ai_data += struct.pack("<Q", 0)          # ai_canonname = NULL
        ai_data += struct.pack("<Q", ai + sockaddr_off)  # ai_addr
        ai_data += struct.pack("<Q", 0)          # ai_next = NULL
        self.uc.mem_write(ai, ai_data)

        # Write result pointer
        if result_ptr:
            self.uc.mem_write(result_ptr, struct.pack("<Q", ai))

        self._addrinfo_ptr = ai
        self._log_net("getaddrinfo", {"hostname": hostname, "service": service,
                                       "result_addr": hex(ai)}, result=0)
        return 0

    def handle_freeaddrinfo(self) -> int:
        """_freeaddrinfo(ai) -> void (returns 0)"""
        ai_ptr = self.reg(0)
        self._log_net("freeaddrinfo", {"ptr": hex(ai_ptr)})
        print(f"  [NET] freeaddrinfo({ai_ptr:#x})")
        return 0

    def handle_send(self) -> int:
        """_send(fd, buf, len, flags) -> len"""
        fd = self.reg(0)
        buf = self.reg(1)
        length = self.reg(2)
        flags = self.reg(3)
        data = bytes(self.uc.mem_read(buf, length))
        self.send_log.append(data)
        self._log_net("send", {"fd": fd, "len": length, "flags": hex(flags)}, data,
                      result=length)
        print(f"  [NET] send(fd={fd}, len={length}, flags={flags:#x})")
        print(f"         data[:{min(64, length)}] = {data[:64].hex()}")
        if length <= 256:
            # Try ASCII interpretation
            try:
                text = data.decode("ascii")
                if all(32 <= c < 127 or c in (10, 13, 9) for c in data):
                    print(f"         ascii: {text!r}")
            except Exception:
                pass
        # Queue a synthetic response
        self._queue_response_for(data)
        return length

    def handle_recv(self) -> int:
        """_recv(fd, buf, len, flags) -> bytes_read"""
        fd = self.reg(0)
        buf = self.reg(1)
        length = self.reg(2)
        flags = self.reg(3)

        # Fill recv buffer from queued responses if needed
        if not self.recv_buffer and self.recv_queue:
            self.recv_buffer.extend(self.recv_queue.pop(0))

        if self.recv_buffer:
            to_read = min(length, len(self.recv_buffer))
            data = bytes(self.recv_buffer[:to_read])
            del self.recv_buffer[:to_read]
            self.uc.mem_write(buf, data)
            self._log_net("recv", {"fd": fd, "len": length, "flags": hex(flags),
                                    "read": to_read}, data, result=to_read)
            print(f"  [NET] recv(fd={fd}, len={length}, flags={flags:#x}) -> {to_read}")
            print(f"         data[:{min(64, to_read)}] = {data[:64].hex()}")
            return to_read
        else:
            # No data available -- return EAGAIN (35) or 0
            # Return -1 with errno=EAGAIN to signal "try again"
            self._log_net("recv", {"fd": fd, "len": length, "flags": hex(flags),
                                    "read": 0, "note": "no data, returning EAGAIN"},
                          result=0xFFFFFFFFFFFFFFFF)
            print(f"  [NET] recv(fd={fd}, len={length}) -> EAGAIN (no data)")
            return 0xFFFFFFFFFFFFFFFF  # -1 as unsigned 64-bit

    def handle_select(self) -> int:
        """_select(nfds, readfds, writefds, errorfds, timeout) -> 1"""
        nfds = self.reg(0)
        self._log_net("select", {"nfds": nfds}, result=1)
        print(f"  [NET] select(nfds={nfds}) -> 1 (ready)")
        # Mark the fd as ready in writefds (x2) if provided
        writefds_ptr = self.reg(2)
        if writefds_ptr:
            # fd_set: bit array, FAKE_FD=42 -> word 0 bit 42 (on 64-bit: word 0)
            fd_mask = 1 << FAKE_FD
            try:
                self.uc.mem_write(writefds_ptr, struct.pack("<Q", fd_mask))
            except Exception:
                pass
        # Also mark readfds if provided
        readfds_ptr = self.reg(1)
        if readfds_ptr and self.recv_buffer:
            fd_mask = 1 << FAKE_FD
            try:
                self.uc.mem_write(readfds_ptr, struct.pack("<Q", fd_mask))
            except Exception:
                pass
        return 1

    def handle_setsockopt(self) -> int:
        """_setsockopt(fd, level, optname, optval, optlen) -> 0"""
        fd = self.reg(0)
        level = self.reg(1)
        optname = self.reg(2)
        self._log_net("setsockopt", {"fd": fd, "level": level, "optname": optname})
        print(f"  [NET] setsockopt(fd={fd}, level={level}, opt={optname}) -> 0")
        return 0

    def handle_getsockopt(self) -> int:
        """_getsockopt(fd, level, optname, optval, optlen) -> 0"""
        fd = self.reg(0)
        level = self.reg(1)
        optname = self.reg(2)
        optval = self.reg(3)
        optlen = self.reg(4)
        # SO_ERROR check: write 0 (no error)
        if optval:
            try:
                self.uc.mem_write(optval, struct.pack("<I", 0))
            except Exception:
                pass
        self._log_net("getsockopt", {"fd": fd, "level": level, "optname": optname})
        print(f"  [NET] getsockopt(fd={fd}, level={level}, opt={optname}) -> 0")
        return 0

    def handle_fcntl(self) -> int:
        """_fcntl(fd, cmd, ...) -> 0"""
        fd = self.reg(0)
        cmd = self.reg(1)
        arg = self.reg(2)
        self._log_net("fcntl", {"fd": fd, "cmd": cmd, "arg": arg})
        if cmd == 3:  # F_GETFL
            print(f"  [NET] fcntl(fd={fd}, F_GETFL) -> 0")
            return 0
        elif cmd == 4:  # F_SETFL
            print(f"  [NET] fcntl(fd={fd}, F_SETFL, {arg:#x}) -> 0")
            return 0
        else:
            print(f"  [NET] fcntl(fd={fd}, cmd={cmd}, arg={arg:#x}) -> 0")
            return 0

    def handle_close(self) -> int:
        """_close(fd) -> 0"""
        fd = self.reg(0)
        if fd == FAKE_FD:
            self.socket_created = False
            self.connected = False
            print(f"  [NET] close(fd={fd}) -- socket closed")
        self._log_net("close", {"fd": fd})
        return 0

    def handle_ioctl(self) -> int:
        """_ioctl(fd, request, ...) -> 0"""
        fd = self.reg(0)
        request = self.reg(1)
        self._log_net("ioctl", {"fd": fd, "request": hex(request)})
        print(f"  [NET] ioctl(fd={fd}, request={request:#x}) -> 0")
        return 0

    def handle_read(self) -> int:
        """_read(fd, buf, count) -> used by mbedTLS bio"""
        fd = self.reg(0)
        buf = self.reg(1)
        count = self.reg(2)
        if fd == FAKE_FD:
            return self.handle_recv()
        # Default file read
        self._log_net("read", {"fd": fd, "count": count}, result=0)
        return 0

    def handle_popen(self) -> int:
        """_popen(command, mode) -> fake FILE*"""
        cmd_ptr = self.reg(0)
        cmd = self.cstr(cmd_ptr).decode("utf-8", errors="replace")
        self.popen_cmds.append(cmd)
        print(f"  [NET] popen(\"{cmd}\")")
        self._log_net("popen", {"command": cmd})

        # If it's a DNS query (host -4 ...), prepare fake output
        if "host" in cmd:
            hostname = cmd.split()[-1] if cmd.split() else "unknown"
            self.dns_queries.append(f"popen:{hostname}")
            # Store fake output for fgets/fread
            self._popen_output = f"{hostname} has address 127.0.0.1\n".encode()
            self._popen_offset = 0

        fd = EXTERNAL_BASE + 0xF00
        return fd

    def handle_pclose(self) -> int:
        """_pclose(stream) -> 0"""
        self._log_net("pclose", {})
        return 0

    def _queue_response_for(self, sent_data: bytes):
        """Analyze sent data and queue an appropriate synthetic response."""
        if len(sent_data) < 4:
            return
        # Check if it looks like HTTP
        if sent_data[:4] in (b"GET ", b"POST", b"CONN", b"HEAD"):
            # HTTP response
            body = b'{"status":"ok","session":"fake"}'
            resp = (f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n").encode() + body
            self.recv_queue.append(resp)
            print(f"         -> queued HTTP 200 response ({len(resp)} bytes)")
            return

        # Check if it looks like TLS ClientHello
        if len(sent_data) >= 5 and sent_data[0] == 0x16:
            # TLS record: content_type=0x16 (handshake)
            # Send back a minimal ServerHello
            # For now just queue a TLS alert to see what happens
            server_hello = bytes([
                0x16,  # handshake
                0x03, 0x03,  # TLS 1.2
                0x00, 0x05,  # length = 5
                0x02,  # ServerHello type
                0x00, 0x00, 0x02,  # length
                0x03, 0x03,  # TLS 1.2
            ])
            self.recv_queue.append(server_hello)
            self.ssl_events.append({"type": "client_hello", "data": sent_data[:64].hex()})
            print(f"         -> queued TLS ServerHello stub ({len(server_hello)} bytes)")
            return

        # Check if it looks like the EAC binary protocol (12-byte header)
        if len(sent_data) >= 12:
            total_len = struct.unpack_from("<I", sent_data, 0)[0]
            if 12 <= total_len <= 0x100000 and total_len <= len(sent_data) + 100:
                session_id = struct.unpack_from("<Q", sent_data, 4)[0]
                resp = build_server_hello(session_id)
                self.recv_queue.append(resp)
                print(f"         -> queued EAC protocol response "
                      f"(session={session_id:#x}, {len(resp)} bytes)")
                return

        # Generic: queue a small ack
        self.recv_queue.append(b"\x00" * 4)

    # ----------------------------------------------------------------
    # Override handle_stub with network-aware dispatch
    # ----------------------------------------------------------------
    def handle_stub(self, addr):
        name = next((n for n, a in self.ext.items() if a == addr), hex(addr))
        self.stub_hits[name] += 1
        a0, a1, a2, a3 = self.reg(0), self.reg(1), self.reg(2), self.reg(3)

        if len(self.stub_args) < 5000:
            self.stub_args.append({"name": name, "x0": a0, "x1": a1, "x2": a2})

        # Network stubs -- intercept before generic handling
        if name == "_socket":
            self.return_stub(self.handle_socket())
            return
        elif name == "_connect":
            self.return_stub(self.handle_connect())
            return
        elif name == "_send":
            self.return_stub(self.handle_send())
            return
        elif name == "_recv":
            self.return_stub(self.handle_recv())
            return
        elif name == "_select":
            self.return_stub(self.handle_select())
            return
        elif name == "_getaddrinfo":
            self.return_stub(self.handle_getaddrinfo())
            return
        elif name == "_freeaddrinfo":
            self.return_stub(self.handle_freeaddrinfo())
            return
        elif name == "_setsockopt":
            self.return_stub(self.handle_setsockopt())
            return
        elif name == "_getsockopt":
            self.return_stub(self.handle_getsockopt())
            return
        elif name == "_fcntl":
            self.return_stub(self.handle_fcntl())
            return
        elif name == "_close":
            self.return_stub(self.handle_close())
            return
        elif name == "_ioctl":
            self.return_stub(self.handle_ioctl())
            return
        elif name == "_read":
            # Distinguish socket reads from file reads
            fd = a0
            if fd == FAKE_FD:
                self.return_stub(self.handle_recv())
                return
            # Fall through to generic
        elif name == "_popen":
            self.return_stub(self.handle_popen())
            return
        elif name == "_pclose":
            self.return_stub(self.handle_pclose())
            return

        # Callback interception
        if name == "__callback" or addr == CALLBACK:
            code = a1
            data_ptr = a2
            self.callback_events.append({
                "tick": self.current_tick, "code": code,
                "data_ptr": hex(data_ptr) if data_ptr else "NULL"
            })
            print(f"  [CB] callback(code={code}, data={data_ptr:#x})")
            self.return_stub(0)
            return

        # mbedTLS stubs -- detect SSL activity
        if "mbedtls" in name.lower() or "ssl" in name.lower():
            self.ssl_events.append({"tick": self.current_tick, "call": name,
                                     "x0": hex(a0), "x1": hex(a1)})
            print(f"  [TLS] {name}(x0={a0:#x}, x1={a1:#x})")
            self.return_stub(0)
            return

        # CFNetwork proxy detection
        if name == "_CFNetworkCopySystemProxySettings":
            print(f"  [NET] CFNetworkCopySystemProxySettings -> NULL (no proxy)")
            self.return_stub(0)
            return

        # Fall through to base class generic handling
        # (malloc, free, pthread, time, etc.)
        if name in ("_malloc", "__Znwm", "__ZnwmRKSt9nothrow_t", "__Znam"):
            n = a0
            self.return_stub(self.alloc(n))
        elif name in ("_calloc",):
            self.return_stub(self.alloc(a0 * a1))
        elif name in ("_free", "__ZdlPv", "__ZdaPv"):
            self.return_stub(0)
        elif name == "_memcpy" or name == "___memcpy_chk":
            if a2:
                self.uc.mem_write(a0, bytes(self.uc.mem_read(a1, a2)))
            self.return_stub(a0)
        elif name in ("_memset", "___memset_chk"):
            self.uc.mem_write(a0, bytes([a1 & 0xFF]) * a2)
            self.return_stub(a0)
        elif name == "_memmove":
            self.uc.mem_write(a0, bytes(self.uc.mem_read(a1, a2)))
            self.return_stub(a0)
        elif name == "_strlen":
            self.return_stub(len(self.cstr(a0)))
        elif name.startswith("_pthread_mutex") or name.startswith("_pthread_cond"):
            self.return_stub(0)
        elif name == "_pthread_create":
            fn = p64(self.uc.mem_read(a2, 8)) if a2 else 0
            arg = a3
            self.threads.append({"fn": fn, "arg": arg})
            if a0:
                self.uc.mem_write(a0, u64(0xDEAD0000 + len(self.threads)))
            self.return_stub(0)
        elif name == "_getpid":
            self.return_stub(4321)
        elif name in ("_sysctl", "_sysctlbyname", "_csr_get_active_config",
                       "_csops", "_issetugid"):
            self.return_stub(0)
        elif name == "_open":
            self.return_stub(0xFFFFFFFFFFFFFFFF)
        elif name in ("_write",):
            self.return_stub(a2)  # pretend all bytes written
        elif name == "_ftruncate":
            self.return_stub(0)
        elif name == "_mmap":
            self.return_stub(self.alloc(a1))
        elif name == "_mprotect" or name == "_vm_protect":
            self.return_stub(0)
        elif name == "___cxa_guard_acquire":
            guard_val = int.from_bytes(self.uc.mem_read(a0, 8), "little")
            self.return_stub(1 if guard_val == 0 else 0)
        elif name == "___cxa_guard_release":
            self.uc.mem_write(a0, u64(1))
            self.return_stub(0)
        elif name == "___cxa_guard_abort":
            self.return_stub(0)
        elif name == "_fopen":
            path_s = self.cstr(a0).decode("utf-8", errors="replace")
            self.fopen_files = getattr(self, "fopen_files", {})
            fd = EXTERNAL_BASE + 0xE00 + len(self.fopen_files) * 8
            self.fopen_files[fd] = path_s
            self.return_stub(fd)
        elif name == "_fread":
            total = a1 * a2
            self.fread_counter = getattr(self, "fread_counter", 0) + 1
            rng = hashlib.sha256(f"fread-{self.fread_counter}-{total}".encode()).digest()
            out = (rng * ((total // len(rng)) + 1))[:total]
            self.uc.mem_write(a0, out)
            self.return_stub(a2)
        elif name == "_fclose":
            self.return_stub(0)
        elif name == "_fseek" or name == "_ftell":
            self.return_stub(0)
        elif name in ("_dlopen", "_dlsym"):
            self.return_stub(0)
        elif name == "_dladdr":
            # Integrity check -- fill Dl_info with plausible data
            if a1:
                # Dl_info: dli_fname, dli_fbase, dli_sname, dli_saddr
                info_buf = struct.pack("<QQQQ", 0, 0, 0, a0)
                self.uc.mem_write(a1, info_buf)
            self.return_stub(1)
        elif name == "_mach_task_self":
            self.return_stub(0x103)
        elif name == "_mach_host_self":
            self.return_stub(0x205)
        elif name == "_host_get_clock_service":
            if a2:
                self.uc.mem_write(a2, u64(0x307))
            self.return_stub(0)
        elif name == "_clock_get_time":
            if a1:
                t = int(_time.time())
                self.uc.mem_write(a1, struct.pack("<II", t, 0))
            self.return_stub(0)
        elif name == "_mach_port_deallocate":
            self.return_stub(0)
        elif name == "__ZNSt3__16chrono12steady_clock3nowEv":
            self.steady_ns = getattr(self, "steady_ns", 1000000000000) + 1000000
            self.uc.mem_write(a0, struct.pack("<Q", self.steady_ns))
            self.return_stub(a0)
        elif name == "_vsnprintf":
            self.return_stub(0)
        elif name in ("_time", "_gettimeofday"):
            # Advance time slightly each tick to simulate real progression
            base_time = 1786000000 + self.current_tick
            if name == "_gettimeofday" and a0:
                self.uc.mem_write(a0, struct.pack("<QQ", base_time, 0))
            self.return_stub(base_time)
        elif name == "_CGEventSourceCounterForEventType":
            self.return_stub(100 + self.current_tick)
        elif name.startswith("_CF") or name.startswith("_IO") or name.startswith("_DA"):
            self.return_stub(0)
        elif name == "_strcmp" or name == "_strncmp":
            s1 = self.cstr(a0)
            s2 = self.cstr(a1)
            self.return_stub(0 if s1 == s2 else 1)
        elif name == "_memcmp":
            d1 = bytes(self.uc.mem_read(a0, a2))
            d2 = bytes(self.uc.mem_read(a1, a2))
            self.return_stub(0 if d1 == d2 else 1)
        elif name == "_snprintf" or name == "_sprintf":
            self.return_stub(0)
        elif name == "_atoi":
            s = self.cstr(a0).decode("utf-8", errors="replace")
            try:
                self.return_stub(int(s))
            except ValueError:
                self.return_stub(0)
        elif name == "_strtol" or name == "_strtoul":
            s = self.cstr(a0).decode("utf-8", errors="replace")
            try:
                self.return_stub(int(s, 0))
            except ValueError:
                self.return_stub(0)
        elif name == "_poll":
            # poll(fds, nfds, timeout) -> 1 (ready)
            nfds = a1
            fds_ptr = a0
            if fds_ptr and nfds > 0:
                # Set revents = POLLOUT | POLLIN
                try:
                    # struct pollfd { int fd; short events; short revents; }
                    for i in range(min(nfds, 4)):
                        off = i * 8
                        self.uc.mem_write(fds_ptr + off + 6, struct.pack("<H", 0x0005))
                except Exception:
                    pass
            self.return_stub(1)
        else:
            self.return_stub(0)

    # ----------------------------------------------------------------
    # CAS spin-loop handling (from trace_y_twophase.py)
    # ----------------------------------------------------------------
    def on_code(self, uc, addr, size, ud):
        if self.phase == 2 and addr in CAS_LDAXR_ADDRS:
            x9 = uc.reg_read(UC_ARM64_REG_X0 + 9)
            x8 = uc.reg_read(UC_ARM64_REG_X0 + 8)
            x3 = uc.reg_read(UC_ARM64_REG_X0 + 3)
            key = (addr, x9, x8 & 0xFFFFFFFF)
            self.cas_spins[key] += 1
            if self.cas_spins[key] == 1 and self._cas_log_limit > 0:
                self._cas_log_limit -= 1
                try:
                    cur = int.from_bytes(uc.mem_read(x9, 4), "little")
                except Exception:
                    cur = -1
            if self.cas_spins[key] >= CAS_THRESHOLD:
                uc.mem_write(x9, struct.pack("<I", x8 & 0xFFFFFFFF))
                self.cas_forces.append({
                    "pc": addr, "target_addr": x9,
                    "old_expected": x8 & 0xFFFFFFFF,
                    "new_val": x3 & 0xFFFFFFFF,
                    "spins": self.cas_spins[key]
                })
                self.cas_spins[key] = 0
        super().on_code(uc, addr, size, ud)

    # ----------------------------------------------------------------
    # Main execution flow
    # ----------------------------------------------------------------
    def run_network_trace(self) -> dict:
        """Run _x init, manipulate state, tick _y, and capture network I/O."""

        # Phase 1: Run _x to initialize context
        print("=" * 70)
        print("PHASE 1: Running _x (0x1B664) -- service initialization")
        print("=" * 70)
        self.phase = 1
        self.run()

        ctx = int.from_bytes(self.uc.mem_read(CTX_PTR_ADDR, 8), "little")
        print(f"\nContext pointer: {ctx:#x}")
        if ctx == 0:
            print("ERROR: Context not initialized, cannot proceed")
            return {"error": "context_null"}

        # Read initial connection state
        conn_state = int.from_bytes(self.uc.mem_read(ctx + CTX_CONN_STATE_OFF, 4), "little")
        print(f"Connection state (ctx+{CTX_CONN_STATE_OFF:#x}): {conn_state:#x}")

        # Dump key context fields
        print("\nContext snapshot (key fields):")
        for off, label in [
            (0x0000, "vtable"),
            (0x0008, "sub-vtable"),
            (0x0070, "init-complete"),
            (0x0218, "config-flags"),
            (0x26A8, "conn-state"),
            (0x26B0, "self-ptr"),
            (0x27B8, "task-mgr-vtable"),
        ]:
            if off <= 0x2B20 - 8:
                val = int.from_bytes(self.uc.mem_read(ctx + off, 8), "little")
                if val:
                    print(f"  +{off:#06x} ({label:20s}): {val:#018x}")

        # Phase 2: Trigger network activity
        print()
        print("=" * 70)
        print("PHASE 2: Triggering network stack")
        print("=" * 70)
        self.phase = 2

        if self.trigger_mode == "state":
            self._trigger_via_state(ctx)
        elif self.trigger_mode == "vtable2":
            self._trigger_via_vtable2(ctx)
        elif self.trigger_mode == "vtable7":
            self._trigger_via_vtable7(ctx)
        elif self.trigger_mode == "all":
            # Try all approaches sequentially
            self._trigger_via_state(ctx)
            if not self.net_events:
                print("\n--- State trigger produced no network I/O, trying vtable2 ---")
                self._trigger_via_vtable2(ctx)
            if not self.net_events:
                print("\n--- vtable2 produced no network I/O, trying vtable7 ---")
                self._trigger_via_vtable7(ctx)

        # Generate report
        return self._build_report(ctx)

    def _trigger_via_state(self, ctx: int):
        """Manipulate connection state and tick _y to trigger network."""
        # Try various state values that might trigger connection
        states_to_try = [
            (0x01, "connecting"),
            (0x10, "pre-connect"),
            (0x02, "handshake-start"),
            (0x04, "awaiting-connection"),
            (0x00, "reset"),
            (0x08, "network-init"),
            (0x20, "secure-flag"),
        ]

        for state_val, label in states_to_try:
            self._state_attempts.append({"state": state_val, "label": label})
            print(f"\n--- Setting connection state to {state_val:#x} ({label}) ---")
            self.uc.mem_write(ctx + CTX_CONN_STATE_OFF,
                              struct.pack("<I", state_val))

            net_before = len(self.net_events)
            self._tick_y(ticks=min(self.num_ticks, 3),
                         label=f"state={state_val:#x}")

            # Check if any network activity happened
            net_after = len(self.net_events)
            if net_after > net_before:
                print(f"  ** Network activity detected with state={state_val:#x}! "
                      f"({net_after - net_before} events)")
                # Continue ticking with this state
                self._tick_y(ticks=self.num_ticks - 3,
                             label=f"state={state_val:#x} (continued)")
                break
            else:
                print(f"  No network activity with state={state_val:#x}")

    def _trigger_via_vtable2(self, ctx: int):
        """Call vtable[2] process_message to feed connection parameters."""
        vtable_ptr = int.from_bytes(self.uc.mem_read(ctx, 8), "little")
        print(f"\nVtable pointer: {vtable_ptr:#x}")

        # Read vtable[2] = process_message at 0xc4f0
        vt2_addr = int.from_bytes(self.uc.mem_read(vtable_ptr + 2 * 8, 8), "little")
        print(f"vtable[2] (process_message): {vt2_addr:#x}")

        # Build a synthetic message that might trigger connection
        # The game would send connection parameters here
        msg = self.alloc(0x100)
        # Try a simple message: type=1 (connect), with a fake server address
        msg_data = struct.pack("<I", 1)  # message type
        msg_data += b"eac-cdn.epicgames.com\x00"
        msg_data += struct.pack("<H", 443)
        msg_data += b"\x00" * (0x100 - len(msg_data))
        self.uc.mem_write(msg, msg_data)

        # Call process_message(ctx, msg, callback)
        print(f"Calling vtable[2] process_message({ctx:#x}, {msg:#x}, {CALLBACK:#x})")
        self._call_function(vt2_addr, [ctx, msg, CALLBACK])

        # Now tick
        self._tick_y(ticks=self.num_ticks, label="after vtable[2]")

    def _trigger_via_vtable7(self, ctx: int):
        """Call vtable[7] connection management."""
        vtable_ptr = int.from_bytes(self.uc.mem_read(ctx, 8), "little")
        vt7_addr = int.from_bytes(self.uc.mem_read(vtable_ptr + 7 * 8, 8), "little")
        print(f"vtable[7] (connection mgmt): {vt7_addr:#x}")

        print(f"Calling vtable[7]({ctx:#x})")
        self._call_function(vt7_addr, [ctx])

        self._tick_y(ticks=self.num_ticks, label="after vtable[7]")

    def _call_function(self, addr: int, args: list[int]):
        """Call an arbitrary function with args in x0-x7."""
        # Save state
        old_sp = self.uc.reg_read(UC_ARM64_REG_SP)
        sp = STACK_BASE + STACK_SIZE - 0x6000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X30, STOP)
        for i, v in enumerate(args):
            self.uc.reg_write(UC_ARM64_REG_X0 + i, v)

        # Reset execution counters
        self.steps = 0
        self.stop_reason = "instruction limit"
        self.fault = None

        try:
            self.uc.emu_start(addr, STOP, count=self.max_y_per_tick)
        except Exception as exc:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            print(f"  Exception at pc={pc:#x}: {exc}")

        final_pc = self.uc.reg_read(UC_ARM64_REG_PC)
        ret_val = self.reg(0)
        print(f"  Returned: x0={ret_val:#x}, steps={self.steps}, "
              f"stop={self.stop_reason}, final_pc={final_pc:#x}")
        self.uc.reg_write(UC_ARM64_REG_SP, old_sp)

    def _tick_y(self, ticks: int, label: str = ""):
        """Tick _y repeatedly."""
        print(f"\nTicking _y x{ticks} [{label}]")
        for i in range(ticks):
            self.current_tick += 1

            # Reset per-tick state
            self.steps = 0
            self.stop_reason = "instruction limit"
            self.fault = None
            self.cas_spins = Counter()
            self._cas_log_limit = 10

            sp = STACK_BASE + STACK_SIZE - 0x4000
            self.uc.reg_write(UC_ARM64_REG_SP, sp)
            self.uc.reg_write(UC_ARM64_REG_X30, STOP)

            net_before = len(self.net_events)

            try:
                self.uc.emu_start(0x1B744, STOP, count=self.max_y_per_tick)
            except Exception as exc:
                pc = self.uc.reg_read(UC_ARM64_REG_PC)
                print(f"  tick[{self.current_tick}] Exception at pc={pc:#x}: {exc}")

            final_pc = self.uc.reg_read(UC_ARM64_REG_PC)
            net_new = len(self.net_events) - net_before

            # Compact tick summary
            stop = self.stop_reason
            if final_pc == STOP and stop == "instruction limit":
                stop = "returned"

            stub_summary = ", ".join(f"{n}:{c}" for n, c in
                                      Counter(sa["name"] for sa in
                                              self.stub_args[-100:]).most_common(5))
            print(f"  tick[{self.current_tick:3d}] steps={self.steps:>8d} "
                  f"stop={stop:20s} net_events={net_new} "
                  f"stubs=[{stub_summary}]")

            if self.fault:
                print(f"    FAULT: {self.fault}")
                if self.recent:
                    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
                    print("    Last 20 PCs:")
                    for pc in list(self.recent)[-20:]:
                        fo = self._va2fo(pc)
                        raw = bytes(self.data[fo:fo + 4])
                        insn = next(cs.disasm(raw, pc), None)
                        lbl = f"{insn.mnemonic} {insn.op_str}" if insn else "??"
                        print(f"      {pc:#x}: {lbl}")
                break

    # ----------------------------------------------------------------
    # Report generation
    # ----------------------------------------------------------------
    def _build_report(self, ctx: int) -> dict:
        """Build and print the final report."""
        print()
        print("=" * 70)
        print("NETWORK TRACE RESULTS")
        print("=" * 70)

        # Final connection state
        conn_state = int.from_bytes(self.uc.mem_read(ctx + CTX_CONN_STATE_OFF, 4), "little")
        print(f"\nFinal connection state: {conn_state:#x}")
        is_connected = (conn_state & 0xDF) == 0x11
        print(f"is_connected: {is_connected}")

        # Network events summary
        print(f"\nTotal network events: {len(self.net_events)}")
        event_counts = Counter(ev.call for ev in self.net_events)
        for call, count in event_counts.most_common():
            print(f"  {call:20s}: {count}")

        # DNS queries
        print(f"\nDNS queries: {len(self.dns_queries)}")
        for q in self.dns_queries:
            print(f"  {q}")

        # Connection attempts
        print(f"\nConnection attempts: {len(self.connect_addrs)}")
        for ca in self.connect_addrs:
            print(f"  {ca['ip']}:{ca['port']} (family={ca['family']})")

        # Sent data
        print(f"\nData sent: {len(self.send_log)} messages")
        for i, data in enumerate(self.send_log):
            print(f"\n  --- Send #{i} ({len(data)} bytes) ---")
            # Hex dump (first 128 bytes)
            for row in range(0, min(len(data), 128), 16):
                hex_part = " ".join(f"{b:02x}" for b in data[row:row + 16])
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "."
                                     for b in data[row:row + 16])
                print(f"  {row:04x}: {hex_part:<48s} {ascii_part}")
            if len(data) > 128:
                print(f"  ... ({len(data) - 128} more bytes)")

        # SSL/TLS events
        print(f"\nSSL/TLS events: {len(self.ssl_events)}")
        for ev in self.ssl_events[:20]:
            print(f"  {ev}")

        # Callback events
        print(f"\nCallback invocations: {len(self.callback_events)}")
        for ev in self.callback_events[:20]:
            print(f"  tick={ev['tick']} code={ev['code']} data={ev['data_ptr']}")

        # popen commands
        print(f"\npopen commands: {len(self.popen_cmds)}")
        for cmd in self.popen_cmds:
            print(f"  {cmd}")

        # State attempts
        print(f"\nState manipulation attempts: {len(self._state_attempts)}")
        for sa in self._state_attempts:
            print(f"  state={sa['state']:#x} ({sa['label']})")

        # Stub hits
        print(f"\nAll stub hits (top 30):")
        for n, c in self.stub_hits.most_common(30):
            print(f"  {c:6d}  {n}")

        # Build JSON report
        report = {
            "summary": {
                "total_ticks": self.current_tick,
                "net_events": len(self.net_events),
                "dns_queries": self.dns_queries,
                "connect_addrs": self.connect_addrs,
                "sends": len(self.send_log),
                "ssl_events": len(self.ssl_events),
                "callbacks": len(self.callback_events),
                "popen_cmds": self.popen_cmds,
                "final_conn_state": hex(conn_state),
                "is_connected": is_connected,
                "trigger_mode": self.trigger_mode,
            },
            "state_attempts": self._state_attempts,
            "net_events": [ev.to_dict() for ev in self.net_events],
            "send_data": [d.hex() for d in self.send_log],
            "ssl_events": self.ssl_events,
            "callback_events": self.callback_events,
            "stub_hits": dict(self.stub_hits),
            "cas_forces": self.cas_forces[:50],
        }

        rpt_path = Path("/tmp/svc_network_trace.json")
        rpt_path.write_text(json.dumps(report, default=str, indent=2) + "\n")
        print(f"\nFull report: {rpt_path}")
        return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="EAC network handshake tracer")
    ap.add_argument("module", type=Path, help="Path to eac_service_decoded.dylib")
    ap.add_argument("--max-x", type=int, default=8_000_000,
                    help="Max instructions for _x init (default: 8M)")
    ap.add_argument("--max-y", type=int, default=5_000_000,
                    help="Max instructions per _y tick (default: 5M)")
    ap.add_argument("--ticks", type=int, default=10,
                    help="Number of _y ticks to run (default: 10)")
    ap.add_argument("--trigger", choices=["state", "vtable2", "vtable7", "all"],
                    default="all",
                    help="How to trigger network activity (default: all)")
    args = ap.parse_args()

    h = NetworkTraceHarness(args.module, args.max_x, args.max_y,
                            args.ticks, args.trigger)
    result = h.run_network_trace()

    # Exit summary
    print()
    print("=" * 70)
    if result.get("summary", {}).get("net_events", 0) > 0:
        print("Network activity was captured. Check /tmp/svc_network_trace.json")
    else:
        print("No network activity observed. The service may need additional")
        print("triggers (e.g., specific message types via vtable[2], or")
        print("connection parameters embedded in the init block callback).")
    print("=" * 70)
