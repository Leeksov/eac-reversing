#!/usr/bin/env python3
"""Harness to trace EAC's hash catalogue / file integrity checking.

Extends the core Unicorn harness from service_cv_trace.py to model the
filesystem operations needed for catalogue loading:
  - _NSGetExecutablePath + realpath for executable path resolution
  - fopen/fread/fseek/ftell/rewind/fclose serving a synthetic catalogue
  - iconv for UTF-8 <-> UTF-32LE conversion
  - wcslen, wmemcpy, stat, glob, basename, bzero, snprintf
  - C++ std::string and std::wstring imported operations

Trace targets:
  --mode init     -> sub_113DC  (exe verification against catalogue tree)
  --mode load     -> sub_2B8D0  (catalogue file loading + parsing)
  --mode full     -> sub_113DC with pre-loaded catalogue context

The synthetic catalogue has magic 0x00434145, version 4 or 5, and
enough structure to pass the header check in sub_2CE38.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from collections import Counter, deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import (UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MODE_ARM, Uc)
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X30)

# ---------------------------------------------------------------------------
# Memory layout
# ---------------------------------------------------------------------------
IMAGE_LIMIT  = 0x660000
CV_START     = 0xCC000
CV_END       = 0x644000
STACK_BASE   = 0x10000000
STACK_SIZE   = 0x800000
HEAP_BASE    = 0x20000000
HEAP_SIZE    = 0x8000000
EXTERNAL_BASE = 0x30000000
EXTERNAL_SIZE = 0x10000
STOP     = EXTERNAL_BASE + 0xFFF0
CALLBACK = EXTERNAL_BASE + 0x100
RET = struct.pack("<I", 0xD65F03C0)

# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
ENTRY_INIT   = 0x113DC   # sub_113DC: main file integrity init
ENTRY_LOAD   = 0x2B8D0   # sub_2B8D0: catalogue load + parse
ENTRY_X      = 0x1B664   # _x: full service entry

# ---------------------------------------------------------------------------
# Fake filesystem
# ---------------------------------------------------------------------------
FAKE_EXE_PATH = b"/Games/Rust/RustClient.app/Contents/MacOS/Rust"
FAKE_GAME_DIR = b"/Games/Rust/RustClient.app/Contents/MacOS/"
FAKE_CERT_DIR = b"/Games/Rust/RustClient.app/Contents/MacOS/EasyAntiCheat/Certificates/"
FAKE_CATALOGUE_FILE = FAKE_CERT_DIR + b"game_429c2212.bin"
FAKE_CERTIFICATE_FILE = FAKE_CERT_DIR + b"game_429c2212.cer"

# Catalogue magic and version
CATALOGUE_MAGIC   = 0x00434145   # "EAC\0" little-endian
CATALOGUE_VERSION = 4            # default; overridable via --catalogue-version

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def u64(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
def p64(b): return struct.unpack("<Q", b)[0]
def u32(v): return struct.pack("<I", v & 0xFFFFFFFF)
def p32(b): return struct.unpack("<I", b)[0]
def align(v, a=0x10): return (v + a - 1) & -a


def parse_binds(path: Path):
    out = subprocess.run(["dyld_info", "-fixups", str(path)],
                         capture_output=True, text=True, check=True).stdout
    binds = {}
    for line in out.splitlines():
        m = re.search(r"(0x[0-9A-Fa-f]{6,})\s+(?:lazy-)?bind\s+(\S+)", line)
        if m:
            binds[int(m.group(1), 16)] = m.group(2).split("/")[-1]
    return binds


def segments(data: bytes):
    _, _, _, _, ncmds, *_ = struct.unpack_from("<IiiIIIII", data, 0)
    off, segs = 32, []
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            name = data[off + 8:off + 24].split(b"\0")[0].decode()
            vm, vs = struct.unpack_from("<QQ", data, off + 24)
            fo, fl = struct.unpack_from("<QQ", data, off + 40)
            segs.append((name, vm, vs, fo, fl))
        off += sz
    return segs


def build_catalogue(version: int = 4) -> bytes:
    """Build a minimal synthetic hash catalogue file.

    Catalogue v4 layout (from sub_2F73C validation):
      offset 0x000: u32 magic        = 0x00434145 ("EAC\\0")
      offset 0x004: u16 version_low  = 4
      offset 0x006: u16 version_high = 1
      offset 0x008: [0x400 bytes]    cert/key area (1024 bytes)
      offset 0x408: u32 dword[258]   flag (set to 0 by one code path)
      offset 0x40C: u32 dword[259]   signed_data_size
      offset 0x410: u32 dword[260]   signature_size
      offset 0x414: u32 dword[261]   entry_table_size
      offset 0x418: ...              (padding)
      offset 0x41C: [signed_data_size bytes] hash entries
      offset 0x41C + signed_data_size: [signature_size bytes] ECDSA signature

    Size constraint: total_size - 1052 == signed_data_size + signature_size

    The version_high field at offset 6 controls which parsing path is taken:
      if version_high == HIWORD(0x10004) == 1:
          decrypt cert area (clear dword[258], zero offset 8..0x408)
      else:
          use raw data from offset 0x41C

    Minimum valid size: 0x41C (1052 bytes).
    """
    # Give some room for signed data and signature
    signed_data_size = 0x100   # 256 bytes of hash entry area
    signature_size = 0x80      # 128 bytes of ECDSA signature placeholder
    total_size = 0x41C + signed_data_size + signature_size  # 1052 + 256 + 128 = 1436

    cat = bytearray(total_size)

    # Header
    struct.pack_into("<I", cat, 0x000, CATALOGUE_MAGIC)   # magic
    struct.pack_into("<H", cat, 0x004, version)            # version_low
    struct.pack_into("<H", cat, 0x006, 1)                  # version_high

    # Cert/key area (offset 0x008, 0x400 bytes) - fill with pattern
    for off in range(0x008, 0x408, 4):
        struct.pack_into("<I", cat, off, 0xCE000000 | off)

    # Size fields
    struct.pack_into("<I", cat, 0x408, 0x400)               # dword[258] cert_data_len (1024 bytes)
    struct.pack_into("<I", cat, 0x40C, signed_data_size)   # dword[259] signed_data_size
    struct.pack_into("<I", cat, 0x410, signature_size)     # dword[260] signature_size
    struct.pack_into("<I", cat, 0x414, signed_data_size)   # dword[261] entry_table_size

    # Signed data area (hash entries) at offset 0x41C
    for off in range(0x41C, 0x41C + signed_data_size, 4):
        struct.pack_into("<I", cat, off, 0xDA000000 | (off - 0x41C))

    # Signature area at offset 0x41C + signed_data_size
    sig_start = 0x41C + signed_data_size
    for off in range(sig_start, sig_start + signature_size, 4):
        struct.pack_into("<I", cat, off, 0xEC000000 | (off - sig_start))

    return bytes(cat)


class FakeFile:
    """In-memory file object served through fopen/fread/fseek/ftell."""
    def __init__(self, data: bytes, path: str):
        self.data = data
        self.path = path
        self.pos = 0

    def read(self, buf_size: int) -> bytes:
        chunk = self.data[self.pos:self.pos + buf_size]
        self.pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int):
        if whence == 0:    # SEEK_SET
            self.pos = offset
        elif whence == 1:  # SEEK_CUR
            self.pos += offset
        elif whence == 2:  # SEEK_END
            self.pos = len(self.data) + offset

    def tell(self) -> int:
        return self.pos


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
class CatalogueHarness:
    def __init__(self, path: Path, max_instr: int, mode: str,
                 catalogue_version: int, report: Path | None,
                 trace_report: Path | None):
        self.data = bytearray(path.read_bytes())
        self.max_instr = max_instr
        self.mode = mode
        self.report = report
        self.trace_report = trace_report
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.binds = parse_binds(path)
        self.segs = segments(self.data)

        # Synthetic catalogue
        self.catalogue_data = build_catalogue(catalogue_version)
        self.catalogue_version = catalogue_version

        # Emulator setup
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(0, IMAGE_LIMIT)
        for name, vm, vs, fo, fl in self.segs:
            if name != "__LINKEDIT":
                self.uc.mem_write(vm, bytes(self.data[fo:fo + fl]))
        self.patch_ldaprb()
        self.scan_lse()
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)
        self.uc.mem_map(EXTERNAL_BASE, EXTERNAL_SIZE)
        self.uc.mem_write(CALLBACK, RET)
        self.uc.mem_write(STOP, RET)

        # External symbol slots
        names = sorted(set(self.binds.values()))
        self.ext = {n: EXTERNAL_BASE + 0x2000 + 8 * i for i, n in enumerate(names)}
        for addr in self.ext.values():
            self.uc.mem_write(addr, RET)
        for got, name in self.binds.items():
            if name == "dyld_stub_binder":
                self.uc.mem_write(got, u64(EXTERNAL_BASE + 0xD00))
                self.uc.mem_write(EXTERNAL_BASE + 0xD00, RET)
                continue
            if name in self.ext:
                self.uc.mem_write(got, u64(self.ext[name]))
        # Stack guard
        for got, name in self.binds.items():
            if name == "___stack_chk_guard":
                self.uc.mem_write(got, u64(EXTERNAL_BASE + 0x900))
                self.uc.mem_write(EXTERNAL_BASE + 0x900, u64(0xA11CE5EED1234567))
            elif name == "_mach_task_self_":
                self.uc.mem_write(got, u64(0x103))

        # Tracking state
        self.stub_hits = Counter()
        self.stub_args = []
        self.fopen_log = []
        self.fread_log = []
        self.hash_ops = []
        self.error_codes = []
        self.threads = []
        self.pc_hits = Counter()
        self.recent = deque(maxlen=128)
        self.cv_reads = Counter()
        self.cv_writes = Counter()
        self.heap_next = HEAP_BASE + 0x10000
        self.stop_reason = "instruction limit"
        self.fault = None
        self.pcs = [] if trace_report else None
        self.steps = 0

        # File system model
        self.open_files: dict[int, FakeFile] = {}
        self.next_fd = EXTERNAL_BASE + 0xE00

        # iconv model
        self.iconv_handles: dict[int, tuple[str, str]] = {}
        self.next_iconv = 0x50000001

        # glob model
        self.glob_results: dict[int, int] = {}  # glob_t addr -> result array addr

        # Initialize runtime globals that are normally set by __mod_init_func
        # dword_C1288 = 0x10004 (InitFunc_2 at 0x302B8)
        # Low 16 bits = 4 (version 4), High 16 bits = 1 (sub-version)
        self.uc.mem_write(0xC1288, struct.pack("<I", 0x00010004))

        # Set up entry and arguments
        self._setup_entry()

        # Hooks
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.on_invalid)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    # ----------------------------------------------------------------
    # Patching (same as service_cv_trace.py)
    # ----------------------------------------------------------------
    def patch_ldaprb(self):
        patched = 0
        for sname, vm, vs, fo, fl in self.segs:
            if sname == "__LINKEDIT":
                continue
            for off in range(0, fl, 4):
                pc = vm + off
                insn = next(self.cs.disasm(self.data[fo + off:fo + off + 4], pc), None)
                if insn and insn.mnemonic.startswith("ldapr"):
                    m = re.match(r"ldapr([bh]?)(w|x)(\d+), \[(x\d+)\]",
                                 insn.mnemonic + " " + insn.op_str)
                    mm = re.match(r"(w|x)(\d+), \[(x\d+)\]$", insn.op_str)
                    if mm:
                        rt = int(mm.group(2))
                        rn = int(mm.group(3)[1:])
                        size = {"": 3, "b": 0, "h": 1}[m.group(1)] if m else 3
                        sf = 1 if mm.group(1) == "x" else 0
                        enc = ((sf << 31) | (0x39 << 24) | (0x40 << 22)
                               | (size << 30) | (rn << 5) | rt)
                        self.data[fo + off:fo + off + 4] = struct.pack("<I", enc)
                        self.uc.mem_write(pc, struct.pack("<I", enc))
                        patched += 1
        print(f"ldapr patched: {patched}")

    def scan_lse(self):
        self.lse = {}
        mnems = ("cas", "casb", "casab", "casalb", "casl", "casa", "casal",
                 "swp", "swpb", "swpab", "swpalb", "swpal", "swpl", "swpa",
                 "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin",
                 "ldumax", "ldumin", "ldmax", "ldmin")
        for name, vm, vs, fo, fl in self.segs:
            if name == "__LINKEDIT":
                continue
            for off in range(0, fl, 4):
                pc = vm + off
                insn = next(self.cs.disasm(bytes(self.data[fo + off:fo + off + 4]), pc), None)
                if insn and (insn.mnemonic.startswith(mnems) or
                             re.match(r"^(cas|swp|ld(add|clr|eor|set|smax|smin|umax|umin|max|min))[ab]*",
                                      insn.mnemonic)):
                    self.lse[pc] = (insn.mnemonic, insn.op_str)

    def emulate_lse(self, addr):
        mnem, ops = self.lse[addr]
        m = re.match(r"^(\w+?)(b|h)?$", mnem)
        base = m.group(1).rstrip("al")
        width = {"": None, "b": 1, "h": 2}[m.group(2) or ""]
        regs = [r.strip() for r in ops.split(",")]
        src, dst, mem = regs[0], regs[1], regs[2]
        mreg = re.match(r"\[(x\d+)\](?:.*)?$", mem)
        rn = int(mreg.group(1)[1:])
        base_addr = self.uc.reg_read(UC_ARM64_REG_X0 + rn)
        if width is None:
            width = 8 if src.startswith("x") else 4
        try:
            old = int.from_bytes(self.uc.mem_read(base_addr, width), "little")
        except Exception:
            page = base_addr & ~0xFFF
            try:
                self.uc.mem_map(page, 0x1000)
                self.uc.mem_write(page, bytes(0x1000))
                old = int.from_bytes(self.uc.mem_read(base_addr, width), "little")
            except Exception:
                self.fault = {"pc": addr, "addr": base_addr, "size": width, "access": "lse-read"}
                self.stop_reason = f"lse fault at {addr:#x} reading {base_addr:#x}"
                self.uc.emu_stop()
                return
        sval = self.reg(int(src[1:])) & ((1 << (8 * width)) - 1)
        mask = (1 << (8 * width)) - 1
        if base.startswith("cas"):
            if old == sval:
                self.uc.mem_write(base_addr, self.reg(int(regs[1][1:])).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("swp"):
            self.uc.mem_write(base_addr, sval.to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldadd"):
            self.uc.mem_write(base_addr, ((old + sval) & mask).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldset"):
            self.uc.mem_write(base_addr, ((old | sval) & mask).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldeor"):
            self.uc.mem_write(base_addr, ((old ^ sval) & mask).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldclr"):
            self.uc.mem_write(base_addr, ((old & ~sval) & mask).to_bytes(width, "little"))
            newdst = old
        else:
            newdst = old
        self.uc.reg_write(UC_ARM64_REG_X0 + int(regs[1][1:]), newdst)

    # ----------------------------------------------------------------
    # Memory helpers
    # ----------------------------------------------------------------
    def alloc(self, size):
        size = max(1, align(size))
        r = self.heap_next
        self.heap_next += size
        self.uc.mem_write(r, bytes(size))
        return r

    def cstr(self, addr, limit=0x2000):
        out = bytearray()
        for i in range(limit):
            b = self.uc.mem_read(addr + i, 1)[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def wcstr(self, addr, limit=1024):
        """Read a null-terminated UTF-32LE (wchar_t) string."""
        chars = []
        for i in range(limit):
            w = p32(bytes(self.uc.mem_read(addr + i * 4, 4)))
            if w == 0:
                break
            chars.append(chr(w))
        return "".join(chars)

    def write_cstr(self, addr, data: bytes):
        self.uc.mem_write(addr, data + b"\x00")

    def write_wcstr(self, addr, text: str):
        """Write a null-terminated UTF-32LE string."""
        for i, ch in enumerate(text):
            self.uc.mem_write(addr + i * 4, struct.pack("<I", ord(ch)))
        self.uc.mem_write(addr + len(text) * 4, b"\x00\x00\x00\x00")

    def _va2fo(self, va):
        for name, vm, vs, fo, fl in self.segs:
            if vm <= va < vm + vs:
                off = va - vm
                return fo + off if off < fl else va
        return va

    def reg(self, i):
        return self.uc.reg_read(UC_ARM64_REG_X0 + i)

    def return_stub(self, value):
        self.uc.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)

    # ----------------------------------------------------------------
    # Entry point setup
    # ----------------------------------------------------------------
    def _setup_entry(self):
        sp = STACK_BASE + STACK_SIZE - 0x2000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X30, STOP)

        if self.mode == "init":
            self._setup_init()
        elif self.mode == "load":
            self._setup_load()
        elif self.mode == "full":
            self._setup_full()
        else:
            raise ValueError(f"Unknown mode: {self.mode}")

    def _setup_init(self):
        """Set up for sub_113DC (file integrity init).

        sub_113DC(a1) where a1 is the main service context.
        We create a minimal context with:
          - vtable pointer at *a1 with error handler at vtable+128
          - zero-initialized catalogue tree at a1+9904
          - field at a1+10792 for alt exe path (unused, zero)
        """
        self.entry = ENTRY_INIT
        # Context: 0x2B20 bytes (11040)
        ctx_size = 0x2B20
        self.ctx = self.alloc(ctx_size)

        # Vtable: needs entry at offset 128 (error handler)
        vtable = self.alloc(0x200)
        # Error handler at vtable+128 = a callback that logs the error code
        error_handler = CALLBACK  # reuse the callback slot
        self.uc.mem_write(vtable + 128, u64(error_handler))
        # Write vtable pointer at ctx[0]
        self.uc.mem_write(self.ctx, u64(vtable))

        # Mutex at ctx+9904+4 (used by sub_2C3AC)
        # pthread_mutex is typically 64 bytes on macOS; just leave zeroed

        self.uc.reg_write(UC_ARM64_REG_X0, self.ctx)

    def _setup_load(self):
        """Set up for sub_2B8D0 (catalogue loading).

        sub_2B8D0(a1, a2, a3, a4) where:
          a1 = _QWORD* catalogue context (hash entries stored here)
          a2 = std::wstring (the catalogue certificate path, UTF-32LE)
          a3 = additional context
          a4 = flag (int, use 1)

        Note: sub_2CE38 treats a2 as a std::wstring, not std::string.
        It reads byte 23 for SSO check, then passes the wchar_t* data
        to sub_348D8 -> sub_340DC (wstring copy) -> sub_51664 (wide-to-narrow)
        -> sub_347F0 (fopen).
        """
        self.entry = ENTRY_LOAD

        # a1: catalogue context object (at least 33 QWORDs needed)
        cat_ctx = self.alloc(0x200)
        # a1[0] = pointer to cert chain wstring (empty wstring)
        cert_str = self.alloc(0x40)
        self.uc.mem_write(cat_ctx, u64(cert_str))

        # a2: std::wstring holding the catalogue FILE path (with .bin extension)
        # rfind('.') will find '.bin' and replace with '.cer' for the certificate
        path_text = FAKE_CATALOGUE_FILE.decode("utf-8")
        path_wstr_addr = self.alloc(0x40)
        self._cxx_wstring_assign(path_wstr_addr, path_text)
        print(f"[setup] catalogue wstring path = {path_text!r}")
        readback = self._cxx_wstring_read(path_wstr_addr)
        print(f"[setup] readback = {readback!r}")

        # a3: additional context, zero
        a3_ctx = self.alloc(0x40)

        # a4: flag = 1
        self.uc.reg_write(UC_ARM64_REG_X0, cat_ctx)
        self.uc.reg_write(UC_ARM64_REG_X1, path_wstr_addr)
        self.uc.reg_write(UC_ARM64_REG_X2, a3_ctx)
        self.uc.reg_write(UC_ARM64_REG_X3, 1)

    def _setup_full(self):
        """Set up for _x entry (full service init), then trace into
        sub_113DC when it's reached."""
        self.entry = ENTRY_X
        # v1 block for _x (same as service_cv_trace.py)
        block = bytearray(0x300)
        struct.pack_into("<I", block, 0, 1)        # version
        struct.pack_into("<I", block, 4, len(block))  # size
        struct.pack_into("<I", block, 8, 1)         # flags
        struct.pack_into("<Q", block, 0xC, CALLBACK)  # callback
        struct.pack_into("<I", block, 0x18, 5)      # count
        guids = [b"429c2212ad284866aee071454c2125b5",
                 b"ec47bae0651a4765a063c1e83ec41b34",
                 b"76796531e86443548754600511f42e9e",
                 b"local", b"Rust"]
        for i, g in enumerate(guids):
            block[0x1C + i * 0x40:0x1C + i * 0x40 + len(g)] = g
        self.args = self.alloc(0x400)
        self.uc.mem_write(self.args, bytes(block))
        self.uc.reg_write(UC_ARM64_REG_X0, self.args)
        self.uc.reg_write(UC_ARM64_REG_X1, len(block))

    # ----------------------------------------------------------------
    # Stub models
    # ----------------------------------------------------------------
    def handle_stub(self, addr):
        name = next((n for n, a in self.ext.items() if a == addr), hex(addr))
        self.stub_hits[name] += 1
        a0, a1, a2, a3 = self.reg(0), self.reg(1), self.reg(2), self.reg(3)
        if len(self.stub_args) < 5000:
            self.stub_args.append({"name": name, "x0": a0, "x1": a1,
                                   "x2": a2, "x3": a3})

        # -- Memory allocation ------------------------------------------
        if name in ("_malloc", "__Znwm", "__ZnwmRKSt9nothrow_t", "__Znam"):
            self.return_stub(self.alloc(a0))
        elif name == "_calloc":
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
        elif name == "_memcmp":
            b1 = bytes(self.uc.mem_read(a0, a2))
            b2 = bytes(self.uc.mem_read(a1, a2))
            self.return_stub(0 if b1 == b2 else (1 if b1 > b2 else 0xFFFFFFFFFFFFFFFF))
        elif name == "_strlen":
            self.return_stub(len(self.cstr(a0)))
        elif name == "_bzero":
            self.uc.mem_write(a0, bytes(a1))
            self.return_stub(0)
        elif name == "_strcmp":
            s1 = self.cstr(a0)
            s2 = self.cstr(a1)
            self.return_stub(0 if s1 == s2 else (1 if s1 > s2 else 0xFFFFFFFFFFFFFFFF))

        # -- Executable path resolution ---------------------------------
        elif name == "__NSGetExecutablePath":
            # _NSGetExecutablePath(buf, &bufsize)
            buf, bufsize_ptr = a0, a1
            bufsize = p32(bytes(self.uc.mem_read(bufsize_ptr, 4)))
            path = FAKE_EXE_PATH
            if bufsize >= len(path) + 1:
                self.write_cstr(buf, path)
                self.uc.mem_write(bufsize_ptr, u32(len(path)))
                self.return_stub(0)
                print(f"[NSGetExecutablePath] -> {path.decode()}")
            else:
                self.uc.mem_write(bufsize_ptr, u32(len(path) + 1))
                self.return_stub(0xFFFFFFFFFFFFFFFF)  # -1
                print(f"[NSGetExecutablePath] buffer too small ({bufsize} < {len(path)+1})")

        elif name == "_realpath$DARWIN_EXTSN":
            # realpath(path, resolved_path)
            path = self.cstr(a0)
            resolved = a1
            if resolved:
                self.write_cstr(resolved, path)
            self.return_stub(resolved if resolved else 0)
            print(f"[realpath] {path.decode('utf-8', errors='replace')} -> {resolved:#x}")

        elif name == "_basename":
            # basename(path) -> pointer to last component
            path = self.cstr(a0)
            idx = max(path.rfind(b"/"), path.rfind(b"\\"))
            if idx >= 0:
                result_addr = a0 + idx + 1
            else:
                result_addr = a0
            bname = self.cstr(result_addr)
            self.return_stub(result_addr)
            print(f"[basename] {path.decode('utf-8', errors='replace')} -> {bname.decode('utf-8', errors='replace')}")

        # -- iconv (charset conversion) ---------------------------------
        elif name == "_iconv_open":
            tocode = self.cstr(a0).decode("utf-8", errors="replace")
            fromcode = self.cstr(a1).decode("utf-8", errors="replace")
            handle = self.next_iconv
            self.next_iconv += 1
            self.iconv_handles[handle] = (fromcode, tocode)
            self.return_stub(handle)
            print(f"[iconv_open] {fromcode} -> {tocode} = {handle:#x}")

        elif name == "_iconv":
            # iconv(cd, **inbuf, *inbytesleft, **outbuf, *outbytesleft)
            cd = a0
            inbuf_ptr = a1
            inbytesleft_ptr = a2
            outbuf_ptr = a3

            # 5th argument is in x4
            outbytesleft_ptr = self.reg(4)

            if cd in self.iconv_handles:
                fromcode, tocode = self.iconv_handles[cd]
                inbuf_addr = p64(bytes(self.uc.mem_read(inbuf_ptr, 8)))
                inbytesleft = p64(bytes(self.uc.mem_read(inbytesleft_ptr, 8)))
                outbuf_addr = p64(bytes(self.uc.mem_read(outbuf_ptr, 8)))
                outbytesleft = p64(bytes(self.uc.mem_read(outbytesleft_ptr, 8)))

                # Read input
                in_data = bytes(self.uc.mem_read(inbuf_addr, inbytesleft))

                # Convert
                try:
                    # Map iconv encoding names to Python codec names
                    codec_map = {"UTF-8": "utf-8", "UTF-32LE": "utf-32-le",
                                 "UTF-16LE": "utf-16-le", "ASCII": "ascii"}
                    from_codec = codec_map.get(fromcode, fromcode)
                    to_codec = codec_map.get(tocode, tocode)
                    text = in_data.decode(from_codec)
                    out_data = text.encode(to_codec)
                except Exception as e:
                    print(f"[iconv] conversion error: {e}")
                    self.return_stub(0xFFFFFFFFFFFFFFFF)
                    return

                # Write output
                write_len = min(len(out_data), outbytesleft)
                self.uc.mem_write(outbuf_addr, out_data[:write_len])

                # Update pointers
                consumed = inbytesleft  # consumed all input
                self.uc.mem_write(inbuf_ptr, u64(inbuf_addr + consumed))
                self.uc.mem_write(inbytesleft_ptr, u64(0))
                self.uc.mem_write(outbuf_ptr, u64(outbuf_addr + write_len))
                self.uc.mem_write(outbytesleft_ptr, u64(outbytesleft - write_len))

                self.return_stub(0)  # success
                print(f"[iconv] {fromcode}->{tocode}: {inbytesleft} bytes in, {write_len} bytes out")
            else:
                print(f"[iconv] unknown handle {cd:#x}")
                self.return_stub(0xFFFFFFFFFFFFFFFF)

        elif name == "_iconv_close":
            if a0 in self.iconv_handles:
                del self.iconv_handles[a0]
            self.return_stub(0)

        # -- Wide string operations -------------------------------------
        elif name == "_wcslen":
            length = 0
            while True:
                w = p32(bytes(self.uc.mem_read(a0 + length * 4, 4)))
                if w == 0:
                    break
                length += 1
            self.return_stub(length)

        elif name == "_wmemcpy":
            # wmemcpy(dst, src, n) - n is count of wchar_t (4 bytes each)
            nbytes = a2 * 4
            if nbytes:
                self.uc.mem_write(a0, bytes(self.uc.mem_read(a1, nbytes)))
            self.return_stub(a0)

        # -- File I/O (with catalogue serving) --------------------------
        elif name == "_fopen":
            path = self.cstr(a0).decode("utf-8", errors="replace")
            mode = self.cstr(a1).decode("utf-8", errors="replace")
            self.fopen_log.append({"path": path, "mode": mode})
            print(f"[fopen] {path} mode={mode}")

            # Decide what to serve based on file extension and path
            fd = self.next_fd
            self.next_fd += 8
            lpath = path.lower()
            if lpath.endswith(".cer") or lpath.endswith(".pem"):
                # Serve a fake ECDSA certificate (DER-encoded placeholder)
                cert_data = self._build_fake_certificate()
                self.open_files[fd] = FakeFile(cert_data, path)
                self.return_stub(fd)
                print(f"  -> serving fake certificate ({len(cert_data)} bytes), fd={fd:#x}")
            elif (lpath.endswith(".bin") or "catalogue" in lpath
                    or "certificates/" in lpath):
                # Serve synthetic catalogue
                self.open_files[fd] = FakeFile(self.catalogue_data, path)
                self.return_stub(fd)
                print(f"  -> serving synthetic catalogue ({len(self.catalogue_data)} bytes), fd={fd:#x}")
            elif any(marker in lpath for marker in
                     ["rust", "game", ".app", "macos"]):
                macho = self._build_fake_macho()
                self.open_files[fd] = FakeFile(macho, path)
                self.return_stub(fd)
                print(f"  -> serving fake Mach-O ({len(macho)} bytes), fd={fd:#x}")
            else:
                self.open_files[fd] = FakeFile(b"\x00" * 256, path)
                self.return_stub(fd)

        elif name == "_fread":
            # fread(buf, size, count, stream)
            buf, size, count, stream = a0, a1, a2, a3
            total = size * count
            ff = self.open_files.get(stream)
            if ff:
                data = ff.read(total)
                self.uc.mem_write(buf, data + b"\x00" * max(0, total - len(data)))
                items_read = len(data) // size if size else 0
                self.return_stub(items_read)
                self.fread_log.append({"stream": stream, "path": ff.path,
                                       "offset": ff.pos - len(data),
                                       "requested": total, "read": len(data)})
                print(f"[fread] {ff.path}: offset={ff.pos - len(data):#x} "
                      f"size={size} count={count} -> {items_read} items")
            else:
                self.return_stub(0)

        elif name == "_fseek":
            # fseek(stream, offset, whence)
            ff = self.open_files.get(a0)
            if ff:
                ff.seek(a1 if a1 < 0x8000000000000000 else a1 - (1 << 64), a2)
                self.return_stub(0)
            else:
                self.return_stub(0xFFFFFFFFFFFFFFFF)

        elif name == "_ftell":
            ff = self.open_files.get(a0)
            self.return_stub(ff.tell() if ff else 0)

        elif name == "_rewind":
            ff = self.open_files.get(a0)
            if ff:
                ff.seek(0, 0)
            self.return_stub(0)

        elif name == "_fclose":
            if a0 in self.open_files:
                print(f"[fclose] {self.open_files[a0].path}")
                del self.open_files[a0]
            self.return_stub(0)

        # -- stat -------------------------------------------------------
        elif name == "_stat":
            path = self.cstr(a0).decode("utf-8", errors="replace")
            stat_buf = a1
            print(f"[stat] {path}")
            # Always report success, fill stat_buf with plausible values
            if stat_buf:
                # struct stat on macOS/ARM64: st_mode at offset 4
                self.uc.mem_write(stat_buf, bytes(144))  # zero
                struct.pack_into("<H", bytearray(144), 4, 0o100644)  # regular file
                self.uc.mem_write(stat_buf + 4, struct.pack("<H", 0o100644))
                self.uc.mem_write(stat_buf + 96, u64(len(self.catalogue_data)))  # st_size
            self.return_stub(0)  # success

        # -- glob -------------------------------------------------------
        elif name == "_glob":
            # glob(pattern, flags, errfunc, pglob)
            pattern = self.cstr(a0).decode("utf-8", errors="replace")
            pglob = a3
            print(f"[glob] pattern={pattern}")

            # Build glob result: one path = fake catalogue file
            result_path = FAKE_CATALOGUE_FILE
            path_buf = self.alloc(len(result_path) + 16)
            self.write_cstr(path_buf, result_path)

            # pathv array (null-terminated array of char*)
            pathv = self.alloc(16)
            self.uc.mem_write(pathv, u64(path_buf))
            self.uc.mem_write(pathv + 8, u64(0))

            # glob_t structure on macOS:
            #   size_t gl_pathc;   // offset 0
            #   int    gl_matchc;  // offset 8
            #   size_t gl_offs;    // offset 12 (or 16 with padding)
            #   int    gl_flags;   // offset 16 (or 20)
            #   char** gl_pathv;   // offset 24
            # Actually on macOS ARM64 the struct is:
            #   offset 0:  gl_pathc (size_t = 8 bytes)
            #   offset 8:  gl_matchc (int = 4 bytes)
            #   offset 12: gl_offs (size_t = 8 bytes) -- with padding
            #   offset 16: gl_offs (actually)
            #   offset 24: gl_flags (int)
            #   offset 32: gl_pathv (char**)
            # Let me just set pathc and pathv reliably:
            self.uc.mem_write(pglob, u64(1))       # gl_pathc = 1
            self.uc.mem_write(pglob + 32, u64(pathv))  # gl_pathv

            self.glob_results[pglob] = pathv
            self.return_stub(0)  # GLOB_NOMATCH = 3, success = 0

        elif name == "_globfree":
            self.return_stub(0)

        # -- snprintf ---------------------------------------------------
        elif name == "_snprintf":
            # snprintf(buf, size, fmt, ...)
            fmt = self.cstr(a2).decode("utf-8", errors="replace")
            # We can't fully format, but log it
            print(f"[snprintf] fmt={fmt!r}")
            # Write a placeholder
            placeholder = fmt.encode("utf-8", errors="replace")[:a1 - 1] if a1 > 0 else b""
            self.write_cstr(a0, placeholder)
            self.return_stub(len(placeholder))

        elif name == "_vsnprintf":
            self.return_stub(0)

        # -- Threading --------------------------------------------------
        elif name.startswith("_pthread_mutex") or name.startswith("_pthread_cond"):
            self.return_stub(0)
        elif name == "_pthread_create":
            fn = p64(bytes(self.uc.mem_read(a2, 8))) if a2 else 0
            self.threads.append({"fn": fn, "arg": a3})
            if a0:
                self.uc.mem_write(a0, u64(0xDEAD0000 + len(self.threads)))
            self.return_stub(0)

        # -- Guard variables --------------------------------------------
        elif name == "___cxa_guard_acquire":
            guard_val = int.from_bytes(self.uc.mem_read(a0, 8), "little")
            self.return_stub(1 if guard_val == 0 else 0)
        elif name == "___cxa_guard_release":
            self.uc.mem_write(a0, u64(1))
            self.return_stub(0)
        elif name == "___cxa_guard_abort":
            self.return_stub(0)

        # -- System calls -----------------------------------------------
        elif name == "_getpid":
            self.return_stub(4321)
        elif name in ("_sysctl", "_sysctlbyname", "_csr_get_active_config",
                       "_csops", "_issetugid"):
            self.return_stub(0)
        elif name == "_open":
            path = self.cstr(a0).decode("utf-8", errors="replace")
            print(f"[open] {path}")
            self.return_stub(0xFFFFFFFFFFFFFFFF)
        elif name in ("_close", "_read", "_write", "_fcntl", "_ftruncate"):
            self.return_stub(0)
        elif name == "_mmap":
            self.return_stub(self.alloc(a1))
        elif name in ("_mprotect", "_vm_protect"):
            self.return_stub(0)
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
                self.uc.mem_write(a1, struct.pack("<II", 1786000000, 0))
            self.return_stub(0)
        elif name == "_mach_port_deallocate":
            self.return_stub(0)
        elif name in ("_time", "_gettimeofday"):
            self.return_stub(1786000000)

        # -- C++ string operations (narrow) ----------------------------
        elif name == "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc":
            # string::resize(this, n, c)
            self._cxx_string_resize(a0, a1, a2 & 0xFF)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc":
            # string::assign(this, s)
            s = self.cstr(a1)
            self._cxx_string_assign(a0, s)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9__grow_byEmmmmmm":
            # string::__grow_by(this, old_cap, delta_cap, old_size, n_copy, n_del, n_add)
            self._cxx_string_grow_by(a0, a1, a2, a3,
                                      self.reg(4), self.reg(5), self.reg(6))
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_":
            # string copy constructor: string(this, other)
            other_data = self._cxx_string_data(a1)
            self._cxx_string_assign(a0, other_data)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_":
            # string::operator=(this, other)
            other_data = self._cxx_string_data(a1)
            self._cxx_string_assign(a0, other_data)
            self.return_stub(a0)

        # -- C++ string operations (wide, wstring) ----------------------
        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6appendEPKwm":
            # wstring::append(this, s, n)
            self._cxx_wstring_append(a0, a1, a2)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6appendEPKw":
            # wstring::append(this, s) - null-terminated
            n = 0
            while p32(bytes(self.uc.mem_read(a1 + n * 4, 4))) != 0:
                n += 1
            self._cxx_wstring_append(a0, a1, n)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6assignEPKw":
            # wstring::assign(this, s)
            ws = self.wcstr(a1)
            self._cxx_wstring_assign(a0, ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6assignEPKwm":
            # wstring::assign(this, s, n)
            ws_chars = []
            for i in range(a2):
                w = p32(bytes(self.uc.mem_read(a1 + i * 4, 4)))
                ws_chars.append(chr(w))
            self._cxx_wstring_assign(a0, "".join(ws_chars))
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6insertEmPKw":
            # wstring::insert(this, pos, s)
            ws = self.wcstr(a2)
            self._cxx_wstring_insert(a0, a1, ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE6insertEmPKwm":
            # wstring::insert(this, pos, s, n)
            ws_chars = []
            for i in range(a3):
                w = p32(bytes(self.uc.mem_read(a2 + i * 4, 4)))
                ws_chars.append(chr(w))
            self._cxx_wstring_insert(a0, a1, "".join(ws_chars))
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEEC1ERKS5_":
            # wstring copy constructor (this, other)
            other_ws = self._cxx_wstring_read(a1)
            self._cxx_wstring_assign(a0, other_ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEEC1ERKS5_mmRKS4_":
            # wstring(this, other, pos, n, alloc) - substring constructor
            other_ws = self._cxx_wstring_read(a1)
            pos = a2
            n = a3
            if n == 0xFFFFFFFFFFFFFFFF:
                n = len(other_ws) - pos
            sub = other_ws[pos:pos + n]
            self._cxx_wstring_assign(a0, sub)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEEaSERKS5_":
            # wstring::operator=(this, other)
            other_ws = self._cxx_wstring_read(a1)
            self._cxx_wstring_assign(a0, other_ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEED1Ev":
            # wstring destructor
            byte23 = self.uc.mem_read(a0 + 23, 1)[0]
            if byte23 & 0x80:
                ptr = p64(bytes(self.uc.mem_read(a0, 8)))
                # Would free ptr, but we skip
            # Zero out the string object
            self.uc.mem_write(a0, bytes(24))
            self.return_stub(0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE5eraseEmm":
            # wstring::erase(this, pos, len)
            ws = self._cxx_wstring_read(a0)
            ws = ws[:a1] + ws[a1 + a2:]
            self._cxx_wstring_assign(a0, ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE7replaceEmmPKwm":
            # wstring::replace(this, pos, len1, s, len2)
            ws = self._cxx_wstring_read(a0)
            rep_chars = []
            for i in range(a3):
                w = p32(bytes(self.uc.mem_read(a2 + i * 4, 4)))
                rep_chars.append(chr(w))
            ws = ws[:a1] + "".join(rep_chars) + ws[a1 + self.reg(4):]
            self._cxx_wstring_assign(a0, ws)
            self.return_stub(a0)

        elif name == "__ZNSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE9push_backEw":
            # wstring::push_back(this, ch)
            ws = self._cxx_wstring_read(a0)
            ws += chr(a1 & 0xFFFFFFFF)
            self._cxx_wstring_assign(a0, ws)
            self.return_stub(a0)

        elif name == "__ZNKSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE5rfindEwm":
            # wstring::rfind(this, ch, pos)
            ws = self._cxx_wstring_read(a0)
            ch = chr(a1 & 0xFFFFFFFF)
            pos = min(a2, len(ws)) if a2 != 0xFFFFFFFFFFFFFFFF else len(ws)
            idx = ws.rfind(ch, 0, pos + 1)
            self.return_stub(idx if idx >= 0 else 0xFFFFFFFFFFFFFFFF)

        elif name == "__ZNKSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE7compareEmmPKwm":
            # wstring::compare(this, pos, len1, s, len2)
            ws = self._cxx_wstring_read(a0)
            sub = ws[a1:a1 + a2]
            cmp_chars = []
            for i in range(a3):
                # a3 is actually the s pointer, reg(4) is len2
                w = p32(bytes(self.uc.mem_read(a2 + i * 4, 4)))
                cmp_chars.append(chr(w))
            # This signature is tricky; a2=s, a3=len2 based on the mangled name
            # Actually: compare(pos1, count1, s, count2)
            # x0=this, x1=pos, x2=count1, x3=s, stack[0]=count2
            # Let me just return 0 for now
            self.return_stub(0)

        # -- dlopen/dlsym -----------------------------------------------
        elif name in ("_dlopen", "_dlsym"):
            self.return_stub(0)

        # -- Steady clock -----------------------------------------------
        elif name == "__ZNSt3__16chrono12steady_clock3nowEv":
            self.steady_ns = getattr(self, "steady_ns", 1000000000000) + 1000000
            self.uc.mem_write(a0, struct.pack("<Q", self.steady_ns))
            self.return_stub(a0)

        # -- swap_fat_arch (Mach-O parsing) -----------------------------
        elif name == "_swap_fat_arch":
            # swap_fat_arch(fat_arch *archs, uint32_t nfat_arch, enum NXByteOrder)
            # Each fat_arch is 20 bytes: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
            # Byte-swap each field
            for i in range(a1):
                base = a0 + i * 20
                for f in range(5):
                    val = p32(bytes(self.uc.mem_read(base + f * 4, 4)))
                    swapped = struct.unpack(">I", struct.pack("<I", val))[0]
                    self.uc.mem_write(base + f * 4, u32(swapped))
            self.return_stub(0)

        # -- opendir / readdir / closedir (directory scanning) ----------
        elif name == "_opendir":
            path = self.cstr(a0).decode("utf-8", errors="replace")
            print(f"[opendir] {path}")
            self.return_stub(0)  # NULL = failure (no real dir)

        elif name == "_readdir":
            self.return_stub(0)  # NULL = no more entries

        elif name == "_closedir":
            self.return_stub(0)

        # -- Environment ------------------------------------------------
        elif name == "_getenv":
            key = self.cstr(a0).decode("utf-8", errors="replace")
            print(f"[getenv] {key}")
            # Return EAC_LAUNCHERDIR for that specific key
            if key == "EAC_LAUNCHERDIR":
                buf = self.alloc(len(FAKE_GAME_DIR) + 16)
                self.write_cstr(buf, FAKE_GAME_DIR)
                self.return_stub(buf)
            else:
                self.return_stub(0)

        # -- CoreFoundation / IOKit stubs -------------------------------
        elif name.startswith("_CF") or name.startswith("_IO") or name.startswith("_DA"):
            self.return_stub(0)

        # -- Catch-all --------------------------------------------------
        else:
            self.return_stub(0)

    # ----------------------------------------------------------------
    # C++ string helpers (narrow, element_size=1)
    # ----------------------------------------------------------------
    def _cxx_string_is_long(self, addr):
        return self.uc.mem_read(addr + 23, 1)[0] & 0x80 != 0

    def _cxx_string_data(self, addr) -> bytes:
        """Read the raw bytes of a std::string."""
        if self._cxx_string_is_long(addr):
            ptr = p64(bytes(self.uc.mem_read(addr, 8)))
            size = p64(bytes(self.uc.mem_read(addr + 8, 8)))
            return bytes(self.uc.mem_read(ptr, size))
        else:
            size = self.uc.mem_read(addr + 23, 1)[0]
            return bytes(self.uc.mem_read(addr, size))

    def _cxx_string_assign(self, addr, data: bytes):
        """Write data into a std::string object at addr."""
        n = len(data)
        if n < 23:
            # SSO mode
            self.uc.mem_write(addr, data + b"\x00" * (23 - n))
            self.uc.mem_write(addr + 23, bytes([n]))
        else:
            # Long mode
            cap = (n + 16) & ~0xF
            buf = self.alloc(cap)
            self.uc.mem_write(buf, data + b"\x00")
            self.uc.mem_write(addr, u64(buf))
            self.uc.mem_write(addr + 8, u64(n))
            self.uc.mem_write(addr + 16, u64(cap | 0x8000000000000000))

    def _cxx_string_resize(self, addr, n, fill_char):
        """Implement string::resize."""
        current = self._cxx_string_data(addr)
        if n <= len(current):
            self._cxx_string_assign(addr, current[:n])
        else:
            self._cxx_string_assign(addr, current + bytes([fill_char]) * (n - len(current)))

    def _cxx_string_grow_by(self, addr, old_cap, delta_cap, old_size,
                             n_copy, n_del, n_add):
        """Implement string::__grow_by (internal reallocation)."""
        new_cap = old_cap + delta_cap
        new_cap = max(new_cap, 2 * old_cap)
        new_cap = (new_cap + 16) & ~0xF
        old_data = self._cxx_string_data(addr)
        # The caller will write new data; we just need to reallocate
        buf = self.alloc(new_cap)
        # Copy old data up to n_copy
        copy_len = min(n_copy, len(old_data))
        self.uc.mem_write(buf, old_data[:copy_len] + b"\x00" * (new_cap - copy_len))
        self.uc.mem_write(addr, u64(buf))
        new_size = old_size - n_del + n_add
        self.uc.mem_write(addr + 8, u64(new_size))
        self.uc.mem_write(addr + 16, u64(new_cap | 0x8000000000000000))

    # ----------------------------------------------------------------
    # C++ wstring helpers (wide, element_size=4)
    # ----------------------------------------------------------------
    def _cxx_wstring_read(self, addr) -> str:
        """Read a std::wstring from memory."""
        byte23 = self.uc.mem_read(addr + 23, 1)[0]
        if byte23 & 0x80:
            ptr = p64(bytes(self.uc.mem_read(addr, 8)))
            size = p64(bytes(self.uc.mem_read(addr + 8, 8)))
            chars = []
            for i in range(size):
                w = p32(bytes(self.uc.mem_read(ptr + i * 4, 4)))
                chars.append(chr(w))
            return "".join(chars)
        else:
            size = byte23
            chars = []
            for i in range(size):
                w = p32(bytes(self.uc.mem_read(addr + i * 4, 4)))
                chars.append(chr(w))
            return "".join(chars)

    def _cxx_wstring_assign(self, addr, text: str):
        """Write a std::wstring to memory."""
        n = len(text)
        if n < 5:  # SSO for wstring: 22 bytes / 4 = 5 chars max
            # Zero out first
            self.uc.mem_write(addr, bytes(24))
            for i, ch in enumerate(text):
                self.uc.mem_write(addr + i * 4, struct.pack("<I", ord(ch)))
            # Null terminator
            self.uc.mem_write(addr + n * 4, b"\x00\x00\x00\x00")
            self.uc.mem_write(addr + 23, bytes([n]))
        else:
            cap = (n + 4) & ~3
            buf = self.alloc(cap * 4 + 4)
            for i, ch in enumerate(text):
                self.uc.mem_write(buf + i * 4, struct.pack("<I", ord(ch)))
            self.uc.mem_write(buf + n * 4, b"\x00\x00\x00\x00")
            self.uc.mem_write(addr, u64(buf))
            self.uc.mem_write(addr + 8, u64(n))
            self.uc.mem_write(addr + 16, u64(cap | 0x8000000000000000))

    def _cxx_wstring_append(self, addr, src, n):
        """Append n wide chars from src to wstring at addr."""
        current = self._cxx_wstring_read(addr)
        append_chars = []
        for i in range(n):
            w = p32(bytes(self.uc.mem_read(src + i * 4, 4)))
            append_chars.append(chr(w))
        self._cxx_wstring_assign(addr, current + "".join(append_chars))

    def _cxx_wstring_insert(self, addr, pos, text):
        """Insert text at position pos in wstring at addr."""
        current = self._cxx_wstring_read(addr)
        result = current[:pos] + text + current[pos:]
        self._cxx_wstring_assign(addr, result)

    # ----------------------------------------------------------------
    # Fake Mach-O for exe path resolution
    # ----------------------------------------------------------------
    def _build_fake_certificate(self) -> bytes:
        """Build a minimal fake DER-encoded certificate.

        This is a placeholder; the binary uses mbedTLS to parse it.
        We provide just enough structure to observe what fields are read.
        """
        # Minimal self-signed X.509 cert stub (DER format)
        # SEQUENCE { SEQUENCE { version, serial, algo, issuer, validity,
        #            subject, pubkey }, sigAlgo, signature }
        # We use a known-bad but structurally valid DER blob
        cert = bytearray(0x400)
        # DER SEQUENCE tag + length
        cert[0] = 0x30  # SEQUENCE
        cert[1] = 0x82  # length in 2 bytes
        cert[2] = 0x03  # length high byte
        cert[3] = 0xFC  # length low byte = 1020
        # Inner SEQUENCE
        cert[4] = 0x30  # SEQUENCE
        cert[5] = 0x82  # length in 2 bytes
        cert[6] = 0x02  # length high byte
        cert[7] = 0xE4  # length low byte
        # Fill with recognizable pattern
        for off in range(8, len(cert), 4):
            struct.pack_into("<I", cert, off, off | 0xCE000000)
        return bytes(cert)

    def _build_fake_macho(self) -> bytes:
        """Build a minimal thin ARM64 Mach-O header."""
        # MH_MAGIC_64 = 0xFEEDFACF
        # CPU_TYPE_ARM64 = 0x0100000C
        # CPU_SUBTYPE_ARM64_ALL = 0
        # MH_EXECUTE = 2
        header = struct.pack("<IiiIIIII",
                             0xFEEDFACF,    # magic
                             0x0100000C,    # cputype (ARM64)
                             0,             # cpusubtype
                             2,             # filetype (MH_EXECUTE)
                             0,             # ncmds
                             0,             # sizeofcmds
                             0,             # flags
                             0)             # reserved
        return header + b"\x00" * (0x1000 - len(header))

    # ----------------------------------------------------------------
    # Hooks
    # ----------------------------------------------------------------
    def on_code(self, uc, addr, size, ud):
      try:
        if EXTERNAL_BASE + 0x2000 <= addr < EXTERNAL_BASE + 0x2000 + 8 * 0x400:
            self.handle_stub(addr)
            return
        if addr == STOP:
            self.stop_reason = "returned from entry"
            uc.emu_stop()
            return
        if addr == CALLBACK:
            code = self.reg(1)
            self.error_codes.append(code)
            self.stub_hits[f"__callback(code={code})"] += 1
            print(f"[CALLBACK] error code={code}")
            self.return_stub(0)
            return
        if addr in self.lse:
            self.emulate_lse(addr)
            if self.fault:
                return
            self.uc.reg_write(UC_ARM64_REG_PC, addr + 4)
            self.steps += 1
            if self.steps >= self.max_instr:
                uc.emu_stop()
            return

        # Track notable addresses
        if addr == 0x113DC:
            print(f"[ENTRY] sub_113DC reached at step {self.steps}")
        elif addr == 0x2CE38:
            print(f"[ENTER] sub_2CE38 (catalogue header check) at step {self.steps}")
        elif addr == 0x2CECC:
            print(f"[ENTER] sub_2CECC (format factory v4/v5) at step {self.steps}")
        elif addr == 0x2B8D0:
            print(f"[ENTER] sub_2B8D0 (catalogue load) at step {self.steps}")
        elif addr == 0x2C3AC:
            print(f"[ENTER] sub_2C3AC (catalogue lookup) at step {self.steps}")
        elif addr == 0x2BB24:
            print(f"[ENTER] sub_2BB24 (catalogue entry lookup) at step {self.steps}")
        elif addr == 0x34DF0:
            print(f"[ENTER] sub_34DF0 (exe path resolution) at step {self.steps}")
        elif addr == 0x347F0:
            print(f"[ENTER] sub_347F0 (generic file reader) at step {self.steps}")
        elif addr == 0x2919C:
            # CRC32 computation - log the input
            r0 = self.reg(0)
            r1 = self.reg(1)
            data = bytes(self.uc.mem_read(r0, min(r1, 256)))
            self.hash_ops.append({"type": "crc32", "addr": r0, "len": r1,
                                  "data_preview": data[:64].hex()})
            print(f"[HASH] CRC32 at step {self.steps}: len={r1} data={data[:32].hex()}...")

        self.pc_hits[addr] += 1
        self.recent.append(addr)
        if self.pcs is not None and len(self.pcs) < 40_000_000:
            self.pcs.append(addr)
        self.steps += 1
        if self.steps >= self.max_instr:
            uc.emu_stop()
      except Exception as exc:
        import traceback
        print(f"[hook-error] pc={addr:#x}: {exc}")
        traceback.print_exc()
        self.stop_reason = f"hook error at {addr:#x}: {exc}"
        uc.emu_stop()

    def on_invalid(self, uc, access, addr, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if access >= 16:
            regs = {f"x{i}": hex(uc.reg_read(UC_ARM64_REG_X0 + i)) for i in range(9)}
            print(f"[bad-jump] pc={pc:#x} target={addr:#x} access={access}")
            print(f"  regs: {regs}")
            self.stop_reason = f"bad jump to {addr:#x} from {pc:#x}"
            self.fault = {"pc": pc, "addr": addr, "size": size, "access": access}
            return False
        page = addr & ~0xFFF
        self.automap_count = getattr(self, "automap_count", 0) + 1
        if self.automap_count <= 2000:
            try:
                uc.mem_map(page, 0x1000)
                uc.mem_write(page, bytes(0x1000))
                if self.automap_count <= 30:
                    print(f"[automap] pc={pc:#x} addr={addr:#x} size={size} access={access}")
                return True
            except Exception:
                pass
        self.stop_reason = f"invalid memory at {addr:#x} from {pc:#x}"
        self.fault = {"pc": pc, "addr": addr, "size": size, "access": access}
        return False

    def on_read(self, uc, access, addr, size, value, ud):
        if CV_START <= addr < CV_END:
            self.cv_reads[(addr, size)] += 1

    def on_write(self, uc, access, addr, size, value, ud):
        if CV_START <= addr < CV_END:
            self.cv_writes[(addr, size)] += 1

    # ----------------------------------------------------------------
    # Run
    # ----------------------------------------------------------------
    def run(self):
        try:
            self.uc.emu_start(self.entry, STOP, count=self.max_instr)
        except Exception as exc:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            fo = self._va2fo(pc)
            raw = bytes(self.data[fo:fo + 4]) if fo + 4 <= len(self.data) else b"\x00" * 4
            insn = next(self.cs.disasm(raw, pc), None)
            label = f"{insn.mnemonic} {insn.op_str}" if insn else f"?? ({raw.hex()})"
            regs = {f"x{i}": hex(self.uc.reg_read(UC_ARM64_REG_X0 + i)) for i in range(9)}
            print(f"[crash] pc={pc:#x}: {label}")
            print(f"  regs: {regs}")
            self.stop_reason = f"exception: {exc}"
            self.fault = {"pc": pc, "addr": pc, "access": "exec"}

        # Check if we stopped at STOP (Unicorn stops WITHOUT executing the 'until' address)
        final_pc = self.uc.reg_read(UC_ARM64_REG_PC)
        if final_pc == STOP and self.stop_reason == "instruction limit":
            self.stop_reason = "returned from entry"
        # Log return value
        ret_val = self.reg(0)
        print(f"\n[RETURN] x0={ret_val:#x} ({ret_val}) final_pc={final_pc:#x}")

        # -- Summary output --
        print(f"\n{'='*60}")
        print(f"CATALOGUE TRACE SUMMARY (mode={self.mode})")
        print(f"{'='*60}")
        print(f"steps={self.steps}  stop={self.stop_reason}")
        print(f"unique_pcs={len(self.pc_hits)}  cv_reads={len(self.cv_reads)}  "
              f"cv_writes={len(self.cv_writes)}")

        # Files opened
        print(f"\nFiles opened ({len(self.fopen_log)}):")
        for f in self.fopen_log:
            print(f"  {f['mode']:4s} {f['path']}")

        # File reads
        print(f"\nFile reads ({len(self.fread_log)}):")
        for r in self.fread_log:
            print(f"  {r['path']}: offset={r['offset']:#x} "
                  f"requested={r['requested']} read={r['read']}")

        # Hash operations
        print(f"\nHash operations ({len(self.hash_ops)}):")
        for h in self.hash_ops:
            print(f"  {h['type']}: len={h['len']} data={h['data_preview'][:40]}...")

        # Error codes dispatched
        print(f"\nError codes: {self.error_codes}")

        # Threads
        print(f"\nThreads created: {len(self.threads)}")
        for t in self.threads:
            print(f"  fn={t['fn']:#x} arg={t['arg']:#x}")

        # Fault info
        if self.fault and self.recent:
            print(f"\nFault: {self.fault}")
            print("Last 30 PCs before fault:")
            for pc in list(self.recent)[-30:]:
                fo = self._va2fo(pc)
                raw = bytes(self.data[fo:fo + 4]) if fo + 4 <= len(self.data) else b"\x00" * 4
                insn = next(self.cs.disasm(raw, pc), None)
                if insn:
                    print(f"  {pc:#x}: {insn.mnemonic} {insn.op_str}")
                else:
                    print(f"  {pc:#x}: ?? ({raw.hex()})")

        # Stub hits
        print(f"\nStub hits (top 40):")
        for n, c in self.stub_hits.most_common(40):
            print(f"  {c:6d} {n}")

        cv_pcs = sum(1 for p in self.pc_hits if CV_START <= p < CV_END)
        print(f"\nCV PCs executed: {cv_pcs}")

        # -- JSON report --
        if self.report:
            out = {
                "mode": self.mode,
                "entry": hex(self.entry),
                "catalogue_version": self.catalogue_version,
                "steps": self.steps,
                "stop_reason": self.stop_reason,
                "fault": self.fault,
                "unique_pcs": len(self.pc_hits),
                "cv_pcs": cv_pcs,
                "fopen_log": self.fopen_log,
                "fread_log": self.fread_log,
                "hash_ops": self.hash_ops,
                "error_codes": self.error_codes,
                "threads": [{"fn": hex(t["fn"]), "arg": hex(t["arg"])} for t in self.threads],
                "stub_hits": dict(self.stub_hits),
                "stub_args": self.stub_args[:2000],
            }
            self.report.write_text(json.dumps(out, indent=2) + "\n")
            print(f"\nReport: {self.report}")

        if self.trace_report and self.pcs is not None:
            self.trace_report.write_text(json.dumps({"pcs": self.pcs}) + "\n")
            print(f"Trace: {self.trace_report}")


def main():
    ap = argparse.ArgumentParser(
        description="Trace EAC hash catalogue / file integrity checking")
    ap.add_argument("module", type=Path,
                    help="Path to eac_service_decoded.dylib")
    ap.add_argument("--mode", choices=["init", "load", "full"],
                    default="init",
                    help="Trace mode: init (sub_113DC), load (sub_2B8D0), "
                         "full (_x entry)")
    ap.add_argument("--catalogue-version", type=int, default=4,
                    choices=[4, 5],
                    help="Catalogue format version (4 or 5)")
    ap.add_argument("--max-instructions", type=int, default=10_000_000)
    ap.add_argument("--report", type=Path,
                    help="JSON report output path")
    ap.add_argument("--trace-report", type=Path,
                    help="Full PC trace output path")
    args = ap.parse_args()

    h = CatalogueHarness(
        path=args.module,
        max_instr=args.max_instructions,
        mode=args.mode,
        catalogue_version=args.catalogue_version,
        report=args.report,
        trace_report=args.trace_report,
    )
    h.run()


if __name__ == "__main__":
    main()
