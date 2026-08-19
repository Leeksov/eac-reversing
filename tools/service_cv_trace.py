#!/usr/bin/env python3
"""Offline Unicorn harness for the DECODED EAC in-game service dylib.

Maps eac_service_decoded.dylib at base 0, models its imports (direct binds +
225 lazy stubs), serves a synthetic v1 argument block for the export `_x`
(0x1B664) and traces execution — including the Code Virtualizer region
(0xCC000..0x644000) — without loading the dylib into the host process and
without the game.
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
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30)

IMAGE_LIMIT = 0x660000
CV_START = 0xCC000
CV_END = 0x644000
STACK_BASE = 0x10000000
STACK_SIZE = 0x800000
HEAP_BASE = 0x20000000
HEAP_SIZE = 0x8000000
EXTERNAL_BASE = 0x30000000
EXTERNAL_SIZE = 0x10000
STOP = EXTERNAL_BASE + 0xFFF0
CALLBACK = EXTERNAL_BASE + 0x100
RET = struct.pack("<I", 0xD65F03C0)

X_ENTRY = 0x1B664


def u64(v): return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def p64(b): return struct.unpack("<Q", b)[0]


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


class Harness:
    def __init__(self, path: Path, max_instr: int, entry: int, report: Path | None,
                 trace_report: Path | None, coverage: bool):
        self.data = bytearray(path.read_bytes())
        self.max_instr = max_instr
        self.entry = entry
        self.report = report
        self.trace_report = trace_report
        self.coverage = coverage
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.binds = parse_binds(path)
        self.segs = segments(self.data)
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
        # external symbol slots
        names = sorted(set(self.binds.values()))
        self.ext = {n: EXTERNAL_BASE + 0x2000 + 8 * i for i, n in enumerate(names)}
        for addr, name in self.ext.items():
            self.uc.mem_write(name, RET)
        for got, name in self.binds.items():
            if name == "dyld_stub_binder":
                self.uc.mem_write(got, u64(EXTERNAL_BASE + 0xD00))
                self.uc.mem_write(EXTERNAL_BASE + 0xD00, RET)
                continue
            if name in self.ext:
                self.uc.mem_write(got, u64(self.ext[name]))
        # data symbol defaults
        guard = EXTERNAL_BASE + 0x800
        for sym, addr in self.binds.items():
            n = self.ext.get(addr) if False else None
        for got, name in self.binds.items():
            if name == "___stack_chk_guard":
                self.uc.mem_write(got, u64(EXTERNAL_BASE + 0x900))
                self.uc.mem_write(EXTERNAL_BASE + 0x900, u64(0xA11CE5EED1234567))
            elif name == "_mach_task_self_":
                self.uc.mem_write(got, u64(0x103))
        self.stub_hits = Counter()
        self.stub_args = []
        self.threads = []
        self.pc_hits = Counter()
        self.recent = deque(maxlen=128)
        self.cv_reads = Counter()
        self.cv_writes = Counter()
        self.heap_next = HEAP_BASE + 0x10000
        self.stop_reason = "instruction limit"
        self.fault = None
        self.pcs = [] if trace_report else None
        self._map_args()
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.on_invalid)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    def patch_ldaprb(self):
        patched = 0
        for sname, vm, vs, fo, fl in self.segs:
            if sname == "__LINKEDIT":
                continue
            for off in range(0, fl, 4):
                pc = vm + off
                insn = next(self.cs.disasm(self.data[fo + off:fo + off + 4], pc), None)
                if insn and insn.mnemonic.startswith("ldapr"):
                    m = re.match(r"ldapr([bh]?)(w|x)(\d+), \[(x\d+)\]", insn.mnemonic + " " + insn.op_str)
                    mm = re.match(r"(w|x)(\d+), \[(x\d+)\]$", insn.op_str)
                    if mm:
                        rt, rn = (int(mm.group(2))), (int(mm.group(3)[1:]))
                        size = {"": 3, "b": 0, "h": 1}[m.group(1)] if m else 3
                        sf = 1 if mm.group(1) == "x" else 0
                        enc = (sf << 31) | (0x39 << 24) | (0x40 << 22) | (size << 30) | (rn << 5) | rt
                        self.data[fo + off:fo + off + 4] = struct.pack("<I", enc)
                        self.uc.mem_write(pc, struct.pack("<I", enc))
                        patched += 1
        print(f"ldapr patched: {patched}")

    def scan_lse(self):
        """LSE atomics (casal/ldaddal/...) are unsupported by Unicorn 2.x.
        Collect them and emulate in the code hook (single-threaded)."""
        import re as _re
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
                             _re.match(r"^(cas|swp|ld(add|clr|eor|set|smax|smin|umax|umin|max|min))[ab]*", insn.mnemonic)):
                    self.lse[pc] = (insn.mnemonic, insn.op_str)

    def emulate_lse(self, addr):
        import re as _re
        from unicorn.arm64_const import UC_ARM64_REG_X0
        mnem, ops = self.lse[addr]
        m = _re.match(r"^(\w+?)(b|h)?$", mnem)
        base = m.group(1).rstrip("al")  # drop acquire/release suffix for semantics
        width = {"": None, "b": 1, "h": 2}[m.group(2) or ""]
        regs = [r.strip() for r in ops.split(",")]
        src, dst, mem = regs[0], regs[1], regs[2]
        mreg = _re.match(r"\[(x\d+)\](?:.*)?$", mem)
        rn = int(mreg.group(1)[1:])
        base_addr = self.uc.reg_read(UC_ARM64_REG_X0 + rn)
        # width from src register when not byte/halfword variant
        if width is None:
            width = 8 if src.startswith("x") else 4
        try:
            old = int.from_bytes(self.uc.mem_read(base_addr, width), "little")
        except Exception:
            page = base_addr & ~0xFFF
            try:
                self.uc.mem_map(page, 0x1000)
                self.uc.mem_write(page, bytes(0x1000))
                self.lse_automap_count = getattr(self, "lse_automap_count", 0) + 1
                if self.lse_automap_count <= 20:
                    print(f"[lse-automap] pc={addr:#x} {mnem} {ops} mapped {page:#x} for addr {base_addr:#x}")
                old = int.from_bytes(self.uc.mem_read(base_addr, width), "little")
            except Exception:
                regs_dump = {f"x{i}": hex(self.uc.reg_read(UC_ARM64_REG_X0 + i)) for i in range(31)}
                print(f"[lse-fault] pc={addr:#x} {mnem} {ops} base_addr={base_addr:#x} width={width}")
                print(f"  regs: {regs_dump}")
                self.fault = {"pc": addr, "addr": base_addr, "size": width, "access": "lse-read"}
                self.stop_reason = f"lse fault at {addr:#x} reading {base_addr:#x}"
                self.uc.emu_stop()
                return
        sval = self.uc.reg_read(UC_ARM64_REG_X0 + int(src[1:])) & ((1 << (8 * width)) - 1)
        if base.startswith("cas"):
            if old == sval:
                self.uc.mem_write(base_addr, self.reg(int(regs[1][1:])).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("swp"):
            self.uc.mem_write(base_addr, sval.to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldadd"):
            self.uc.mem_write(base_addr, ((old + sval) & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldset"):
            self.uc.mem_write(base_addr, ((old | sval) & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldeor"):
            self.uc.mem_write(base_addr, ((old ^ sval) & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))
            newdst = old
        elif base.startswith("ldclr"):
            self.uc.mem_write(base_addr, ((old & ~sval) & ((1 << (8 * width)) - 1)).to_bytes(width, "little"))
            newdst = old
        else:
            newdst = old  # min/max variants: leave old, write dst
        self.uc.reg_write(UC_ARM64_REG_X0 + int(regs[1][1:]), newdst)

    def alloc(self, size):
        size = max(1, align(size))
        r = self.heap_next
        self.heap_next += size
        self.uc.mem_write(r, bytes(size))
        return r

    def cstr(self, addr, limit=0x1000):
        out = bytearray()
        for i in range(limit):
            b = self.uc.mem_read(addr + i, 1)[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _va2fo(self, va):
        for name, vm, vs, fo, fl in self.segs:
            if vm <= va < vm + vs:
                off = va - vm
                return fo + off if off < fl else va
        return va

    def _map_args(self):
        # v1 block for _x: ver@0 size@4 flags8=1 cb@0xC ... count@0x18,
        # five inline 0x40 strings from 0x1C
        block = bytearray(0x300)
        struct.pack_into("<I", block, 0, 1)
        struct.pack_into("<I", block, 4, len(block))
        struct.pack_into("<I", block, 8, 1)
        struct.pack_into("<Q", block, 0xC, CALLBACK)
        struct.pack_into("<I", block, 0x18, 5)
        guids = [b"429c2212ad284866aee071454c2125b5",
                 b"ec47bae0651a4765a063c1e83ec41b34",
                 b"76796531e86443548754600511f42e9e",
                 b"local", b"Rust"]
        for i, g in enumerate(guids):
            block[0x1C + i * 0x40:0x1C + i * 0x40 + len(g)] = g
        self.args = self.alloc(0x400)
        self.uc.mem_write(self.args, bytes(block))
        sp = STACK_BASE + STACK_SIZE - 0x2000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X0, self.args)
        self.uc.reg_write(UC_ARM64_REG_X1, len(block))
        self.uc.reg_write(UC_ARM64_REG_X30, STOP)

    # -- models -------------------------------------------------------
    def return_stub(self, value):
        # ext slots contain a single RET; the caller used BL, so returning
        # happens via that RET -- only set the result register here.
        from unicorn.arm64_const import UC_ARM64_REG_X0
        self.uc.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)

    def reg(self, i):
        from unicorn.arm64_const import UC_ARM64_REG_X0
        return self.uc.reg_read(UC_ARM64_REG_X0 + i)

    def handle_stub(self, addr):
        name = next((n for n, a in self.ext.items() if a == addr), hex(addr))
        self.stub_hits[name] += 1
        a0, a1, a2, a3 = self.reg(0), self.reg(1), self.reg(2), self.reg(3)
        if len(self.stub_args) < 2000:
            self.stub_args.append({"name": name, "x0": a0, "x1": a1, "x2": a2})
        if name in ("_malloc", "__Znwm", "__ZnwmRKSt9nothrow_t", "__Znam"):
            n = a0 if name.startswith("__Zn") else a0
            self.return_stub(self.alloc(n))
        elif name in ("_calloc",):
            self.return_stub(self.alloc(a0 * a1))
        elif name in ("_free", "__ZdlPv", "__ZdaPv"):
            self.return_stub(0)
        elif name == "_memcpy" or name == "___memcpy_chk":
            n = a2
            self.uc.mem_write(a0, bytes(self.uc.mem_read(a1, n)) if n else b"")
            self.return_stub(a0)
        elif name in ("_memset", "___memset_chk"):
            self.uc.mem_write(a0, bytes([a1 & 0xFF]) * a2)
            self.return_stub(a0)
        elif name == "_memmove":
            self.uc.mem_write(a0, bytes(self.uc.mem_read(a1, a2)))
            self.return_stub(a0)
        elif name == "_strlen":
            self.return_stub(len(self.cstr(a0)))
        elif name.startswith("_pthread_mutex") or name.startswith("_pthread_cond_wait"):
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
        elif name in ("_close", "_read", "_write", "_fcntl", "_ftruncate"):
            self.return_stub(0)
        elif name == "_mmap":
            self.return_stub(self.alloc(a1))
        elif name == "_mprotect" or name == "_vm_protect":
            self.return_stub(0)
        elif name == "___cxa_guard_acquire":
            guard_val = int.from_bytes(self.uc.mem_read(a0, 8), "little")
            if guard_val == 0:
                self.return_stub(1)
            else:
                self.return_stub(0)
        elif name == "___cxa_guard_release":
            self.uc.mem_write(a0, u64(1))
            self.return_stub(0)
        elif name == "___cxa_guard_abort":
            self.return_stub(0)
        elif name == "_fopen":
            path = self.cstr(a0).decode("utf-8", errors="replace")
            self.fopen_files = getattr(self, "fopen_files", {})
            fd = EXTERNAL_BASE + 0xE00 + len(self.fopen_files) * 8
            self.fopen_files[fd] = path
            self.return_stub(fd)
        elif name == "_fread":
            # fread(buf, size, count, stream) - fill with pseudo-random
            total = a1 * a2
            import hashlib
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
        elif name == "_mach_task_self":
            self.return_stub(0x103)
        elif name == "_mach_host_self":
            self.return_stub(0x205)
        elif name == "_host_get_clock_service":
            # host_get_clock_service(host, clock_id, *clock_serv)
            if a2:
                self.uc.mem_write(a2, u64(0x307))
            self.return_stub(0)
        elif name == "_clock_get_time":
            # clock_get_time(clock_serv, *cur_time) -> mach_timespec {sec, nsec}
            if a1:
                import time
                t = int(time.time())
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
            self.return_stub(1786000000)
        elif name.startswith("_CF") or name.startswith("_IO") or name.startswith("_DA"):
            self.return_stub(0)
        else:
            self.return_stub(0)

    # -- hooks --------------------------------------------------------
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
            # service callback to the game: log code
            code = self.reg(1) if self.reg(1) else 0
            self.stub_hits[f"__callback(code={code})"] += 1
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
        if addr == 0x1003F4:
            x14 = self.reg(14)
            print(f"[diag] 0x1003F4: ldr x2, [x14={x14:#x}]")
            try:
                val = p64(self.uc.mem_read(x14, 8))
                print(f"  [x14] = {val:#x}")
            except:
                print(f"  [x14] = UNMAPPED")
        elif addr == 0x100478:
            x2 = self.reg(2)
            print(f"[diag] 0x100478: br x2={x2:#x}")
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
        raise

    steps = 0

    def on_invalid(self, uc, access, addr, size, value, ud):
        from unicorn.arm64_const import UC_ARM64_REG_X0
        pc = uc.reg_read(UC_ARM64_REG_PC)
        # access 16-23 = fetch; only automap data reads/writes
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
        regs = {f"x{i}": hex(uc.reg_read(UC_ARM64_REG_X0 + i)) for i in range(9)}
        print(f"[invalid] pc={pc:#x} addr={addr:#x} size={size} access={access} {regs}")
        self.stop_reason = f"invalid memory at {addr:#x} from {pc:#x}"
        self.fault = {"pc": pc, "addr": addr, "size": size, "access": access}
        return False

    def on_read(self, uc, access, addr, size, value, ud):
        if CV_START <= addr < CV_END:
            self.cv_reads[(addr, size)] += 1

    def on_write(self, uc, access, addr, size, value, ud):
        if CV_START <= addr < CV_END:
            self.cv_writes[(addr, size)] += 1

    def run(self):
        try:
            self.uc.emu_start(self.entry, STOP, count=self.max_instr)
        except Exception as exc:
            from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X0
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            fo = self._va2fo(pc)
            raw = bytes(self.data[fo:fo+4]) if fo + 4 <= len(self.data) else b"\x00\x00\x00\x00"
            insn = next(self.cs.disasm(raw, pc), None)
            label = f"{insn.mnemonic} {insn.op_str}" if insn else f"?? ({raw.hex()})"
            regs = {f"x{i}": hex(self.uc.reg_read(UC_ARM64_REG_X0 + i)) for i in range(9)}
            print(f"[crash] pc={pc:#x}: {label}")
            print(f"  regs: {regs}")
            self.stop_reason = f"exception: {exc}"
            self.fault = {"pc": pc, "addr": pc, "access": "exec"}
        print(f"steps={self.steps} stop={self.stop_reason}")
        print(f"unique_pcs={len(self.pc_hits)} cv_reads={len(self.cv_reads)} cv_writes={len(self.cv_writes)}")
        print(f"threads={len(self.threads)}")
        if self.fault and self.recent:
            print("last 50 PCs before fault:")
            disasm_list = list(self.recent)[-50:]
            for pc in disasm_list:
                fo = self._va2fo(pc)
                raw = bytes(self.data[fo:fo+4]) if fo + 4 <= len(self.data) else b"\x00\x00\x00\x00"
                insn = next(self.cs.disasm(raw, pc), None)
                if insn:
                    print(f"  {pc:#x}: {insn.mnemonic} {insn.op_str}")
                else:
                    print(f"  {pc:#x}: ?? ({raw.hex()})")
        for t in self.threads:
            print(f"  thread fn={t['fn']:#x} arg={t['arg']:#x}")
        print("stub hits:")
        for n, c in self.stub_hits.most_common(40):
            print(f"  {c:6d} {n}")
        cv_pcs = sum(1 for p in self.pc_hits if CV_START <= p < CV_END)
        print(f"cv pcs executed: {cv_pcs}")
        if self.report:
            out = {
                "entry": hex(self.entry), "steps": self.steps,
                "stop_reason": self.stop_reason,
                "fault": self.fault,
                "unique_pcs": len(self.pc_hits),
                "cv_pcs": cv_pcs,
                "threads": self.threads,
                "stub_hits": dict(self.stub_hits),
                "stub_args": self.stub_args,
                "pcs": [p for p in (self.pcs or [])],
            }
            self.report.write_text(json.dumps(out) + "\n")
            print(f"report={self.report}")
        if self.trace_report and self.pcs is not None:
            self.trace_report.write_text(json.dumps({"pcs": self.pcs}) + "\n")
            print(f"trace={self.trace_report}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module", type=Path)
    ap.add_argument("--max-instructions", type=int, default=5_000_000)
    ap.add_argument("--entry", type=lambda v: int(v, 0), default=X_ENTRY)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--trace-report", type=Path)
    args = ap.parse_args()
    h = Harness(args.module, args.max_instructions, args.entry,
                args.report, args.trace_report, coverage=True)
    h.run()


if __name__ == "__main__":
    main()
