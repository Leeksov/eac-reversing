#!/usr/bin/env python3
"""Local replay oracle for the runtime.conf VM decoder iteration.

Loads a memory/regs snapshot taken at the start of one decode iteration and
re-executes the fixed per-byte window in a private Unicorn instance.  Inputs
(ciphertext bytes and VM state slots) can be patched before each replay,
giving a microsecond-level oracle for the codec without re-running the
launcher flow.
"""
from __future__ import annotations

import pickle
import struct

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP

SNAP = "/tmp/dec_snap.pkl"
WRITE_PC = 0x76B7B8
READ_PC_2 = 0x73E554  # ldrb w17,[x17] : ciphertext fetch (backward)
INPUT_BASE = 0x200119D0  # decoded-output buffer; ciphertext sits at 0x20011BE7


class Oracle:
    def __init__(self, snap_path: str = SNAP):
        d = pickle.loads(open(snap_path, "rb").read())
        self.base_regs = d["regs"]
        self.regions = d["regions"]
        self.start_pc = d["pc"]
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for lo, blob in self.regions.items():
            try:
                self.uc.mem_map(lo, (len(blob) + 0xFFF) & ~0xFFF)
            except Exception:
                pass
            self.uc.mem_write(lo, blob)
        self.regs_idx = {
            name: getattr(__import__("unicorn.arm64_const", fromlist=[f"UC_ARM64_REG_{name.upper()}"]),
                          f"UC_ARM64_REG_{name.upper()}")
            for name in list(self.base_regs)
        }

    def replay(self, patches: dict[int, bytes] | None = None, max_instr: int = 40000) -> dict:
        uc = self.uc
        for lo, blob in self.regions.items():
            uc.mem_write(lo, blob)
        for name, val in self.base_regs.items():
            uc.reg_write(self.regs_idx[name], val)
        for addr, blob in (patches or {}).items():
            uc.mem_write(addr, blob)
        events = {"reads": [], "writes": []}
        state = {"count": 0}

        from unicorn import UC_HOOK_CODE
        import unicorn.arm64_const as A

        def hook(u, address, size, ud):
            state["count"] += 1
            if address == READ_PC_2:
                base = u.reg_read(A.UC_ARM64_REG_X17)
                events["reads"].append((base, u.mem_read(base, 1)[0]))
            elif address == WRITE_PC:
                out = u.reg_read(A.UC_ARM64_REG_X22)
                val = u.reg_read(A.UC_ARM64_REG_X6)
                events["writes"].append((out, val & 0xFF, val))
                if len(events["writes"]) >= 2:
                    u.emu_stop()
            if state["count"] > max_instr:
                u.emu_stop()

        h = uc.hook_add(UC_HOOK_CODE, hook)
        try:
            uc.emu_start(self.start_pc, 0, count=max_instr)
        finally:
            uc.hook_del(h)
        return events


if __name__ == "__main__":
    o = Oracle()
    ev = o.replay()
    print("reads:", [(hex(a), hex(b)) for a, b in ev["reads"][:6]])
    print("writes:", [(hex(a), hex(b), hex(c)) for a, b, c in ev["writes"]])
