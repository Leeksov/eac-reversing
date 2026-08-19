#!/usr/bin/env python3
"""Two-phase harness: run _x to init, then trace _y (stop/shutdown).

Handles CAS spin loops by forcing success after a threshold.
"""
import json
import struct
import sys
from collections import Counter, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from service_cv_trace import (Harness, STOP, STACK_BASE, STACK_SIZE,
                               CV_START, CV_END, EXTERNAL_BASE, RET, u64, p64)
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X30)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


# All ldaxr w12, [x9] sites in the CV region (CAS loops)
CAS_LDAXR_ADDRS = {
    0x1CD6F4, 0x1D80C8, 0x1D9F5C, 0x1DB984, 0x1DD9E4, 0x1DFBD8,
    0x1E27D0, 0x1E4B88, 0x1E6394, 0x1E8F24, 0x1EA640, 0x1EC4CC,
    0x1EF3BC, 0x1F4C24, 0x22278C, 0x22644C,
}
CAS_THRESHOLD = 5  # force success after this many spins per (addr, target, expected)


class TwoPhaseHarness(Harness):
    """Extend the base harness for two-phase _x then _y execution."""

    def __init__(self, path, max_x, max_y):
        self.max_y = max_y
        self.cas_spins = Counter()
        self.cas_forces = []
        self.phase = 1
        self._cas_log_limit = 50
        super().__init__(path, max_x, entry=0x1B664, report=None,
                         trace_report=None, coverage=False)

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
                except:
                    cur = -1
                print(f"[CAS] pc={addr:#x} addr=[x9={x9:#x}] cur={cur:#x} "
                      f"expected(w8)={x8 & 0xFFFFFFFF:#x} new(w3)={x3 & 0xFFFFFFFF:#x}")
            if self.cas_spins[key] >= CAS_THRESHOLD:
                uc.mem_write(x9, struct.pack("<I", x8 & 0xFFFFFFFF))
                self.cas_forces.append({
                    "pc": addr, "target_addr": x9,
                    "old_expected": x8 & 0xFFFFFFFF,
                    "new_val": x3 & 0xFFFFFFFF,
                    "spins": self.cas_spins[key]
                })
                if len(self.cas_forces) <= 50:
                    print(f"  -> forced CAS #{len(self.cas_forces)} at pc={addr:#x} "
                          f"[{x9:#x}]: {x8 & 0xFFFFFFFF:#x} -> {x3 & 0xFFFFFFFF:#x}")
                self.cas_spins[key] = 0
        super().on_code(uc, addr, size, ud)

    def run_two_phase(self):
        # Phase 1: Run _x
        print("=" * 60)
        print("Phase 1: Running _x (0x1B664) to initialize context")
        print("=" * 60)
        self.phase = 1
        self.run()
        ctx = int.from_bytes(self.uc.mem_read(0xC1278, 8), "little")
        print(f"\nContext pointer at 0xC1278 = {ctx:#x}")
        if ctx == 0:
            print("ERROR: Context not initialized")
            return None

        # Dump context
        print("\nContext structure (non-zero fields in first 0x200 bytes):")
        region = self.uc.mem_read(ctx, 0x200)
        for i in range(0, 0x200, 8):
            qw = struct.unpack_from("<Q", bytes(region), i)[0]
            if qw:
                print(f"  +{i:03x}: {qw:#018x}")

        # Phase 2: Run _y
        print()
        print("=" * 60)
        print("Phase 2: Running _y (0x1B744) with initialized context")
        print("=" * 60)
        self.phase = 2
        self.stub_hits = Counter()
        self.stub_args = []
        self.threads = []
        self.pc_hits = Counter()
        self.recent = deque(maxlen=512)
        self.steps = 0
        self.stop_reason = "instruction limit"
        self.fault = None
        self.max_instr = self.max_y
        self.cas_spins = Counter()
        self._cas_log_limit = 50

        # Fresh stack
        sp = STACK_BASE + STACK_SIZE - 0x4000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        self.uc.reg_write(UC_ARM64_REG_X30, STOP)

        try:
            self.uc.emu_start(0x1B744, STOP, count=0)
        except Exception as exc:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            print(f"Exception at pc={pc:#x}: {exc}")
            self.stop_reason = f"exception: {exc}"

        # Check if we stopped because PC reached STOP (emu_start until= semantics)
        final_pc = self.uc.reg_read(UC_ARM64_REG_PC)
        if final_pc == STOP and self.stop_reason == "instruction limit":
            self.stop_reason = "returned from entry"
            print(f"[info] PC={final_pc:#x} == STOP, _y returned normally!")

        # Report
        print(f"\nsteps={self.steps}  stop={self.stop_reason}")
        print(f"unique_pcs={len(self.pc_hits)}")

        non_cv = {p: c for p, c in self.pc_hits.items()
                  if not (CV_START <= p < CV_END)}
        cv = {p: c for p, c in self.pc_hits.items()
              if CV_START <= p < CV_END}
        print(f"native PCs: {len(non_cv)}  CV PCs: {len(cv)}")

        if self.fault and self.recent:
            print(f"\nFault: {self.fault}")
            print("Last 60 PCs:")
            cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            for pc in list(self.recent)[-60:]:
                fo = self._va2fo(pc)
                raw = bytes(self.data[fo:fo + 4])
                insn = next(cs.disasm(raw, pc), None)
                lbl = f"{insn.mnemonic} {insn.op_str}" if insn else f"?? ({raw.hex()})"
                tag = "CV" if CV_START <= pc < CV_END else ""
                print(f"  {pc:#x}: {lbl} {tag}")

        if self.stop_reason == "returned from entry":
            print("\n*** _y returned successfully ***")

        print("\nstub hits:")
        for n, c in self.stub_hits.most_common(50):
            print(f"  {c:6d}  {n}")

        if self.stub_args:
            print(f"\nstub_args ({len(self.stub_args)} total):")
            for sa in self.stub_args[:200]:
                print(f"  {sa['name']:40s}  x0={sa['x0']:#x}  x1={sa['x1']:#x}  x2={sa['x2']:#x}")

        if self.threads:
            print(f"\nthreads spawned: {len(self.threads)}")
            for t in self.threads:
                print(f"  fn={t['fn']:#x}  arg={t['arg']:#x}")

        print(f"\nCAS forces: {len(self.cas_forces)}")
        for cf in self.cas_forces[:30]:
            print(f"  pc={cf['pc']:#x} [{cf['target_addr']:#x}]: "
                  f"expected={cf['old_expected']:#x} -> new={cf['new_val']:#x} "
                  f"(after {cf['spins']} spins)")

        # Check context after
        ctx_after = int.from_bytes(self.uc.mem_read(0xC1278, 8), "little")
        print(f"\nContext pointer after _y: {ctx_after:#x}")
        if ctx_after:
            region_after = self.uc.mem_read(ctx_after, 0x200)
            print("Context after (non-zero fields):")
            for i in range(0, 0x200, 8):
                qw = struct.unpack_from("<Q", bytes(region_after), i)[0]
                if qw:
                    print(f"  +{i:03x}: {qw:#018x}")

        # Save report
        report = {
            "entry": "0x1b744", "steps": self.steps,
            "stop_reason": self.stop_reason, "fault": self.fault,
            "unique_pcs": len(self.pc_hits),
            "native_pcs": len(non_cv), "cv_pcs": len(cv),
            "threads": self.threads,
            "stub_hits": dict(self.stub_hits),
            "stub_args": self.stub_args,
            "cas_forces": self.cas_forces,
            "context_ptr": hex(ctx),
        }
        rpt = Path("/tmp/svc_y_twophase_report.json")
        rpt.write_text(json.dumps(report, default=str) + "\n")
        print(f"\nReport: {rpt}")
        return report


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("module", type=Path)
    ap.add_argument("--max-x", type=int, default=5_000_000)
    ap.add_argument("--max-y", type=int, default=5_000_000)
    args = ap.parse_args()

    h = TwoPhaseHarness(args.module, args.max_x, args.max_y)
    h.run_two_phase()
