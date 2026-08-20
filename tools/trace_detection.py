#!/usr/bin/env python3
"""Detection trigger harness: simulate suspicious conditions and trace EAC responses.

Extends the two-phase harness (_x init -> _y ticks) with scenario-specific
stub overrides that simulate detectable conditions (VM, debugger, SIP,
suspicious processes, input automation, integrity violations).

For each scenario, runs _x + multiple _y ticks and logs:
  - Which stubs are called and with what arguments
  - Whether the callback fires with an error code
  - Which game_error.* identifier maps to the error code
"""

import argparse
import json
import struct
import sys
from collections import Counter, deque, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from service_cv_trace import (
    Harness, STOP, STACK_BASE, STACK_SIZE, HEAP_BASE,
    CV_START, CV_END, EXTERNAL_BASE, RET, CALLBACK,
    u64, p64, align,
)
from trace_y_twophase import TwoPhaseHarness, CAS_LDAXR_ADDRS, CAS_THRESHOLD
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X30,
)

# ── Error code table (from sub_C9F4 in doc 14) ──────────────────────────
ERROR_TABLE = {
    0:  ("(custom/fallback)",                  "Internal anti-cheat error"),
    1:  ("game_error.error_catalogue_not_found", "Easy Anti-Cheat Hash Catalogue not found"),
    2:  ("game_error.error_catalogue_corrupted", "Corrupt Easy Anti-Cheat Hash Catalogue"),
    3:  ("game_error.error_certificate_revoked", "EAC index certificate revoked"),
    4:  ("game_error.error_file_version",        "Unknown file version"),
    5:  ("game_error.error_file_not_found",      "Missing required file"),
    6:  ("game_error.error_file_forbidden",      "Unknown game file"),
    7:  ("game_error.error_system_version",      "Untrusted system file"),
    8:  ("game_error.error_module_forbidden",    "Forbidden module"),
    9:  ("game_error.error_corrupted_memory",    "Corrupted memory"),
    10: ("game_error.error_tool_forbidden",      "Forbidden tool"),
    11: ("game_error.error_violation",           "Internal anti-cheat error"),
    12: ("game_error.error_corrupted_network",   "Corrupted packet flow"),
    13: ("game_error.error_virtual",             "Cannot run under Virtual Machine."),
    14: ("game_error.error_system_configuration","Forbidden system configuration"),
    15: ("game_error.executable_not_hashed",     "Could not locate game executable entry in the catalogue."),
}

# ── Scenario definitions ────────────────────────────────────────────────

SCENARIOS = [
    "baseline",           # 0: no injection -- clean run for comparison
    "debugger_attached",  # 1: sysctl returns P_TRACED
    "vm_detected",        # 2: IOKit returns VM hardware strings
    "sip_disabled",       # 3: csr_get_active_config returns non-zero
    "suspicious_process", # 4: proc_listpids/proc_pidpath return cheat tools
    "input_automation",   # 5: CGEventSource counters mismatch
    "integrity_dladdr",   # 6: dladdr returns wrong module for 0xe6ec
    "hook_detected",      # 7: dladdr returns address in foreign image
]


class DetectionHarness(TwoPhaseHarness):
    """Harness that injects detection-triggering conditions per scenario."""

    def __init__(self, path, max_x, max_y, scenario, num_ticks):
        self.scenario = scenario
        self.num_ticks = num_ticks
        self.callback_log = []       # [{tick, code, game_error, message}]
        self.detection_stubs = defaultdict(list)  # stub_name -> [{tick, args}]
        self.current_tick = -1       # -1 = init phase
        self._hid_counter = 100      # baseline HID event count
        self._combined_counter = 100 # baseline combined event count
        self._pid_list = []          # fake PIDs for process scanning
        self._cheat_paths = {}       # pid -> path for proc_pidpath

        # Pre-configure scenario-specific state
        if scenario == "input_automation":
            # HID count much lower than combined = synthetic input detected
            self._hid_counter = 50
            self._combined_counter = 500
        elif scenario == "suspicious_process":
            self._pid_list = [1001, 1002, 1003, 1004, 1005]
            self._cheat_paths = {
                1001: b"/usr/local/bin/cheatengine",
                1002: b"/Applications/GameGuardian.app/Contents/MacOS/GameGuardian",
                1003: b"/usr/bin/frida-server",
                1004: b"/usr/local/bin/lldb",
                1005: b"/Applications/IDA Pro.app/Contents/MacOS/ida64",
            }

        super().__init__(path, max_x, max_y)

    # ── Stub dispatch (overrides base) ──────────────────────────────────

    def handle_stub(self, addr):
        name = next((n for n, a in self.ext.items() if a == addr), hex(addr))
        self.stub_hits[name] += 1
        a0, a1, a2, a3 = self.reg(0), self.reg(1), self.reg(2), self.reg(3)
        a4, a5 = self.reg(4), self.reg(5)

        if len(self.stub_args) < 5000:
            self.stub_args.append({"name": name, "x0": a0, "x1": a1, "x2": a2})

        # ── Scenario-specific overrides ─────────────────────────────────

        # -- sysctl: debugger detection via P_TRACED ----------------------
        if name == "_sysctl" and self.scenario == "debugger_attached":
            self._handle_sysctl_debugger(a0, a1, a2, a3)
            return

        # -- IOKit: VM detection via hardware strings ---------------------
        if name in ("_IORegistryEntrySearchCFProperty",
                     "_IORegistryEntryCreateCFProperty",
                     "_IOServiceGetMatchingService",
                     "_IOServiceGetMatchingServices") \
                and self.scenario == "vm_detected":
            self._handle_iokit_vm(name, a0, a1, a2, a3)
            return

        # -- DiskArbitration: VM disk detection ---------------------------
        if name in ("_DADiskCopyDescription", "_DADiskCopyIOMedia") \
                and self.scenario == "vm_detected":
            self._handle_da_vm(name, a0)
            return

        # -- csr_get_active_config: SIP disabled --------------------------
        if name == "_csr_get_active_config" and self.scenario == "sip_disabled":
            self._handle_csr_disabled(a0)
            return

        # -- Process scanning: suspicious processes -----------------------
        if name == "_proc_listpids" and self.scenario == "suspicious_process":
            self._handle_proc_listpids(a0, a1, a2, a3)
            return
        if name == "_proc_pidpath" and self.scenario == "suspicious_process":
            self._handle_proc_pidpath(a0, a1, a2)
            return
        if name == "_proc_pidinfo" and self.scenario == "suspicious_process":
            self._handle_proc_pidinfo(a0, a1, a2, a3, a4, a5)
            return

        # -- Input automation: CGEventSource counter mismatch -------------
        if name == "_CGEventSourceCounterForEventType":
            self._handle_cgevent_counter(a0, a1)
            return

        # -- dladdr: integrity / hook detection ---------------------------
        if name == "_dladdr" and self.scenario in ("integrity_dladdr", "hook_detected"):
            self._handle_dladdr_tampered(a0, a1)
            return

        # -- sysctlbyname: VM detection via kern.hv_vmm_present -----------
        if name == "_sysctlbyname" and self.scenario == "vm_detected":
            self._handle_sysctlbyname_vm(a0, a1, a2, a3)
            return

        # ── Default handling (delegate to base for common stubs) ─────────
        self._handle_default(name, a0, a1, a2, a3)

    # ── Scenario stub implementations ───────────────────────────────────

    def _handle_sysctl_debugger(self, name_ptr, namelen, oldp, oldlenp):
        """Make sysctl return P_TRACED (0x800) in kinfo_proc.kp_proc.p_flag."""
        self._log_detection("_sysctl", {
            "name_ptr": name_ptr, "namelen": namelen,
            "oldp": oldp, "oldlenp": oldlenp,
        })
        # Read the MIB to check if this is CTL_KERN/KERN_PROC
        try:
            mib = struct.unpack_from("<II", bytes(self.uc.mem_read(name_ptr, 8)))
        except Exception:
            mib = (0, 0)

        if mib[0] == 1 and mib[1] == 14:  # CTL_KERN=1, KERN_PROC=14
            if oldp:
                # kinfo_proc is ~648 bytes; p_flag is at offset 16 in kp_proc
                # (struct extern_proc: p_un at 0, p_vmspace at 8, p_sigacts at 8,
                #  p_flag at 16)
                # Write a minimal kinfo_proc with P_TRACED set
                buf = bytearray(648)
                # p_flag at offset 16: set P_TRACED (0x800) + normal flags
                struct.pack_into("<I", buf, 16, 0x4004 | 0x800)  # P_TRACED
                # p_pid at offset 72
                struct.pack_into("<I", buf, 72, 4321)
                self.uc.mem_write(oldp, bytes(buf))
                if oldlenp:
                    self.uc.mem_write(oldlenp, struct.pack("<Q", 648))
            self.return_stub(0)
        else:
            # Non-KERN_PROC query: pass through
            self.return_stub(0)

    def _handle_iokit_vm(self, fname, a0, a1, a2, a3):
        """Return VM-identifying hardware properties from IOKit."""
        self._log_detection(fname, {"a0": a0, "a1": a1, "a2": a2})

        if fname == "_IOServiceGetMatchingService":
            # Return a fake IO service handle
            self.return_stub(0xF00D0001)
        elif fname == "_IOServiceGetMatchingServices":
            # Write a fake iterator handle to the output pointer (a2)
            if a2:
                self.uc.mem_write(a2, struct.pack("<I", 0xF00D0002))
            self.return_stub(0)  # KERN_SUCCESS
        elif fname in ("_IORegistryEntrySearchCFProperty",
                        "_IORegistryEntryCreateCFProperty"):
            # Return a CFString-like object containing "VMware" or "VirtualBox"
            # Allocate a fake CFString that contains a VM model identifier
            vm_str = b"VMware Virtual Platform\x00"
            ptr = self.alloc(len(vm_str) + 32)
            # Write a minimal CFString-ish layout:
            # For simplicity, write the raw C string and return a pointer to it.
            # The real code will call CFStringGetCStringPtr or similar.
            self.uc.mem_write(ptr, vm_str)
            self.return_stub(ptr)
        else:
            self.return_stub(0)

    def _handle_da_vm(self, fname, a0):
        """Return VM disk description from DiskArbitration."""
        self._log_detection(fname, {"disk_ref": a0})
        if fname == "_DADiskCopyDescription":
            # Return a fake CFDictionary pointer
            # Real code extracts DAMediaModel -> "VBOX HARDDISK"
            desc = self.alloc(0x100)
            model = b"VBOX HARDDISK\x00"
            self.uc.mem_write(desc, model)
            self.return_stub(desc)
        else:
            self.return_stub(0)

    def _handle_csr_disabled(self, config_ptr):
        """Write non-zero CSR config indicating SIP is disabled."""
        self._log_detection("_csr_get_active_config", {"config_ptr": config_ptr})
        if config_ptr:
            # CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_UNRESTRICTED_FS |
            # CSR_ALLOW_TASK_FOR_PID | CSR_ALLOW_UNRESTRICTED_DTRACE
            csr_flags = 0x01 | 0x02 | 0x04 | 0x20  # = 0x27
            self.uc.mem_write(config_ptr, struct.pack("<I", csr_flags))
        self.return_stub(0)

    def _handle_proc_listpids(self, ptype, typeinfo, buf, bufsize):
        """Return a list of fake PIDs including known cheat tools."""
        self._log_detection("_proc_listpids", {
            "type": ptype, "typeinfo": typeinfo,
            "buf": buf, "bufsize": bufsize,
        })
        if buf and bufsize >= len(self._pid_list) * 4:
            for i, pid in enumerate(self._pid_list):
                self.uc.mem_write(buf + i * 4, struct.pack("<I", pid))
            # Return number of bytes written
            self.return_stub(len(self._pid_list) * 4)
        else:
            self.return_stub(0)

    def _handle_proc_pidpath(self, pid, buf, bufsize):
        """Return cheat tool executable paths for fake PIDs."""
        self._log_detection("_proc_pidpath", {
            "pid": pid, "buf": buf, "bufsize": bufsize,
        })
        path = self._cheat_paths.get(pid, b"/usr/bin/unknown\x00")
        if not path.endswith(b"\x00"):
            path += b"\x00"
        if buf and bufsize >= len(path):
            self.uc.mem_write(buf, path)
            self.return_stub(len(path) - 1)  # return strlen
        else:
            self.return_stub(-1)

    def _handle_proc_pidinfo(self, pid, flavor, arg, buf, bufsize, retsize):
        """Return basic proc info for fake PIDs."""
        self._log_detection("_proc_pidinfo", {
            "pid": pid, "flavor": flavor, "buf": buf, "bufsize": bufsize,
        })
        if buf and bufsize >= 8:
            # Write minimal proc_bsdinfo-like data
            self.uc.mem_write(buf, struct.pack("<II", 0, pid))
        self.return_stub(bufsize if bufsize else 0)

    def _handle_cgevent_counter(self, state_id, event_type):
        """Return mismatched event counters for input automation detection.

        stateID: 0=private, 1=combined, 2=HID
        When HID count << combined count, synthetic input is detected.
        """
        self._log_detection("_CGEventSourceCounterForEventType", {
            "stateID": state_id, "eventType": event_type,
        })
        if self.scenario == "input_automation":
            if state_id == 2:  # kCGEventSourceStateHIDSystem
                self.return_stub(self._hid_counter)
            else:  # combined or private
                self.return_stub(self._combined_counter)
        else:
            # Baseline: same count for both
            self.return_stub(100)

    def _handle_dladdr_tampered(self, addr, info_ptr):
        """Return dladdr results indicating a hooked or relocated function."""
        self._log_detection("_dladdr", {"addr": addr, "info_ptr": info_ptr})

        if info_ptr:
            # Dl_info: {dli_fname, dli_fbase, dli_sname, dli_saddr}
            if self.scenario == "integrity_dladdr":
                # Wrong module: point to a different library name
                fname = self.alloc(64)
                self.uc.mem_write(fname, b"/usr/lib/libevil.dylib\x00")
                sname = self.alloc(32)
                self.uc.mem_write(sname, b"_evil_func\x00")
                struct.pack_into("<Q", dl := bytearray(32), 0, fname)
                struct.pack_into("<Q", dl, 8, 0xDEAD0000)   # wrong base
                struct.pack_into("<Q", dl, 16, sname)
                struct.pack_into("<Q", dl, 24, addr)
                self.uc.mem_write(info_ptr, bytes(dl))
            elif self.scenario == "hook_detected":
                # Correct module name but wrong base address (hook trampoline)
                fname = self.alloc(128)
                self.uc.mem_write(fname,
                    b"/Library/Application Support/EasyAntiCheat/"
                    b"eac_service_decoded.dylib\x00")
                sname = self.alloc(32)
                self.uc.mem_write(sname, b"_x\x00")
                dl = bytearray(32)
                struct.pack_into("<Q", dl, 0, fname)
                struct.pack_into("<Q", dl, 8, 0xBAAD0000)  # wrong base
                struct.pack_into("<Q", dl, 16, sname)
                struct.pack_into("<Q", dl, 24, 0xBAADE6EC)  # addr in foreign image
                self.uc.mem_write(info_ptr, bytes(dl))

        self.return_stub(1)  # 1 = success (symbol found)

    def _handle_sysctlbyname_vm(self, name_ptr, oldp_ptr, oldlenp, newp, newlen):
        """Make sysctlbyname return 1 for kern.hv_vmm_present."""
        try:
            name = self.cstr(name_ptr).decode("utf-8", errors="replace")
        except Exception:
            name = "?"
        self._log_detection("_sysctlbyname", {"name": name, "oldp": oldp_ptr})

        if "hv_vmm_present" in name:
            if oldp_ptr:
                self.uc.mem_write(oldp_ptr, struct.pack("<I", 1))
            if oldlenp:
                self.uc.mem_write(oldlenp, struct.pack("<Q", 4))
            self.return_stub(0)
        elif "hw.model" in name:
            if oldp_ptr:
                model = b"VMware7,1\x00"
                self.uc.mem_write(oldp_ptr, model)
            if oldlenp:
                self.uc.mem_write(oldlenp, struct.pack("<Q", 10))
            self.return_stub(0)
        else:
            self.return_stub(0)

    # ── Default stub handler (same as base with logging) ────────────────

    def _handle_default(self, name, a0, a1, a2, a3):
        """Delegate to base harness for non-scenario stubs."""
        if name in ("_malloc", "__Znwm", "__ZnwmRKSt9nothrow_t", "__Znam"):
            self.return_stub(self.alloc(a0))
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
            self.return_stub(1 if guard_val == 0 else 0)
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
        elif name == "_dladdr":
            # Default dladdr: return valid Dl_info for our binary
            if a1:
                fname = self.alloc(128)
                self.uc.mem_write(fname, b"eac_service_decoded.dylib\x00")
                sname = self.alloc(32)
                self.uc.mem_write(sname, b"_unknown\x00")
                dl = bytearray(32)
                struct.pack_into("<Q", dl, 0, fname)   # dli_fname
                struct.pack_into("<Q", dl, 8, 0)       # dli_fbase = image base
                struct.pack_into("<Q", dl, 16, sname)   # dli_sname
                struct.pack_into("<Q", dl, 24, a0)      # dli_saddr
                self.uc.mem_write(a1, bytes(dl))
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
        elif name == "_CGEventSourceCounterForEventType":
            # Baseline: return consistent counts
            self.return_stub(100)
        elif name == "_proc_listpids":
            # Baseline: no processes found
            self.return_stub(0)
        elif name == "_proc_pidpath":
            self.return_stub(0)
        elif name == "_proc_pidinfo":
            self.return_stub(0)
        elif name.startswith("_CF") or name.startswith("_IO") or name.startswith("_DA"):
            self.return_stub(0)
        else:
            self.return_stub(0)

    # ── Callback interception ───────────────────────────────────────────

    def on_code(self, uc, addr, size, ud):
        """Override to intercept callback with error code logging."""
        if addr == CALLBACK:
            code = self.reg(1)
            error_id, message = ERROR_TABLE.get(code, (f"unknown_{code}", "?"))
            entry = {
                "tick": self.current_tick,
                "code": code,
                "game_error": error_id,
                "message": message,
            }
            self.callback_log.append(entry)
            print(f"  [CALLBACK] tick={self.current_tick} code={code} "
                  f"-> {error_id}: {message}")
            self.stub_hits[f"__callback(code={code})"] += 1
            self.return_stub(0)
            return
        super().on_code(uc, addr, size, ud)

    # ── Logging helpers ─────────────────────────────────────────────────

    def _log_detection(self, stub_name, args):
        """Record a detection-relevant stub call."""
        entry = {"tick": self.current_tick, **{k: hex(v) if isinstance(v, int) else v
                                                for k, v in args.items()}}
        self.detection_stubs[stub_name].append(entry)
        if len(self.detection_stubs[stub_name]) <= 10:
            print(f"  [DETECT-STUB] {stub_name} tick={self.current_tick} "
                  f"{', '.join(f'{k}={v}' for k, v in args.items() if k != 'tick')}")

    # ── Multi-tick runner ───────────────────────────────────────────────

    def run_scenario(self):
        """Run _x init + num_ticks _y calls, collecting detection events."""
        print("=" * 72)
        print(f"SCENARIO: {self.scenario}")
        print(f"  ticks: {self.num_ticks}, max_x: {self.max_instr}, max_y: {self.max_y}")
        print("=" * 72)

        # Phase 1: _x init (detection stubs active but no triggers expected)
        print(f"\n--- Phase 1: _x initialization ---")
        self.current_tick = -1
        self.phase = 1
        self.run()
        ctx = int.from_bytes(self.uc.mem_read(0xC1278, 8), "little")
        print(f"  Context pointer: {ctx:#x}")
        if ctx == 0:
            print("ERROR: Context not initialized, aborting scenario")
            return self._build_report()

        init_stubs = dict(self.stub_hits)
        init_callbacks = list(self.callback_log)
        print(f"  Init stubs: {len(init_stubs)}, callbacks: {len(init_callbacks)}")
        if init_callbacks:
            for cb in init_callbacks:
                print(f"    code={cb['code']} -> {cb['game_error']}")

        # Phase 2: _y ticks
        tick_results = []
        for tick in range(self.num_ticks):
            self.current_tick = tick
            print(f"\n--- Tick {tick} ---")

            # Reset per-tick counters
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
            self._cas_log_limit = 10

            # Fresh stack
            sp = STACK_BASE + STACK_SIZE - 0x4000
            self.uc.reg_write(UC_ARM64_REG_SP, sp)
            self.uc.reg_write(UC_ARM64_REG_X30, STOP)

            # x0 = context pointer (loaded by _y's first BL to 0x109fc)
            # The function loads it from 0xC1278 itself, so no need to set x0

            try:
                self.uc.emu_start(0x1B744, STOP, count=0)
            except Exception as exc:
                pc = self.uc.reg_read(UC_ARM64_REG_PC)
                print(f"  Exception at pc={pc:#x}: {exc}")
                self.stop_reason = f"exception: {exc}"

            final_pc = self.uc.reg_read(UC_ARM64_REG_PC)
            if final_pc == STOP and self.stop_reason == "instruction limit":
                self.stop_reason = "returned from entry"

            tick_result = {
                "tick": tick,
                "steps": self.steps,
                "stop_reason": self.stop_reason,
                "stubs": dict(self.stub_hits),
                "callbacks_this_tick": [
                    cb for cb in self.callback_log if cb["tick"] == tick
                ],
            }
            tick_results.append(tick_result)

            print(f"  steps={self.steps} stop={self.stop_reason}")
            print(f"  stubs: {dict(self.stub_hits.most_common(10))}")

            # Check for early termination on detection
            tick_cbs = tick_result["callbacks_this_tick"]
            if tick_cbs:
                print(f"  ** DETECTION TRIGGERED: {len(tick_cbs)} callback(s) **")
                for cb in tick_cbs:
                    print(f"     code={cb['code']} {cb['game_error']}: {cb['message']}")

        return self._build_report(init_stubs, tick_results)

    def _build_report(self, init_stubs=None, tick_results=None):
        report = {
            "scenario": self.scenario,
            "num_ticks": self.num_ticks,
            "callbacks": self.callback_log,
            "detection_stubs": {k: v for k, v in self.detection_stubs.items()},
            "init_stubs": init_stubs or {},
            "tick_results": tick_results or [],
        }
        return report


# ── Main ────────────────────────────────────────────────────────────────

def run_all_scenarios(module_path, max_x, max_y, num_ticks, scenarios, output):
    """Run selected scenarios and collect results."""
    all_results = {}

    for scenario in scenarios:
        print(f"\n{'#' * 72}")
        print(f"# Starting scenario: {scenario}")
        print(f"{'#' * 72}\n")

        h = DetectionHarness(module_path, max_x, max_y, scenario, num_ticks)
        report = h.run_scenario()
        all_results[scenario] = report

        # Summary
        cbs = report.get("callbacks", [])
        print(f"\n>>> SCENARIO SUMMARY: {scenario}")
        print(f"    Total callbacks: {len(cbs)}")
        if cbs:
            for cb in cbs:
                print(f"    tick={cb['tick']} code={cb['code']} "
                      f"{cb['game_error']}: {cb['message']}")
        else:
            print("    No detection triggered")

        det_stubs = report.get("detection_stubs", {})
        if det_stubs:
            print(f"    Detection stubs called: {list(det_stubs.keys())}")

        print()

    # Save combined report
    if output:
        out_path = Path(output)
        out_path.write_text(json.dumps(all_results, indent=2, default=str) + "\n")
        print(f"\nCombined report saved to: {out_path}")

    # Print summary table
    print("\n" + "=" * 90)
    print("DETECTION TRIGGER SUMMARY")
    print("=" * 90)
    print(f"{'Scenario':<22} {'Triggered':<10} {'Code':<6} {'game_error.*':<42} {'Message'}")
    print("-" * 90)
    for scenario in scenarios:
        r = all_results.get(scenario, {})
        cbs = r.get("callbacks", [])
        if not cbs:
            print(f"{scenario:<22} {'No':<10} {'-':<6} {'-':<42} -")
        else:
            for i, cb in enumerate(cbs):
                label = scenario if i == 0 else ""
                print(f"{label:<22} {'YES':<10} {cb['code']:<6} "
                      f"{cb['game_error']:<42} {cb['message']}")
    print("=" * 90)

    return all_results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Trace EAC detection mechanisms by simulating suspicious conditions"
    )
    ap.add_argument("module", type=Path,
                    help="Path to eac_service_decoded.dylib")
    ap.add_argument("--max-x", type=int, default=8_000_000,
                    help="Max instructions for _x init (default: 8M)")
    ap.add_argument("--max-y", type=int, default=500_000,
                    help="Max instructions per _y tick (default: 500K)")
    ap.add_argument("--ticks", type=int, default=3,
                    help="Number of _y ticks per scenario (default: 3)")
    ap.add_argument("--scenario", type=str, default="all",
                    choices=SCENARIOS + ["all"],
                    help="Scenario to run (default: all)")
    ap.add_argument("--output", type=str,
                    default="/tmp/detection_trace_report.json",
                    help="Output JSON report path")
    args = ap.parse_args()

    if args.scenario == "all":
        scenarios = SCENARIOS
    else:
        scenarios = [args.scenario]

    run_all_scenarios(args.module, args.max_x, args.max_y,
                      args.ticks, scenarios, args.output)
