#!/usr/bin/env python3
"""Offline ARM64 trace harness for the decoded EAC Code Virtualizer module.

This maps the Mach-O at its preferred base (0), supplies a synthetic version-2
launcher argument block, intercepts imported stubs, and starts at sub_420C --
the native wrapper immediately before the __CV dispatcher.

It never loads the dylib into the host process and never starts the game.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
from collections import Counter, deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_WRITE, UC_MODE_ARM
from unicorn.arm64_const import *


IMAGE_LIMIT = 0x940000
CV_START = 0x6D0000
CV_EXEC_START = 0x6D8000
CV_END = 0x920000
DEFAULT_ENTRY = 0x35E0
OBJECT = 0x6CC5B0
VTABLE = 0x6C40A8
STACK_BASE = 0x10000000
STACK_SIZE = 0x400000
HEAP_BASE = 0x20000000
HEAP_SIZE = 0x4000000
EXTERNAL_BASE = 0x30000000
EXTERNAL_SIZE = 0x10000
STOP_ADDRESS = EXTERNAL_BASE + 0xFFF0
CALLBACK_ADDRESS = EXTERNAL_BASE + 0x100
MOD_INIT_FUNCTIONS = (0x553C, 0x4CDD4, 0x5322C, 0x53288)


def u64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def p64(data: bytes) -> int:
    return struct.unpack("<Q", data)[0]


def align(value: int, alignment: int = 0x10) -> int:
    return (value + alignment - 1) & -alignment


def parse_stub_symbols(path: Path) -> dict[int, str]:
    output = subprocess.run(
        ["otool", "-Iv", str(path)], check=True, text=True, capture_output=True
    ).stdout
    symbols: dict[int, str] = {}
    in_stubs = False
    for line in output.splitlines():
        if line.startswith("Indirect symbols for "):
            in_stubs = "(__TEXT,__stubs)" in line
            continue
        if not in_stubs:
            continue
        match = re.match(r"0x([0-9a-fA-F]+)\s+\d+\s+(\S+)", line.strip())
        if match:
            symbols[int(match.group(1), 16)] = match.group(2)
    return symbols


def parse_bound_symbols(path: Path) -> dict[int, str]:
    output = subprocess.run(
        ["dyld_info", "-fixups", str(path)],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    symbols: dict[int, str] = {}
    pattern = re.compile(
        r"\s0x([0-9a-fA-F]+)\s+(?:lazy-)?bind\s+\S+/(\S+)\s*$"
    )
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            symbols[int(match.group(1), 16)] = match.group(2)
    return symbols


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def macho_rebase_targets(data: bytes) -> list[int]:
    """Decode LC_DYLD_INFO_ONLY rebase opcodes into preferred VM addresses."""
    _, _, _, _, command_count, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
    command_offset = 32
    segments: list[tuple[int, int]] = []
    rebase_offset = rebase_size = 0
    for _ in range(command_count):
        command, command_size = struct.unpack_from("<II", data, command_offset)
        if command == 0x19:  # LC_SEGMENT_64
            vm_address, vm_size = struct.unpack_from("<QQ", data, command_offset + 24)
            segments.append((vm_address, vm_size))
        elif command == 0x80000022:  # LC_DYLD_INFO_ONLY
            rebase_offset, rebase_size = struct.unpack_from(
                "<II", data, command_offset + 8
            )
        command_offset += command_size

    stream = data[rebase_offset : rebase_offset + rebase_size]
    cursor = 0
    segment_index = 0
    segment_offset = 0
    targets: list[int] = []

    def append_target() -> None:
        targets.append(segments[segment_index][0] + segment_offset)

    while cursor < len(stream):
        byte = stream[cursor]
        cursor += 1
        opcode, immediate = byte & 0xF0, byte & 0x0F
        if opcode == 0x00:  # DONE
            break
        if opcode == 0x10:  # SET_TYPE_IMM
            continue
        if opcode == 0x20:  # SET_SEGMENT_AND_OFFSET_ULEB
            segment_index = immediate
            segment_offset, cursor = read_uleb128(stream, cursor)
        elif opcode == 0x30:  # ADD_ADDR_ULEB
            delta, cursor = read_uleb128(stream, cursor)
            segment_offset += delta
        elif opcode == 0x40:  # ADD_ADDR_IMM_SCALED
            segment_offset += immediate * 8
        elif opcode == 0x50:  # DO_REBASE_IMM_TIMES
            for _ in range(immediate):
                append_target()
                segment_offset += 8
        elif opcode == 0x60:  # DO_REBASE_ULEB_TIMES
            count, cursor = read_uleb128(stream, cursor)
            for _ in range(count):
                append_target()
                segment_offset += 8
        elif opcode == 0x70:  # DO_REBASE_ADD_ADDR_ULEB
            append_target()
            delta, cursor = read_uleb128(stream, cursor)
            segment_offset += 8 + delta
        elif opcode == 0x80:  # DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            count, cursor = read_uleb128(stream, cursor)
            skip, cursor = read_uleb128(stream, cursor)
            for _ in range(count):
                append_target()
                segment_offset += 8 + skip
        else:
            raise ValueError(f"unsupported Mach-O rebase opcode {byte:#x}")
    return targets


class Harness:
    def __init__(
        self,
        path: Path,
        max_instructions: int,
        fork_child: bool,
        entry: int,
        verbose: bool,
        report: Path | None,
        flag_present: bool,
        flag_content: str,
        sysctl_p_flag: int,
        sysctl_result: int,
        register_overrides: dict[int, int],
        memory_overrides: list[tuple[int, bytes]],
        virtual_files: dict[str, bytes],
        open_result: int,
        dlopen_result: int,
        trace_report: Path | None,
        image_base: int,
        target_executable: str,
        process_executable: str,
        game_args: list[str],
        coverage_report: Path | None,
        effects_report: Path | None,
        memory_dumps: list[tuple[int, int]],
    ):
        self.path = path
        self.data = bytearray(path.read_bytes())
        self.max_instructions = max_instructions
        self.fork_child = fork_child
        self.entry = entry
        self.verbose = verbose
        self.report = report
        self.flag_present = flag_present
        self.flag_content = flag_content.encode()
        self.open_files: dict[int, bytes] = {}
        self.sysctl_p_flag = sysctl_p_flag
        self.sysctl_result = sysctl_result
        self.register_overrides = register_overrides
        self.memory_overrides = memory_overrides
        self.virtual_files = virtual_files
        self.file_streams: dict[int, dict[str, object]] = {}
        self.open_result = open_result
        self.dlopen_result = dlopen_result
        self.trace_report = trace_report
        self.pc_trace: list[int] = []
        self.image_base = image_base
        self.target_executable_text = target_executable
        self.process_executable_text = process_executable
        self.game_args = game_args
        self.coverage_report = coverage_report
        self.effects_report = effects_report
        self.memory_dumps = memory_dumps
        if image_base:
            for target in macho_rebase_targets(self.data):
                value = p64(self.data[target : target + 8])
                self.data[target : target + 8] = u64(value + image_base)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.stubs = {
            image_base + address: name
            for address, name in parse_stub_symbols(path).items()
        }
        self.bound_symbols = parse_bound_symbols(path)
        external_names = sorted(
            set(self.bound_symbols.values())
            - {"___stack_chk_guard", "_mach_task_self_"}
        )
        self.external_symbols = {
            EXTERNAL_BASE + 0x1000 + index * 4: name
            for index, name in enumerate(external_names)
        }
        self.external_addresses = {
            name: address for address, name in self.external_symbols.items()
        }
        self.stubs.update(self.external_symbols)
        self.stub_hits: Counter[str] = Counter()
        self.pc_hits: Counter[int] = Counter()
        self.recent_pcs: deque[int] = deque(maxlen=256)
        self.cv_writes: list[tuple[int, int, int]] = []
        self.last_cv_writes: dict[int, tuple[int, int, int]] = {}
        self.last_stack_writes: dict[int, tuple[int, int, int]] = {}
        self.slot_6d0160_events: list[tuple[int, int, int]] = []
        self.last_slot_context: list[int] = []
        self.callback_events: list[dict[str, object]] = []
        self.close_candidates: set[int] | None = None
        self.close_candidate_widths: dict[int, int] = {}
        self.environment: dict[str, str] = {}
        self.exec_events: list[dict[str, object]] = []
        self.ipc_events: list[dict[str, object]] = []
        self.edge_hits: Counter[tuple[int, int]] = Counter()
        self.write_sites: Counter[tuple[int, str, int]] = Counter()
        self.read_effects: Counter[tuple[int, str, int, int]] = Counter()
        self.write_effects: Counter[tuple[int, str, int, int]] = Counter()
        self.write_effect_values: dict[tuple[int, str, int, int], int] = {}
        self.effect_contexts: dict[tuple[int, str, int, int], dict[str, object]] = {}
        self.boundary_states: dict[tuple[int, int], dict[str, object]] = {}
        self.boundary_events: list[dict[str, object]] = []
        self.cv_byte_reads: list[dict[str, int]] = []
        self.decoder_trace = True
        self.decoder_events: list[dict[str, int]] = []
        self.iter_capture: list[dict[str, int]] = []
        self.iter_countdown: int | None = None
        self.steps = 0
        self.previous_pc: int | None = None
        self.callouts: list[tuple[int, int, int, int, int]] = []
        self.heap_next = HEAP_BASE + 0x10000
        self.iconv_next = 0x40000000
        self.iconv_descriptors: dict[int, tuple[str, str]] = {}
        self.stop_reason = "instruction limit"
        self._map_memory()
        self._make_arguments()

    def ia(self, preferred_address: int) -> int:
        return self.image_base + preferred_address

    def _map_memory(self) -> None:
        self.uc.mem_map(self.image_base, IMAGE_LIMIT)
        self.uc.mem_write(self.image_base, bytes(self.data))
        # Unicorn 2.1 does not implement LDAPRB. Atomic ordering is irrelevant
        # in this single-threaded harness, so replace it with LDRB w8, [x8].
        self.uc.mem_write(self.ia(0x3648), struct.pack("<I", 0x39400108))
        self.uc.mem_write(self.ia(0x55338), struct.pack("<I", 0x3940010C))
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)
        self.uc.mem_map(EXTERNAL_BASE, EXTERNAL_SIZE)

        for target, name in self.bound_symbols.items():
            if name in {"___stack_chk_guard", "_mach_task_self_"}:
                continue
            self.uc.mem_write(
                self.ia(target), u64(self.external_addresses[name])
            )

        # RET at callback and stop sentinels.
        ret = struct.pack("<I", 0xD65F03C0)
        self.uc.mem_write(CALLBACK_ADDRESS, ret)
        self.uc.mem_write(STOP_ADDRESS, ret)

        # BSS is zero-filled by dyld.  sub_3634 installs the vtable and runs the
        # real singleton constructor once its guard is acquired.
        self.uc.mem_write(self.ia(OBJECT), bytes(0x108))

        # Non-lazy GOT entries used by the wrapper.
        stack_guard_ptr = EXTERNAL_BASE + 0x800
        self.uc.mem_write(self.ia(0x6C4018), u64(stack_guard_ptr))
        self.uc.mem_write(stack_guard_ptr, u64(0xA11CE5EED1234567))
        self.uc.mem_write(self.ia(0x6C4020), u64(EXTERNAL_BASE + 0x808))
        self.uc.mem_write(EXTERNAL_BASE + 0x808, struct.pack("<I", 1))

    def alloc(self, size: int) -> int:
        size = max(1, align(size))
        result = self.heap_next
        self.heap_next += size
        if self.heap_next >= HEAP_BASE + HEAP_SIZE:
            raise RuntimeError("synthetic heap exhausted")
        self.uc.mem_write(result, bytes(size))
        return result

    def put_cstr(self, value: str) -> int:
        raw = value.encode() + b"\0"
        address = self.alloc(len(raw))
        self.uc.mem_write(address, raw)
        return address

    def read_cstr(self, address: int, limit: int = 0x4000) -> bytes:
        if address == 0:
            return b""
        out = bytearray()
        for offset in range(limit):
            byte = self.uc.mem_read(address + offset, 1)[0]
            if byte == 0:
                break
            out.append(byte)
        return bytes(out)

    def _make_arguments(self) -> None:
        product = self.put_cstr("429c2212ad284866aee071454c2125b5")
        sandbox = self.put_cstr("ec47bae0651a4765a063c1e83ec41b34")
        deployment = self.put_cstr("76796531e86443548754600511f42e9e")
        executable = self.put_cstr(self.target_executable_text)
        argv = self.alloc((len(self.game_args) + 1) * 8)
        argument_pointers = [self.put_cstr(value) for value in self.game_args]
        self.uc.mem_write(
            argv, b"".join(u64(pointer) for pointer in argument_pointers) + u64(0)
        )

        self.args = self.alloc(0x80)
        block = bytearray(0x80)
        struct.pack_into("<I", block, 0, 2)
        # v2 ABI: offset 8 is reserved; offset 16 is the callback context.
        struct.pack_into("<Q", block, 16, HEAP_BASE + 0x800)
        struct.pack_into("<Q", block, 24, product)
        struct.pack_into("<Q", block, 32, sandbox)
        struct.pack_into("<Q", block, 40, deployment)
        struct.pack_into("<Q", block, 48, CALLBACK_ADDRESS)
        struct.pack_into("<Q", block, 56, executable)
        struct.pack_into("<I", block, 64, len(self.game_args))
        struct.pack_into("<Q", block, 72, argv)
        self.uc.mem_write(self.args, bytes(block))

        sp = STACK_BASE + STACK_SIZE - 0x1000
        self.uc.reg_write(UC_ARM64_REG_SP, sp)
        if self.entry == 0x35E0:
            self.uc.reg_write(UC_ARM64_REG_X0, self.args)
            self.uc.reg_write(UC_ARM64_REG_X1, 0)
        elif self.entry == 0x3724:
            # export e takes the compact v1 ABI used by the launcher:
            #   u32 version; u32 reserved; void *arg1; void *arg2
            # Keep both opaque arguments backed by writable memory so the
            # protected implementation can safely probe/update them without
            # granting it access to any native process state.
            self.e_arg1 = self.alloc(0x1000)
            self.e_arg2 = self.alloc(0x1000)
            self.e_args = self.alloc(0x18)
            e_block = bytearray(0x18)
            struct.pack_into("<I", e_block, 0, 1)
            struct.pack_into("<Q", e_block, 8, self.e_arg1)
            struct.pack_into("<Q", e_block, 16, self.e_arg2)
            self.uc.mem_write(self.e_args, bytes(e_block))
            self.uc.reg_write(UC_ARM64_REG_X0, self.e_args)
            self.uc.reg_write(UC_ARM64_REG_X1, 0)
        else:
            self.uc.reg_write(UC_ARM64_REG_X0, self.ia(OBJECT))
            self.uc.reg_write(UC_ARM64_REG_X1, self.args)
        self.uc.reg_write(UC_ARM64_REG_X30, STOP_ADDRESS)
        for index, value in self.register_overrides.items():
            self.set_reg(index, value)
        for address, raw in self.memory_overrides:
            self.uc.mem_write(address, raw)

    def string_read(self, obj: int) -> bytes:
        tail = self.uc.mem_read(obj + 23, 1)[0]
        if tail & 0x80:
            pointer = p64(self.uc.mem_read(obj, 8))
            size = p64(self.uc.mem_read(obj + 8, 8))
            return bytes(self.uc.mem_read(pointer, size))
        return bytes(self.uc.mem_read(obj, tail))

    def string_write(self, obj: int, value: bytes) -> None:
        if len(value) <= 22:
            self.uc.mem_write(obj, value + bytes(23 - len(value)) + bytes([len(value)]))
        else:
            pointer = self.alloc(len(value) + 1)
            self.uc.mem_write(pointer, value + b"\0")
            capacity = align(len(value) + 1, 0x10) | (1 << 63)
            self.uc.mem_write(obj, u64(pointer) + u64(len(value)) + u64(capacity))

    def wstring_read(self, obj: int) -> bytes:
        tail = self.uc.mem_read(obj + 23, 1)[0]
        if tail & 0x80:
            pointer = p64(self.uc.mem_read(obj, 8))
            element_count = p64(self.uc.mem_read(obj + 8, 8))
            return bytes(self.uc.mem_read(pointer, element_count * 4))
        return bytes(self.uc.mem_read(obj, tail * 4))

    def wstring_write(self, obj: int, value: bytes) -> None:
        if len(value) % 4:
            raise ValueError("wide string byte count is not wchar_t aligned")
        element_count = len(value) // 4
        if element_count <= 5:
            raw = value + bytes(20 - len(value)) + bytes(3) + bytes([element_count])
            self.uc.mem_write(obj, raw)
        else:
            pointer = self.alloc(len(value) + 4)
            self.uc.mem_write(pointer, value + bytes(4))
            capacity = align(element_count + 1, 4) | (1 << 63)
            self.uc.mem_write(obj, u64(pointer) + u64(element_count) + u64(capacity))

    def reg(self, index: int) -> int:
        return self.uc.reg_read(UC_ARM64_REG_X0 + index)

    def set_reg(self, index: int, value: int) -> None:
        self.uc.reg_write(UC_ARM64_REG_X0 + index, value & 0xFFFFFFFFFFFFFFFF)

    def return_from_stub(self, value: int = 0) -> None:
        self.set_reg(0, value)
        self.uc.reg_write(UC_ARM64_REG_PC, self.uc.reg_read(UC_ARM64_REG_X30))

    def _handle_string_import(self, name: str) -> bool:
        x0, x1, x2, x3 = (self.reg(i) for i in range(4))
        if "basic_stringIc" not in name and "basic_stringIw" not in name:
            return False
        is_wide = "basic_stringIw" in name
        read_string = self.wstring_read if is_wide else self.string_read
        write_string = self.wstring_write if is_wide else self.string_write
        if "D1Ev" in name:
            self.return_from_stub(x0)
            return True
        if "C1ERKS5_mmRKS4_" in name:
            source = read_string(x1)
            unit = 4 if is_wide else 1
            source_count = len(source) // unit
            count = min(x3, source_count - min(x2, source_count))
            write_string(x0, source[x2 * unit : (x2 + count) * unit])
            self.return_from_stub(x0)
            return True
        if "C1ERKS5_" in name or "aSERKS5_" in name:
            write_string(x0, read_string(x1))
            self.return_from_stub(x0)
            return True
        if "resizeEmc" in name:
            current = read_string(x0)
            unit = 4 if is_wide else 1
            current_count = len(current) // unit
            if x1 <= current_count:
                current = current[:x1 * unit]
            else:
                fill = struct.pack("<I", x2 & 0xFFFFFFFF) if is_wide else bytes([x2 & 0xFF])
                current += fill * (x1 - current_count)
            write_string(x0, current)
            self.return_from_stub(x0)
            return True
        if "assignEPKc" in name:
            value = self.read_cstr(x1)
            if name.endswith("m"):
                value = bytes(self.uc.mem_read(x1, x2))
            self.string_write(x0, value)
            self.return_from_stub(x0)
            return True
        if "appendEPKc" in name:
            value = self.read_cstr(x1)
            if name.endswith("m"):
                value = bytes(self.uc.mem_read(x1, x2))
            self.string_write(x0, self.string_read(x0) + value)
            self.return_from_stub(x0)
            return True
        if "appendEPKw" in name:
            count = x2 if name.endswith("m") else 0
            if not name.endswith("m"):
                while struct.unpack("<I", self.uc.mem_read(x1 + count * 4, 4))[0]:
                    count += 1
            value = bytes(self.uc.mem_read(x1, count * 4))
            self.wstring_write(x0, self.wstring_read(x0) + value)
            self.return_from_stub(x0)
            return True
        if "push_backEc" in name:
            self.string_write(x0, self.string_read(x0) + bytes([x1 & 0xFF]))
            self.return_from_stub(x0)
            return True
        if "compare" in name:
            left = self.string_read(x0)
            right = bytes(self.uc.mem_read(x3, self.reg(4))) if x3 else b""
            self.return_from_stub((left > right) - (left < right))
            return True
        # Conservative no-op for less important libc++ string helpers.
        self.return_from_stub(x0)
        return True

    def handle_stub(self, address: int, name: str) -> None:
        self.stub_hits[name] += 1
        x0, x1, x2, x3, x4, x5 = (self.reg(i) for i in range(6))
        if self.verbose:
            print(
                f"[import] {name} lr={self.uc.reg_read(UC_ARM64_REG_X30):#x} "
                f"x0={x0:#x} x1={x1:#x} x2={x2:#x} x3={x3:#x} "
                f"x4={x4:#x} x5={x5:#x}"
            )

        if self._handle_string_import(name):
            return
        if name in {"__Znwm", "__Znam"}:
            self.return_from_stub(self.alloc(x0))
        elif name in {"__ZdlPv", "__ZdaPv", "_free"}:
            self.return_from_stub(0)
        elif name == "_calloc":
            self.return_from_stub(self.alloc(x0 * x1))
        elif name in {"_memcpy", "_memmove"}:
            self.uc.mem_write(x0, bytes(self.uc.mem_read(x1, x2)))
            self.return_from_stub(x0)
        elif name == "_wmemcpy":
            # Darwin wchar_t is 32-bit. libc++ uses this while building the
            # EasyAntiCheat/Certificates wide paths before iconv conversion.
            self.uc.mem_write(x0, bytes(self.uc.mem_read(x1, x2 * 4)))
            self.return_from_stub(x0)
        elif name == "_memset":
            self.uc.mem_write(x0, bytes([x1 & 0xFF]) * x2)
            self.return_from_stub(x0)
        elif name == "_bzero":
            self.uc.mem_write(x0, bytes(x1))
            self.return_from_stub(0)
        elif name == "_strlen":
            self.return_from_stub(len(self.read_cstr(x0)))
        elif name == "_wcslen":
            length = 0
            while struct.unpack("<I", self.uc.mem_read(x0 + length * 4, 4))[0]:
                length += 1
            self.return_from_stub(length)
        elif name == "_glob":
            # Darwin glob(3) writes a glob_t through x3.  Leaving that native
            # output object untouched makes protected code consume stale VM
            # stack words as path pointers.  Model a deterministic no-match.
            if x3:
                self.uc.mem_write(x3, bytes(0x40))
            self.return_from_stub(3)  # GLOB_NOMATCH
        elif name == "_globfree":
            self.return_from_stub(0)
        elif name == "_memchr":
            data = bytes(self.uc.mem_read(x0, x2))
            position = data.find(bytes([x1 & 0xFF]))
            self.return_from_stub(0 if position < 0 else x0 + position)
        elif name == "_vsnprintf":
            format_text = self.read_cstr(x2).decode(errors="replace")
            va_raw = bytes(self.uc.mem_read(x3, 0x30)) if x3 else b""
            values = struct.unpack("<6Q", va_raw)
            try:
                rendered = format_text % values
            except (TypeError, ValueError):
                rendered = ""
            raw = rendered.encode()[: max(0, x1 - 1)] if x1 else b""
            if x0 and x1:
                self.uc.mem_write(x0, raw + b"\0")
            print(f"[vsnprintf] format={format_text!r} rendered={rendered!r}")
            self.return_from_stub(len(rendered))
        elif name == "_strcmp":
            a, b = self.read_cstr(x0), self.read_cstr(x1)
            self.return_from_stub((a > b) - (a < b))
        elif name == "_strncmp":
            a = bytes(self.uc.mem_read(x0, x2))
            b = bytes(self.uc.mem_read(x1, x2))
            self.return_from_stub((a > b) - (a < b))
        elif name == "_getenv":
            key = self.read_cstr(x0).decode(errors="replace")
            value = self.environment.get(key)
            self.return_from_stub(0 if value is None else self.put_cstr(value))
        elif name == "_setenv":
            key = self.read_cstr(x0).decode(errors="replace")
            value = self.read_cstr(x1).decode(errors="replace")
            if x2 or key not in self.environment:
                self.environment[key] = value
            print(f"[setenv] {key}={value}")
            self.return_from_stub(0)
        elif name == "_unsetenv":
            key = self.read_cstr(x0).decode(errors="replace")
            self.environment.pop(key, None)
            print(f"[unsetenv] {key}")
            self.return_from_stub(0)
        elif name == "_iconv_open":
            to_code = self.read_cstr(x0).decode(errors="replace")
            from_code = self.read_cstr(x1).decode(errors="replace")
            descriptor = self.iconv_next
            self.iconv_next += 1
            self.iconv_descriptors[descriptor] = (to_code, from_code)
            self.return_from_stub(descriptor)
        elif name == "_iconv":
            if not x1:
                self.return_from_stub(0)
            else:
                to_code, from_code = self.iconv_descriptors.get(x0, ("UTF-8", "UTF-8"))
                input_pointer = p64(bytes(self.uc.mem_read(x1, 8)))
                input_left = p64(bytes(self.uc.mem_read(x2, 8)))
                output_pointer = p64(bytes(self.uc.mem_read(x3, 8)))
                output_left = p64(bytes(self.uc.mem_read(x4, 8)))
                source = bytes(self.uc.mem_read(input_pointer, input_left))
                codec = {"UTF-32LE": "utf-32-le", "UTF-8": "utf-8"}
                converted = source.decode(codec.get(from_code, from_code)).encode(
                    codec.get(to_code, to_code)
                )
                if len(converted) > output_left:
                    self.return_from_stub(0xFFFFFFFFFFFFFFFF)
                else:
                    self.uc.mem_write(output_pointer, converted)
                    self.uc.mem_write(x1, u64(input_pointer + input_left))
                    self.uc.mem_write(x2, u64(0))
                    self.uc.mem_write(x3, u64(output_pointer + len(converted)))
                    self.uc.mem_write(x4, u64(output_left - len(converted)))
                    self.return_from_stub(0)
        elif name == "_iconv_close":
            self.iconv_descriptors.pop(x0, None)
            self.return_from_stub(0)
        elif name == "__NSGetExecutablePath":
            raw = self.process_executable_text.encode() + b"\0"
            capacity = struct.unpack("<I", self.uc.mem_read(x1, 4))[0] if x1 else 0
            if not x0 or capacity < len(raw):
                if x1:
                    self.uc.mem_write(x1, struct.pack("<I", len(raw)))
                self.return_from_stub(0xFFFFFFFFFFFFFFFF)
            else:
                self.uc.mem_write(x0, raw)
                self.return_from_stub(0)
        elif name == "_realpath$DARWIN_EXTSN":
            source = self.read_cstr(x0).decode(errors="surrogateescape")
            raw = os.path.realpath(source).encode(errors="surrogateescape") + b"\0"
            destination = x1 if x1 else self.alloc(len(raw))
            self.uc.mem_write(destination, raw)
            self.return_from_stub(destination)
        elif name in {"_dirname", "_basename"}:
            source = self.read_cstr(x0).decode(errors="surrogateescape")
            result = os.path.dirname(source) if name == "_dirname" else os.path.basename(source)
            raw = result.encode(errors="surrogateescape") + b"\0"
            self.uc.mem_write(x0, raw)
            self.return_from_stub(x0)
        elif name == "_open":
            path = self.read_cstr(x0).decode(errors="replace")
            print(f"[open] {path}")
            if path == "/tmp/eac.flag" and self.flag_present:
                self.open_files[3] = self.flag_content
                self.return_from_stub(3)
            else:
                self.return_from_stub(self.open_result)
        elif name == "_fopen":
            path = self.read_cstr(x0).decode(errors="replace")
            mode = self.read_cstr(x1).decode(errors="replace")
            print(f"[fopen] {path} mode={mode}")
            content = self.virtual_files.get(path)
            if content is None:
                self.return_from_stub(0)
            else:
                stream = self.alloc(0x100)
                self.file_streams[stream] = {"data": content, "position": 0}
                self.return_from_stub(stream)
        elif name == "_fseek":
            stream = self.file_streams.get(x0)
            if stream is None:
                self.return_from_stub(0xFFFFFFFFFFFFFFFF)
            else:
                data = stream["data"]
                base = 0 if x2 == 0 else int(stream["position"]) if x2 == 1 else len(data)
                offset = x1 if x1 < (1 << 63) else x1 - (1 << 64)
                stream["position"] = max(0, min(len(data), base + offset))
                self.return_from_stub(0)
        elif name == "_ftell":
            stream = self.file_streams.get(x0)
            self.return_from_stub(0xFFFFFFFFFFFFFFFF if stream is None else int(stream["position"]))
        elif name == "_rewind":
            stream = self.file_streams.get(x0)
            if stream is not None:
                stream["position"] = 0
            if self.verbose:
                print(f"[rewind-model] stream={x0:#x} known={stream is not None}")
            self.return_from_stub(0)
        elif name == "_fread":
            stream = self.file_streams.get(x3)
            if stream is None or x1 == 0:
                self.return_from_stub(0)
            else:
                data = stream["data"]
                position = int(stream["position"])
                requested = x1 * x2
                raw = data[position:position + requested]
                if raw and x0:
                    self.uc.mem_write(x0, raw)
                stream["position"] = position + len(raw)
                if self.verbose:
                    print(
                        f"[fread-model] stream={x3:#x} position={position} "
                        f"requested={requested} returned={len(raw)}"
                    )
                self.return_from_stub(len(raw) // x1)
        elif name == "_fclose":
            self.file_streams.pop(x0, None)
            self.return_from_stub(0)
        elif name == "_close":
            if self.fork_child and 3 <= x0 <= 16:
                matches: dict[int, int] = {}
                regions = (
                    (self.ia(CV_START), self.ia(CV_EXEC_START)),
                    (STACK_BASE, STACK_BASE + STACK_SIZE),
                )
                needle4, needle8 = struct.pack("<I", x0), u64(x0)
                for start, end in regions:
                    raw = bytes(self.uc.mem_read(start, end - start))
                    for needle, width in ((needle4, 4), (needle8, 8)):
                        cursor = raw.find(needle)
                        while cursor >= 0:
                            address = start + cursor
                            if address % width == 0:
                                matches[address] = width
                            cursor = raw.find(needle, cursor + 1)
                current = set(matches)
                self.close_candidates = (
                    current
                    if self.close_candidates is None
                    else self.close_candidates & current
                )
                self.close_candidate_widths.update(matches)
                if self.verbose:
                    print(
                        f"[close-scan] fd={x0} candidates="
                        + ",".join(hex(value) for value in sorted(self.close_candidates))
                    )
                if x0 == 6 and self.close_candidates:
                    # The child closes descriptors 3..1023. All surviving
                    # candidates have tracked that loop value across four
                    # iterations; advance its replicated VM state to the last
                    # iteration to avoid ~100M opaque instructions.
                    for candidate in self.close_candidates:
                        width = self.close_candidate_widths[candidate]
                        raw = u64(1023) if width == 8 else struct.pack("<I", 1023)
                        self.uc.mem_write(candidate, raw)
                    print(
                        f"[close-scan] fast-forwarded {len(self.close_candidates)} "
                        "replicas to fd=1023"
                    )
            self.return_from_stub(0)
        elif name == "_shm_open":
            name_text = self.read_cstr(x0).decode(errors="replace")
            event = {"name": name_text, "flags": x1, "mode": x2, "fd": 100}
            self.ipc_events.append(event)
            print(f"[shm_open] {name_text} flags={x1:#x} mode={x2:#o}")
            self.return_from_stub(100)
        elif name in {"_shm_unlink", "_ftruncate", "_munmap"}:
            self.return_from_stub(0)
        elif name == "_mmap":
            self.return_from_stub(self.alloc(x1))
        elif name == "_mach_host_self":
            self.return_from_stub(0x1234)
        elif name == "_host_get_clock_service":
            if x2:
                self.uc.mem_write(x2, struct.pack("<I", 0x1235))
            self.return_from_stub(0)
        elif name == "_clock_get_time":
            if x1:
                self.uc.mem_write(x1, struct.pack("<II", 1_700_000_000, 123_456_789))
            self.return_from_stub(0)
        elif name == "_mach_port_deallocate":
            self.return_from_stub(0)
        elif name == "_read":
            remaining = self.open_files.get(x0, b"")
            content = remaining[:x2]
            if content and x1:
                self.uc.mem_write(x1, content)
            if x0 in self.open_files:
                self.open_files[x0] = remaining[len(content):]
            self.return_from_stub(len(content))
        elif name == "_write":
            self.return_from_stub(x2)
        elif name == "_unlink":
            self.return_from_stub(0)
        elif name == "_dlopen":
            self.return_from_stub(self.dlopen_result)
        elif name == "_getpid":
            self.return_from_stub(1337)
        elif name == "_vm_region_64":
            query = p64(bytes(self.uc.mem_read(x1, 8))) if x1 else 0
            regions = [
                (STACK_BASE, STACK_SIZE, 3),
                (HEAP_BASE, HEAP_SIZE, 3),
                (EXTERNAL_BASE, EXTERNAL_SIZE, 5),
                (self.image_base, IMAGE_LIMIT, 5),
            ]
            match = next(
                ((start, size, protection) for start, size, protection in regions
                 if start + size > query),
                None,
            )
            if match is None:
                self.return_from_stub(1)  # KERN_INVALID_ADDRESS
            else:
                start, region_size, protection = match
                if query > start:
                    region_size -= query - start
                    start = query
                if x1:
                    self.uc.mem_write(x1, u64(start))
                if x2:
                    self.uc.mem_write(x2, u64(region_size))
                if x4:
                    # vm_region_basic_info_data_64_t: protection,
                    # max_protection, inheritance, shared, reserved, offset,
                    # behavior, user_wired_count.
                    info = bytearray(36)
                    struct.pack_into("<ii", info, 0, protection, protection)
                    self.uc.mem_write(x4, bytes(info))
                if x5:
                    self.uc.mem_write(x5, struct.pack("<I", 9))
                object_name = self.reg(6)
                if object_name:
                    self.uc.mem_write(object_name, struct.pack("<I", 0))
                self.return_from_stub(0)
        elif name == "_proc_regionfilename":
            path = str(self.path).encode() + b"\0"
            capacity = x3 if x3 else 0
            raw = path[:capacity]
            if x2 and raw:
                self.uc.mem_write(x2, raw)
            self.return_from_stub(max(0, len(raw) - 1))
        elif name == "_getuid":
            self.return_from_stub(501)
        elif name in {"_pthread_mutex_init", "_pthread_mutex_destroy", "_pthread_mutex_lock", "_pthread_mutex_trylock", "_pthread_mutex_unlock", "_pthread_mutexattr_init", "_pthread_mutexattr_settype"}:
            self.return_from_stub(0)
        elif name == "_fork":
            self.return_from_stub(0 if self.fork_child else 4242)
        elif name == "_execv":
            path = self.read_cstr(x0).decode(errors="replace")
            argv: list[str] = []
            if x1:
                for index in range(128):
                    pointer = p64(bytes(self.uc.mem_read(x1 + index * 8, 8)))
                    if not pointer:
                        break
                    argv.append(self.read_cstr(pointer).decode(errors="replace"))
            event = {"path": path, "argv": argv, "environment": dict(self.environment)}
            self.exec_events.append(event)
            print(f"[execv] {path} argv={argv}")
            self.stop_reason = f"reached execv({path})"
            self.uc.emu_stop()
        elif name == "_sysctl":
            # Darwin anti-debugging commonly asks for
            # CTL_KERN/KERN_PROC/KERN_PROC_PID and checks P_TRACED in the
            # returned kinfo_proc.  Supply a zeroed, untraced process record.
            mib = []
            if x0 and 0 < x1 <= 16:
                mib = list(struct.unpack(f"<{x1}i", self.uc.mem_read(x0, x1 * 4)))
            old_length = 0
            if x3:
                old_length = p64(bytes(self.uc.mem_read(x3, 8)))
            if self.verbose:
                print(f"[sysctl] mib={mib} oldp={x2:#x} oldlen={old_length:#x}")
            if x2 and old_length:
                self.uc.mem_write(x2, bytes(min(old_length, 0x4000)))
                if old_length >= 36:
                    self.uc.mem_write(x2 + 32, struct.pack("<I", self.sysctl_p_flag))
            self.return_from_stub(self.sysctl_result)
        elif name in {"_ptrace", "_task_for_pid"}:
            self.return_from_stub(0)
        elif name == "___cxa_guard_acquire":
            self.return_from_stub(0 if self.uc.mem_read(x0, 1)[0] else 1)
        elif name == "___cxa_guard_release":
            self.uc.mem_write(x0, b"\x01")
            self.return_from_stub(0)
        elif name in {"___cxa_atexit", "___chkstk_darwin"}:
            self.return_from_stub(0)
        elif name in {"___stack_chk_fail", "_abort", "_exit"}:
            self.stop_reason = f"reached fatal import {name}"
            self.uc.emu_stop()
        else:
            # Default failure/success-neutral value. The hit list makes it easy
            # to add semantic handlers iteratively.
            self.return_from_stub(0)

    def on_code(self, uc: Uc, address: int, size: int, _user_data: object) -> None:
        self.steps += 1
        if (os.environ.get("CV_ITER_CAPTURE") and address == self.ia(0x76B7B8)
                and not self.iter_capture and self.iter_countdown is None):
            arm64c = __import__("unicorn.arm64_const", fromlist=["UC_ARM64_REG_X22"])
            out_ptr = uc.reg_read(arm64c.UC_ARM64_REG_X22)
            if 0x200119D0 <= out_ptr <= 0x20011E40:
                # capture one full decode iteration AFTER this write
                self.iter_countdown = 30890
                self.iter_capture = []
                snap = os.environ.get("CV_SNAPSHOT")
                if snap:
                    import pickle
                    regions = {}
                    for lo, size in (
                        (self.image_base, IMAGE_LIMIT),
                        (HEAP_BASE, 0x20000),
                        (STACK_BASE + STACK_SIZE - 0x20000, 0x20000),
                    ):
                        regions[lo] = bytes(self.uc.mem_read(lo, size))
                    arm64s = __import__("unicorn.arm64_const", fromlist=["UC_ARM64_REG_X0"])
                    regs = {
                        f"x{i}": uc.reg_read(getattr(arm64s, f"UC_ARM64_REG_X{i}"))
                        for i in range(31)
                    }
                    regs["sp"] = uc.reg_read(arm64s.UC_ARM64_REG_SP)
                    Path(snap).write_bytes(pickle.dumps(
                        {"regs": regs, "regions": regions, "pc": address}))
                    print(f"snapshot={snap}")
        if self.iter_countdown is not None and self.iter_countdown > 0:
            self.iter_countdown -= 1
            arm64 = __import__("unicorn.arm64_const", fromlist=["UC_ARM64_REG_X0"])
            snap = {"pc": address - self.image_base}
            for i in list(range(0, 8)) + list(range(9, 12)) + [16, 17] + list(range(19, 29)) + [29, 30]:
                snap[f"x{i}"] = uc.reg_read(getattr(arm64, f"UC_ARM64_REG_X{i}"))
            self.iter_capture.append(snap)
        if self.decoder_trace and address in (
            self.ia(0x76B7B8), self.ia(0x7569A4), self.ia(0x73E554),
        ):
            arm64 = __import__("unicorn.arm64_const", fromlist=["UC_ARM64_REG_X0"])
            def xr(i):
                return uc.reg_read(getattr(arm64, f"UC_ARM64_REG_X{i}"))
            event = {"pc": address - self.image_base}
            for i in list(range(0, 8)) + [17] + list(range(19, 29)):
                event[f"x{i}"] = xr(i)
            if event["pc"] != 0x76B7B8:
                base = event.get("x11") if event["pc"] == 0x7569A4 else event.get("x17")
                if base:
                    event["byte"] = uc.mem_read(base, 1)[0]
            self.decoder_events.append(event)
        if self.trace_report is not None and len(self.pc_trace) < 20_000_000:
            self.pc_trace.append(
                address - self.image_base
                if self.image_base <= address < self.ia(IMAGE_LIMIT)
                else address
            )
        self.pc_hits[address] += 1
        self.recent_pcs.append(address)
        if self.coverage_report is not None and self.previous_pc is not None:
            self.edge_hits[(self.previous_pc, address)] += 1
        if self.effects_report is not None and self.previous_pc is not None:
            previous_in_cv = self.ia(CV_EXEC_START) <= self.previous_pc < self.ia(CV_END)
            current_in_cv = self.ia(CV_EXEC_START) <= address < self.ia(CV_END)
            if previous_in_cv != current_in_cv:
                source = self.previous_pc - self.image_base if self.image_base <= self.previous_pc < self.ia(IMAGE_LIMIT) else self.previous_pc
                target = address - self.image_base if self.image_base <= address < self.ia(IMAGE_LIMIT) else address
                key = (source, target)
                state = {
                        "source": source,
                        "target": target,
                        "direction": "vm-exit" if previous_in_cv else "vm-entry",
                        "registers": {
                            **{f"x{index}": self.reg(index) for index in range(8)},
                            **{f"x{index}": self.reg(index) for index in range(19, 29)},
                            "x29": self.uc.reg_read(UC_ARM64_REG_X29),
                            "x30": self.uc.reg_read(UC_ARM64_REG_X30),
                            "sp": self.uc.reg_read(UC_ARM64_REG_SP),
                        },
                    }
                if key not in self.boundary_states:
                    self.boundary_states[key] = state
                if len(self.boundary_events) < 20_000:
                    self.boundary_events.append({"index": len(self.boundary_events), **state})
        if (
            self.previous_pc is not None
            and self.ia(CV_EXEC_START) <= self.previous_pc < self.ia(CV_END)
            and not (self.ia(CV_EXEC_START) <= address < self.ia(CV_END))
            and len(self.callouts) < 2000
        ):
            self.callouts.append(
                (self.previous_pc, address, self.reg(0), self.reg(1), self.reg(2))
            )
        self.previous_pc = address
        if self.verbose and address in {self.ia(0x7B218C), self.ia(0x7B21AC)}:
            print(
                f"[debug {address:#x}] sp={self.uc.reg_read(UC_ARM64_REG_SP):#x} "
                f"x17={self.uc.reg_read(UC_ARM64_REG_X17):#x} "
                f"x3={self.uc.reg_read(UC_ARM64_REG_X3):#x} "
                f"x16={self.uc.reg_read(UC_ARM64_REG_X16):#x}"
            )
        if self.verbose and address == self.ia(0x4AB98):
            vector = self.uc.reg_read(UC_ARM64_REG_X19)
            try:
                words = [p64(bytes(self.uc.mem_read(vector + i * 8, 8))) for i in range(3)]
                print(f"[file-vector] address={vector:#x} words={[hex(x) for x in words]}")
            except UcError:
                pass
        if self.verbose and address == self.ia(0x3924):
            for label, pointer, size in (
                ("config-launcher", self.reg(0), 0x100),
                ("config-result", self.reg(1), 0x80),
            ):
                try:
                    raw = bytes(self.uc.mem_read(pointer, size))
                    print(f"[{label}] address={pointer:#x} hex={raw.hex()}")
                except UcError:
                    pass
            try:
                result_pointer = self.reg(1)
                indirect = p64(bytes(self.uc.mem_read(result_pointer, 8)))
                raw = bytes(self.uc.mem_read(indirect, 0x100))
                print(f"[config-result-indirect] address={indirect:#x} hex={raw.hex()}")
            except UcError:
                pass
        if address == 0:
            self.stop_reason = "indirect branch to null"
            self.uc.emu_stop()
            return
        if address == CALLBACK_ADDRESS:
            arguments = [self.reg(index) for index in range(6)]
            event: dict[str, object] = {"arguments": arguments}
            for label, pointer in (("x0", arguments[0]), ("x1", arguments[1])):
                try:
                    raw = bytes(self.uc.mem_read(pointer, 0x80))
                except UcError:
                    continue
                event[f"{label}_hex"] = raw.hex()
                event[f"{label}_qwords"] = [
                    p64(raw[offset : offset + 8]) for offset in range(0, 0x80, 8)
                ]
            if "x0_qwords" in event:
                fields = event["x0_qwords"]
                event["context"] = fields[0]
                event["code"] = fields[1]
                message_pointer = fields[2]
                event["message_pointer"] = message_pointer
                try:
                    event["message"] = self.read_cstr(message_pointer).decode(
                        errors="replace"
                    )
                except UcError:
                    pass
            self.callback_events.append(event)
            print(
                "[callback] "
                + " ".join(f"x{index}={value:#x}" for index, value in enumerate(arguments))
            )
            self.return_from_stub(0)
            return
        name = self.stubs.get(address)
        if name is not None:
            self.handle_stub(address, name)

    def _effect_location(self, address: int) -> tuple[str, int]:
        if self.ia(CV_START) <= address < self.ia(CV_END):
            return "cv", address - self.image_base
        if self.image_base <= address < self.ia(IMAGE_LIMIT):
            return "image", address - self.image_base
        if STACK_BASE <= address < STACK_BASE + STACK_SIZE:
            return "stack", address - STACK_BASE
        if HEAP_BASE <= address < HEAP_BASE + HEAP_SIZE:
            return "heap", address - HEAP_BASE
        if EXTERNAL_BASE <= address < EXTERNAL_BASE + EXTERNAL_SIZE:
            return "external", address - EXTERNAL_BASE
        return "unmapped", address

    def on_read(self, uc: Uc, access: int, address: int, size: int, value: int, _user_data: object) -> None:
        pc = self.uc.reg_read(UC_ARM64_REG_PC)
        if not (self.ia(CV_EXEC_START) <= pc < self.ia(CV_END)):
            return
        region, normalized = self._effect_location(address)
        self.read_effects[(pc - self.image_base, region, normalized, size)] += 1
        if region == "cv" and size == 1 and len(self.cv_byte_reads) < 1_000_000:
            self.cv_byte_reads.append({
                "step": self.steps,
                "pc": pc - self.image_base,
                "address": normalized,
                "value": self.uc.mem_read(address, 1)[0],
                # Register state before LDRB executes.  Besides identifying the
                # opaque pointer expression, this recovers dispatcher compare
                # constants that were materialized earlier in the block.
                "registers": {
                    **{f"x{index}": self.reg(index) for index in range(29)},
                    "x29": self.uc.reg_read(UC_ARM64_REG_X29),
                    "x30": self.uc.reg_read(UC_ARM64_REG_X30),
                    "sp": self.uc.reg_read(UC_ARM64_REG_SP),
                },
            })

    def on_write(self, uc: Uc, access: int, address: int, size: int, value: int, _user_data: object) -> None:
        pc = self.uc.reg_read(UC_ARM64_REG_PC)
        if self.effects_report is not None and self.ia(CV_EXEC_START) <= pc < self.ia(CV_END):
            region, normalized = self._effect_location(address)
            key = (pc - self.image_base, region, normalized, size)
            self.write_effects[key] += 1
            self.write_effect_values[key] = value & ((1 << min(size * 8, 64)) - 1)
            if region not in {"cv", "stack"} and key not in self.effect_contexts:
                self.effect_contexts[key] = {
                    "pc": pc - self.image_base,
                    "region": region,
                    "address": normalized,
                    "size": size,
                    "first_value": value & ((1 << min(size * 8, 64)) - 1),
                    "recent_pcs": [
                        item - self.image_base if self.image_base <= item < self.ia(IMAGE_LIMIT) else item
                        for item in self.recent_pcs
                    ],
                    "registers": {
                        **{f"x{index}": self.reg(index) for index in range(8)},
                        "x29": self.uc.reg_read(UC_ARM64_REG_X29),
                        "x30": self.uc.reg_read(UC_ARM64_REG_X30),
                        "sp": self.uc.reg_read(UC_ARM64_REG_SP),
                    },
                }
        if self.coverage_report is not None:
            if self.ia(CV_START) <= address < self.ia(CV_END):
                region = "cv"
            elif STACK_BASE <= address < STACK_BASE + STACK_SIZE:
                region = "stack"
            elif HEAP_BASE <= address < HEAP_BASE + HEAP_SIZE:
                region = "heap"
            elif self.image_base <= address < self.ia(IMAGE_LIMIT):
                region = "image"
            else:
                region = "external"
            self.write_sites[(pc, region, size)] += 1
        if STACK_BASE <= address < STACK_BASE + STACK_SIZE:
            self.last_stack_writes[address] = (
                self.uc.reg_read(UC_ARM64_REG_PC), size, value
            )
        if self.ia(CV_START) <= address < self.ia(CV_END):
            self.last_cv_writes[address] = (
                self.uc.reg_read(UC_ARM64_REG_PC), size, value
            )
            if len(self.cv_writes) < 1000:
                self.cv_writes.append((address, size, value))
            if address == self.ia(0x6D0160) and len(self.slot_6d0160_events) < 5000:
                predecessor = self.recent_pcs[-2] if len(self.recent_pcs) >= 2 else 0
                self.slot_6d0160_events.append(
                    (self.uc.reg_read(UC_ARM64_REG_PC), predecessor, value)
                )
                self.last_slot_context = list(self.recent_pcs)

    def on_invalid(self, uc: Uc, access: int, address: int, size: int, value: int, _user_data: object) -> bool:
        pc = self.uc.reg_read(UC_ARM64_REG_PC)
        self.stop_reason = f"invalid memory access type={access} pc={pc:#x} address={address:#x} size={size}"
        return False

    def run(self) -> None:
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        if self.effects_report is not None:
            self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.on_invalid)
        for initializer_offset in MOD_INIT_FUNCTIONS:
            initializer = self.ia(initializer_offset)
            init_sp = STACK_BASE + STACK_SIZE - 0x1000
            self.uc.reg_write(UC_ARM64_REG_SP, init_sp)
            for index in range(3):
                self.set_reg(index, 0)
            self.uc.reg_write(UC_ARM64_REG_X30, STOP_ADDRESS)
            try:
                self.uc.emu_start(initializer, STOP_ADDRESS, count=500_000)
            except UcError as error:
                pc = self.uc.reg_read(UC_ARM64_REG_PC)
                raise RuntimeError(
                    f"module initializer {initializer:#x} failed at {pc:#x}: {error}"
                ) from error
        # Constructor activity is loader setup, not part of the protected
        # export trace. Preserve memory but reset trace state and entry ABI.
        self.pc_hits.clear()
        self.recent_pcs.clear()
        self.cv_writes.clear()
        self.last_cv_writes.clear()
        self.last_stack_writes.clear()
        self.slot_6d0160_events.clear()
        self.last_slot_context.clear()
        self.edge_hits.clear()
        self.write_sites.clear()
        self.read_effects.clear()
        self.write_effects.clear()
        self.write_effect_values.clear()
        self.effect_contexts.clear()
        self.boundary_states.clear()
        self.boundary_events.clear()
        self.cv_byte_reads.clear()
        self.stub_hits.clear()
        self.callouts.clear()
        self.steps = 0
        self.pc_trace.clear()
        self.previous_pc = None
        self.stop_reason = "instruction limit"
        self._make_arguments()
        try:
            self.uc.emu_start(self.ia(self.entry), STOP_ADDRESS, count=self.max_instructions)
            if self.uc.reg_read(UC_ARM64_REG_PC) == STOP_ADDRESS:
                self.stop_reason = f"returned from entry {self.entry:#x}"
        except UcError as error:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            raw = (
                bytes(self.uc.mem_read(pc, 16))
                if self.image_base <= pc < self.ia(IMAGE_LIMIT)
                else b""
            )
            decoded = next(self.cs.disasm(raw, pc), None)
            insn = f"{decoded.mnemonic} {decoded.op_str}" if decoded else raw.hex()
            self.stop_reason = f"{error} at {pc:#x}: {insn}"

        print(f"steps={self.steps}")
        print(f"unique_pcs={len(self.pc_hits)}")
        print(f"stop={self.stop_reason}")
        print(f"pc={self.uc.reg_read(UC_ARM64_REG_PC):#x}")
        print(f"x0={self.reg(0):#x}")
        print(f"sp={self.uc.reg_read(UC_ARM64_REG_SP):#x}")
        for address, size in self.memory_dumps:
            try:
                raw = bytes(self.uc.mem_read(address, size))
                print(f"memory[{address:#x}:{size:#x}]={raw.hex()}")
            except UcError as error:
                print(f"memory[{address:#x}:{size:#x}]=<unmapped: {error}>")
        final_sp = self.uc.reg_read(UC_ARM64_REG_SP)
        print("stack words before final SP:")
        for address in range(final_sp - 0x80, final_sp + 0x10, 0x10):
            value = p64(bytes(self.uc.mem_read(address, 8)))
            writer = self.last_stack_writes.get(address)
            suffix = f" writer={writer[0]:#x}" if writer else ""
            print(f"  {address:#x}: {value:#x}{suffix}")
        print("recent instructions:")
        for address in self.recent_pcs:
            if not (self.image_base <= address < self.ia(IMAGE_LIMIT)):
                print(f"  {address:#x} <external>")
                continue
            raw = bytes(self.uc.mem_read(address, 4))
            decoded = next(self.cs.disasm(raw, address), None)
            text = f"{decoded.mnemonic} {decoded.op_str}" if decoded else raw.hex()
            print(f"  {address:#x}: {text}")
        print("imports:")
        for name, count in self.stub_hits.most_common():
            print(f"  {count:8d} {name}")
        print(f"callouts={len(self.callouts)}")
        for source, target, x0, x1, x2 in self.callouts[:1000]:
            symbol = self.stubs.get(target, "")
            print(
                f"  {source:#x} -> {target:#x} {symbol} "
                f"x0={x0:#x} x1={x1:#x} x2={x2:#x}"
            )
        print(f"cv_writes={len(self.cv_writes)}")
        for address, size, value in self.cv_writes[:20]:
            print(f"  write {address:#x} size={size} value={value:#x}")
        print("CV runtime slots 0x6d0100..0x6d0180:")
        for address in range(self.ia(0x6D0100), self.ia(0x6D0188), 8):
            value = p64(bytes(self.uc.mem_read(address, 8)))
            writer = self.last_cv_writes.get(address)
            suffix = f" writer={writer[0]:#x}" if writer else ""
            print(f"  {address:#x}: {value:#x}{suffix}")
        print(f"slot_6d0160_writes={len(self.slot_6d0160_events)}")
        for writer, predecessor, value in self.slot_6d0160_events[-40:]:
            print(
                f"  writer={writer:#x} predecessor={predecessor:#x} value={value:#x}"
            )
        print("last slot write dynamic context:")
        for address in self.last_slot_context:
            raw = bytes(self.uc.mem_read(address, 4))
            decoded = next(self.cs.disasm(raw, address), None)
            text = f"{decoded.mnemonic} {decoded.op_str}" if decoded else raw.hex()
            print(f"  {address:#x}: {text}")

        if self.report:
            report = {
                "module": str(self.path),
                "entry": self.entry,
                "steps": self.steps,
                "unique_pcs": len(self.pc_hits),
                "stop_reason": self.stop_reason,
                "final_pc": self.uc.reg_read(UC_ARM64_REG_PC),
                "final_x0": self.reg(0),
                "imports": dict(self.stub_hits),
                "callbacks": self.callback_events,
                "exec_events": self.exec_events,
                "environment": self.environment,
                "ipc_events": self.ipc_events,
                "decoder_events": getattr(self, "decoder_events", []),
                "iter_capture": getattr(self, "iter_capture", []),
                "callouts": [
                    {"source": source, "target": target, "symbol": self.stubs.get(target),
                     "x0": x0, "x1": x1, "x2": x2}
                    for source, target, x0, x1, x2 in self.callouts
                ],
            }
            self.report.parent.mkdir(parents=True, exist_ok=True)
            self.report.write_text(json.dumps(report, indent=2) + "\n")
            print(f"report={self.report}")

        if self.coverage_report:
            protected_map_path = Path(__file__).resolve().parent.parent / "devirt" / "protected_functions.json"
            protected = json.loads(protected_map_path.read_text())
            known_edges = {
                (self.ia(entry["source"]), self.ia(entry["target"])): {
                    "function": function["name"],
                    "wrapper": function["start"],
                    "source": entry["source"],
                    "target": entry["target"],
                }
                for function in protected["functions"]
                for entry in function["entries"]
            }
            entry_hits = []
            for edge, metadata in known_edges.items():
                count = self.edge_hits.get(edge, 0)
                if count:
                    entry_hits.append({**metadata, "count": count})
            coverage = {
                "schema": "cv-dynamic-coverage-v1",
                "module": str(self.path),
                "slide": self.image_base,
                "entry": self.entry,
                "fork_child": self.fork_child,
                "steps": self.steps,
                "stop_reason": self.stop_reason,
                "nodes": [
                    {"pc": pc, "count": count}
                    for pc, count in self.pc_hits.items()
                ],
                "edges": [
                    {"source": source, "target": target, "count": count}
                    for (source, target), count in self.edge_hits.items()
                ],
                "write_sites": [
                    {"pc": pc, "region": region, "size": size, "count": count}
                    for (pc, region, size), count in self.write_sites.items()
                ],
                "protected_entry_hits": entry_hits,
                "imports": dict(self.stub_hits),
                "callbacks": self.callback_events,
                "exec_events": self.exec_events,
            }
            self.coverage_report.parent.mkdir(parents=True, exist_ok=True)
            self.coverage_report.write_text(json.dumps(coverage) + "\n")
            print(f"coverage_report={self.coverage_report}")

        if self.effects_report:
            effects = {
                "schema": "cv-memory-effects-v1",
                "module": str(self.path),
                "slide": self.image_base,
                "entry": self.entry,
                "stop_reason": self.stop_reason,
                "final_x0": self.reg(0),
                "reads": [
                    {"pc": pc, "region": region, "address": address, "size": size, "count": count}
                    for (pc, region, address, size), count in self.read_effects.items()
                ],
                "writes": [
                    {"pc": pc, "region": region, "address": address, "size": size,
                     "count": count, "last_value": self.write_effect_values[(pc, region, address, size)]}
                    for (pc, region, address, size), count in self.write_effects.items()
                ],
                "boundary_states": list(self.boundary_states.values()),
                "boundary_events": self.boundary_events,
                "cv_byte_reads": self.cv_byte_reads,
                "observable_write_contexts": list(self.effect_contexts.values()),
            }
            self.effects_report.parent.mkdir(parents=True, exist_ok=True)
            self.effects_report.write_text(json.dumps(effects) + "\n")
            print(f"effects_report={self.effects_report}")
        if self.trace_report:
            self.trace_report.parent.mkdir(parents=True, exist_ok=True)
            self.trace_report.write_text(json.dumps({
                "schema": "cv-pc-trace-v1",
                "module": str(self.path),
                "entry": self.entry,
                "stop_reason": self.stop_reason,
                "pcs": self.pc_trace,
            }) + "\n")
            print(f"trace_report={self.trace_report}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", type=Path)
    parser.add_argument("--max-instructions", type=int, default=5_000_000)
    parser.add_argument("--fork-child", action="store_true")
    parser.add_argument("--entry", type=lambda value: int(value, 0), default=DEFAULT_ENTRY)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--flag-present", action="store_true")
    parser.add_argument("--flag-content", default="")
    parser.add_argument("--sysctl-p-flag", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--sysctl-result", type=lambda value: int(value, 0), default=0)
    parser.add_argument(
        "--reg",
        action="append",
        default=[],
        metavar="INDEX=VALUE",
        help="override an entry register, for example --reg 0=1",
    )
    parser.add_argument(
        "--write-hex",
        action="append",
        default=[],
        metavar="ADDRESS=HEX",
        help="write bytes before entering the selected function",
    )
    parser.add_argument(
        "--virtual-file",
        action="append",
        default=[],
        metavar="PATH=HEX",
        help="serve deterministic contents to fopen/fread",
    )
    parser.add_argument("--open-result", type=lambda value: int(value, 0), default=0xFFFFFFFFFFFFFFFF)
    parser.add_argument("--dlopen-result", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--trace-report", type=Path)
    parser.add_argument("--slide", type=lambda value: int(value, 0), default=0)
    parser.add_argument(
        "--target-executable",
        default="/Users/leeksov/Library/Application Support/Steam/steamapps/common/Rust/RustClient.app/Contents/MacOS/Rust",
    )
    parser.add_argument(
        "--process-executable",
        default="/Users/leeksov/Desktop/reversesmth/pcrust/start_protected_game",
    )
    parser.add_argument("--game-arg", action="append", default=[])
    parser.add_argument("--coverage-report", type=Path)
    parser.add_argument("--effects-report", type=Path)
    parser.add_argument(
        "--dump-memory",
        action="append",
        default=[],
        metavar="ADDRESS:SIZE",
        help="print final emulated memory as hex",
    )
    args = parser.parse_args()
    register_overrides = {}
    for item in args.reg:
        index_text, value_text = item.split("=", 1)
        index = int(index_text, 0)
        if not 0 <= index <= 30:
            parser.error(f"register index out of range: {index}")
        register_overrides[index] = int(value_text, 0)
    memory_overrides = []
    for item in args.write_hex:
        address_text, hex_text = item.split("=", 1)
        memory_overrides.append((int(address_text, 0), bytes.fromhex(hex_text)))
    virtual_files = {}
    for item in args.virtual_file:
        path_text, hex_text = item.split("=", 1)
        virtual_files[path_text] = bytes.fromhex(hex_text)
    memory_dumps = []
    for item in args.dump_memory:
        address_text, size_text = item.split(":", 1)
        memory_dumps.append((int(address_text, 0), int(size_text, 0)))
    Harness(
        args.module,
        args.max_instructions,
        args.fork_child,
        args.entry,
        args.verbose,
        args.report,
        args.flag_present,
        args.flag_content,
        args.sysctl_p_flag,
        args.sysctl_result,
        register_overrides,
        memory_overrides,
        virtual_files,
        args.open_result,
        args.dlopen_result,
        args.trace_report,
        args.slide,
        args.target_executable,
        args.process_executable,
        args.game_arg,
        args.coverage_report,
        args.effects_report,
        memory_dumps,
    ).run()


if __name__ == "__main__":
    main()
