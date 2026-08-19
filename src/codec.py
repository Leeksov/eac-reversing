#!/usr/bin/env python3
"""EAC container codec — deobfuscation/obfuscation of runtime.conf and embedded images.

Formula recovered from the unobfuscated EOS SDK parser (sub_563D5C in
libEOSSDK-Mac-Shipping.dylib). Verified against ground truth: 1108/1108
byte-identical matches.

Container format:
    u64  0x0000000000000000   (reserved)
    u32  0xE6ACC57F           (magic)
    u32  len1                 (obfuscated payload length)
    u32  len2                 (secondary length / flags)
    u8[] obfuscated(len1)     (payload)
"""

import struct
import sys
from pathlib import Path


MAGIC = 0xE6ACC57F
HEADER_SIZE = 20  # 8 + 4 + 4 + 4


def deobfuscate(ciphertext: bytes) -> bytes:
    b = bytearray(ciphertext)
    n = len(b)
    if n == 0:
        return bytes(b)
    v = (b[n - 1] - 3 * (n - 1)) & 0xFF
    b[n - 1] = v
    for i in range(n - 2, 0, -1):
        v = (b[i] - v - 3 * i) & 0xFF
        b[i] = v
    b[0] = (b[0] - b[1]) & 0xFF
    return bytes(b)


def obfuscate(plaintext: bytes) -> bytes:
    p = bytearray(plaintext)
    n = len(p)
    if n == 0:
        return bytes(p)
    c = bytearray(n)
    c[n - 1] = (p[n - 1] + 3 * (n - 1)) & 0xFF
    for i in range(n - 2, 0, -1):
        c[i] = (p[i] + p[i + 1] + 3 * i) & 0xFF
    c[0] = (p[0] + p[1]) & 0xFF
    return bytes(c)


def parse_container(data: bytes) -> bytes:
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Too short: {len(data)} < {HEADER_SIZE}")
    reserved, magic, len1, len2 = struct.unpack_from("<QIII", data, 0)
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic:#x} (expected {MAGIC:#x})")
    payload = data[HEADER_SIZE:HEADER_SIZE + len1]
    if len(payload) != len1:
        raise ValueError(f"Truncated payload: {len(payload)} < {len1}")
    return deobfuscate(payload)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <container> [output]")
        print("  Decodes an EAC obfuscated container file.")
        sys.exit(1)

    inpath = Path(sys.argv[1])
    data = inpath.read_bytes()

    plain = parse_container(data)

    if len(sys.argv) >= 3:
        outpath = Path(sys.argv[2])
        outpath.write_bytes(plain)
        print(f"Decoded {len(plain)} bytes -> {outpath}")
    else:
        sys.stdout.buffer.write(plain)


if __name__ == "__main__":
    main()
