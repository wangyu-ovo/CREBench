from __future__ import annotations


BLOCK_SIZE = 8
MAX_KEY_BYTES = 16

_KEY_TABLE = bytes(
    [
        0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79,
        0x4A, 0xA0, 0xD8, 0x9D, 0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
        0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2, 0x17, 0x9A, 0x59, 0xF5,
        0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
        0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22,
        0x5C, 0x6B, 0x4E, 0x82, 0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
        0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC, 0x12, 0x75, 0xCA, 0x1F,
        0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
        0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B,
        0xBC, 0x94, 0x43, 0x03, 0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
        0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7, 0x08, 0xE8, 0xEA, 0xDE,
        0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
        0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E,
        0x04, 0x18, 0xA4, 0xEC, 0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
        0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39, 0x99, 0x7C, 0x3A, 0x85,
        0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
        0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10,
        0x67, 0x6C, 0xBA, 0xC9, 0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
        0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9, 0x0D, 0x38, 0x34, 0x1B,
        0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
        0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68,
        0xFE, 0x7F, 0xC1, 0xAD,
    ]
)


def _rol16(x: int, shift: int) -> int:
    x &= 0xFFFF
    return ((x << shift) | (x >> (16 - shift))) & 0xFFFF


def _ror16(x: int, shift: int) -> int:
    x &= 0xFFFF
    return ((x >> shift) | (x << (16 - shift))) & 0xFFFF


def _expand_key(key: bytes) -> list[int]:
    if not key:
        raise ValueError("key must not be empty")
    if len(key) > MAX_KEY_BYTES:
        key = key[:MAX_KEY_BYTES]

    bits = len(key) * 8
    k = bytearray(128)
    k[: len(key)] = key

    d = k[len(key) - 1]
    j = 0
    for i in range(len(key), 128):
        d = _KEY_TABLE[(k[j] + d) & 0xFF]
        k[i] = d
        j += 1

    j = (bits + 7) >> 3
    i = 128 - j
    c = 0xFF >> (-bits & 0x07)

    d = _KEY_TABLE[k[i] & c]
    k[i] = d
    while i > 0:
        i -= 1
        d = _KEY_TABLE[k[i + j] ^ d]
        k[i] = d

    return [((k[2 * idx + 1] << 8) | k[2 * idx]) & 0xFFFF for idx in range(64)]


def _encrypt_block(block: bytes, schedule: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")

    x0 = int.from_bytes(block[0:2], "little")
    x1 = int.from_bytes(block[2:4], "little")
    x2 = int.from_bytes(block[4:6], "little")
    x3 = int.from_bytes(block[6:8], "little")

    p = 0
    for rounds, do_mash in ((5, True), (6, True), (5, False)):
        for _ in range(rounds):
            x0 = _rol16((x0 + (x1 & ~x3) + (x2 & x3) + schedule[p]), 1)
            p += 1
            x1 = _rol16((x1 + (x2 & ~x0) + (x3 & x0) + schedule[p]), 2)
            p += 1
            x2 = _rol16((x2 + (x3 & ~x1) + (x0 & x1) + schedule[p]), 3)
            p += 1
            x3 = _rol16((x3 + (x0 & ~x2) + (x1 & x2) + schedule[p]), 5)
            p += 1
        if do_mash:
            x0 = (x0 + schedule[x3 & 0x3F]) & 0xFFFF
            x1 = (x1 + schedule[x0 & 0x3F]) & 0xFFFF
            x2 = (x2 + schedule[x1 & 0x3F]) & 0xFFFF
            x3 = (x3 + schedule[x2 & 0x3F]) & 0xFFFF

    return (
        x0.to_bytes(2, "little")
        + x1.to_bytes(2, "little")
        + x2.to_bytes(2, "little")
        + x3.to_bytes(2, "little")
    )


def _decrypt_block(block: bytes, schedule: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")

    x0 = int.from_bytes(block[0:2], "little")
    x1 = int.from_bytes(block[2:4], "little")
    x2 = int.from_bytes(block[4:6], "little")
    x3 = int.from_bytes(block[6:8], "little")

    p = 63
    for rounds, do_unmash in ((5, True), (6, True), (5, False)):
        for _ in range(rounds):
            x3 = (_ror16(x3, 5) - (x0 & ~x2) - (x1 & x2) - schedule[p]) & 0xFFFF
            p -= 1
            x2 = (_ror16(x2, 3) - (x3 & ~x1) - (x0 & x1) - schedule[p]) & 0xFFFF
            p -= 1
            x1 = (_ror16(x1, 2) - (x2 & ~x0) - (x3 & x0) - schedule[p]) & 0xFFFF
            p -= 1
            x0 = (_ror16(x0, 1) - (x1 & ~x3) - (x2 & x3) - schedule[p]) & 0xFFFF
            p -= 1
        if do_unmash:
            x3 = (x3 - schedule[x2 & 0x3F]) & 0xFFFF
            x2 = (x2 - schedule[x1 & 0x3F]) & 0xFFFF
            x1 = (x1 - schedule[x0 & 0x3F]) & 0xFFFF
            x0 = (x0 - schedule[x3 & 0x3F]) & 0xFFFF

    return (
        x0.to_bytes(2, "little")
        + x1.to_bytes(2, "little")
        + x2.to_bytes(2, "little")
        + x3.to_bytes(2, "little")
    )


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    schedule = _expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, schedule)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    schedule = _expand_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, schedule)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
