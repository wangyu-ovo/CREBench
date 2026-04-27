from __future__ import annotations


BLOCK_SIZE = 32
MIN_KEY_SIZE = 16
MAX_KEY_SIZE = 64
MASK32 = 0xFFFFFFFF
RC = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _choose(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def _majority(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
    return _rotr32(x, 2) ^ _rotr32(x, 13) ^ _rotr32(x, 22)


def _big_sigma1(x: int) -> int:
    return _rotr32(x, 6) ^ _rotr32(x, 11) ^ _rotr32(x, 25)


def _small_sigma0(x: int) -> int:
    return _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)


def _small_sigma1(x: int) -> int:
    return _rotr32(x, 17) ^ _rotr32(x, 19) ^ (x >> 10)


def _fwd(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, rk: int) -> tuple[int, int]:
    h = (h + _big_sigma1(e) + _choose(e, f, g) + rk) & MASK32
    d = (d + h) & MASK32
    h = (h + _big_sigma0(a) + _majority(a, b, c)) & MASK32
    return d, h


def _rev(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, rk: int) -> tuple[int, int]:
    h = (h - _big_sigma0(a) - _majority(a, b, c)) & MASK32
    d = (d - h) & MASK32
    h = (h - _big_sigma1(e) - _choose(e, f, g) - rk) & MASK32
    return d, h


def _set_key(key: bytes) -> list[int]:
    if len(key) < MIN_KEY_SIZE or len(key) > MAX_KEY_SIZE or (len(key) % 4) != 0:
        raise ValueError("invalid key length")
    rk = [0] * 64
    words = len(key) // 4
    for i in range(words):
        rk[i] = int.from_bytes(key[i * 4 : i * 4 + 4], "big")
    for i in range(16, 64):
        rk[i] = (rk[i - 16] + _small_sigma0(rk[i - 15]) + rk[i - 7] + _small_sigma1(rk[i - 2])) & MASK32
    for i in range(64):
        rk[i] = (rk[i] + RC[i]) & MASK32
    return rk


def _encrypt_block(block: bytes, rk: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "big")
    b = int.from_bytes(block[4:8], "big")
    c = int.from_bytes(block[8:12], "big")
    d = int.from_bytes(block[12:16], "big")
    e = int.from_bytes(block[16:20], "big")
    f = int.from_bytes(block[20:24], "big")
    g = int.from_bytes(block[24:28], "big")
    h = int.from_bytes(block[28:32], "big")

    for r in range(0, 64, 8):
        d, h = _fwd(a, b, c, d, e, f, g, h, rk[r + 0])
        c, g = _fwd(h, a, b, c, d, e, f, g, rk[r + 1])
        b, f = _fwd(g, h, a, b, c, d, e, f, rk[r + 2])
        a, e = _fwd(f, g, h, a, b, c, d, e, rk[r + 3])
        h, d = _fwd(e, f, g, h, a, b, c, d, rk[r + 4])
        g, c = _fwd(d, e, f, g, h, a, b, c, rk[r + 5])
        f, b = _fwd(c, d, e, f, g, h, a, b, rk[r + 6])
        e, a = _fwd(b, c, d, e, f, g, h, a, rk[r + 7])

    return b"".join(x.to_bytes(4, "big") for x in [a, b, c, d, e, f, g, h])


def _decrypt_block(block: bytes, rk: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "big")
    b = int.from_bytes(block[4:8], "big")
    c = int.from_bytes(block[8:12], "big")
    d = int.from_bytes(block[12:16], "big")
    e = int.from_bytes(block[16:20], "big")
    f = int.from_bytes(block[20:24], "big")
    g = int.from_bytes(block[24:28], "big")
    h = int.from_bytes(block[28:32], "big")

    for r in range(0, 64, 8):
        e, a = _rev(b, c, d, e, f, g, h, a, rk[63 - r])
        f, b = _rev(c, d, e, f, g, h, a, b, rk[62 - r])
        g, c = _rev(d, e, f, g, h, a, b, c, rk[61 - r])
        h, d = _rev(e, f, g, h, a, b, c, d, rk[60 - r])
        a, e = _rev(f, g, h, a, b, c, d, e, rk[59 - r])
        b, f = _rev(g, h, a, b, c, d, e, f, rk[58 - r])
        c, g = _rev(h, a, b, c, d, e, f, g, rk[57 - r])
        d, h = _rev(a, b, c, d, e, f, g, h, rk[56 - r])

    return b"".join(x.to_bytes(4, "big") for x in [a, b, c, d, e, f, g, h])


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    rk = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, rk)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    rk = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, rk)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
