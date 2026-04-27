from __future__ import annotations


BLOCK_SIZE = 16
VALID_KEY_SIZES = {16, 24, 32}
ROUNDS = 20
P32 = 0xB7E15163
Q32 = 0x9E3779B9
MASK32 = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    r &= 31
    x &= MASK32
    return ((x << r) | (x >> (32 - r))) & MASK32


def _rotr32(x: int, r: int) -> int:
    r &= 31
    x &= MASK32
    return ((x >> r) | (x << (32 - r))) & MASK32


def _set_key(key: bytes) -> list[int]:
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError("key must be 16, 24, or 32 bytes")

    l_words = [0] * (32 // 4)
    for i, byte in enumerate(key):
        l_words[i // 4] |= byte << (8 * (i % 4))

    c = max(1, (len(key) + 3) // 4)
    t = 2 * (ROUNDS + 2)
    s = [0] * t
    s[0] = P32
    for i in range(1, t):
        s[i] = (s[i - 1] + Q32) & MASK32

    a = b = 0
    n = 3 * max(t, c)
    for i in range(n):
        a = s[i % t] = _rotl32((s[i % t] + a + b) & MASK32, 3)
        b = l_words[i % c] = _rotl32((l_words[i % c] + a + b) & MASK32, a + b)
    return s


def _encrypt_block(block: bytes, s: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little")
    b = int.from_bytes(block[4:8], "little")
    c = int.from_bytes(block[8:12], "little")
    d = int.from_bytes(block[12:16], "little")

    b = (b + s[0]) & MASK32
    d = (d + s[1]) & MASK32

    for i in range(ROUNDS):
        t = _rotl32((b * ((2 * b + 1) & MASK32)) & MASK32, 5)
        u = _rotl32((d * ((2 * d + 1) & MASK32)) & MASK32, 5)
        a = (_rotl32(a ^ t, u) + s[2 * i + 2]) & MASK32
        c = (_rotl32(c ^ u, t) + s[2 * i + 3]) & MASK32
        a, b, c, d = b, c, d, a

    a = (a + s[2 * ROUNDS + 2]) & MASK32
    c = (c + s[2 * ROUNDS + 3]) & MASK32

    return (
        a.to_bytes(4, "little")
        + b.to_bytes(4, "little")
        + c.to_bytes(4, "little")
        + d.to_bytes(4, "little")
    )


def _decrypt_block(block: bytes, s: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little")
    b = int.from_bytes(block[4:8], "little")
    c = int.from_bytes(block[8:12], "little")
    d = int.from_bytes(block[12:16], "little")

    c = (c - s[2 * ROUNDS + 3]) & MASK32
    a = (a - s[2 * ROUNDS + 2]) & MASK32

    for i in range(ROUNDS - 1, -1, -1):
        a, b, c, d = d, a, b, c
        u = _rotl32((d * ((2 * d + 1) & MASK32)) & MASK32, 5)
        t = _rotl32((b * ((2 * b + 1) & MASK32)) & MASK32, 5)
        c = _rotr32((c - s[2 * i + 3]) & MASK32, t) ^ u
        a = _rotr32((a - s[2 * i + 2]) & MASK32, u) ^ t

    d = (d - s[1]) & MASK32
    b = (b - s[0]) & MASK32

    return (
        a.to_bytes(4, "little")
        + b.to_bytes(4, "little")
        + c.to_bytes(4, "little")
        + d.to_bytes(4, "little")
    )


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    s = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, s)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    s = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, s)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
