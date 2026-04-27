from __future__ import annotations


BLOCK_SIZE = 8
KEY_SIZE = 16
ROUNDS = 12
P32 = 0xB7E15163
Q32 = 0x9E3779B9
MASK32 = 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def _rotr32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def _set_key(key: bytes) -> list[int]:
    if len(key) > 255:
        raise ValueError("key too long")

    c = max(1, (len(key) + 3) // 4)
    t = 2 * (ROUNDS + 1)

    l_words = [0] * 64
    for i, byte in enumerate(key):
        l_words[i // 4] |= byte << (8 * (i % 4))

    s = [0] * t
    s[0] = P32
    for i in range(1, t):
        s[i] = (s[i - 1] + Q32) & MASK32

    a = b = 0
    n = 3 * max(t, c)
    i = j = 0
    for _ in range(n):
        a = s[i] = _rotl32((s[i] + a + b) & MASK32, 3)
        b = l_words[j] = _rotl32((l_words[j] + a + b) & MASK32, (a + b) & 31)
        i = (i + 1) % t
        j = (j + 1) % c

    return s


def _encrypt_block(block: bytes, s: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little")
    b = int.from_bytes(block[4:8], "little")

    a = (a + s[0]) & MASK32
    b = (b + s[1]) & MASK32
    for i in range(1, ROUNDS + 1):
        a = (_rotl32(a ^ b, b & 31) + s[2 * i]) & MASK32
        b = (_rotl32(b ^ a, a & 31) + s[2 * i + 1]) & MASK32

    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


def _decrypt_block(block: bytes, s: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little")
    b = int.from_bytes(block[4:8], "little")

    for i in range(ROUNDS, 0, -1):
        b = _rotr32((b - s[2 * i + 1]) & MASK32, a & 31) ^ a
        a = _rotr32((a - s[2 * i]) & MASK32, b & 31) ^ b

    b = (b - s[1]) & MASK32
    a = (a - s[0]) & MASK32
    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


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
