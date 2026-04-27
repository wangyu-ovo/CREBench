from __future__ import annotations

from struct import pack, unpack


BLOCK_SIZE = 16
KEY_SIZE = 16
DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF


def _to_words_le(data: bytes) -> list[int]:
    if len(data) % 4 != 0:
        raise ValueError("data length must be a multiple of 4")
    return list(unpack("<" + "I" * (len(data) // 4), data))


def _from_words_le(words: list[int]) -> bytes:
    return pack("<" + "I" * len(words), *[word & MASK32 for word in words])


def _mx(z: int, y: int, total: int, key: list[int], p: int, e: int) -> int:
    return ((((z >> 5) ^ ((y << 2) & MASK32)) + ((y >> 3) ^ ((z << 4) & MASK32))) ^ ((total ^ y) + (key[(p & 3) ^ e] ^ z))) & MASK32


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")

    out = _to_words_le(block)
    key_words = _to_words_le(key)
    n = len(out) - 1
    if n < 1:
        return block

    z = out[n]
    q = 6 + 52 // (n + 1)
    total = 0
    while q > 0:
        q -= 1
        total = (total + DELTA) & MASK32
        e = (total >> 2) & 3
        for p in range(n):
            y = out[p + 1]
            out[p] = (out[p] + _mx(z, y, total, key_words, p, e)) & MASK32
            z = out[p]
        y = out[0]
        out[n] = (out[n] + _mx(z, y, total, key_words, n, e)) & MASK32
        z = out[n]
    return _from_words_le(out)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")

    out = _to_words_le(block)
    key_words = _to_words_le(key)
    n = len(out) - 1
    if n < 1:
        return block

    q = 6 + 52 // (n + 1)
    total = (q * DELTA) & MASK32
    y = out[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n, 0, -1):
            z = out[p - 1]
            out[p] = (out[p] - _mx(z, y, total, key_words, p, e)) & MASK32
            y = out[p]
        z = out[n]
        out[0] = (out[0] - _mx(z, y, total, key_words, 0, e)) & MASK32
        y = out[0]
        total = (total - DELTA) & MASK32
    return _from_words_le(out)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != BLOCK_SIZE:
        raise ValueError(f"plaintext length must be exactly {BLOCK_SIZE} bytes")
    return encrypt_block(plaintext, key)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) != BLOCK_SIZE:
        raise ValueError(f"ciphertext length must be exactly {BLOCK_SIZE} bytes")
    return decrypt_block(ciphertext, key)
