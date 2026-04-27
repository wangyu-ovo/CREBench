from __future__ import annotations


BLOCK_SIZE = 8
KEY_SIZE = 12
MASK32 = 0xFFFFFFFF


def _ror32(x: int, r: int) -> int:
    return ((x >> r) | (x << (32 - r))) & MASK32


def _rol32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & MASK32


def _round(x: int, y: int, k: int) -> tuple[int, int]:
    x = _ror32(x, 8)
    x = (x + y) & MASK32
    x ^= k
    y = _rol32(y, 3)
    y ^= x
    return x & MASK32, y & MASK32


def _iround(x: int, y: int, k: int) -> tuple[int, int]:
    y ^= x
    y = _ror32(y, 3)
    x ^= k
    x = (x - y) & MASK32
    x = _rol32(x, 8)
    return x & MASK32, y & MASK32


def _expand_key(key: bytes) -> list[int]:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, KEY_SIZE, 4)]
    c, b, a = words[2], words[1], words[0]
    expanded = [0] * 26
    for i in range(0, 26, 2):
        expanded[i] = a
        b, a = _round(b, a, i)
        expanded[i + 1] = a
        c, a = _round(c, a, i + 1)
    return expanded


def _encrypt_block(block: bytes, expanded: list[int]) -> bytes:
    x = int.from_bytes(block[0:4], "little")
    y = int.from_bytes(block[4:8], "little")
    for k in expanded:
        x, y = _round(x, y, k)
    return x.to_bytes(4, "little") + y.to_bytes(4, "little")


def _decrypt_block(block: bytes, expanded: list[int]) -> bytes:
    x = int.from_bytes(block[0:4], "little")
    y = int.from_bytes(block[4:8], "little")
    for k in reversed(expanded):
        x, y = _iround(x, y, k)
    return x.to_bytes(4, "little") + y.to_bytes(4, "little")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    expanded = _expand_key(key)
    return b"".join(_encrypt_block(plaintext[i : i + BLOCK_SIZE], expanded) for i in range(0, len(plaintext), BLOCK_SIZE))


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    expanded = _expand_key(key)
    return b"".join(_decrypt_block(ciphertext[i : i + BLOCK_SIZE], expanded) for i in range(0, len(ciphertext), BLOCK_SIZE))
