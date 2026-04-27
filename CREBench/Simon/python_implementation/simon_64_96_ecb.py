from __future__ import annotations


BLOCK_SIZE = 8
KEY_SIZE = 12
C = 0xFFFFFFFC
Z = 0x7369F885192C0EF5
MASK32 = 0xFFFFFFFF


def _ror32(x: int, r: int) -> int:
    return ((x >> r) | (x << (32 - r))) & MASK32


def _rol32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & MASK32


def _f(x: int) -> int:
    return ((_rol32(x, 1) & _rol32(x, 8)) ^ _rol32(x, 2)) & MASK32


def _r2(x: int, y: int, k: int, l: int) -> tuple[int, int]:
    y ^= _f(x)
    y ^= k
    y &= MASK32
    x ^= _f(y)
    x ^= l
    x &= MASK32
    return x, y


def _expand_key(key: bytes) -> list[int]:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, KEY_SIZE, 4)]
    expanded = [0] * 42
    expanded[0], expanded[1], expanded[2] = words[0], words[1], words[2]
    z = Z
    for i in range(3, 42):
        expanded[i] = (C ^ (z & 1) ^ expanded[i - 3] ^ _ror32(expanded[i - 1], 3) ^ _ror32(expanded[i - 1], 4)) & MASK32
        z >>= 1
    return expanded


def _encrypt_block(block: bytes, expanded: list[int]) -> bytes:
    x = int.from_bytes(block[0:4], "little")
    y = int.from_bytes(block[4:8], "little")
    for i in range(0, 42, 2):
        x, y = _r2(x, y, expanded[i], expanded[i + 1])
    return x.to_bytes(4, "little") + y.to_bytes(4, "little")


def _decrypt_block(block: bytes, expanded: list[int]) -> bytes:
    x = int.from_bytes(block[0:4], "little")
    y = int.from_bytes(block[4:8], "little")
    for i in range(41, 0, -2):
        y, x = _r2(y, x, expanded[i], expanded[i - 1])
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
