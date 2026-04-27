from __future__ import annotations

from struct import pack, unpack


BLOCK_SIZE = 8
KEY_SIZE = 16
ROUNDS = 32
DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF


def _load_block(block: bytes) -> tuple[int, int]:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")
    return unpack(">2I", block)


def _load_key(key: bytes) -> tuple[int, int, int, int]:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    return unpack(">4I", key)


def encrypt_block(block: bytes, key: bytes) -> bytes:
    v0, v1 = _load_block(block)
    k0, k1, k2, k3 = _load_key(key)
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & MASK32
        v0 = (v0 + ((((v1 << 4) & MASK32) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK32
        v1 = (v1 + ((((v0 << 4) & MASK32) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK32
    return pack(">2I", v0, v1)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    v0, v1 = _load_block(block)
    k0, k1, k2, k3 = _load_key(key)
    total = (DELTA * ROUNDS) & MASK32
    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0 << 4) & MASK32) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK32
        v0 = (v0 - ((((v1 << 4) & MASK32) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK32
        total = (total - DELTA) & MASK32
    return pack(">2I", v0, v1)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    return b"".join(encrypt_block(plaintext[i : i + BLOCK_SIZE], key) for i in range(0, len(plaintext), BLOCK_SIZE))


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    return b"".join(decrypt_block(ciphertext[i : i + BLOCK_SIZE], key) for i in range(0, len(ciphertext), BLOCK_SIZE))
