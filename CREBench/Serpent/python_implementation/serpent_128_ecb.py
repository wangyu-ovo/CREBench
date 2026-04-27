from __future__ import annotations

from pyserpent import Serpent


BLOCK_SIZE = 16
KEY_SIZE = 16


def _new_cipher(key: bytes) -> Serpent:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    return Serpent(key)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    return _new_cipher(key).encrypt(plaintext)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    return _new_cipher(key).decrypt(ciphertext)
