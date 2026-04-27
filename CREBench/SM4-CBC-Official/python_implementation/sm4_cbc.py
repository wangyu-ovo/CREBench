from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BLOCK_SIZE = 16
KEY_SIZE = 16


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
