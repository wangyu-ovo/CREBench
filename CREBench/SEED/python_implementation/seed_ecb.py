from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BLOCK_SIZE = 16
KEY_SIZE = 16


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    cipher = Cipher(algorithms.SEED(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    cipher = Cipher(algorithms.SEED(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
