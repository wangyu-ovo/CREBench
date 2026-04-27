from __future__ import annotations


def _ksa(key: bytes) -> list[int]:
    if not key:
        raise ValueError("key must not be empty")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def _prga(s: list[int], data: bytes) -> bytes:
    i = 0
    j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(byte ^ k)
    return bytes(out)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    return _prga(_ksa(key), plaintext)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return _prga(_ksa(key), ciphertext)

