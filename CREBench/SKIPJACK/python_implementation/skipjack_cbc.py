from __future__ import annotations


BLOCK_SIZE = 8
KEY_SIZE = 10

SBOX = [
    0xA3,0xD7,0x09,0x83,0xF8,0x48,0xF6,0xF4,0xB3,0x21,0x15,0x78,0x99,0xB1,0xAF,0xF9,
    0xE7,0x2D,0x4D,0x8A,0xCE,0x4C,0xCA,0x2E,0x52,0x95,0xD9,0x1E,0x4E,0x38,0x44,0x28,
    0x0A,0xDF,0x02,0xA0,0x17,0xF1,0x60,0x68,0x12,0xB7,0x7A,0xC3,0xE9,0xFA,0x3D,0x53,
    0x96,0x84,0x6B,0xBA,0xF2,0x63,0x9A,0x19,0x7C,0xAE,0xE5,0xF5,0xF7,0x16,0x6A,0xA2,
    0x39,0xB6,0x7B,0x0F,0xC1,0x93,0x81,0x1B,0xEE,0xB4,0x1A,0xEA,0xD0,0x91,0x2F,0xB8,
    0x55,0xB9,0xDA,0x85,0x3F,0x41,0xBF,0xE0,0x5A,0x58,0x80,0x5F,0x66,0x0B,0xD8,0x90,
    0x35,0xD5,0xC0,0xA7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6D,0x98,0x9B,0x76,
    0x97,0xFC,0xB2,0xC2,0xB0,0xFE,0xDB,0x20,0xE1,0xEB,0xD6,0xE4,0xDD,0x47,0x4A,0x1D,
    0x42,0xED,0x9E,0x6E,0x49,0x3C,0xCD,0x43,0x27,0xD2,0x07,0xD4,0xDE,0xC7,0x67,0x18,
    0x89,0xCB,0x30,0x1F,0x8D,0xC6,0x8F,0xAA,0xC8,0x74,0xDC,0xC9,0x5D,0x5C,0x31,0xA4,
    0x70,0x88,0x61,0x2C,0x9F,0x0D,0x2B,0x87,0x50,0x82,0x54,0x64,0x26,0x7D,0x03,0x40,
    0x34,0x4B,0x1C,0x73,0xD1,0xC4,0xFD,0x3B,0xCC,0xFB,0x7F,0xAB,0xE6,0x3E,0x5B,0xA5,
    0xAD,0x04,0x23,0x9C,0x14,0x51,0x22,0xF0,0x29,0x79,0x71,0x7E,0xFF,0x8C,0x0E,0xE2,
    0x0C,0xEF,0xBC,0x72,0x75,0x6F,0x37,0xA1,0xEC,0xD3,0x8E,0x62,0x8B,0x86,0x10,0xE8,
    0x08,0x77,0x11,0xBE,0x92,0x4F,0x24,0xC5,0x32,0x36,0x9D,0xCF,0xF3,0xA6,0xBB,0xAC,
    0x5E,0x6C,0xA9,0x13,0x57,0x25,0xB5,0xE3,0xBD,0xA8,0x3A,0x01,0x05,0x59,0x2A,0x46,
]
KEYSTEP = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0]
IKEYSTEP = [9, 0, 1, 2, 3, 4, 5, 6, 7, 8]


def _load_le16(block: bytes) -> int:
    return block[0] | (block[1] << 8)


def _store_le16(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF))


def _set_key(key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    return key[::-1]


def _g_func(w: int, kp: int, key: bytes) -> tuple[int, int]:
    g1 = (w >> 8) & 0xFF
    g2 = w & 0xFF

    g1 ^= SBOX[g2 ^ key[kp]]
    kp = KEYSTEP[kp]
    g2 ^= SBOX[g1 ^ key[kp]]
    kp = KEYSTEP[kp]
    g1 ^= SBOX[g2 ^ key[kp]]
    kp = KEYSTEP[kp]
    g2 ^= SBOX[g1 ^ key[kp]]
    kp = KEYSTEP[kp]

    return ((g1 << 8) | g2) & 0xFFFF, kp


def _ig_func(w: int, kp: int, key: bytes) -> tuple[int, int]:
    g1 = (w >> 8) & 0xFF
    g2 = w & 0xFF

    kp = IKEYSTEP[kp]
    g2 ^= SBOX[g1 ^ key[kp]]
    kp = IKEYSTEP[kp]
    g1 ^= SBOX[g2 ^ key[kp]]
    kp = IKEYSTEP[kp]
    g2 ^= SBOX[g1 ^ key[kp]]
    kp = IKEYSTEP[kp]
    g1 ^= SBOX[g2 ^ key[kp]]

    return ((g1 << 8) | g2) & 0xFFFF, kp


def _encrypt_block(block: bytes, key: bytes) -> bytes:
    w4 = _load_le16(block[0:2])
    w3 = _load_le16(block[2:4])
    w2 = _load_le16(block[4:6])
    w1 = _load_le16(block[6:8])

    x = 1
    kp = 0
    while x < 9:
        tmp, kp = _g_func(w1, kp, key)
        w1 = (tmp ^ w4 ^ x) & 0xFFFF
        w4, w3, w2 = w3, w2, tmp
        x += 1

    while x < 17:
        tmp, kp = _g_func(w1, kp, key)
        tmp1 = w4
        w4 = w3
        w3 = (w1 ^ w2 ^ x) & 0xFFFF
        w1 = tmp1
        w2 = tmp
        x += 1

    while x < 25:
        tmp, kp = _g_func(w1, kp, key)
        w1 = (tmp ^ w4 ^ x) & 0xFFFF
        w4, w3, w2 = w3, w2, tmp
        x += 1

    while x < 33:
        tmp, kp = _g_func(w1, kp, key)
        tmp1 = w4
        w4 = w3
        w3 = (w1 ^ w2 ^ x) & 0xFFFF
        w1 = tmp1
        w2 = tmp
        x += 1

    return _store_le16(w4) + _store_le16(w3) + _store_le16(w2) + _store_le16(w1)


def _decrypt_block(block: bytes, key: bytes) -> bytes:
    w4 = _load_le16(block[0:2])
    w3 = _load_le16(block[2:4])
    w2 = _load_le16(block[4:6])
    w1 = _load_le16(block[6:8])

    x = 32
    kp = 8
    while x > 24:
        tmp, kp = _ig_func(w2, kp, key)
        w2 = (tmp ^ w3 ^ x) & 0xFFFF
        w3, w4, w1 = w4, w1, tmp
        x -= 1

    while x > 16:
        tmp = (w1 ^ w2 ^ x) & 0xFFFF
        w1, kp = _ig_func(w2, kp, key)
        w2, w3, w4 = w3, w4, tmp
        x -= 1

    while x > 8:
        tmp, kp = _ig_func(w2, kp, key)
        w2 = (tmp ^ w3 ^ x) & 0xFFFF
        w3, w4, w1 = w4, w1, tmp
        x -= 1

    while x > 0:
        tmp = (w1 ^ w2 ^ x) & 0xFFFF
        w1, kp = _ig_func(w2, kp, key)
        w2, w3, w4 = w3, w4, tmp
        x -= 1

    return _store_le16(w4) + _store_le16(w3) + _store_le16(w2) + _store_le16(w1)


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    schedule_key = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, schedule_key)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    schedule_key = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, schedule_key)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
