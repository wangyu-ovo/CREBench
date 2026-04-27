from __future__ import annotations


BLOCK_SIZE = 16
KEY_SIZE = 16
MASK32 = 0xFFFFFFFF
RC_TABLE = [
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
]


def _rotl32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x << n) | (x >> ((32 - n) & 31))) & MASK32


def _rotr32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x >> n) | (x << ((32 - n) & 31))) & MASK32


def _theta_null(a: list[int]) -> None:
    tmp = a[0] ^ a[2]
    tmp ^= _rotl32(tmp, 8) ^ _rotr32(tmp, 8)
    a[1] ^= tmp
    a[3] ^= tmp

    tmp = a[1] ^ a[3]
    tmp ^= _rotl32(tmp, 8) ^ _rotr32(tmp, 8)
    a[0] ^= tmp
    a[2] ^= tmp

    for i in range(4):
        a[i] &= MASK32


def _theta_key(a: list[int], k: list[int]) -> None:
    tmp = a[0] ^ a[2]
    tmp ^= _rotl32(tmp, 8) ^ _rotr32(tmp, 8)
    a[1] ^= tmp
    a[3] ^= tmp

    a[0] ^= k[0]
    a[1] ^= k[1]
    a[2] ^= k[2]
    a[3] ^= k[3]

    tmp = a[1] ^ a[3]
    tmp ^= _rotl32(tmp, 8) ^ _rotr32(tmp, 8)
    a[0] ^= tmp
    a[2] ^= tmp

    for i in range(4):
        a[i] &= MASK32


def _gamma_layer(a: list[int]) -> None:
    a[1] ^= ~(a[2] | a[3]) & MASK32
    a[0] ^= a[2] & a[1]

    a[0], a[3] = a[3], a[0]

    a[2] ^= a[0] ^ a[1] ^ a[3]

    a[1] ^= ~(a[2] | a[3]) & MASK32
    a[0] ^= a[2] & a[1]

    for i in range(4):
        a[i] &= MASK32


def _pi1_layer(a: list[int]) -> None:
    a[1] = _rotl32(a[1], 1)
    a[2] = _rotl32(a[2], 5)
    a[3] = _rotl32(a[3], 2)


def _pi2_layer(a: list[int]) -> None:
    a[1] = _rotr32(a[1], 1)
    a[2] = _rotr32(a[2], 5)
    a[3] = _rotr32(a[3], 2)


def _load_state(block: bytes) -> list[int]:
    return [
        int.from_bytes(block[0:4], "big"),
        int.from_bytes(block[4:8], "big"),
        int.from_bytes(block[8:12], "big"),
        int.from_bytes(block[12:16], "big"),
    ]


def _store_state(state: list[int]) -> bytes:
    return b"".join((word & MASK32).to_bytes(4, "big") for word in state)


def _set_key(key: bytes) -> tuple[list[int], list[int]]:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")

    a = _load_state(key)
    for i in range(16):
        a[0] ^= RC_TABLE[i]
        a[0] &= MASK32
        _theta_null(a)
        _pi1_layer(a)
        _gamma_layer(a)
        _pi2_layer(a)

    a[0] ^= RC_TABLE[16]
    a[0] &= MASK32
    dk = a.copy()

    _theta_null(a)
    k = a.copy()
    return k, dk


def _encrypt_block(block: bytes, k: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")

    a = _load_state(block)
    for i in range(16):
        a[0] ^= RC_TABLE[i]
        a[0] &= MASK32
        _theta_key(a, k)
        _pi1_layer(a)
        _gamma_layer(a)
        _pi2_layer(a)

    a[0] ^= RC_TABLE[16]
    a[0] &= MASK32
    _theta_key(a, k)
    return _store_state(a)


def _decrypt_block(block: bytes, dk: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")

    a = _load_state(block)
    for i in range(16, 0, -1):
        _theta_key(a, dk)
        a[0] ^= RC_TABLE[i]
        a[0] &= MASK32
        _pi1_layer(a)
        _gamma_layer(a)
        _pi2_layer(a)

    _theta_key(a, dk)
    a[0] ^= RC_TABLE[0]
    a[0] &= MASK32
    return _store_state(a)


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    k, _ = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, k)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")

    _, dk = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, dk)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
