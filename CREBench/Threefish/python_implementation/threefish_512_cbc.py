from __future__ import annotations


BLOCK_SIZE = 64
KEY_SIZE = 64
ROUNDS = 72
C240 = 0x1BD11BDAA9FC1A22
R512 = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
]
P512 = [6, 1, 0, 7, 2, 5, 4, 3]


def _u64(value: int) -> int:
    return value & 0xFFFFFFFFFFFFFFFF


def _rotl64(value: int, shift: int) -> int:
    return _u64((value << shift) | (value >> (64 - shift)))


def _rotr64(value: int, shift: int) -> int:
    return _u64((value >> shift) | (value << (64 - shift)))


def _subkeys(key: bytes) -> list[list[int]]:
    k = [int.from_bytes(key[i : i + 8], "little") for i in range(0, KEY_SIZE, 8)]
    k.append(C240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7])
    t = [0, 0, 0]
    out = [[0] * 8 for _ in range(ROUNDS // 4 + 1)]
    for s in range(ROUNDS // 4 + 1):
        for i in range(8):
            value = k[(s + i) % 9]
            if i == 5:
                value = _u64(value + t[s % 3])
            elif i == 6:
                value = _u64(value + t[(s + 1) % 3])
            elif i == 7:
                value = _u64(value + s)
            out[s][i] = value
    return out


def _encrypt_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    state = [int.from_bytes(block[i : i + 8], "little") for i in range(0, BLOCK_SIZE, 8)]
    for d in range(ROUNDS):
        temp = state[:]
        for j in range(4):
            x0 = temp[2 * j]
            x1 = temp[2 * j + 1]
            if (d % 4) == 0:
                x0 = _u64(x0 + subkeys[d // 4][2 * j])
                x1 = _u64(x1 + subkeys[d // 4][2 * j + 1])
            y0 = _u64(x0 + x1)
            y1 = _rotl64(x1, R512[d % 8][j]) ^ y0
            state[P512[2 * j]] = y0
            state[P512[2 * j + 1]] = _u64(y1)
    for i in range(8):
        state[i] = _u64(state[i] + subkeys[ROUNDS // 4][i])
    return b"".join(word.to_bytes(8, "little") for word in state)


def _decrypt_block(block: bytes, subkeys: list[list[int]]) -> bytes:
    state = [int.from_bytes(block[i : i + 8], "little") for i in range(0, BLOCK_SIZE, 8)]
    for i in range(8):
        state[i] = _u64(state[i] - subkeys[ROUNDS // 4][i])
    for d in range(ROUNDS - 1, -1, -1):
        temp = state[:]
        for j in range(4):
            y0 = temp[P512[2 * j]]
            y1 = temp[P512[2 * j + 1]]
            x1 = _rotr64(y0 ^ y1, R512[d % 8][j])
            x0 = _u64(y0 - x1)
            if (d % 4) == 0:
                x0 = _u64(x0 - subkeys[d // 4][2 * j])
                x1 = _u64(x1 - subkeys[d // 4][2 * j + 1])
            state[2 * j] = x0
            state[2 * j + 1] = x1
    return b"".join(word.to_bytes(8, "little") for word in state)


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    subkeys = _subkeys(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, subkeys)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    subkeys = _subkeys(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, subkeys)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
