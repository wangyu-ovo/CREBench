from __future__ import annotations


BLOCK_SIZE = 8
MAX_ROUNDS = 13
K128_DEFAULT_ROUNDS = 10

EBOX = [
    1, 45, 226, 147, 190, 69, 21, 174, 120, 3, 135, 164, 184, 56, 207, 63,
    8, 103, 9, 148, 235, 38, 168, 107, 189, 24, 52, 27, 187, 191, 114, 247,
    64, 53, 72, 156, 81, 47, 59, 85, 227, 192, 159, 216, 211, 243, 141, 177,
    255, 167, 62, 220, 134, 119, 215, 166, 17, 251, 244, 186, 146, 145, 100, 131,
    241, 51, 239, 218, 44, 181, 178, 43, 136, 209, 153, 203, 140, 132, 29, 20,
    129, 151, 113, 202, 95, 163, 139, 87, 60, 130, 196, 82, 92, 28, 232, 160,
    4, 180, 133, 74, 246, 19, 84, 182, 223, 12, 26, 142, 222, 224, 57, 252,
    32, 155, 36, 78, 169, 152, 158, 171, 242, 96, 208, 108, 234, 250, 199, 217,
    0, 212, 31, 110, 67, 188, 236, 83, 137, 254, 122, 93, 73, 201, 50, 194,
    249, 154, 248, 109, 22, 219, 89, 150, 68, 233, 205, 230, 70, 66, 143, 10,
    193, 204, 185, 101, 176, 210, 198, 172, 30, 65, 98, 41, 46, 14, 116, 80,
    2, 90, 195, 37, 123, 138, 42, 91, 240, 6, 13, 71, 111, 112, 157, 126,
    16, 206, 18, 39, 213, 76, 79, 214, 121, 48, 104, 54, 117, 125, 228, 237,
    128, 106, 144, 55, 162, 94, 118, 170, 197, 127, 61, 175, 165, 229, 25, 97,
    253, 77, 124, 183, 11, 238, 173, 75, 34, 245, 231, 115, 35, 33, 200, 5,
    225, 102, 221, 179, 88, 105, 99, 86, 15, 161, 49, 149, 23, 7, 58, 40,
]
LBOX = [
    128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173, 248,
    192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168, 130,
    112, 237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1, 172, 37,
    201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50, 15,
    32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225, 115, 198,
    175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139, 213, 84,
    121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147, 131, 188,
    189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205, 191, 217,
    208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107, 158,
    210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118, 42,
    95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7, 219,
    164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4, 29,
    41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154, 193, 14,
    122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242, 108, 104,
    109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207, 229, 66,
    184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224, 137, 48,
]


def _rol8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _pht(x: int, y: int) -> tuple[int, int]:
    y = (y + x) & 0xFF
    x = (x + y) & 0xFF
    return x, y


def _ipht(x: int, y: int) -> tuple[int, int]:
    x = (x - y) & 0xFF
    y = (y - x) & 0xFF
    return x, y


def _expand_userkey(userkey1: bytes, userkey2: bytes, rounds: int, strengthened: bool) -> list[int]:
    if rounds > MAX_ROUNDS:
        rounds = MAX_ROUNDS
    ka = [0] * (BLOCK_SIZE + 1)
    kb = [0] * (BLOCK_SIZE + 1)
    schedule = [rounds]

    k = 0
    for j in range(BLOCK_SIZE):
        ka[j] = _rol8(userkey1[j], 5)
        ka[BLOCK_SIZE] ^= ka[j]
        kb[j] = userkey2[j]
        schedule.append(kb[j])
        kb[BLOCK_SIZE] ^= kb[j]

    for i in range(1, rounds + 1):
        for j in range(BLOCK_SIZE + 1):
            ka[j] = _rol8(ka[j], 6)
            kb[j] = _rol8(kb[j], 6)

        if strengthened:
            k = 2 * i - 1
            while k >= (BLOCK_SIZE + 1):
                k -= BLOCK_SIZE + 1
        for j in range(BLOCK_SIZE):
            rnd = EBOX[EBOX[(18 * i + j + 1) & 0xFF]]
            schedule.append(((ka[k] if strengthened else ka[j]) + rnd) & 0xFF)
            if strengthened:
                k = (k + 1) % (BLOCK_SIZE + 1)

        if strengthened:
            k = 2 * i
            while k >= (BLOCK_SIZE + 1):
                k -= BLOCK_SIZE + 1
        for j in range(BLOCK_SIZE):
            rnd = EBOX[EBOX[(18 * i + j + 10) & 0xFF]]
            schedule.append(((kb[k] if strengthened else kb[j]) + rnd) & 0xFF)
            if strengthened:
                k = (k + 1) % (BLOCK_SIZE + 1)

    return schedule


def _set_key(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    return _expand_userkey(key[:8], key[8:], K128_DEFAULT_ROUNDS, False)


def _encrypt_block(block: bytes, key_schedule: list[int]) -> bytes:
    a, b, c, d, e, f, g, h = block
    key_idx = 1
    rounds = min(key_schedule[0], MAX_ROUNDS)

    for _ in range(rounds):
        a ^= key_schedule[key_idx]; key_idx += 1
        b = (b + key_schedule[key_idx]) & 0xFF; key_idx += 1
        c = (c + key_schedule[key_idx]) & 0xFF; key_idx += 1
        d ^= key_schedule[key_idx]; key_idx += 1
        e ^= key_schedule[key_idx]; key_idx += 1
        f = (f + key_schedule[key_idx]) & 0xFF; key_idx += 1
        g = (g + key_schedule[key_idx]) & 0xFF; key_idx += 1
        h ^= key_schedule[key_idx]; key_idx += 1

        a = (EBOX[a] + key_schedule[key_idx]) & 0xFF; key_idx += 1
        b = LBOX[b] ^ key_schedule[key_idx]; key_idx += 1
        c = LBOX[c] ^ key_schedule[key_idx]; key_idx += 1
        d = (EBOX[d] + key_schedule[key_idx]) & 0xFF; key_idx += 1
        e = (EBOX[e] + key_schedule[key_idx]) & 0xFF; key_idx += 1
        f = LBOX[f] ^ key_schedule[key_idx]; key_idx += 1
        g = LBOX[g] ^ key_schedule[key_idx]; key_idx += 1
        h = (EBOX[h] + key_schedule[key_idx]) & 0xFF; key_idx += 1

        a, b = _pht(a, b)
        c, d = _pht(c, d)
        e, f = _pht(e, f)
        g, h = _pht(g, h)
        a, c = _pht(a, c)
        e, g = _pht(e, g)
        b, d = _pht(b, d)
        f, h = _pht(f, h)
        a, e = _pht(a, e)
        b, f = _pht(b, f)
        c, g = _pht(c, g)
        d, h = _pht(d, h)

        b, e, c = e, c, b
        d, f, g = f, g, d

    a ^= key_schedule[key_idx]; key_idx += 1
    b = (b + key_schedule[key_idx]) & 0xFF; key_idx += 1
    c = (c + key_schedule[key_idx]) & 0xFF; key_idx += 1
    d ^= key_schedule[key_idx]; key_idx += 1
    e ^= key_schedule[key_idx]; key_idx += 1
    f = (f + key_schedule[key_idx]) & 0xFF; key_idx += 1
    g = (g + key_schedule[key_idx]) & 0xFF; key_idx += 1
    h ^= key_schedule[key_idx]
    return bytes((a, b, c, d, e, f, g, h))


def _decrypt_block(block: bytes, key_schedule: list[int]) -> bytes:
    a, b, c, d, e, f, g, h = block
    rounds = min(key_schedule[0], MAX_ROUNDS)
    p = BLOCK_SIZE * (1 + 2 * rounds)

    h ^= key_schedule[p]
    p -= 1
    g = (g - key_schedule[p]) & 0xFF
    p -= 1
    f = (f - key_schedule[p]) & 0xFF
    p -= 1
    e ^= key_schedule[p]
    p -= 1
    d ^= key_schedule[p]
    p -= 1
    c = (c - key_schedule[p]) & 0xFF
    p -= 1
    b = (b - key_schedule[p]) & 0xFF
    p -= 1
    a ^= key_schedule[p]

    for _ in range(rounds):
        e, b, c = b, c, e
        f, d, g = d, g, f

        a, e = _ipht(a, e)
        b, f = _ipht(b, f)
        c, g = _ipht(c, g)
        d, h = _ipht(d, h)
        a, c = _ipht(a, c)
        e, g = _ipht(e, g)
        b, d = _ipht(b, d)
        f, h = _ipht(f, h)
        a, b = _ipht(a, b)
        c, d = _ipht(c, d)
        e, f = _ipht(e, f)
        g, h = _ipht(g, h)

        p -= 1
        h = (h - key_schedule[p]) & 0xFF
        p -= 1
        g ^= key_schedule[p]
        p -= 1
        f ^= key_schedule[p]
        p -= 1
        e = (e - key_schedule[p]) & 0xFF
        p -= 1
        d = (d - key_schedule[p]) & 0xFF
        p -= 1
        c ^= key_schedule[p]
        p -= 1
        b ^= key_schedule[p]
        p -= 1
        a = (a - key_schedule[p]) & 0xFF

        p -= 1
        h = (LBOX[h] ^ key_schedule[p]) & 0xFF
        p -= 1
        g = (EBOX[g] - key_schedule[p]) & 0xFF
        p -= 1
        f = (EBOX[f] - key_schedule[p]) & 0xFF
        p -= 1
        e = (LBOX[e] ^ key_schedule[p]) & 0xFF
        p -= 1
        d = (LBOX[d] ^ key_schedule[p]) & 0xFF
        p -= 1
        c = (EBOX[c] - key_schedule[p]) & 0xFF
        p -= 1
        b = (EBOX[b] - key_schedule[p]) & 0xFF
        p -= 1
        a = (LBOX[a] ^ key_schedule[p]) & 0xFF

    return bytes((a, b, c, d, e, f, g, h))


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    schedule = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, schedule)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    schedule = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, schedule)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
