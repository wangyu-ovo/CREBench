from __future__ import annotations


BLOCK_SIZE = 16
KEY_SIZE = 32
_MASK32 = 0xFFFFFFFF

_S6 = [
    47, 59, 25, 42, 15, 23, 28, 39, 26, 38, 36, 19, 60, 24, 29, 56,
    37, 63, 20, 61, 55, 2, 30, 44, 9, 10, 6, 22, 53, 48, 51, 11,
    62, 52, 35, 18, 14, 46, 0, 54, 17, 40, 27, 4, 31, 8, 5, 12,
    3, 16, 41, 34, 33, 7, 45, 49, 50, 58, 1, 21, 43, 57, 32, 13,
]
_S5 = [
    20, 26, 7, 31, 19, 12, 10, 15, 22, 30, 13, 14, 4, 24, 9, 18,
    27, 11, 1, 21, 6, 16, 2, 28, 23, 5, 8, 3, 0, 17, 29, 25,
]
_S4 = [2, 5, 10, 12, 7, 15, 1, 11, 13, 6, 0, 9, 4, 8, 3, 14]
_S4I = [10, 6, 0, 14, 12, 1, 9, 4, 13, 11, 2, 7, 3, 8, 15, 5]
_M = [
    0xD0C19225, 0xA5A2240A, 0x1B84D250, 0xB728A4A1,
    0x6A704902, 0x85DDDBE6, 0x766FF4A4, 0xECDFE128,
    0xAFD13E94, 0xDF837D09, 0xBB27FA52, 0x695059AC,
    0x52A1BB58, 0xCC322F1D, 0x1844565B, 0xB4A8ACF6,
    0x34235438, 0x6847A851, 0xE48C0CBB, 0xCD181136,
    0x9A112A0C, 0x43EC6D0E, 0x87D8D27D, 0x487DC995,
    0x90FB9B4B, 0xA1F63697, 0xFC513ED9, 0x78A37D93,
    0x8D16C5DF, 0x9E0C8BBE, 0x3C381F7C, 0xE9FB0779,
]
_ORDER = [
    (0, 1, 2, 3),
    (1, 0, 3, 2),
    (2, 3, 0, 1),
    (3, 2, 1, 0),
    (0, 2, 3, 1),
    (1, 3, 2, 0),
    (2, 0, 1, 3),
    (3, 1, 0, 2),
    (0, 3, 1, 2),
    (1, 2, 0, 3),
    (2, 1, 3, 0),
    (3, 0, 2, 1),
]
_INDEX = [
    (0, 0, 0, 0),
    (1, 1, 1, 1),
    (2, 2, 2, 2),
    (0, 1, 0, 1),
    (1, 2, 1, 2),
    (2, 0, 2, 0),
    (0, 2, 0, 2),
    (1, 0, 1, 0),
    (2, 1, 2, 1),
]


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & _MASK32) | (value >> (32 - shift))


def _s_func(value: int) -> int:
    q = _S6[(value >> 26) & 0x3F]
    r = _S5[(value >> 21) & 0x1F]
    s = _S5[(value >> 16) & 0x1F]
    t = _S5[(value >> 11) & 0x1F]
    u = _S5[(value >> 6) & 0x1F]
    v = _S6[value & 0x3F]
    return ((q << 26) | (r << 21) | (s << 16) | (t << 11) | (u << 6) | v) & _MASK32


def _m_func(value: int) -> int:
    out = 0
    for index in range(31, -1, -1):
        if value & 1:
            out ^= _M[index]
        value >>= 1
    return out & _MASK32


def _l_func(a: int, b: int, mask: int) -> tuple[int, int]:
    inverse_mask = mask ^ _MASK32
    s = a & mask
    t = b & inverse_mask
    return (s ^ b) & _MASK32, (t ^ a) & _MASK32


def _f_func(a: int, b: int, mask: int) -> tuple[int, int]:
    return _l_func(_m_func(_s_func(a)), _m_func(_s_func(b)), mask)


def _r_func(a: int, b: int, c: int, d: int, mask: int) -> tuple[int, int, int, int]:
    s, t = _f_func(c, d, mask)
    return (a ^ s) & _MASK32, (b ^ t) & _MASK32, c & _MASK32, d & _MASK32


def _b_func(a: int, b: int, c: int, d: int, inverse: bool = False) -> tuple[int, int, int, int]:
    sbox = _S4I if inverse else _S4
    e = f = g = h = 0
    bit = 1
    for _ in range(32):
        value = 0
        if a & bit:
            value |= 8
        if b & bit:
            value |= 4
        if c & bit:
            value |= 2
        if d & bit:
            value |= 1
        value = sbox[value]
        if value & 8:
            e |= bit
        if value & 4:
            f |= bit
        if value & 2:
            g |= bit
        if value & 1:
            h |= bit
        bit <<= 1
    return e & _MASK32, f & _MASK32, g & _MASK32, h & _MASK32


def _i_func(a: int, b: int, c: int, d: int, ka: int, kb: int, kc: int, kd: int) -> tuple[int, int, int, int]:
    return (a ^ ka) & _MASK32, (b ^ kb) & _MASK32, (c ^ kc) & _MASK32, (d ^ kd) & _MASK32


def _make_one_imkey(k1: int, k2: int, i: int, j: int) -> int:
    ka = _m_func(_s_func(k1))
    kb = _m_func(_s_func(k2))
    m = _m_func(_s_func(4 * i + j))
    ka = (ka + m) & _MASK32
    kb = (kb * (i + 1)) & _MASK32
    ka ^= kb
    return _m_func(_s_func(ka))


def _make_imkeys(user_key: list[int]) -> list[list[int]]:
    return [
        [_make_one_imkey(user_key[0], user_key[1], i, 0) for i in range(3)],
        [_make_one_imkey(user_key[2], user_key[3], i, 1) for i in range(3)],
        [_make_one_imkey(user_key[4], user_key[5], i, 2) for i in range(3)],
        [_make_one_imkey(user_key[6], user_key[7], i, 3) for i in range(3)],
    ]


def _make_one_ekey(imkey: list[list[int]], t: int, s: int) -> int:
    x = imkey[_ORDER[t][0]][_INDEX[s][0]]
    y = imkey[_ORDER[t][1]][_INDEX[s][1]]
    z = imkey[_ORDER[t][2]][_INDEX[s][2]]
    w = imkey[_ORDER[t][3]][_INDEX[s][3]]
    x = _rotl32(x, 1)
    x = (x + y) & _MASK32
    z = _rotl32(z, 1)
    z = (z - w) & _MASK32
    z = _rotl32(z, 1)
    return (x ^ z) & _MASK32


def _make_ekeys(imkey: list[list[int]]) -> list[int]:
    return [_make_one_ekey(imkey, (n + (n // 36)) % 12, n % 9) for n in range(64)]


def _setup(user_key: bytes) -> list[int]:
    if len(user_key) != KEY_SIZE:
        raise ValueError(f"SC2000 reference key must be {KEY_SIZE} bytes")
    user_words = [int.from_bytes(user_key[index : index + 4], "little") for index in range(0, KEY_SIZE, 4)]
    return _make_ekeys(_make_imkeys(user_words))


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"SC2000 reference block must be {BLOCK_SIZE} bytes")
    ek = _setup(key)
    a, b, c, d = [int.from_bytes(block[index : index + 4], "little") for index in range(0, BLOCK_SIZE, 4)]

    a, b, c, d = _i_func(a, b, c, d, *ek[0:4])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[4:8])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[8:12])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[12:16])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[16:20])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[20:24])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[24:28])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[28:32])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[32:36])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[36:40])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[40:44])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[44:48])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[48:52])
    a, b, c, d = _b_func(a, b, c, d)
    a, b, c, d = _i_func(a, b, c, d, *ek[52:56])

    return b"".join(word.to_bytes(4, "little") for word in (a, b, c, d))


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"SC2000 reference block must be {BLOCK_SIZE} bytes")
    ek = _setup(key)
    a, b, c, d = [int.from_bytes(block[index : index + 4], "little") for index in range(0, BLOCK_SIZE, 4)]

    a, b, c, d = _i_func(a, b, c, d, *ek[52:56])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[48:52])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[44:48])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[40:44])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[36:40])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[32:36])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[28:32])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[24:28])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[20:24])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[16:20])
    a, b, c, d = _r_func(a, b, c, d, 0x33333333)
    a, b, c, d = _r_func(c, d, a, b, 0x33333333)
    a, b, c, d = _i_func(a, b, c, d, *ek[12:16])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[8:12])
    a, b, c, d = _r_func(a, b, c, d, 0x55555555)
    a, b, c, d = _r_func(c, d, a, b, 0x55555555)
    a, b, c, d = _i_func(a, b, c, d, *ek[4:8])
    a, b, c, d = _b_func(a, b, c, d, inverse=True)
    a, b, c, d = _i_func(a, b, c, d, *ek[0:4])

    return b"".join(word.to_bytes(4, "little") for word in (a, b, c, d))
