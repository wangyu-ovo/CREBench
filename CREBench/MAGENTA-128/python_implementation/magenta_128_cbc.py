from __future__ import annotations


BLOCK_SIZE = 16
KEY_SIZE = 16
GF_POLY = 0x0165

_F_TAB: list[int] | None = None


def _load_le32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _store_le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _byte_of(value: int, index: int) -> int:
    return (value >> (8 * index)) & 0xFF


def _f_tab() -> list[int]:
    global _F_TAB
    if _F_TAB is not None:
        return _F_TAB
    table = [0] * 256
    f = 1
    for i in range(255):
        table[i] = f
        f <<= 1
        if f & 0x100:
            f ^= GF_POLY
    table[255] = 0
    _F_TAB = table
    return table


def _pi_fun(x: list[int]) -> list[int]:
    tab = _f_tab()
    return [
        tab[_byte_of(x[0], 0) ^ tab[_byte_of(x[2], 0)]]
        | (tab[_byte_of(x[2], 0) ^ tab[_byte_of(x[0], 0)]] << 8)
        | (tab[_byte_of(x[0], 1) ^ tab[_byte_of(x[2], 1)]] << 16)
        | (tab[_byte_of(x[2], 1) ^ tab[_byte_of(x[0], 1)]] << 24),
        tab[_byte_of(x[0], 2) ^ tab[_byte_of(x[2], 2)]]
        | (tab[_byte_of(x[2], 2) ^ tab[_byte_of(x[0], 2)]] << 8)
        | (tab[_byte_of(x[0], 3) ^ tab[_byte_of(x[2], 3)]] << 16)
        | (tab[_byte_of(x[2], 3) ^ tab[_byte_of(x[0], 3)]] << 24),
        tab[_byte_of(x[1], 0) ^ tab[_byte_of(x[3], 0)]]
        | (tab[_byte_of(x[3], 0) ^ tab[_byte_of(x[1], 0)]] << 8)
        | (tab[_byte_of(x[1], 1) ^ tab[_byte_of(x[3], 1)]] << 16)
        | (tab[_byte_of(x[3], 1) ^ tab[_byte_of(x[1], 1)]] << 24),
        tab[_byte_of(x[1], 2) ^ tab[_byte_of(x[3], 2)]]
        | (tab[_byte_of(x[3], 2) ^ tab[_byte_of(x[1], 2)]] << 8)
        | (tab[_byte_of(x[1], 3) ^ tab[_byte_of(x[3], 3)]] << 16)
        | (tab[_byte_of(x[3], 3) ^ tab[_byte_of(x[1], 3)]] << 24),
    ]


def _mix_words(words: list[int]) -> list[int]:
    return [
        _byte_of(words[0], 0) | (_byte_of(words[0], 2) << 8) | (_byte_of(words[1], 0) << 16) | (_byte_of(words[1], 2) << 24),
        _byte_of(words[2], 0) | (_byte_of(words[2], 2) << 8) | (_byte_of(words[3], 0) << 16) | (_byte_of(words[3], 2) << 24),
        _byte_of(words[0], 1) | (_byte_of(words[0], 3) << 8) | (_byte_of(words[1], 1) << 16) | (_byte_of(words[1], 3) << 24),
        _byte_of(words[2], 1) | (_byte_of(words[2], 3) << 8) | (_byte_of(words[3], 1) << 16) | (_byte_of(words[3], 3) << 24),
    ]


def _e3_fun(x: list[int]) -> tuple[int, int]:
    u = x[:]
    for _ in range(2):
        u = _pi_fun(_pi_fun(_pi_fun(_pi_fun(u))))
        v = _mix_words(u)
        u = [x[i] ^ v[i] for i in range(4)]
    u = _pi_fun(_pi_fun(_pi_fun(_pi_fun(u))))
    v = _mix_words(u)
    return v[0], v[1]


def _r_fun(blk: list[int], x_offset: int, y_offset: int, k: list[int]) -> None:
    tt = [blk[y_offset], blk[y_offset + 1], k[0], k[1]]
    r0, r1 = _e3_fun(tt)
    blk[x_offset] ^= r0
    blk[x_offset + 1] ^= r1


def _set_key(key: bytes) -> list[int]:
    k0 = _load_le32(key, 0)
    k1 = _load_le32(key, 4)
    k2 = _load_le32(key, 8)
    k3 = _load_le32(key, 12)
    return [k0, k1, k0, k1, k2, k3, k2, k3, k0, k1, k0, k1]


def _encrypt_words(l_key: list[int], in_blk: list[int]) -> list[int]:
    blk = in_blk[:]
    _r_fun(blk, 0, 2, l_key[0:2])
    _r_fun(blk, 2, 0, l_key[2:4])
    _r_fun(blk, 0, 2, l_key[4:6])
    _r_fun(blk, 2, 0, l_key[6:8])
    _r_fun(blk, 0, 2, l_key[8:10])
    _r_fun(blk, 2, 0, l_key[10:12])
    return blk


def _decrypt_words(l_key: list[int], in_blk: list[int]) -> list[int]:
    blk = [in_blk[2], in_blk[3], in_blk[0], in_blk[1]]
    _r_fun(blk, 0, 2, l_key[0:2])
    _r_fun(blk, 2, 0, l_key[2:4])
    _r_fun(blk, 0, 2, l_key[4:6])
    _r_fun(blk, 2, 0, l_key[6:8])
    _r_fun(blk, 0, 2, l_key[8:10])
    _r_fun(blk, 2, 0, l_key[10:12])
    return [blk[2], blk[3], blk[0], blk[1]]


def _encrypt_block(block: bytes, l_key: list[int]) -> bytes:
    words = [_load_le32(block, i) for i in range(0, BLOCK_SIZE, 4)]
    out = _encrypt_words(l_key, words)
    return b"".join(_store_le32(word) for word in out)


def _decrypt_block(block: bytes, l_key: list[int]) -> bytes:
    words = [_load_le32(block, i) for i in range(0, BLOCK_SIZE, 4)]
    out = _decrypt_words(l_key, words)
    return b"".join(_store_le32(word) for word in out)


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"iv must be {BLOCK_SIZE} bytes")
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError(f"plaintext length must be a multiple of {BLOCK_SIZE}")
    l_key = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(plaintext[i : i + BLOCK_SIZE], prev))
        enc = _encrypt_block(block, l_key)
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
    l_key = _set_key(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        dec = _decrypt_block(block, l_key)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)
