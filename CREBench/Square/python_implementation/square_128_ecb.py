from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


BLOCK_SIZE = 16
KEY_SIZE = 16
ROUNDS = 8
_MOD = 0xF5
_MIX = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)
_INV_MIX = (
    (14, 11, 13, 9),
    (9, 14, 11, 13),
    (13, 9, 14, 11),
    (11, 13, 9, 14),
)


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def _gmul(a: int, b: int) -> int:
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= _MOD
        b >>= 1
    return product


@lru_cache(maxsize=1)
def _load_tables() -> tuple[list[int], list[list[int]]]:
    source = (Path(__file__).resolve().parents[1] / "src" / "square-constant.c").read_text(encoding="utf-8")

    se_match = re.search(r"const uint8_t Se\[256\] = \{(.*?)\};", source, re.S)
    if se_match is None:
        raise RuntimeError("failed to parse Se")
    se_values = [int(token) for token in re.findall(r"\b\d+\b", se_match.group(1))]
    if len(se_values) != 256:
        raise RuntimeError(f"expected 256 Se values, got {len(se_values)}")

    te_match = re.search(
        r"const uint32_t Te\[4\]\[256\] = \{\s*\{(.*?)\},\s*\{(.*?)\},\s*\{(.*?)\},\s*\{(.*?)\}\s*\};",
        source,
        re.S,
    )
    if te_match is None:
        raise RuntimeError("failed to parse Te")
    te_tables: list[list[int]] = []
    for group in te_match.groups():
        table = [int(token, 16) for token in re.findall(r"0x([0-9a-fA-F]+)UL", group)]
        if len(table) != 256:
            raise RuntimeError(f"expected 256 Te values, got {len(table)}")
        te_tables.append(table)
    return se_values, te_tables


@lru_cache(maxsize=1)
def _inverse_sbox() -> list[int]:
    se, _ = _load_tables()
    inv = [0] * 256
    for index, value in enumerate(se):
        inv[value] = index
    return inv


def _bytes_to_words(block: bytes) -> list[int]:
    return [int.from_bytes(block[index : index + 4], "big") for index in range(0, BLOCK_SIZE, 4)]


def _words_to_bytes(words: list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "big") for word in words)


def _get_byte(word: int, index: int) -> int:
    return (word >> (index * 8)) & 0xFF


def _set_byte(word: int, index_from_msb: int, value: int) -> int:
    shift = (3 - index_from_msb) * 8
    mask = 0xFF << shift
    return (word & ~mask) | ((value & 0xFF) << shift)


def _square_transform(words: list[int]) -> list[int]:
    out = [0] * 4
    for i in range(4):
        word = words[i]
        temp = 0
        for j in range(4):
            result_byte = 0
            for k in range(4):
                input_byte = _get_byte(word, 3 - k)
                result_byte ^= _gmul(input_byte, ((2, 1, 1, 3), (3, 2, 1, 1), (1, 3, 2, 1), (1, 1, 3, 2))[k][j])
            temp |= result_byte << ((3 - j) * 8)
        out[i] = temp
    return out


def _key_schedule(key: bytes) -> list[int]:
    round_keys = [0] * ((ROUNDS + 1) * 4)
    initial = _bytes_to_words(key)
    round_keys[0:4] = initial
    offsets = (
        0x01000000,
        0x02000000,
        0x04000000,
        0x08000000,
        0x10000000,
        0x20000000,
        0x40000000,
        0x80000000,
    )
    for round_index in range(1, ROUNDS + 1):
        base = round_index * 4
        prev = (round_index - 1) * 4
        round_keys[base + 0] = round_keys[prev + 0] ^ _rotl32(round_keys[prev + 3], 8) ^ offsets[round_index - 1]
        round_keys[base + 1] = round_keys[prev + 1] ^ round_keys[base + 0]
        round_keys[base + 2] = round_keys[prev + 2] ^ round_keys[base + 1]
        round_keys[base + 3] = round_keys[prev + 3] ^ round_keys[base + 2]
    for round_index in range(ROUNDS):
        base = round_index * 4
        round_keys[base : base + 4] = _square_transform(round_keys[base : base + 4])
    return round_keys


def _square_round(words: list[int], round_key: list[int], te: list[list[int]]) -> list[int]:
    out = [0] * 4
    for word_index in range(4):
        shift = 24 - (word_index * 8)
        out[word_index] = (
            te[0][(words[0] >> shift) & 0xFF]
            ^ te[1][(words[1] >> shift) & 0xFF]
            ^ te[2][(words[2] >> shift) & 0xFF]
            ^ te[3][(words[3] >> shift) & 0xFF]
            ^ round_key[word_index]
        )
    return out


def _square_final(words: list[int], round_key: list[int], se: list[int]) -> list[int]:
    out = [0] * 4
    for word_index in range(4):
        shift = 24 - (word_index * 8)
        out[word_index] = (
            (se[(words[0] >> shift) & 0xFF] << 24)
            ^ (se[(words[1] >> shift) & 0xFF] << 16)
            ^ (se[(words[2] >> shift) & 0xFF] << 8)
            ^ se[(words[3] >> shift) & 0xFF]
            ^ round_key[word_index]
        )
    return out


def _mul_vector(matrix: tuple[tuple[int, ...], ...], values: list[int]) -> list[int]:
    out = [0] * 4
    for row_index, row in enumerate(matrix):
        acc = 0
        for coeff, value in zip(row, values):
            acc ^= _gmul(value, coeff)
        out[row_index] = acc
    return out


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Square block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Square key must be {KEY_SIZE} bytes")

    se, te = _load_tables()
    round_keys = _key_schedule(key)
    state = _bytes_to_words(block)

    for round_index in range(ROUNDS):
        round_key = round_keys[round_index * 4 : (round_index + 1) * 4]
        if round_index == 0:
            state = [(word ^ rk) & 0xFFFFFFFF for word, rk in zip(state, round_key)]
        else:
            state = _square_round(state, round_key, te)
    state = _square_final(state, round_keys[ROUNDS * 4 : (ROUNDS + 1) * 4], se)
    return _words_to_bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"Square block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Square key must be {KEY_SIZE} bytes")

    se, _ = _load_tables()
    inv_se = _inverse_sbox()
    round_keys = _key_schedule(key)
    state = _bytes_to_words(block)

    prev = [0] * 4
    final_key = round_keys[ROUNDS * 4 : (ROUNDS + 1) * 4]
    for position in range(4):
        word = state[position] ^ final_key[position]
        bytes_out = [(word >> shift) & 0xFF for shift in (24, 16, 8, 0)]
        for source_word, byte_value in enumerate(bytes_out):
            prev[source_word] = _set_byte(prev[source_word], position, inv_se[byte_value])
    state = prev

    for round_index in range(ROUNDS - 1, 0, -1):
        prev = [0] * 4
        round_key = round_keys[round_index * 4 : (round_index + 1) * 4]
        for position in range(4):
            word = state[position] ^ round_key[position]
            mixed = [(word >> shift) & 0xFF for shift in (24, 16, 8, 0)]
            s_values = _mul_vector(_INV_MIX, mixed)
            plain_bytes = [inv_se[value] for value in s_values]
            for source_word, byte_value in enumerate(plain_bytes):
                prev[source_word] = _set_byte(prev[source_word], position, byte_value)
        state = prev

    state = [(word ^ rk) & 0xFFFFFFFF for word, rk in zip(state, round_keys[0:4])]
    return _words_to_bytes(state)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    return encrypt_block(plaintext, key)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return decrypt_block(ciphertext, key)
