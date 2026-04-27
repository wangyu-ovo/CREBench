from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


BLOCK_SIZE = 8
KEY_SIZE = 16
ROUNDS = 6
_MOD = 0xF5
_I_G = (
    (0xE7, 0x30, 0x90, 0x85, 0xD0, 0x4B, 0x91, 0x41),
    (0x53, 0x95, 0x9B, 0xA5, 0x96, 0xBC, 0xA1, 0x68),
    (0x02, 0x45, 0xF7, 0x65, 0x5C, 0x1F, 0xB6, 0x52),
    (0xA2, 0xCA, 0x22, 0x94, 0x44, 0x63, 0x2A, 0xA2),
    (0xFC, 0x67, 0x8E, 0x10, 0x29, 0x75, 0x85, 0x71),
    (0x24, 0x45, 0xA2, 0xCF, 0x2F, 0x22, 0xC1, 0x0E),
    (0xA1, 0xF1, 0x71, 0x40, 0x91, 0x27, 0x18, 0xA5),
    (0x56, 0xF4, 0xAF, 0x32, 0xD2, 0xA4, 0xDC, 0x71),
)


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


def _byte_reverse64(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


def _get_byte(word: int, index: int) -> int:
    return (word >> (index * 8)) & 0xFF


@lru_cache(maxsize=1)
def _load_tables() -> tuple[list[int], list[list[int]]]:
    source = (Path(__file__).resolve().parents[1] / "src" / "shark-constant.c").read_text(encoding="utf-8")
    sbox_match = re.search(r"const uint8_t sbox\[256\] = \{(.*?)\};", source, re.S)
    if sbox_match is None:
        raise RuntimeError("failed to parse sbox")
    sbox = [int(token) for token in re.findall(r"\b\d+\b", sbox_match.group(1))]
    if len(sbox) != 256:
        raise RuntimeError(f"expected 256 sbox entries, got {len(sbox)}")

    values = [int(token, 16) for token in re.findall(r"0x([0-9a-fA-F]+)ULL", source)]
    if len(values) != 8 * 256:
        raise RuntimeError(f"expected 2048 cbox entries, got {len(values)}")
    cbox = [values[index * 256 : (index + 1) * 256] for index in range(8)]
    return sbox, cbox


@lru_cache(maxsize=1)
def _inverse_sbox() -> list[int]:
    sbox, _ = _load_tables()
    inv = [0] * 256
    for index, value in enumerate(sbox):
        inv[value] = index
    return inv


def _shark_transform(value: int) -> int:
    result = 0
    for row in range(8):
        for column in range(8):
            result ^= _gmul(_I_G[row][column], (value >> (56 - 8 * column)) & 0xFF) << (56 - 8 * row)
    return result


def _enc_with_transformed_key(block: int, round_keys: list[int]) -> int:
    sbox, cbox = _load_tables()
    temp = block ^ round_keys[0]
    temp = (
        cbox[0][_get_byte(temp, 0)]
        ^ cbox[1][_get_byte(temp, 1)]
        ^ cbox[2][_get_byte(temp, 2)]
        ^ cbox[3][_get_byte(temp, 3)]
        ^ cbox[4][_get_byte(temp, 4)]
        ^ cbox[5][_get_byte(temp, 5)]
        ^ cbox[6][_get_byte(temp, 6)]
        ^ cbox[7][_get_byte(temp, 7)]
        ^ round_keys[1]
    )
    for round_index in range(2, ROUNDS):
        temp = (
            cbox[0][_get_byte(temp, 7)]
            ^ cbox[1][_get_byte(temp, 6)]
            ^ cbox[2][_get_byte(temp, 5)]
            ^ cbox[3][_get_byte(temp, 4)]
            ^ cbox[4][_get_byte(temp, 3)]
            ^ cbox[5][_get_byte(temp, 2)]
            ^ cbox[6][_get_byte(temp, 1)]
            ^ cbox[7][_get_byte(temp, 0)]
            ^ round_keys[round_index]
        )

    result = 0
    for index in range(8):
        result |= sbox[_get_byte(temp, index)] << (8 * (7 - index))
    return result ^ round_keys[ROUNDS]


def _enc_with_transformed_key_cbc(blocks: list[int], round_keys: list[int], iv: int) -> list[int]:
    prev = iv
    out: list[int] = []
    for block in blocks:
        encrypted = _enc_with_transformed_key(prev, round_keys) ^ _byte_reverse64(block)
        out.append(encrypted)
        prev = encrypted
    return out


def _key_schedule(key: bytes) -> list[int]:
    round_keys = [0] * (ROUNDS + 1)
    for index in range(2):
        round_keys[index] = int.from_bytes(key[index * 8 : (index + 1) * 8], "big")
    for index in range(2, ROUNDS + 1):
        round_keys[index] = round_keys[index - 2]

    _, cbox = _load_tables()
    temp_keys = []
    for index in range(ROUNDS + 1):
        value = cbox[0][index]
        if index == 0:
            value = _byte_reverse64(value)
        elif index == ROUNDS:
            value = _byte_reverse64(_shark_transform(value))
        temp_keys.append(value)

    round_keys = _enc_with_transformed_key_cbc(round_keys, temp_keys, 0)
    for index in range(1, ROUNDS + 1):
        round_keys[index] = _byte_reverse64(round_keys[index])
    round_keys[ROUNDS] = _byte_reverse64(_shark_transform(round_keys[ROUNDS]))
    return round_keys


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"SHARK block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"SHARK key must be {KEY_SIZE} bytes")
    round_keys = _key_schedule(key)
    block_value = int.from_bytes(block, "little")
    encrypted = _enc_with_transformed_key(block_value, round_keys)
    return encrypted.to_bytes(8, "little")


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"SHARK block must be {BLOCK_SIZE} bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"SHARK key must be {KEY_SIZE} bytes")

    inv_sbox = _inverse_sbox()
    round_keys = _key_schedule(key)
    state = int.from_bytes(block, "little") ^ round_keys[ROUNDS]

    temp = 0
    for index in range(8):
        value = inv_sbox[(state >> (8 * (7 - index))) & 0xFF]
        temp |= value << (8 * index)
    state = temp

    for round_index in range(ROUNDS - 1, 1, -1):
        transformed = _shark_transform(state ^ round_keys[round_index])
        temp = 0
        for index in range(8):
            value = inv_sbox[(transformed >> (56 - 8 * index)) & 0xFF]
            temp |= value << (8 * (7 - index))
        state = temp

    transformed = _shark_transform(state ^ round_keys[1])
    temp = 0
    for index in range(8):
        value = inv_sbox[(transformed >> (56 - 8 * index)) & 0xFF]
        temp |= value << (8 * index)
    state = temp ^ round_keys[0]
    return state.to_bytes(8, "little")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    return encrypt_block(plaintext, key)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return decrypt_block(ciphertext, key)
