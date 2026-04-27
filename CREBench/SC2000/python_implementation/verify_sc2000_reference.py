from __future__ import annotations

import json
from pathlib import Path

from sc2000_reference import (
    decrypt_block,
    encrypt_block,
)


ROOT = Path(__file__).resolve().parents[1]
GENERATED_ROOT = ROOT / "challenge_src" / "generated"


def _verify_reference_roundtrip() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff00000000000000000000000000000000")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = encrypt_block(block, key)
    if decrypt_block(ciphertext, key) != block:
        raise AssertionError("reference SC2000 full-block roundtrip failed")


def _verify_vectors(path: Path) -> None:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    for index, vector in enumerate(vectors, start=1):
        plaintext = bytes.fromhex(vector["plaintext"])
        key = bytes.fromhex(vector["key"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        if encrypt_block(plaintext, key) != ciphertext:
            raise AssertionError(f"{path.name} vector {index}: encrypt mismatch")
        if decrypt_block(ciphertext, key) != plaintext:
            raise AssertionError(f"{path.name} vector {index}: decrypt mismatch")


def _verify_generated_mode(mode: str) -> None:
    metadata = json.loads((GENERATED_ROOT / mode / "metadata.json").read_text(encoding="utf-8"))
    key = bytes.fromhex(metadata["key"])
    ciphertext = bytes.fromhex(metadata["target_ciphertext"])
    flag = bytes.fromhex(metadata["flag"])
    if encrypt_block(flag, key) != ciphertext:
        raise AssertionError(f"{mode}: encrypt does not reproduce target ciphertext")
    if decrypt_block(ciphertext, key) != flag:
        raise AssertionError(f"{mode}: decrypt does not recover flag from target ciphertext")


def main() -> int:
    _verify_reference_roundtrip()
    print("[PASS] reference SC2000 128-bit encrypt/decrypt roundtrip")

    for vectors_name in [
        "test_vectors.json",
        "test_vectors-hardcode_plain.json",
        "test_vectors-fragmented_build.json",
        "test_vectors-weak_prng_seeded.json",
    ]:
        _verify_vectors(ROOT / vectors_name)
        print(f"[PASS] {vectors_name} encrypt/decrypt matches committed vectors")

    for mode in ["hardcode_plain", "fragmented_build", "weak_prng_seeded"]:
        _verify_generated_mode(mode)
        print(f"[PASS] generated/{mode}/metadata.json target ciphertext roundtrips to the flag")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
