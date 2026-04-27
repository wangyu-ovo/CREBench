from __future__ import annotations

import json
from pathlib import Path

from tea import decrypt, encrypt


ROOT = Path(__file__).resolve().parents[1]
GENERATED_ROOT = ROOT / "challenge_src" / "generated"


def _verify_vectors(path: Path) -> None:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    for index, vector in enumerate(vectors, start=1):
        plaintext = bytes.fromhex(vector["plaintext"])
        key = bytes.fromhex(vector["key"])
        ciphertext = bytes.fromhex(vector["ciphertext"])
        got_ciphertext = encrypt(plaintext, key)
        if got_ciphertext != ciphertext:
            raise AssertionError(f"{path.name} vector {index}: encrypt mismatch")
        got_plaintext = decrypt(ciphertext, key)
        if got_plaintext != plaintext:
            raise AssertionError(f"{path.name} vector {index}: decrypt mismatch")


def _verify_generated_mode(mode: str) -> None:
    metadata = json.loads((GENERATED_ROOT / mode / "metadata.json").read_text(encoding="utf-8"))
    key = bytes.fromhex(metadata["key"])
    ciphertext = bytes.fromhex(metadata["target_ciphertext"])
    flag = bytes.fromhex(metadata["flag"])
    if decrypt(ciphertext, key) != flag:
        raise AssertionError(f"{mode}: target ciphertext does not decrypt to flag")
    if encrypt(flag, key) != ciphertext:
        raise AssertionError(f"{mode}: flag does not encrypt to target ciphertext")


def main() -> int:
    for vectors_name in [
        "test_vectors.json",
        "test_vectors-hardcode_plain.json",
        "test_vectors-fragmented_build.json",
        "test_vectors-weak_prng_seeded.json",
    ]:
        _verify_vectors(ROOT / vectors_name)
        print(f"[PASS] {vectors_name}")

    for mode in ["hardcode_plain", "fragmented_build", "weak_prng_seeded"]:
        _verify_generated_mode(mode)
        print(f"[PASS] generated/{mode}/metadata.json target ciphertext decrypts to flag")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
