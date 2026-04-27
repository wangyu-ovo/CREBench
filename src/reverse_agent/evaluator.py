"""Evaluation logic for each level of the crypto reverse challenge."""

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional, Tuple

from .config import ChallengeConfig
from .environment import DockerEnvironment

logger = logging.getLogger(__name__)
HOST_CONDA_PREFIX = Path.home() / "miniconda3"


# ---------------------------------------------------------------------------
# Level 1: Algorithm identification
# ---------------------------------------------------------------------------

def normalize_algorithm_name(name: str) -> str:
    """Normalize algorithm name for comparison: lowercase, strip punctuation/spaces."""
    return re.sub(r'[\s\-_/]+', '', name.lower())


def score_algorithm(submitted: str, config: ChallengeConfig) -> Tuple[int, str]:
    """Score algorithm identification. Returns (score, explanation).

    Full match (canonical or alias): 25 points.
    """
    if not config.algorithm:
        return 0, "No ground truth algorithm configured."

    norm_submitted = normalize_algorithm_name(submitted)
    norm_canonical = normalize_algorithm_name(config.algorithm)

    # Exact match with canonical name
    if norm_submitted == norm_canonical:
        return 25, f"Exact match with canonical name '{config.algorithm}'."

    # Match with any alias
    for alias in config.algorithm_aliases:
        if normalize_algorithm_name(alias) == norm_submitted:
            return 25, f"Matched alias '{alias}'."

    # Partial match: check if the core algorithm family is correct
    # e.g. submitted "AES" for ground truth "AES-128-CBC" -> partial credit
    core_families = _extract_algorithm_family(config.algorithm)
    submitted_families = _extract_algorithm_family(submitted)
    if core_families and submitted_families and core_families == submitted_families:
        return 15, f"Partial match: correct algorithm family '{core_families}' but missing mode/params."

    return 0, f"No match. Expected '{config.algorithm}', got '{submitted}'."


def _extract_algorithm_family(name: str) -> Optional[str]:
    """Extract the core algorithm family (e.g. 'aes' from 'AES-128-CBC')."""
    norm = normalize_algorithm_name(name)
    # Remove common suffixes: block sizes, modes
    for mode in ['ecb', 'cbc', 'ctr', 'cfb', 'ofb', 'gcm']:
        norm = norm.replace(mode, '')
    # Remove numeric block/key sizes
    norm = re.sub(r'\d+', '', norm)
    return norm.strip() if norm.strip() else None


# ---------------------------------------------------------------------------
# Level 2: Key extraction
# ---------------------------------------------------------------------------

_NAMED_HEX_PATTERN = re.compile(r'([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*([0-9a-fA-F]{8,})')


def score_key_material(submitted: Any, config: ChallengeConfig) -> Tuple[int, str]:
    """Score Level 2 key extraction based on recovered key material.

    Full credit requires recovering all expected embedded key material
    (for example key, iv, nonce) from the reversed binary.
    Partial credit is proportional to the number of expected hex values found.
    """
    expected = config.level2_expected_material
    if not expected:
        return 0, "No ground truth key material configured."

    expected_items = _extract_expected_key_material(expected)
    if not expected_items:
        return 0, "Configured key material does not contain any extractable hex values."

    submitted_items = _extract_submitted_key_material(submitted)
    if not submitted_items:
        return 0, "Submission did not contain any extractable key material."

    matched_labels = []
    missing_labels = []

    for label, value in expected_items:
        submitted_value = submitted_items.get(label)
        if submitted_value and submitted_value.lower() == value.lower():
            matched_labels.append(label)
        else:
            missing_labels.append(label)

    matched = len(matched_labels)
    total = len(expected_items)
    score = round(25 * matched / total)

    if matched == total:
        labels = ", ".join(matched_labels)
        return 25, f"Recovered all expected key material: {labels}."

    if matched == 0:
        labels = ", ".join(missing_labels)
        return 0, f"No expected key material recovered. Missing: {labels}."

    matched_text = ", ".join(matched_labels)
    missing_text = ", ".join(missing_labels)
    return score, f"Partially recovered key material. Matched: {matched_text}. Missing: {missing_text}."


def _extract_expected_key_material(expected: str) -> list[tuple[str, str]]:
    """Extract labeled or unlabeled hex values from config key material."""
    named = [(label.lower(), value.lower()) for label, value in _NAMED_HEX_PATTERN.findall(expected)]
    if named:
        return named

    values = [value.lower() for value in re.findall(r'[0-9a-fA-F]{8,}', expected)]
    return [(f"value{i + 1}", value) for i, value in enumerate(values)]


def _extract_submitted_key_material(submitted: Any) -> dict[str, str]:
    if isinstance(submitted, dict):
        out: dict[str, str] = {}
        for key, value in submitted.items():
            if isinstance(key, str) and isinstance(value, str) and value.strip():
                out[key.lower()] = value.strip().lower()
        return out

    if isinstance(submitted, str):
        named = {
            label.lower(): value.lower()
            for label, value in _NAMED_HEX_PATTERN.findall(submitted)
        }
        if named:
            return named

    return {}


# ---------------------------------------------------------------------------
# Level 3: Code recovery (test vector validation)
# ---------------------------------------------------------------------------

TEST_HARNESS_TEMPLATE = '''#!/usr/bin/env python3
"""Auto-generated test harness for code recovery evaluation."""
import json
import re
import subprocess
import sys


def extract_ciphertext(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        raise ValueError("program produced no stdout")

    if re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return stripped.lower()

    match = re.search(r"Ciphertext\\(hex\\):\\s*([0-9a-fA-F]+)", text)
    if match:
        return match.group(1).lower()

    tokens = re.findall(r"\\b[0-9a-fA-F]{{8,}}\\b", text)
    if len(tokens) == 1:
        return tokens[0].lower()

    raise ValueError("could not parse ciphertext hex from stdout")


with open("{vectors_path}") as f:
    vectors = json.load(f)

passed = 0
total = len(vectors)
for i, v in enumerate(vectors):
    input_hex = v["plaintext"].lower()

    try:
        oracle = subprocess.run(
            [{challenge_binary_path}, input_hex],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if oracle.returncode not in (0, 1, 2):
            print(f"Test {{i+1}}/{{total}}: ERROR - oracle returncode={{oracle.returncode}}")
            if oracle.stdout.strip():
                print(f"  oracle stdout: {{oracle.stdout.strip()}}")
            if oracle.stderr.strip():
                print(f"  oracle stderr: {{oracle.stderr.strip()}}")
            continue

        expected_hex = extract_ciphertext(oracle.stdout)

        proc = subprocess.run(
            [sys.executable, "{submitted_path}", input_hex],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            print(f"Test {{i+1}}/{{total}}: ERROR - returncode={{proc.returncode}}")
            if proc.stdout.strip():
                print(f"  stdout: {{proc.stdout.strip()}}")
            if proc.stderr.strip():
                print(f"  stderr: {{proc.stderr.strip()}}")
            continue

        actual_hex = extract_ciphertext(proc.stdout)
        if actual_hex == expected_hex:
            passed += 1
            print(f"Test {{i+1}}/{{total}}: PASS")
        else:
            print(f"Test {{i+1}}/{{total}}: FAIL")
            print(f"  input:    {{input_hex}}")
            print(f"  expected: {{expected_hex}}")
            print(f"  got:      {{actual_hex}}")
    except Exception as e:
        print(f"Test {{i+1}}/{{total}}: ERROR - {{e}}")

print(f"\\nResult: {{passed}}/{{total}} passed")
sys.exit(0 if passed == total else 1)
'''


def _candidate_oracle_paths(config: ChallengeConfig) -> list[Path]:
    candidates: list[Path] = []

    if config.public_path:
        for name in ("challenge", "a.out"):
            candidate = (config.public_path / name).resolve()
            if candidate not in candidates:
                candidates.append(candidate)

    builder_artifact = config.level3_validation.get("builder_artifact")
    if builder_artifact and config.challenge_path is not None:
        candidate = (config.challenge_path / builder_artifact).resolve()
        if candidate not in candidates:
            candidates.append(candidate)

    return candidates


def _locate_existing_oracle_binary(config: ChallengeConfig) -> Path | None:
    for candidate in _candidate_oracle_paths(config):
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _build_oracle_binary(host_output_dir: Path, config: ChallengeConfig) -> Path:
    if config.challenge_path is None:
        raise RuntimeError("challenge_path is required to build a host-side oracle binary")
    if config.mode_metadata_path is None:
        raise RuntimeError("mode_metadata_path is required to build a host-side oracle binary")

    generated_dir = config.mode_metadata_path.parent.resolve()
    required_generated = [generated_dir / "challenge.c", generated_dir / "key_source.c"]
    missing_generated = [str(path) for path in required_generated if not path.exists()]
    if missing_generated:
        raise FileNotFoundError(
            "missing generated challenge sources for host-side Level 3 evaluation: "
            + ", ".join(missing_generated)
        )

    challenge_src_dir = (config.challenge_path / "challenge_src").resolve()
    makefile_path = challenge_src_dir / "Makefile"
    src_dir = (config.challenge_path / "src").resolve()
    if not makefile_path.exists():
        raise FileNotFoundError(f"missing challenge_src Makefile: {makefile_path}")
    if not src_dir.exists():
        raise FileNotFoundError(f"missing challenge source directory: {src_dir}")

    build_root = host_output_dir / "_oracle_build"
    if build_root.exists():
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True, exist_ok=True)

    staged_challenge_src = build_root / "challenge_src"
    staged_src = build_root / "src"
    staged_public = build_root / "public"
    staged_challenge_src.mkdir(parents=True, exist_ok=True)
    staged_public.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_dir, staged_src)
    shutil.copy2(makefile_path, staged_challenge_src / "Makefile")
    shutil.copy2(generated_dir / "challenge.c", staged_challenge_src / "challenge.c")
    shutil.copy2(generated_dir / "key_source.c", staged_challenge_src / "key_source.c")

    result = subprocess.run(
        ["make", "-C", str(staged_challenge_src)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
        raise RuntimeError(
            "Host-side Level 3 oracle build failed.\n"
            f"{combined}"
        )

    oracle_path = staged_public / "challenge"
    if not oracle_path.exists():
        raise FileNotFoundError(f"host-side Level 3 oracle build did not produce {oracle_path}")
    return oracle_path


def run_code_tests(
    code: str,
    config: ChallengeConfig,
    env: DockerEnvironment,
) -> Tuple[int, int, int]:
    """Write submitted code to the host run directory and evaluate on the host.

    Returns (score, passed, total).
    Score: 25 * (passed / total).
    """
    if not config.test_vectors_path or not config.test_vectors_path.exists():
        return 0, 0, 0
    if env.host_output_dir is None:
        raise RuntimeError("host_output_dir is required for host-side Level 3 evaluation")

    # Load test vectors to know the count
    with open(config.test_vectors_path) as f:
        vectors = json.load(f)
    total = len(vectors)

    host_output_dir = Path(env.host_output_dir).resolve()
    host_output_dir.mkdir(parents=True, exist_ok=True)
    challenge_binary = _locate_existing_oracle_binary(config)
    if challenge_binary is None:
        challenge_binary = _build_oracle_binary(host_output_dir, config)

    # Save submitted code in the host run directory. The evaluator always executes main.py.
    submitted_path = host_output_dir / "main.py"
    submitted_path.write_text(code, encoding="utf-8")

    vectors_path = host_output_dir / "test_vectors.json"
    vectors_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")

    # Generate and write host-side test harness
    harness_code = TEST_HARNESS_TEMPLATE.format(
        challenge_binary_path=json.dumps(str(challenge_binary)),
        submitted_path=str(submitted_path),
        vectors_path=str(vectors_path),
    )
    harness_path = host_output_dir / "test_harness.py"
    harness_path.write_text(harness_code, encoding="utf-8")

    conda_sh = HOST_CONDA_PREFIX / "etc" / "profile.d" / "conda.sh"
    if not conda_sh.exists():
        raise FileNotFoundError(f"missing conda activation script: {conda_sh}")

    command = (
        f'source {shlex_quote(str(conda_sh))} && '
        "conda activate crypto && "
        f'python3 {shlex_quote(str(harness_path))}'
    )
    result = subprocess.run(
        ["/bin/bash", "-lc", command],
        cwd=host_output_dir,
        text=True,
        capture_output=True,
        check=False,
    )

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    output = stdout
    if stderr:
        output += f"\nSTDERR:\n{stderr}"

    combined = "\n".join(part for part in (stdout, stderr) if part)
    if re.search(r"(ModuleNotFoundError|ImportError):", combined):
        raise RuntimeError(
            "Host-side Level 3 evaluation failed due to an import error.\n"
            f"{combined}"
        )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Host-side Level 3 evaluation harness failed unexpectedly.\n"
            f"{combined}"
        )

    # Parse results
    passed = _parse_test_results(stdout, total)
    score = round(25 * passed / total) if total > 0 else 0

    return score, passed, total


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _parse_test_results(stdout: str, total: int) -> int:
    """Parse 'Result: X/Y passed' from test harness output."""
    match = re.search(r'Result:\s*(\d+)/(\d+)\s*passed', stdout)
    if match:
        return int(match.group(1))
    # Fallback: count PASS lines
    return stdout.count(': PASS')
