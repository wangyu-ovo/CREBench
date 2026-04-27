#!/usr/bin/env python3
"""Run pass@k reverse-eval suites with local resume support."""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.reverse_agent.llm import resolve_provider_for_model

C_ALL_DIR = REPO_ROOT / "CREBench" 
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "outputs" / "passk"
SUPPORTED_KEY_MODES = ["hardcode_plain", "fragmented_build", "weak_prng_seeded"]
SUPPORTED_DIFFICULTIES = ["O0", "O3", "constxor"]
ALL_SUITE_DIFFICULTIES = ["O0", "O3", "constxor"]
EXCLUDED_CHALLENGE_NAMES = {"Classic", "__pycache__"}
DEFAULT_CONTAINER_MEMORY = "8g"
DEFAULT_CONTAINER_CPUS = "4"
DEFAULT_CONTAINER_PIDS_LIMIT = 512
DEFAULT_CONTAINER_NETWORK = "bridge"
LEVEL_FIELDS = [
    ("level1_score", "level1_algorithm"),
    ("level2_score", "level2_key"),
    ("level3_score", "level3_code"),
    ("level4_score", "level4_flag"),
]
TASK_LABELS = {
    "level1_score": "algorithm",
    "level2_score": "key",
    "level3_score": "code",
    "level4_score": "flag",
}


@dataclass(frozen=True)
class CaseSpec:
    suite_index: int
    total_cases: int
    challenge_path: Path
    challenge_name: str
    key_mode: str | None
    mode_label: str
    difficulty: str
    difficulty_dir_name: str
    case_id: str


@dataclass(frozen=True)
class AttemptSpec:
    case: CaseSpec
    attempt_index: int
    run_output_dir: Path
    max_tokens: int
    max_rounds: int

    @property
    def attempt_id(self) -> str:
        return f"{self.case.case_id}::attempt-{self.attempt_index}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_suite_name(model: str, pass_k: int) -> str:
    sanitized = "".join(ch.lower() if ch.isalnum() else "-" for ch in model)
    while "--" in sanitized:
        sanitized = sanitized.replace("--", "-")
    sanitized = sanitized.strip("-")
    return f"{sanitized}-pass{pass_k}"


def _tail(text: str, limit: int = 4000) -> str:
    return text[-limit:] if text else ""


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_official_challenge_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    if path.name.startswith("DIAG-") or path.name in EXCLUDED_CHALLENGE_NAMES:
        return False
    return (path / "config.yaml").exists()


def _discover_challenges(selected: list[str], use_all: bool) -> list[Path]:
    if use_all:
        return sorted(path for path in C_ALL_DIR.iterdir() if _is_official_challenge_dir(path))
    if not selected:
        raise ValueError("select challenges with --challenge or pass --all-c-all")
    paths: list[Path] = []
    for name in selected:
        path = C_ALL_DIR / name
        if not _is_official_challenge_dir(path):
            raise FileNotFoundError(f"missing challenge config: {path / 'config.yaml'}")
        paths.append(path)
    return paths


def _expand_difficulties(requested: str) -> list[str]:
    if requested == "ALL":
        return ALL_SUITE_DIFFICULTIES.copy()
    return [requested]


def _read_mem_available_gib() -> float | None:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None
    try:
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                kib = int(parts[1])
                return kib / 1024 / 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _parse_memory_limit_gib(value: str | None) -> float | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    units = {
        "kb": 1 / (1024 ** 2),
        "k": 1 / (1024 ** 2),
        "mb": 1 / 1024,
        "m": 1 / 1024,
        "gb": 1,
        "g": 1,
        "tb": 1024,
        "t": 1024,
        "b": 1 / (1024 ** 3),
    }
    for suffix, multiplier in units.items():
        if normalized.endswith(suffix):
            number = normalized[: -len(suffix)].strip()
            if not number:
                return None
            return float(number) * multiplier
    return float(normalized) / (1024 ** 3)


def _resolve_jobs(requested_jobs: int | None, memory_gib_per_run: float) -> tuple[int, dict[str, Any]]:
    cpu_count = max(os.cpu_count() or 1, 1)
    mem_available_gib = _read_mem_available_gib()
    cpu_based_limit = max(1, cpu_count // 2)
    if mem_available_gib is None:
        memory_based_limit = cpu_based_limit
    else:
        memory_based_limit = max(1, int(mem_available_gib // memory_gib_per_run))
    host_max_jobs = max(1, min(cpu_based_limit, memory_based_limit))
    if requested_jobs is None:
        resolved_jobs = host_max_jobs
    else:
        if requested_jobs <= 0:
            raise ValueError("--jobs must be a positive integer")
        resolved_jobs = min(requested_jobs, host_max_jobs)
    details = {
        "cpu_count": cpu_count,
        "mem_available_gib": round(mem_available_gib, 2) if mem_available_gib is not None else None,
        "memory_gib_per_run_budget": round(memory_gib_per_run, 2),
        "cpu_based_limit": cpu_based_limit,
        "memory_based_limit": memory_based_limit,
        "host_max_jobs": host_max_jobs,
        "requested_jobs": requested_jobs,
        "resolved_jobs": resolved_jobs,
    }
    return resolved_jobs, details


def _score_fields(score: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "total_score": int(score.get("total_score", 0)),
        "max_total": int(score.get("max_total", 100)),
    }
    for short_name, score_key in LEVEL_FIELDS:
        fields[short_name] = int(score.get(score_key, {}).get("score", 0))
    return fields


def _attempt_record_base(attempt: AttemptSpec) -> dict[str, Any]:
    return {
        "attempt_id": attempt.attempt_id,
        "case_id": attempt.case.case_id,
        "attempt_index": attempt.attempt_index,
        "suite_index": attempt.case.suite_index,
        "total_cases": attempt.case.total_cases,
        "challenge": attempt.case.challenge_name,
        "key_mode": attempt.case.key_mode,
        "mode_label": attempt.case.mode_label,
        "difficulty": attempt.case.difficulty,
        "difficulty_dir_name": attempt.case.difficulty_dir_name,
        "output_dir": str(attempt.run_output_dir),
        "max_tokens": attempt.max_tokens,
        "max_rounds": attempt.max_rounds,
        "imported": False,
    }


def _augment_record_with_outputs(record: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    score_path = output_dir / "score.json"
    metrics_path = output_dir / "run_metrics.json"
    metadata_path = output_dir / "run_metadata.json"
    if score_path.exists():
        try:
            score = _load_json(score_path)
            record.update(_score_fields(score))
            record["score_exists"] = True
        except Exception as exc:
            record["score_exists"] = False
            record["score_error"] = str(exc)
    else:
        record["score_exists"] = False
    if metrics_path.exists():
        try:
            metrics = _load_json(metrics_path)
            record["metrics_exists"] = True
            record["rounds_used"] = int(metrics.get("rounds_used", 0))
            record["model_turns"] = int(metrics.get("model_turns", metrics.get("rounds_used", 0)))
            record["parse_error_count"] = int(metrics.get("parse_error_count", 0))
            record["stop_reason"] = str(metrics.get("stop_reason", ""))
            record["duration_seconds"] = float(metrics.get("duration_seconds", 0.0))
            llm_usage = metrics.get("llm_usage", {})
            record["total_tokens"] = int(llm_usage.get("total_tokens", 0))
            record["input_tokens"] = int(llm_usage.get("input_tokens", 0))
            record["output_tokens"] = int(llm_usage.get("output_tokens", 0))
            record["estimated_cost"] = float(llm_usage.get("estimated_cost", 0.0))
            record["tool_metrics"] = metrics.get("tool_metrics", {})
        except Exception as exc:
            record["metrics_exists"] = False
            record["metrics_error"] = str(exc)
    else:
        record["metrics_exists"] = False
    if metadata_path.exists():
        try:
            metadata = _load_json(metadata_path)
            record["metadata_exists"] = True
            record["provider"] = metadata.get("provider", record.get("provider"))
            record["model"] = metadata.get("model", record.get("model"))
            record["challenge_name"] = metadata.get("challenge_name", record.get("challenge"))
        except Exception as exc:
            record["metadata_exists"] = False
            record["metadata_error"] = str(exc)
    else:
        record["metadata_exists"] = False
    return record


def _build_case_specs(
    challenges: list[Path],
    key_modes: list[str | None],
    difficulties: list[str],
) -> list[CaseSpec]:
    specs: list[CaseSpec] = []
    total_cases = len(challenges) * len(key_modes) * len(difficulties)
    suite_index = 0
    for challenge_path in challenges:
        for key_mode in key_modes:
            mode_label = key_mode or "default"
            for difficulty in difficulties:
                suite_index += 1
                challenge_name = challenge_path.name
                difficulty_dir_name = f"public-{key_mode}-{difficulty}" if key_mode else f"public-{difficulty}"
                case_id = f"{challenge_name}::{mode_label}::{difficulty}"
                specs.append(
                    CaseSpec(
                        suite_index=suite_index,
                        total_cases=total_cases,
                        challenge_path=challenge_path,
                        challenge_name=challenge_name,
                        key_mode=key_mode,
                        mode_label=mode_label,
                        difficulty=difficulty,
                        difficulty_dir_name=difficulty_dir_name,
                        case_id=case_id,
                    )
                )
    return specs


def _load_existing_manifest(manifest_path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if not manifest_path.exists():
        return None, [], {}
    manifest = _load_json(manifest_path)
    ordered = list(manifest.get("attempts", []))
    by_id = {str(record["attempt_id"]): record for record in ordered if "attempt_id" in record}
    return manifest, ordered, by_id


def _validate_resume_manifest(
    existing_manifest: dict[str, Any] | None,
    *,
    suite_dir: Path,
    model: str,
    pass_k: int,
    eval_mode: str,
) -> None:
    if existing_manifest is None:
        return
    mismatches: list[str] = []
    if str(existing_manifest.get("model")) != model:
        mismatches.append(f"model={existing_manifest.get('model')!r} != {model!r}")
    if int(existing_manifest.get("pass_k", pass_k)) != pass_k:
        mismatches.append(f"pass_k={existing_manifest.get('pass_k')!r} != {pass_k!r}")
    existing_eval_mode = existing_manifest.get("eval_mode")
    if existing_eval_mode is not None and str(existing_eval_mode) != eval_mode:
        mismatches.append(f"eval_mode={existing_eval_mode!r} != {eval_mode!r}")
    if mismatches:
        mismatch_text = ", ".join(mismatches)
        raise ValueError(f"resume suite {suite_dir} is incompatible: {mismatch_text}")


def _collect_local_attempt_records(suite_dir: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    runs_dir = suite_dir / "runs"
    if not runs_dir.exists():
        return records
    for score_path in runs_dir.rglob("score.json"):
        attempt_dir = score_path.parent
        rel = attempt_dir.relative_to(runs_dir)
        if len(rel.parts) < 4:
            continue
        challenge, mode_label, difficulty, attempt_label = rel.parts[:4]
        if not attempt_label.startswith("attempt-"):
            continue
        attempt_index = int(attempt_label.split("-", 1)[1])
        case_id = f"{challenge}::{mode_label}::{difficulty}"
        record = {
            "attempt_id": f"{case_id}::attempt-{attempt_index}",
            "case_id": case_id,
            "attempt_index": attempt_index,
            "challenge": challenge,
            "key_mode": None if mode_label == "default" else mode_label,
            "mode_label": mode_label,
            "difficulty": difficulty,
            "output_dir": str(attempt_dir),
            "imported": False,
            "returncode": 0,
            "timed_out": False,
            "skipped": False,
            "dry_run": False,
        }
        records[record["attempt_id"]] = _augment_record_with_outputs(record, attempt_dir)
    return records


def _persist_manifest(
    manifest_path: Path,
    manifest: dict[str, Any],
    ordered_attempt_ids: list[str],
    records_by_attempt_id: dict[str, dict[str, Any]],
) -> None:
    manifest["attempts"] = [records_by_attempt_id[attempt_id] for attempt_id in ordered_attempt_ids if attempt_id in records_by_attempt_id]
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _is_perfect(record: dict[str, Any]) -> bool:
    return int(record.get("total_score", 0)) >= 100


def _completed_attempt_numbers(case_id: str, records_by_attempt_id: dict[str, dict[str, Any]]) -> list[int]:
    numbers: list[int] = []
    for record in records_by_attempt_id.values():
        if record.get("case_id") != case_id:
            continue
        if not (record.get("score_exists", False) or record.get("consumed", False)):
            continue
        numbers.append(int(record.get("attempt_index", 0)))
    return sorted(set(numbers))


def _best_record_for_case(case_id: str, records_by_attempt_id: dict[str, dict[str, Any]], max_attempt_index: int) -> dict[str, Any] | None:
    candidates = [
        record
        for record in records_by_attempt_id.values()
        if record.get("case_id") == case_id
        and int(record.get("attempt_index", 0)) <= max_attempt_index
        and record.get("score_exists", False)
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda record: (
            int(record.get("total_score", 0)),
            int(record.get("level4_score", 0)),
            int(record.get("level3_score", 0)),
            int(record.get("level2_score", 0)),
            int(record.get("level1_score", 0)),
        ),
    )


def _has_perfect_before(case_id: str, records_by_attempt_id: dict[str, dict[str, Any]], max_attempt_index: int) -> bool:
    return any(
        record.get("case_id") == case_id
        and int(record.get("attempt_index", 0)) <= max_attempt_index
        and record.get("score_exists", False)
        and _is_perfect(record)
        for record in records_by_attempt_id.values()
    )


def _has_terminal_skip(case_id: str, records_by_attempt_id: dict[str, dict[str, Any]]) -> bool:
    return any(
        record.get("case_id") == case_id
        and str(record.get("skip_reason", "")).startswith("missing ")
        for record in records_by_attempt_id.values()
    )


def _next_attempt_to_schedule(
    case: CaseSpec,
    pass_k: int,
    records_by_attempt_id: dict[str, dict[str, Any]],
    suite_dir: Path,
    max_tokens: int,
    max_rounds: int,
) -> AttemptSpec | None:
    if _has_perfect_before(case.case_id, records_by_attempt_id, pass_k):
        return None
    if _has_terminal_skip(case.case_id, records_by_attempt_id):
        return None
    completed = set(_completed_attempt_numbers(case.case_id, records_by_attempt_id))
    for attempt_index in range(1, pass_k + 1):
        if attempt_index in completed:
            continue
        run_output_dir = suite_dir / "runs" / case.challenge_name / case.mode_label / case.difficulty / f"attempt-{attempt_index}"
        return AttemptSpec(
            case=case,
            attempt_index=attempt_index,
            run_output_dir=run_output_dir,
            max_tokens=max_tokens,
            max_rounds=max_rounds,
        )
    return None


def _execute_attempt(spec: AttemptSpec, args: argparse.Namespace) -> dict[str, Any]:
    record = _attempt_record_base(spec)
    record["started_at"] = _now_iso()

    difficulty_path = spec.case.challenge_path / spec.case.difficulty_dir_name
    if not difficulty_path.exists():
        record.update(
            {
                "returncode": None,
                "timed_out": False,
                "skipped": True,
                "skip_reason": f"missing {spec.case.difficulty_dir_name}",
                "stdout_tail": "",
                "stderr_tail": "",
                "dry_run": args.dry_run,
                "completed_at": _now_iso(),
                "consumed": True,
            }
        )
        return record

    if args.dry_run:
        record.update(
            {
                "returncode": 0,
                "timed_out": False,
                "skipped": False,
                "stdout_tail": "",
                "stderr_tail": "",
                "dry_run": True,
                "completed_at": _now_iso(),
                "consumed": True,
                "score_exists": True,
                "total_score": 0,
                "max_total": 100,
                "level1_score": 0,
                "level2_score": 0,
                "level3_score": 0,
                "level4_score": 0,
            }
        )
        return record

    score_path = spec.run_output_dir / "score.json"
    if args.resume_dir and score_path.exists():
        record.update(
            {
                "returncode": 0,
                "timed_out": False,
                "skipped": True,
                "skip_reason": "existing score.json",
                "stdout_tail": "",
                "stderr_tail": "",
                "dry_run": False,
                "resumed_from_existing_score": True,
                "completed_at": _now_iso(),
            }
        )
        return _augment_record_with_outputs(record, spec.run_output_dir)

    if args.resume_dir and spec.run_output_dir.exists():
        shutil.rmtree(spec.run_output_dir)

    cmd = [
        sys.executable,
        "run_reverse.py",
        "--model",
        args.model,
        "--challenge-path",
        str(spec.case.challenge_path),
        "--output-dir",
        str(spec.run_output_dir),
        "--difficulty",
        spec.case.difficulty,
        "--eval-mode",
        args.eval_mode,
        "--max-tokens",
        str(spec.max_tokens),
        "--max-rounds",
        str(spec.max_rounds),
        "--container-memory",
        args.container_memory,
        "--container-memory-swap",
        args.container_memory_swap,
        "--container-cpus",
        args.container_cpus,
        "--container-pids-limit",
        str(args.container_pids_limit),
        "--container-network",
        args.container_network,
    ]
    if spec.case.key_mode:
        cmd.extend(["--key-mode", spec.case.key_mode])

    try:
        completed = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=args.run_timeout,
        )
        record.update(
            {
                "returncode": completed.returncode,
                "timed_out": False,
                "skipped": False,
                "stdout_tail": _tail(completed.stdout),
                "stderr_tail": _tail(completed.stderr),
                "dry_run": False,
                "completed_at": _now_iso(),
            }
        )
    except subprocess.TimeoutExpired as exc:
        record.update(
            {
                "returncode": None,
                "timed_out": True,
                "skipped": False,
                "stdout_tail": _tail(exc.stdout if isinstance(exc.stdout, str) else ""),
                "stderr_tail": _tail(exc.stderr if isinstance(exc.stderr, str) else ""),
                "dry_run": False,
                "completed_at": _now_iso(),
            }
        )
    except Exception as exc:
        record.update(
            {
                "returncode": None,
                "timed_out": False,
                "skipped": False,
                "stdout_tail": "",
                "stderr_tail": f"runner_exception: {exc}",
                "dry_run": False,
                "completed_at": _now_iso(),
            }
        )
    return _augment_record_with_outputs(record, spec.run_output_dir)


def _attempt_budget_index(suite_index: int, attempt_index: int, total_attempt_budget: int, total_cases: int | None) -> str:
    if total_cases and total_cases > 0:
        pass_k = max(1, total_attempt_budget // total_cases)
        return str((suite_index - 1) * pass_k + attempt_index)
    return "?"


def _print_launch(spec: AttemptSpec, total: int) -> None:
    attempt_budget_index = _attempt_budget_index(
        spec.case.suite_index,
        spec.attempt_index,
        total,
        spec.case.total_cases,
    )
    print(
        f"[launch {attempt_budget_index}/{total}] {spec.case.challenge_name} mode={spec.case.mode_label} "
        f"difficulty={spec.case.difficulty} attempt={spec.attempt_index}",
        flush=True,
    )


def _print_completion(record: dict[str, Any], total: int) -> None:
    attempt_budget_index = _attempt_budget_index(
        int(record.get("suite_index", 0) or 0),
        int(record.get("attempt_index", 0) or 0),
        total,
        int(record.get("total_cases", 0) or 0),
    )
    prefix = (
        f"[done {attempt_budget_index}/{total}] {record['challenge']} "
        f"mode={record['mode_label']} difficulty={record['difficulty']} attempt={record['attempt_index']}"
    )
    print(prefix, flush=True)
    if record.get("skipped"):
        print(f"  skipped: {record['skip_reason']}", flush=True)
    elif record.get("timed_out"):
        print("  timed_out=true", flush=True)
    else:
        print(
            f"  returncode={record.get('returncode')} total_score={record.get('total_score', 0)}",
            flush=True,
        )


def _attempt_rows(records_by_attempt_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records_by_attempt_id.values():
        row = {
            "attempt_id": record.get("attempt_id"),
            "case_id": record.get("case_id"),
            "challenge": record.get("challenge"),
            "key_mode": record.get("mode_label"),
            "difficulty": record.get("difficulty"),
            "attempt_index": record.get("attempt_index"),
            "imported": record.get("imported", False),
            "total_score": record.get("total_score", 0),
            "level1_score": record.get("level1_score", 0),
            "level2_score": record.get("level2_score", 0),
            "level3_score": record.get("level3_score", 0),
            "level4_score": record.get("level4_score", 0),
            "rounds_used": record.get("rounds_used", 0),
            "model_turns": record.get("model_turns", 0),
            "total_tokens": record.get("total_tokens", 0),
            "parse_error_count": record.get("parse_error_count", 0),
            "stop_reason": record.get("stop_reason", ""),
            "returncode": record.get("returncode"),
            "timed_out": record.get("timed_out", False),
            "output_dir": record.get("output_dir", ""),
            "import_source_suite": record.get("import_source_suite", ""),
        }
        rows.append(row)
    rows.sort(key=lambda row: (row["challenge"], row["key_mode"], row["difficulty"], int(row["attempt_index"])))
    return rows


def _group_case_records(records_by_attempt_id: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records_by_attempt_id.values():
        grouped.setdefault(str(record["case_id"]), []).append(record)
    for records in grouped.values():
        records.sort(key=lambda record: int(record.get("attempt_index", 0)))
    return grouped


def _case_rows(case_specs: list[CaseSpec], records_by_attempt_id: dict[str, dict[str, Any]], pass_k: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    grouped = _group_case_records(records_by_attempt_id)
    for case in case_specs:
        records = grouped.get(case.case_id, [])
        attempt1 = next((record for record in records if int(record.get("attempt_index", 0)) == 1 and record.get("score_exists", False)), None)
        best = _best_record_for_case(case.case_id, records_by_attempt_id, pass_k)
        best_level_scores = {
            short_name: max(
                (
                    int(record.get(short_name, 0))
                    for record in records
                    if int(record.get("attempt_index", 0)) <= pass_k and record.get("score_exists", False)
                ),
                default=0,
            )
            for short_name, _ in LEVEL_FIELDS
        }
        row: dict[str, Any] = {
            "case_id": case.case_id,
            "challenge": case.challenge_name,
            "key_mode": case.mode_label,
            "difficulty": case.difficulty,
            "completed_attempts": len([record for record in records if record.get("score_exists", False)]),
            "perfect_within_k": bool(best and int(best.get("total_score", 0)) == 100),
            "attempt1_total_score": int(attempt1.get("total_score", 0)) if attempt1 else 0,
            "best_of_k_total_score": int(best.get("total_score", 0)) if best else 0,
        }
        for short_name, _ in LEVEL_FIELDS:
            row[f"attempt1_{short_name}"] = int(attempt1.get(short_name, 0)) if attempt1 else 0
            row[f"best_of_k_{short_name}"] = best_level_scores[short_name]
        rows.append(row)
    rows.sort(key=lambda row: (row["challenge"], row["key_mode"], row["difficulty"]))
    return rows


def _aggregate_case_selection(rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    total = len(rows)
    level_names = [name for name, _ in LEVEL_FIELDS]
    if total == 0:
        return {
            "cases": 0,
            "average_total_score": 0.0,
            "average_level_scores": {name: 0.0 for name in level_names},
            "task_pass_rates": {name: 0.0 for name in level_names},
            "task_summary": {
                TASK_LABELS[name]: {"average_score": 0.0, "pass_rate": 0.0}
                for name in level_names
            },
            "perfect_cases": 0,
            "perfect_rate": 0.0,
            "flag_solved_cases": 0,
            "flag_solved_rate": 0.0,
        }
    average_total_score = sum(float(row[f"{prefix}_total_score"]) for row in rows) / total
    average_level_scores = {
        name: sum(float(row[f"{prefix}_{name}"]) for row in rows) / total
        for name in level_names
    }
    task_pass_rates = {
        name: sum(1 for row in rows if int(row[f"{prefix}_{name}"]) == 25) / total
        for name in level_names
    }
    task_summary = {
        TASK_LABELS[name]: {
            "average_score": average_level_scores[name],
            "pass_rate": task_pass_rates[name],
        }
        for name in level_names
    }
    perfect_cases = sum(1 for row in rows if int(row[f"{prefix}_total_score"]) == 100)
    flag_solved_cases = sum(1 for row in rows if int(row[f"{prefix}_level4_score"]) == 25)
    return {
        "cases": total,
        "average_total_score": average_total_score,
        "average_level_scores": average_level_scores,
        "task_pass_rates": task_pass_rates,
        "task_summary": task_summary,
        "perfect_cases": perfect_cases,
        "perfect_rate": perfect_cases / total,
        "flag_solved_cases": flag_solved_cases,
        "flag_solved_rate": flag_solved_cases / total,
    }


def _bucket_summary(case_rows: list[dict[str, Any]], bucket_key: str, prefix: str) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for row in case_rows:
        buckets.setdefault(str(row[bucket_key]), []).append(row)
    return {
        bucket: _aggregate_case_selection(bucket_rows, prefix)
        for bucket, bucket_rows in sorted(buckets.items())
    }


def _task_summary(case_rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    return _aggregate_case_selection(case_rows, prefix)["task_summary"]


def _write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    if not rows:
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _write_report(path: Path, summary: dict[str, Any], case_rows: list[dict[str, Any]]) -> None:
    pass1_tasks = summary["pass_at_1"]["by_task"]
    passk_tasks = summary["pass_at_k"]["by_task"]
    lines = [
        "# Pass@K Eval Report",
        "",
        f"- Model: {summary['model']}",
        f"- Pass K: {summary['pass_k']}",
        f"- Cases: {summary['cases']}",
        "",
        "## Pass@1",
        "",
        f"- Average total score: {summary['pass_at_1']['overall']['average_total_score']:.2f}",
        f"- Perfect rate: {summary['pass_at_1']['overall']['perfect_rate']:.4f}",
        f"- Flag solved rate: {summary['pass_at_1']['overall']['flag_solved_rate']:.4f}",
        "",
        "### Task Summary",
        "",
        "| task | average_score | pass_rate |",
        "|---|---:|---:|",
    ]
    for task_name, task_stats in pass1_tasks.items():
        lines.append(
            f"| {task_name} | {task_stats['average_score']:.2f} | {task_stats['pass_rate']:.4f} |"
        )

    lines.extend(
        [
            "",
        "## Pass@K",
        "",
        f"- Best-of-{summary['pass_k']} average total score: {summary['pass_at_k']['overall']['average_total_score']:.2f}",
        f"- Perfect rate: {summary['pass_at_k']['overall']['perfect_rate']:.4f}",
        f"- Flag solved rate: {summary['pass_at_k']['overall']['flag_solved_rate']:.4f}",
        "",
        "### Task Summary",
        "",
        "| task | average_score | pass_rate |",
        "|---|---:|---:|",
        ]
    )
    for task_name, task_stats in passk_tasks.items():
        lines.append(
            f"| {task_name} | {task_stats['average_score']:.2f} | {task_stats['pass_rate']:.4f} |"
        )

    lines.extend(
        [
            "",
        "## Per Case",
        "",
        "| challenge | key_mode | difficulty | attempt1 | best_of_k | perfect_within_k |",
        "|---|---|---|---:|---:|---|",
        ]
    )
    for row in case_rows:
        lines.append(
            f"| {row['challenge']} | {row['key_mode']} | {row['difficulty']} | "
            f"{row['attempt1_total_score']} | {row['best_of_k_total_score']} | {row['perfect_within_k']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_summary(
    args: argparse.Namespace,
    suite_dir: Path,
    case_specs: list[CaseSpec],
    records_by_attempt_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    case_rows = _case_rows(case_specs, records_by_attempt_id, args.pass_k)
    summary = {
        "suite_dir": str(suite_dir),
        "model": args.model,
        "provider": resolve_provider_for_model(args.model),
        "pass_k": args.pass_k,
        "cases": len(case_rows),
        "attempt_records": len(records_by_attempt_id),
        "pass_at_1": {
            "overall": _aggregate_case_selection(case_rows, "attempt1"),
            "by_difficulty": _bucket_summary(case_rows, "difficulty", "attempt1"),
            "by_key_mode": _bucket_summary(case_rows, "key_mode", "attempt1"),
            "by_task": _task_summary(case_rows, "attempt1"),
        },
        "pass_at_k": {
            "overall": _aggregate_case_selection(case_rows, "best_of_k"),
            "by_difficulty": _bucket_summary(case_rows, "difficulty", "best_of_k"),
            "by_key_mode": _bucket_summary(case_rows, "key_mode", "best_of_k"),
            "by_task": _task_summary(case_rows, "best_of_k"),
        },
    }
    (suite_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    _write_csv(_attempt_rows(records_by_attempt_id), suite_dir / "attempt_results.csv")
    _write_csv(case_rows, suite_dir / "case_results.csv")
    _write_report(suite_dir / "report.md", summary, case_rows)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run pass@k evaluation suites with local resume support.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--pass-k", type=int, default=3)
    parser.add_argument("--difficulty", default="ALL", choices=SUPPORTED_DIFFICULTIES + ["ALL"])
    parser.add_argument("--key-mode", choices=SUPPORTED_KEY_MODES, default=None)
    parser.add_argument("--all-key-modes", action="store_true")
    parser.add_argument("--eval-mode", default="full", choices=["full", "flag_only"])
    parser.add_argument("--challenge", action="append", default=[])
    parser.add_argument("--all-c-all", action="store_true")
    parser.add_argument("--max-tokens", type=int, default=600000)
    parser.add_argument("--max-rounds", type=int, default=30)
    parser.add_argument("--run-timeout", type=int, default=1800)
    parser.add_argument("--jobs", type=int, default=None)
    parser.add_argument("--container-memory", default=os.environ.get("REV_CONTAINER_MEMORY", DEFAULT_CONTAINER_MEMORY))
    parser.add_argument("--container-memory-swap", default=os.environ.get("REV_CONTAINER_MEMORY_SWAP"))
    parser.add_argument("--container-cpus", default=os.environ.get("REV_CONTAINER_CPUS", DEFAULT_CONTAINER_CPUS))
    parser.add_argument("--container-pids-limit", type=int, default=int(os.environ.get("REV_CONTAINER_PIDS_LIMIT", str(DEFAULT_CONTAINER_PIDS_LIMIT))))
    parser.add_argument("--container-network", default=os.environ.get("REV_CONTAINER_NETWORK", DEFAULT_CONTAINER_NETWORK))
    parser.add_argument("--suite-name", default=None)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--resume-dir", type=Path, default=None)
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.pass_k <= 0:
        raise ValueError("--pass-k must be positive")
    if args.key_mode and args.all_key_modes:
        raise ValueError("use either --key-mode or --all-key-modes, not both")
    if not args.suite_name:
        args.suite_name = _default_suite_name(args.model, args.pass_k)

    args.container_memory = args.container_memory.strip() if args.container_memory else None
    args.container_memory_swap = (
        args.container_memory_swap.strip() if args.container_memory_swap else None
    ) or args.container_memory
    args.container_cpus = args.container_cpus.strip() if args.container_cpus else None
    args.container_network = args.container_network.strip() if args.container_network else DEFAULT_CONTAINER_NETWORK

    memory_gib_per_run = _parse_memory_limit_gib(args.container_memory)
    if memory_gib_per_run is None or memory_gib_per_run <= 0:
        raise ValueError(f"invalid --container-memory value: {args.container_memory!r}")

    challenges = _discover_challenges(args.challenge, args.all_c_all)
    key_modes = SUPPORTED_KEY_MODES if args.all_key_modes else [args.key_mode]
    difficulties = _expand_difficulties(args.difficulty)
    case_specs = _build_case_specs(challenges, key_modes, difficulties)
    total_cases = len(case_specs)
    resolved_jobs, parallelism = _resolve_jobs(args.jobs, memory_gib_per_run)

    if args.resume_dir is not None:
        suite_dir = args.resume_dir.resolve()
        if not suite_dir.exists():
            raise FileNotFoundError(f"resume suite directory does not exist: {suite_dir}")
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suite_dir = args.output_root / f"{args.suite_name}-{timestamp}"
    suite_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = suite_dir / "suite_manifest.json"
    existing_manifest, ordered_records, records_by_attempt_id = _load_existing_manifest(manifest_path)
    _validate_resume_manifest(
        existing_manifest,
        suite_dir=suite_dir,
        model=args.model,
        pass_k=args.pass_k,
        eval_mode=args.eval_mode,
    )
    records_by_attempt_id.update(_collect_local_attempt_records(suite_dir))
    ordered_attempt_ids = [record["attempt_id"] for record in ordered_records if "attempt_id" in record]

    manifest = {
        "suite_dir": str(suite_dir),
        "model": args.model,
        "provider": resolve_provider_for_model(args.model),
        "pass_k": args.pass_k,
        "difficulty": args.difficulty,
        "difficulties": difficulties,
        "key_modes": key_modes,
        "eval_mode": args.eval_mode,
        "max_tokens": args.max_tokens,
        "max_rounds": args.max_rounds,
        "run_timeout_seconds": args.run_timeout,
        "container_limits": {
            "memory": args.container_memory,
            "memory_swap": args.container_memory_swap,
            "cpus": args.container_cpus,
            "pids_limit": args.container_pids_limit,
            "network": args.container_network,
        },
        "requested_jobs": args.jobs,
        "resolved_jobs": resolved_jobs,
        "parallelism": parallelism,
        "resume_dir": str(suite_dir) if args.resume_dir else None,
        "dry_run": args.dry_run,
        "cases": [
            {
                "case_id": case.case_id,
                "challenge": case.challenge_name,
                "key_mode": case.mode_label,
                "difficulty": case.difficulty,
            }
            for case in case_specs
        ],
        "attempts": [],
    }
    _persist_manifest(manifest_path, manifest, ordered_attempt_ids, records_by_attempt_id)

    print(
        f"Resolved pass@k parallelism: jobs={resolved_jobs} "
        f"(cpu={parallelism['cpu_count']}, mem_available_gib={parallelism['mem_available_gib']}, "
        f"memory_gib_per_run={parallelism['memory_gib_per_run_budget']}, host_max_jobs={parallelism['host_max_jobs']})",
        flush=True,
    )
    print(f"Cases in scope: {total_cases}", flush=True)

    total_attempt_budget = total_cases * args.pass_k
    stop_submitting = False
    pending: dict[Future[dict[str, Any]], AttemptSpec] = {}
    queued_case_ids: set[str] = set()

    def submit_next_attempt(executor: ThreadPoolExecutor | None, case: CaseSpec) -> None:
        nonlocal stop_submitting
        if stop_submitting:
            return
        if case.case_id in queued_case_ids:
            return
        spec = _next_attempt_to_schedule(case, args.pass_k, records_by_attempt_id, suite_dir, args.max_tokens, args.max_rounds)
        if spec is None:
            return
        if spec.attempt_id not in ordered_attempt_ids:
            ordered_attempt_ids.append(spec.attempt_id)
        if executor is None:
            return
        queued_case_ids.add(case.case_id)
        _print_launch(spec, total_attempt_budget)
        pending[executor.submit(_execute_attempt, spec, args)] = spec

    if resolved_jobs == 1:
        for case in case_specs:
            while True:
                spec = _next_attempt_to_schedule(case, args.pass_k, records_by_attempt_id, suite_dir, args.max_tokens, args.max_rounds)
                if spec is None:
                    break
                if spec.attempt_id not in ordered_attempt_ids:
                    ordered_attempt_ids.append(spec.attempt_id)
                _print_launch(spec, total_attempt_budget)
                record = _execute_attempt(spec, args)
                records_by_attempt_id[record["attempt_id"]] = record
                _persist_manifest(manifest_path, manifest, ordered_attempt_ids, records_by_attempt_id)
                _print_completion(record, total_attempt_budget)
                if args.stop_on_failure and (record.get("timed_out") or record.get("returncode") not in {0, None}):
                    stop_submitting = True
                    break
                if _is_perfect(record):
                    break
            if stop_submitting:
                break
    else:
        with ThreadPoolExecutor(max_workers=resolved_jobs) as executor:
            case_index = 0
            while case_index < len(case_specs) and len(pending) < resolved_jobs:
                submit_next_attempt(executor, case_specs[case_index])
                case_index += 1

            while pending:
                done, _ = wait(set(pending), return_when=FIRST_COMPLETED)
                for future in done:
                    spec = pending.pop(future)
                    queued_case_ids.discard(spec.case.case_id)
                    record = future.result()
                    records_by_attempt_id[record["attempt_id"]] = record
                    _persist_manifest(manifest_path, manifest, ordered_attempt_ids, records_by_attempt_id)
                    _print_completion(record, total_attempt_budget)
                    if args.stop_on_failure and (record.get("timed_out") or record.get("returncode") not in {0, None}):
                        stop_submitting = True
                    if not stop_submitting:
                        submit_next_attempt(executor, spec.case)
                while not stop_submitting and case_index < len(case_specs) and len(pending) < resolved_jobs:
                    submit_next_attempt(executor, case_specs[case_index])
                    case_index += 1

    _persist_manifest(manifest_path, manifest, ordered_attempt_ids, records_by_attempt_id)
    _build_summary(args, suite_dir, case_specs, records_by_attempt_id)
    print(suite_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
