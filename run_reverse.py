import argparse
import logging
from pathlib import Path
import json
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timezone

from src.reverse_agent.config import load_config
from src.reverse_agent.environment import DockerEnvironment
from src.reverse_agent.tools import ToolExecutor
from src.reverse_agent.agent import ReverseAgent, build_initial_prompt
from src.reverse_agent.codex_runner import CodexContainerRunner, CodexRuntimeSpec, HostWorkspaceEnvironment
from src.reverse_agent.logger import setup_logger
from src.reverse_agent.llm import (
    build_provider_for_model,
    resolve_provider_for_model,
)


DEFAULT_CONTAINER_MEMORY = "8g"
DEFAULT_CONTAINER_CPUS = "4"
DEFAULT_CONTAINER_PIDS_LIMIT = 512
DEFAULT_CONTAINER_NETWORK = "bridge"


def _slugify(value: str) -> str:
    normalized = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9._-]+", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized)
    return normalized.strip("-") or "unknown"


def _resolve_output_dir(args: argparse.Namespace, challenge_config, *, resolved_provider: str) -> Path:
    if args.output_dir is not None:
        return args.output_dir

    challenge_label = _slugify(args.challenge_path.name or challenge_config.name)
    key_mode = _slugify(args.key_mode or getattr(challenge_config, "key_mode", "") or "default")
    difficulty = _slugify(args.difficulty or getattr(challenge_config, "difficulty", "") or "default")
    provider = _slugify(resolved_provider)
    model = _slugify(args.model)
    eval_mode = _slugify(args.eval_mode)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("outputs") / challenge_label / key_mode / difficulty / provider / model / eval_mode / timestamp


def _env_or_default(name: str, default: str | None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _normalize_optional_str(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run a reverse engineering CTF solving agent.")
    parser.add_argument("--model", type=str, default="gpt-5.2", help="Model or deployment name.")
    parser.add_argument(
        "--provider",
        type=str,
        default=None,
        choices=["openai", "azure"],
        help="Provider override for OpenAI-family models and codex (openai or azure). If omitted, OPENAI_API_KEY is preferred; otherwise Azure credentials are used.",
    )
    parser.add_argument("--challenge-path", type=Path, required=True, help="Path to the challenge directory containing config.yaml.")
    parser.add_argument("--output-dir", type=Path, default=None, help="Exact directory to save logs and results. If omitted, a structured path under outputs/ is generated automatically.")
    parser.add_argument("--max-tokens", type=int, default=2400000, help="Maximum tokens for LLM responses. ")
    parser.add_argument("--max-rounds", type=int, default=30, help="Maximum number of agent interaction rounds.")
    parser.add_argument("--eval-mode", type=str, default="full", choices=["full", "flag_only"],
                        help="Evaluation mode: 'full' (4-level scoring) or 'flag_only' (legacy, only submit_flag).")
    parser.add_argument("--key-mode", type=str, default=None,
                        choices=["hardcode_plain", "fragmented_build", "weak_prng_seeded"],
                        help="Override the key misuse mode and load mode-specific metadata/public artifacts.")
    parser.add_argument("--difficulty", type=str, default=None, choices=["O0", "O0S", "O3", "tigress", "constxor"],
                        help="Override public path to public-{difficulty} (e.g., public-O0).")
    parser.add_argument(
        "--container-memory",
        type=str,
        default=_env_or_default("REV_CONTAINER_MEMORY", DEFAULT_CONTAINER_MEMORY),
        help="Docker memory limit for the challenge container, e.g. 8g.",
    )
    parser.add_argument(
        "--container-memory-swap",
        type=str,
        default=_env_or_default("REV_CONTAINER_MEMORY_SWAP", None),
        help="Docker memory+swap limit. Defaults to the same value as --container-memory.",
    )
    parser.add_argument(
        "--container-cpus",
        type=str,
        default=_env_or_default("REV_CONTAINER_CPUS", DEFAULT_CONTAINER_CPUS),
        help="Docker CPU quota for the challenge container, e.g. 4 or 2.5.",
    )
    parser.add_argument(
        "--container-pids-limit",
        type=int,
        default=int(_env_or_default("REV_CONTAINER_PIDS_LIMIT", str(DEFAULT_CONTAINER_PIDS_LIMIT))),
        help="Docker PID limit for the challenge container.",
    )
    parser.add_argument(
        "--container-network",
        type=str,
        default=_env_or_default("REV_CONTAINER_NETWORK", DEFAULT_CONTAINER_NETWORK),
        help="Docker network mode for the challenge container, e.g. bridge or none.",
    )

    args = parser.parse_args()
    args.container_memory = _normalize_optional_str(args.container_memory)
    args.container_memory_swap = _normalize_optional_str(args.container_memory_swap) or args.container_memory
    args.container_cpus = _normalize_optional_str(args.container_cpus)
    args.container_network = _normalize_optional_str(args.container_network) or DEFAULT_CONTAINER_NETWORK
    resolved_provider = resolve_provider_for_model(args.model, provider=args.provider)

    try:
        challenge_config = load_config(
            args.challenge_path,
            key_mode=args.key_mode,
            difficulty=args.difficulty,
        )

        args.output_dir = _resolve_output_dir(args, challenge_config, resolved_provider=resolved_provider)
        args.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup
        logger = setup_logger(args.output_dir)
        logger.info(f"Loaded challenge '{challenge_config.name}'")
        logger.info(f"Results will be written to '{args.output_dir}'")
        logger.info(f"Resolved provider '{resolved_provider}' for model '{args.model}'")
        logger.info(
            "Container limits: "
            f"memory={args.container_memory or 'unlimited'}, "
            f"memory_swap={args.container_memory_swap or 'unlimited'}, "
            f"cpus={args.container_cpus or 'unlimited'}, "
            f"pids_limit={args.container_pids_limit}"
        )
        logger.info(f"Container network: {args.container_network}")

        codex_runtime: CodexRuntimeSpec | None = None
        extra_mounts: list[DockerEnvironment.VolumeMount] = []
        if resolved_provider == "codex":
            codex_runtime = CodexRuntimeSpec.detect(args.model, provider=args.provider)
            extra_mounts.extend(codex_runtime.docker_mounts())
            logger.info(f"Codex runtime mount: {codex_runtime.host_node_root}")
            if codex_runtime.backend_model:
                logger.info(f"Codex backend model override: {codex_runtime.backend_model}")
            if codex_runtime.provider_name:
                logger.info(f"Codex backend provider: {codex_runtime.provider_name}")

        if resolved_provider == "codex":
            assert codex_runtime is not None
            workspace_dir = args.output_dir / "codex_workspace"
            workspace_env = HostWorkspaceEnvironment(workspace_dir=workspace_dir, host_output_dir=args.output_dir)
            tool_executor = ToolExecutor(environment=workspace_env, config=challenge_config, eval_mode=args.eval_mode)
            codex_runner = CodexContainerRunner(
                model=args.model,
                max_tokens=args.max_tokens,
                config=challenge_config,
                tool_executor=tool_executor,
                runtime=codex_runtime,
                output_dir=args.output_dir,
                workspace_dir=workspace_dir,
                resource_limits=DockerEnvironment.ResourceLimits(
                    memory=args.container_memory,
                    memory_swap=args.container_memory_swap,
                    cpus=args.container_cpus,
                    pids_limit=args.container_pids_limit,
                ),
                network_mode=args.container_network,
                eval_mode=args.eval_mode,
                provider_override=args.provider,
            )
            run_metrics, final_messages, _ = codex_runner.run()
            record_path = args.output_dir / "record.txt"
            record_path.write_text(
                json.dumps(final_messages, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        else:
            with DockerEnvironment(
                config=challenge_config,
                host_output_dir=args.output_dir,
                resource_limits=DockerEnvironment.ResourceLimits(
                    memory=args.container_memory,
                    memory_swap=args.container_memory_swap,
                    cpus=args.container_cpus,
                    pids_limit=args.container_pids_limit,
                ),
                network_mode=args.container_network,
                extra_mounts=extra_mounts,
            ) as env:
                tool_executor = ToolExecutor(environment=env, config=challenge_config, eval_mode=args.eval_mode)
                _, llm = build_provider_for_model(args.model, provider=args.provider)
                agent = ReverseAgent(model=args.model, tool_executor=tool_executor, llm=llm)
                initial_prompt = build_initial_prompt(args.eval_mode)
                record_path = args.output_dir / "record.txt"
                final_messages = agent.run(
                    initial_prompt,
                    max_steps=args.max_rounds,
                    record_path=record_path,
                    max_tokens=args.max_tokens,
                )
                run_metrics = agent.run_metrics

        # Save final conversation
        output_file = args.output_dir / "conversation.json"
        with open(output_file, 'w', encoding="utf-8") as f:
            json.dump(final_messages, f, indent=4, ensure_ascii=False)
        logger.info(f"Conversation saved to {output_file}")

        # Save score report
        score_report = tool_executor.score_report
        score_path = args.output_dir / "score.json"
        score_report.save(score_path)
        logger.info(f"\n{score_report.summary()}")

        metrics_path = args.output_dir / "run_metrics.json"
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(run_metrics, f, indent=2)
        logger.info(f"Run metrics saved to {metrics_path}")

        metadata = {
            "provider": resolved_provider,
            "resolved_provider": resolved_provider,
            "provider_override": args.provider,
            "model": args.model,
            "challenge_name": challenge_config.name,
            "challenge_path": str(args.challenge_path),
            "key_mode": args.key_mode or getattr(challenge_config, "key_mode", None),
            "difficulty": args.difficulty or getattr(challenge_config, "difficulty", None),
            "eval_mode": args.eval_mode,
            "max_tokens": args.max_tokens,
            "max_rounds": args.max_rounds,
            "output_dir": str(args.output_dir),
            "public_path": str(challenge_config.public_path),
            "test_vectors_path": str(challenge_config.test_vectors_path) if challenge_config.test_vectors_path else None,
            "resolved_key_material": challenge_config.level2_expected_material,
            "mode_variant": getattr(challenge_config, "mode_variant", None),
            "mode_metadata_path": str(challenge_config.mode_metadata_path) if challenge_config.mode_metadata_path else None,
            "container_limits": {
                "memory": args.container_memory,
                "memory_swap": args.container_memory_swap,
                "cpus": args.container_cpus,
                "pids_limit": args.container_pids_limit,
                "network": args.container_network,
            },
        }
        if codex_runtime is not None:
            metadata["codex"] = {
                "host_node_root": str(codex_runtime.host_node_root),
                "backend_model": codex_runtime.backend_model,
                "backend_provider": codex_runtime.provider_name,
            }
        metadata_path = args.output_dir / "run_metadata.json"
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Run metadata saved to {metadata_path}")

    except Exception as e:
        logger = logging.getLogger("reverse_agent")
        logger.error(f"An error occurred: {e}", exc_info=True)
        raise SystemExit(1) from e

if __name__ == "__main__":
    main()
