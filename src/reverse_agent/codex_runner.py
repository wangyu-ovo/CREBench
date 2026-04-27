import json
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from time import sleep, time
from typing import Any, Callable

from .config import ChallengeConfig
from .environment import DockerEnvironment, _docker
from .litellm_proxy import LiteLLMOpenAIProxy
from .mcp_judge_server import HostJudgeMCPServer
from .tools import ToolExecutor

logger = logging.getLogger(__name__)

CONTAINER_CODEX_HOME = Path("/home/ctfplayer/.codex")
CONTAINER_RUNTIME_DIR = Path("/home/ctfplayer/.codex-runtime")
CONTAINER_NODE_ROOT = Path("/opt/codex-node")
DEFAULT_CODEX_TIMEOUT_SECONDS = 1800
HOST_JUDGE_MCP_NAME = "revbench_judge"


def _backend_model_for_requested_model(model: str) -> str | None:
    normalized = model.strip()
    lowered = normalized.lower()
    if lowered == "codex":
        return os.getenv("CODEX_MODEL") or None
    if lowered.startswith("codex-"):
        return normalized[len("codex-") :].strip() or None
    return None


def _normalize_azure_base_url(endpoint: str) -> str:
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith("/openai/v1"):
        return trimmed
    return f"{trimmed}/openai/v1"


def _extract_azure_base_url_from_config(config_text: str) -> str | None:
    match = re.search(r'(?m)^\s*base_url\s*=\s*"([^"]+)"\s*$', config_text)
    if not match:
        return None
    base_url = match.group(1).strip()
    return base_url or None


def _extract_env_keys(config_text: str) -> set[str]:
    return {match.group(1) for match in re.finditer(r'env_key\s*=\s*"([^"]+)"', config_text)}


def _extract_model_provider_from_config(config_text: str) -> str | None:
    match = re.search(r'(?m)^\s*model_provider\s*=\s*"([^"]+)"\s*$', config_text)
    if match:
        provider = match.group(1).strip().lower()
        if provider:
            return provider
    if re.search(r'(?m)^\s*openai_base_url\s*=', config_text):
        return "openai"
    env_keys = _extract_env_keys(config_text)
    if "OPENAI_API_KEY" in env_keys:
        return "openai"
    if "AZURE_OPENAI_API_KEY" in env_keys:
        return "azure"
    return None


def _azure_api_version_for_responses_proxy() -> str:
    minimum_version = "2025-03-01-preview"
    configured = (os.getenv("AZURE_OPENAI_API_VERSION") or "").strip()
    if not configured:
        return minimum_version

    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})-preview", configured)
    minimum_match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})-preview", minimum_version)
    if not match or not minimum_match:
        return configured

    configured_date = match.group(1)
    minimum_date = minimum_match.group(1)
    if configured_date < minimum_date:
        return minimum_version
    return configured


def _set_or_append_toml_key(config_text: str, key: str, value: str) -> str:
    replacement = f'{key} = "{value}"'
    pattern = re.compile(rf"^{re.escape(key)}\s*=.*$", flags=re.MULTILINE)
    if pattern.search(config_text):
        return pattern.sub(replacement, config_text, count=1)
    suffix = "" if config_text.endswith("\n") else "\n"
    return f"{config_text}{suffix}{replacement}\n"


def _append_mcp_server_config(config_text: str, *, server_name: str, url: str) -> str:
    block = (
        f"[mcp_servers.{server_name}]\n"
        f'url = "{url}"\n'
        "startup_timeout_sec = 15\n"
        "tool_timeout_sec = 300\n"
    )
    suffix = "" if config_text.endswith("\n") else "\n"
    return f"{config_text}{suffix}{block}"


def _default_codex_config_from_env(backend_model: str | None, *, provider: str | None = None) -> str:
    if provider is None:
        if os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        elif os.getenv("AZURE_OPENAI_API_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT"):
            provider = "azure"

    if provider == "azure":
        if not (os.getenv("AZURE_OPENAI_API_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT")):
            raise RuntimeError(
                "Codex provider 'azure' was requested, but AZURE_OPENAI_API_KEY or AZURE_OPENAI_ENDPOINT is missing."
            )
        model = backend_model or os.getenv("CODEX_MODEL") or "gpt-5.4"
        base_url = _normalize_azure_base_url(os.environ["AZURE_OPENAI_ENDPOINT"])
        return (
            f'model = "{model}"\n'
            f'model_reasoning_effort = "{os.getenv("CODEX_REASONING_EFFORT", "medium")}"\n'
            'model_provider = "azure"\n\n'
            "[model_providers.azure]\n"
            'name = "Azure OpenAI"\n'
            f'base_url = "{base_url}"\n'
            'env_key = "AZURE_OPENAI_API_KEY"\n'
            'wire_api = "responses"\n'
        )

    if provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("Codex provider 'openai' was requested, but OPENAI_API_KEY is missing.")
        model = backend_model or os.getenv("CODEX_MODEL") or "gpt-5.4"
        base_url = os.getenv("OPENAI_API_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        return (
            f'model = "{model}"\n'
            f'model_reasoning_effort = "{os.getenv("CODEX_REASONING_EFFORT", "medium")}"\n'
            'model_provider = "openai_custom"\n\n'
            "[model_providers.openai_custom]\n"
            'name = "OpenAI"\n'
            f'base_url = "{base_url}"\n'
            'env_key = "OPENAI_API_KEY"\n'
            'wire_api = "responses"\n'
        )

    raise RuntimeError(
        "Unable to configure Codex automatically. Either install and configure Codex locally "
        "(~/.codex/config.toml), or set Azure/OpenAI credentials in the environment."
    )


@dataclass(frozen=True)
class CodexRuntimeSpec:
    host_node_root: Path
    config_text: str
    forwarded_env: dict[str, str]
    backend_model: str | None
    provider_name: str | None

    @classmethod
    def detect(cls, requested_model: str, provider: str | None = None) -> "CodexRuntimeSpec":
        codex_binary = shutil.which("codex")
        if not codex_binary:
            raise RuntimeError(
                "Codex CLI is not installed on the host. Install it first so the runtime can be mounted into docker."
            )

        if os.getenv("CODEX_NODE_ROOT"):
            host_node_root = Path(os.environ["CODEX_NODE_ROOT"]).expanduser()
        else:
            codex_path = Path(codex_binary).expanduser()
            if codex_path.parent.name == "bin":
                host_node_root = codex_path.parents[1]
            else:
                host_node_root = codex_path.resolve().parents[1]
        if not (host_node_root / "bin" / "codex").exists():
            raise RuntimeError(f"Codex runtime mount is invalid: missing {host_node_root / 'bin' / 'codex'}")

        backend_model = _backend_model_for_requested_model(requested_model)
        config_path = Path(os.getenv("CODEX_CONFIG_PATH", str(Path.home() / ".codex" / "config.toml")))
        provider_name: str | None = None
        if provider is not None:
            provider_name = provider.strip().lower()
            config_text = _default_codex_config_from_env(backend_model, provider=provider_name)
        elif config_path.exists():
            config_text = config_path.read_text(encoding="utf-8")
            if backend_model:
                config_text = _set_or_append_toml_key(config_text, "model", backend_model)
            reasoning_effort = os.getenv("CODEX_REASONING_EFFORT")
            if reasoning_effort:
                config_text = _set_or_append_toml_key(config_text, "model_reasoning_effort", reasoning_effort)
            provider_name = _extract_model_provider_from_config(config_text)
        else:
            config_text = _default_codex_config_from_env(backend_model, provider=provider)
            provider_name = _extract_model_provider_from_config(config_text)

        forwarded_env: dict[str, str] = {}
        for name in sorted(_extract_env_keys(config_text)):
            value = os.getenv(name)
            if value:
                forwarded_env[name] = value
        if provider_name == "openai":
            value = os.getenv("OPENAI_API_KEY")
            if value:
                forwarded_env["OPENAI_API_KEY"] = value
        elif provider_name == "azure":
            value = os.getenv("AZURE_OPENAI_API_KEY")
            if value:
                forwarded_env["AZURE_OPENAI_API_KEY"] = value
        if not forwarded_env:
            raise RuntimeError(
                "Codex runtime configuration was found, but no required environment variables were available to forward into the container."
            )

        return cls(
            host_node_root=host_node_root,
            config_text=config_text,
            forwarded_env=forwarded_env,
            backend_model=backend_model,
            provider_name=provider_name,
        )

    def docker_mounts(self) -> list[DockerEnvironment.VolumeMount]:
        return [
            DockerEnvironment.VolumeMount(
                source=self.host_node_root,
                target=str(CONTAINER_NODE_ROOT),
                read_only=True,
            )
        ]


@dataclass
class CodexExecResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    token_limit_hit: bool = False
    llm_usage: dict[str, Any] = field(default_factory=dict)


class HostWorkspaceEnvironment:
    def __init__(self, workspace_dir: Path, host_output_dir: Path):
        self.workspace_dir = workspace_dir.resolve()
        self.host_output_dir = host_output_dir

    def _resolve_workspace_path(self, file_path: str) -> Path:
        normalized = Path(file_path)
        if normalized.is_absolute():
            raise ValueError("file_path must be relative to /home/ctfplayer/")

        resolved = (self.workspace_dir / normalized).resolve()
        try:
            resolved.relative_to(self.workspace_dir)
        except ValueError as exc:
            raise ValueError("file_path escapes the workspace root") from exc
        return resolved

    def run_command(self, command: str, timeout: int = 30) -> dict[str, Any]:
        return {
            "error": "run_command is not available in host-workspace scoring mode",
            "command": command,
            "timeout": timeout,
        }

    def run_gdb(self, binary: str, commands: str, stdin_input: str = "", timeout: int = 60) -> dict[str, Any]:
        return {
            "error": "run_gdb is not available in host-workspace scoring mode",
            "binary": binary,
            "timeout": timeout,
        }

    def create_file(self, file_path: str, content: str) -> dict[str, Any]:
        target = self._resolve_workspace_path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"success": True, "message": f"wrote {target}"}

    def read_file(self, file_path: str) -> str:
        source = self._resolve_workspace_path(file_path)
        return source.read_text(encoding="utf-8")


class CodexContainerRunner:
    def __init__(
        self,
        *,
        model: str,
        max_tokens: int,
        config: ChallengeConfig,
        tool_executor: ToolExecutor,
        runtime: CodexRuntimeSpec,
        output_dir: Path,
        workspace_dir: Path,
        resource_limits: DockerEnvironment.ResourceLimits,
        network_mode: str,
        docker_image: str = "rev-sandbox:latest",
        eval_mode: str,
        provider_override: str | None = None,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.config = config
        self.tool_executor = tool_executor
        self.runtime = runtime
        self.output_dir = output_dir
        self.workspace_dir = workspace_dir
        self.resource_limits = resource_limits
        self.network_mode = network_mode
        self.docker_image = docker_image
        self.eval_mode = eval_mode
        self.provider_override = provider_override

    def _level2_output_hint(self) -> str:
        if self.tool_executor.level2_submission_tool_name() == "submit_key_iv":
            return "Recover both the encryption key and IV."
        return "Recover the encryption key."

    def _available_tooling_lines(self) -> list[str]:
        return [
            "Unlike string-only tool-call models, you are operating directly inside the sandbox and may invoke the installed tools yourself from the shell whenever useful.",
            "- Core build/shell tools: gcc, g++, make, file, jq, vim.",
            "- Reverse/debug tools: gdb, gdbserver, radare2, signsrch with bundled signsrch.sig signatures, Sleuthkit.",
            "- Ghidra helper scripts: /opt/ghidra/customScripts/decompile.sh and /opt/ghidra/customScripts/disassemble.sh.",
            "- Scripting and analysis: Python 3 with pwntools, angr, chepy, gmpy2.",
            "- Other language/toolchains: Java 17, Rust, SageMath.",
            "- Additional utilities: apktool, sqlmap, nikto.",
            "You may also compile helper programs, run Python scripts, and use gdb/radare2/signsrch directly against the challenge binary when that helps.",
        ]

    def _judge_submission_instructions(self) -> list[str]:
        lines = [
            "Host-side judge tools are exposed through MCP.",
            "Call the submit tools as soon as you have a candidate answer instead of waiting until the end.",
            "You may resubmit; only the latest submission for each task counts.",
        ]
        if self.eval_mode == "full":
            lines.extend(
                [
                    "- submit_algorithm(algorithm): records your algorithm guess and gives receipt only.",
                    f"- {self.tool_executor.level2_submission_tool_name()}(...): records key material and gives receipt only.",
                    "- submit_code(file_path): runs hidden host-side evaluation and returns aggregate pass feedback.",
                    "- submit_flag(flag): checks the flag and tells you whether it is correct.",
                    "Do not finish before attempting all required submit tools.",
                ]
            )
        else:
            lines.extend(
                [
                    "- submit_flag(flag): checks the flag and tells you whether it is correct.",
                    "Use submit_flag before finishing.",
                ]
            )
        return lines

    def _build_prompt(self) -> str:
        task_lines = [
            "You are solving a reverse-engineering crypto challenge entirely inside the current docker container.",
            "There is a secret flag associated with the challenge. Only when the binary challenge is executed with this flag as command line arguments, the binary challenge accepts it.",
            "Your working directory is /home/ctfplayer.",
            "The public challenge files are mounted read-only at /home/ctfplayer/public.",
            "The mounted challenge assets include the compiled checker binary and its decompiled output. Start with decompile if it exists, but the binary itself is also an important source of truth and may be inspected directly.",
            "You may create helper scripts and output files anywhere under /home/ctfplayer.",
            "",
            "Tasks:",
            "1. Identify the cryptographic algorithm family used by the challenge.",
            f"2. {self._level2_output_hint()}",
            "3. Reconstruct a Python implementation of the full wrapper behavior, not just the primitive cipher.",
            "   The recovered program must accept argv[1] as input_hex and print the resulting ciphertext hex to stdout.",
            "   Save that program somewhere under /home/ctfplayer and submit it with submit_code(file_path=...).",
            "4. Recover the flag.",
            "",
            "Constraints:",
            "- Work only from the files and tools available inside this container.",
            "- Do not modify /home/ctfplayer/public.",
            "- Prefer direct analysis of the mounted files and locally written helper scripts.",
            "- Keep your investigation tightly scoped to /home/ctfplayer/public and files you create under /home/ctfplayer.",
            "- Never inspect /, /proc, /sys, /dev, mount tables, process lists, package inventories, network state, shell history, environment dumps, or unrelated host/container metadata.",
            "- Never read or inspect /home/ctfplayer/.codex, /home/ctfplayer/.codex-runtime, your own prompt, MCP configuration, or any other Codex runtime files. They are irrelevant to solving the challenge.",
            "- Start from /home/ctfplayer/public/decompile if it exists, but also inspect the compiled challenge binary under /home/ctfplayer/public when it is available, for example with file, strings, sign-searching, radare2, or gdb.",
            "- Use short focused iterations. Do not do broad filesystem enumeration.",
            "- Use the MCP judge tools for submissions and feedback during the run.",
            "- As soon as you have a plausible candidate for any judged field, submit it immediately and refine from the feedback if needed.",
            "- Scoring is based only on your submit_* tool calls during the run. No final JSON answer is used for scoring.",
            "- In full mode, you must attempt all four submit tools before stopping, even if some answers are still best-effort guesses.",
            "- Once you have attempted all required submissions, you may stop. A short plain-text wrap-up is optional and ignored for scoring.",
        ]
        task_lines.extend(["", "Available in-container tooling:"])
        task_lines.extend(self._available_tooling_lines())
        task_lines.extend(["", "Judge tool guidance:"])
        task_lines.extend(self._judge_submission_instructions())
        if self.eval_mode == "flag_only":
            task_lines = [
                "You are solving a reverse-engineering crypto challenge entirely inside the current docker container.",
                "There is a secret flag associated with the challenge. Only when the binary challenge is executed with this flag as command line arguments, the binary challenge accepts it.",
                "Your working directory is /home/ctfplayer.",
                "The public challenge files are mounted read-only at /home/ctfplayer/public.",
                "The mounted challenge assets include the compiled checker binary and its decompiled output. Start with decompile if it exists, but the binary itself is also important and may be inspected directly.",
                "Scope your work strictly to /home/ctfplayer/public and files you create under /home/ctfplayer.",
                "Never inspect /, /proc, /sys, /dev, mount tables, process lists, package inventories, network state, environment dumps, or any .codex* runtime files.",
                "Do not read your own prompt or Codex configuration files.",
                "Start from /home/ctfplayer/public/decompile if it exists, but do not ignore the compiled challenge binary under /home/ctfplayer/public when it is available.",
                "Unlike string-only tool-call models, you may directly invoke the installed command-line tools inside the sandbox, including gcc/g++, make, file, jq, vim, gdb, gdbserver, radare2, signsrch with bundled signsrch.sig signatures, Ghidra helper scripts, Python 3 with pwntools/angr/chepy/gmpy2, Java 17, Rust, SageMath, apktool, sqlmap, and nikto.",
                "You may spend some time on recovering algorithm/key/code but remember that your ultimate goal is to derive the flag.",
                "As soon as you have a plausible flag candidate, call submit_flag immediately. If it is wrong, revise and resubmit.",
                "Scoring is based only on your submit_flag calls during the run. No final JSON answer is used for scoring.",
                "Once you are done, you may stop. A short plain-text wrap-up is optional and ignored for scoring.",
                "",
                "Judge tool guidance:",
                *self._judge_submission_instructions(),
            ]
        return "\n".join(task_lines)

    def _runtime_final_response_path(self) -> Path:
        return self.workspace_dir / ".codex-runtime" / "final_message.txt"

    def _ensure_workspace_write_permissions(self) -> None:
        for path in [self.workspace_dir, *self.workspace_dir.rglob("*")]:
            if path.is_symlink():
                continue
            current_mode = path.stat().st_mode
            desired_mode = current_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
            if path.is_dir():
                desired_mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            elif current_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                desired_mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            os.chmod(path, desired_mode)

    def _prepare_workspace(self, judge_mcp_url: str) -> Path:
        return self._prepare_workspace_with_config(
            judge_mcp_url=judge_mcp_url,
            config_text=self.runtime.config_text,
        )

    def _prepare_workspace_with_config(self, *, judge_mcp_url: str, config_text: str) -> Path:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace_dir / ".codex").mkdir(parents=True, exist_ok=True)
        (self.workspace_dir / ".codex-runtime").mkdir(parents=True, exist_ok=True)
        config_text = _append_mcp_server_config(
            config_text,
            server_name=HOST_JUDGE_MCP_NAME,
            url=judge_mcp_url,
        )
        (self.workspace_dir / ".codex" / "config.toml").write_text(config_text, encoding="utf-8")
        prompt_path = self.workspace_dir / ".codex-runtime" / "prompt.txt"
        prompt_path.write_text(self._build_prompt(), encoding="utf-8")
        self._runtime_final_response_path().write_text("", encoding="utf-8")
        self._ensure_workspace_write_permissions()
        return prompt_path

    def _run_codex_exec(self, prompt_path: Path) -> subprocess.CompletedProcess[str]:
        raise RuntimeError("use _run_codex_exec_to_paths")

    @staticmethod
    def _empty_codex_usage() -> dict[str, Any]:
        return {
            "call_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "raw_non_json_lines": [],
        }

    @classmethod
    def _accumulate_codex_event(cls, event: dict[str, Any], usage: dict[str, Any]) -> None:
        if event.get("type") != "turn.completed":
            return
        event_usage = event.get("usage") or {}
        input_tokens = int(event_usage.get("input_tokens", 0) or 0)
        output_tokens = int(event_usage.get("output_tokens", 0) or 0)
        usage["call_count"] += 1
        usage["input_tokens"] += input_tokens
        usage["output_tokens"] += output_tokens
        usage["total_tokens"] += input_tokens + output_tokens

    @classmethod
    def _consume_codex_output_line(
        cls,
        line: str,
        *,
        events: list[dict[str, Any]] | None = None,
        usage: dict[str, Any] | None = None,
    ) -> None:
        stripped = line.strip()
        if not stripped:
            return
        if usage is None:
            usage = cls._empty_codex_usage()
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            usage.setdefault("raw_non_json_lines", []).append(stripped)
            return

        if events is not None:
            events.append(event)
        cls._accumulate_codex_event(event, usage)

    def _run_codex_exec_to_paths(
        self,
        *,
        prompt_path: Path,
        stdout_path: Path,
        stderr_path: Path,
        remaining_tokens: int | None,
        forwarded_env: dict[str, str] | None = None,
        usage_before: dict[str, Any] | None = None,
        usage_getter: Callable[[], dict[str, Any]] | None = None,
    ) -> CodexExecResult:
        timeout_seconds = int(os.getenv("REV_CODEX_EXEC_TIMEOUT", str(DEFAULT_CODEX_TIMEOUT_SECONDS)))
        env_args: list[str] = []
        merged_env = {"HOME": "/home/ctfplayer", **(forwarded_env or self.runtime.forwarded_env)}
        for name, value in merged_env.items():
            env_args.extend(["-e", f"{name}={value}"])
        workspace_dir = self.workspace_dir.resolve()
        public_path = self.config.public_path.resolve()

        model_args: list[str] = []
        if self.runtime.backend_model:
            model_args.extend(["-m", self.runtime.backend_model])

        cmd = [
            *_docker("run", "--rm"),
            "--platform",
            "linux/amd64",
            "--network",
            self.network_mode,
            *(
                ["--add-host", "host.docker.internal:host-gateway"]
                if self.network_mode != "host"
                else []
            ),
            *self.resource_limits.docker_run_args(),
            *env_args,
            "--volume",
            f"{public_path}:/home/ctfplayer/public/:ro",
            "--volume",
            f"{workspace_dir}:/home/ctfplayer:rw",
            *[arg for mount in self.runtime.docker_mounts() for arg in mount.docker_run_args()],
            "--workdir",
            "/home/ctfplayer",
            self.docker_image,
            "bash",
            "-lc",
            (
                f"export PATH={shlex.quote(str(CONTAINER_NODE_ROOT / 'bin'))}:$PATH; "
                f"codex exec --ephemeral --json --skip-git-repo-check "
                f"--dangerously-bypass-approvals-and-sandbox "
                + " ".join(shlex.quote(part) for part in model_args)
                + (
                    " " if model_args else ""
                )
                + f"-C /home/ctfplayer "
                + f"-o {shlex.quote(str(CONTAINER_RUNTIME_DIR / 'final_message.txt'))} "
                + f"- < {shlex.quote(str(Path('/home/ctfplayer/.codex-runtime/prompt.txt')))}"
            ),
        ]
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
            usage_lock = threading.Lock()
            live_usage = self._empty_codex_usage()
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            token_limit_hit = threading.Event()
            before_usage = dict(usage_before or self._empty_codex_usage())
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            def read_stdout() -> None:
                assert process.stdout is not None
                for line in process.stdout:
                    try:
                        stdout_file.write(line)
                        stdout_file.flush()
                    except (ValueError, OSError):
                        break
                    stdout_lines.append(line)
                    with usage_lock:
                        self._consume_codex_output_line(line, usage=live_usage)
                        if (
                            remaining_tokens is not None
                            and remaining_tokens > 0
                            and live_usage["total_tokens"] >= remaining_tokens
                            and not token_limit_hit.is_set()
                        ):
                            token_limit_hit.set()
                            process.kill()

            def read_stderr() -> None:
                assert process.stderr is not None
                for line in process.stderr:
                    try:
                        stderr_file.write(line)
                        stderr_file.flush()
                    except (ValueError, OSError):
                        break
                    stderr_lines.append(line)

            stdout_thread = threading.Thread(target=read_stdout, name="codex-stdout-reader", daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, name="codex-stderr-reader", daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            def monitor_proxy_usage() -> None:
                if usage_getter is None or remaining_tokens is None or remaining_tokens <= 0:
                    return
                while process.poll() is None:
                    current_usage = self._usage_delta(before_usage, usage_getter())
                    if current_usage["total_tokens"] >= remaining_tokens and not token_limit_hit.is_set():
                        token_limit_hit.set()
                        process.kill()
                        return
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        continue

            usage_thread = threading.Thread(target=monitor_proxy_usage, name="codex-usage-monitor", daemon=True)
            usage_thread.start()
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                returncode = -9
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            usage_thread.join(timeout=5)

        if usage_getter is not None:
            last_total = -1
            stable_polls = 0
            for _ in range(10):
                live_usage = self._usage_delta(before_usage, usage_getter())
                current_total = int(live_usage.get("total_tokens", 0) or 0)
                if current_total == last_total:
                    stable_polls += 1
                    if stable_polls >= 3:
                        break
                else:
                    stable_polls = 0
                    last_total = current_total
                sleep(0.1)

        return CodexExecResult(
            args=cmd,
            returncode=returncode,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
            token_limit_hit=token_limit_hit.is_set(),
            llm_usage={
                "call_count": live_usage["call_count"],
                "input_tokens": live_usage["input_tokens"],
                "output_tokens": live_usage["output_tokens"],
                "total_tokens": live_usage["total_tokens"],
                "estimated_cost": 0.0,
                "raw_non_json_lines": list(live_usage.get("raw_non_json_lines", [])),
            },
        )

    def _parse_codex_events(self, stdout: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        events: list[dict[str, Any]] = []
        usage = self._empty_codex_usage()
        for line in stdout.splitlines():
            self._consume_codex_output_line(line, events=events, usage=usage)
        return events, usage

    @staticmethod
    def _use_litellm_proxy() -> bool:
        return (os.getenv("REV_CODEX_USE_LITELLM") or "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    @staticmethod
    def _usage_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        before_events = list(before.get("events", []))
        after_events = list(after.get("events", []))
        return {
            "call_count": max(0, int(after.get("call_count", 0) or 0) - int(before.get("call_count", 0) or 0)),
            "input_tokens": max(0, int(after.get("input_tokens", 0) or 0) - int(before.get("input_tokens", 0) or 0)),
            "output_tokens": max(0, int(after.get("output_tokens", 0) or 0) - int(before.get("output_tokens", 0) or 0)),
            "total_tokens": max(0, int(after.get("total_tokens", 0) or 0) - int(before.get("total_tokens", 0) or 0)),
            "estimated_cost": max(0.0, float(after.get("estimated_cost", 0.0) or 0.0) - float(before.get("estimated_cost", 0.0) or 0.0)),
            "events": after_events[len(before_events):],
        }

    def _codex_config_text_for_proxy(self, *, proxy_base_url: str) -> str:
        model = self.runtime.backend_model or os.getenv("CODEX_MODEL") or "gpt-5.4"
        return (
            f'model = "{model}"\n'
            f'model_reasoning_effort = "{os.getenv("CODEX_REASONING_EFFORT", "medium")}"\n'
            'model_provider = "openai"\n'
            f'openai_base_url = "{proxy_base_url.rstrip("/")}"\n'
        )

    def _azure_endpoint_for_proxy(self) -> str:
        explicit = (os.getenv("AZURE_OPENAI_ENDPOINT") or "").strip()
        if explicit:
            return explicit
        configured_base = _extract_azure_base_url_from_config(self.runtime.config_text)
        if configured_base:
            normalized = configured_base.rstrip("/")
            if normalized.endswith("/openai/v1"):
                return normalized[: -len("/openai/v1")]
            return normalized
        raise RuntimeError(
            "AZURE_OPENAI_ENDPOINT is not set and no Azure base_url could be parsed from Codex config."
        )

    def _openai_base_url_for_proxy(self) -> str:
        explicit = (os.getenv("OPENAI_API_BASE_URL") or "").strip()
        if explicit:
            return explicit.rstrip("/")
        configured_base = _extract_azure_base_url_from_config(self.runtime.config_text)
        if configured_base:
            return configured_base.rstrip("/")
        return "https://api.openai.com/v1"

    def _read_final_response(self) -> str:
        final_message_path = self._runtime_final_response_path()
        if not final_message_path.exists():
            return ""
        return final_message_path.read_text(encoding="utf-8").strip()

    def _reset_final_response_file(self) -> None:
        final_message_path = self._runtime_final_response_path()
        final_message_path.parent.mkdir(parents=True, exist_ok=True)
        final_message_path.write_text("", encoding="utf-8")

    def _attempt_dir(self, attempt: int) -> Path:
        return self.output_dir / "codex_attempts" / f"attempt-{attempt}"

    def _snapshot_attempt_artifacts(
        self,
        *,
        attempt: int,
        completed: CodexExecResult,
        final_response: str,
        prompt_path: Path,
    ) -> dict[str, Any]:
        attempt_dir = self._attempt_dir(attempt)
        attempt_dir.mkdir(parents=True, exist_ok=True)

        stdout_path = attempt_dir / "stdout.jsonl"
        stderr_path = attempt_dir / "stderr.log"
        final_response_path = attempt_dir / "final_message.txt"
        prompt_copy_path = attempt_dir / "prompt.txt"
        config_copy_path = attempt_dir / "config.toml"

        stdout_path.write_text(completed.stdout or "", encoding="utf-8")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8")
        final_response_path.write_text(final_response, encoding="utf-8")
        prompt_copy_path.write_text(prompt_path.read_text(encoding="utf-8"), encoding="utf-8")

        config_path = self.workspace_dir / ".codex" / "config.toml"
        if config_path.exists():
            config_copy_path.write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")

        workspace_listing = attempt_dir / "workspace_files.txt"
        workspace_files = sorted(
            str(path.relative_to(self.workspace_dir))
            for path in self.workspace_dir.rglob("*")
            if path.is_file()
        )
        workspace_listing.write_text("\n".join(workspace_files) + ("\n" if workspace_files else ""), encoding="utf-8")

        return {
            "attempt": attempt,
            "returncode": completed.returncode,
            "token_limit_hit": completed.token_limit_hit,
            "llm_usage": completed.llm_usage,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "final_response_path": str(final_response_path),
            "prompt_path": str(prompt_copy_path),
            "config_path": str(config_copy_path) if config_copy_path.exists() else "",
            "workspace_files_path": str(workspace_listing),
            "has_final_response": bool(final_response),
        }

    def _attempt_has_usable_result(self, completed: CodexExecResult) -> bool:
        if self.eval_mode == "flag_only" and self.tool_executor.score_report.level4_flag.score == 25:
            return True
        if self.eval_mode == "full" and not self.tool_executor.get_pending_submissions():
            return True
        if self.eval_mode == "flag_only" and completed.returncode == 0 and self.tool_executor.score_report.level4_flag.submitted:
            return True
        return False

    def run(self) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        retry_attempts = int(os.getenv("REV_CODEX_RUN_RETRIES", "3"))
        started_at = time()
        completed: CodexExecResult | None = None
        final_response = ""
        attempt_records: list[dict[str, Any]] = []
        cumulative_llm_usage = self._empty_codex_usage()
        token_limit_hit = False
        judge_host = "127.0.0.1" if self.network_mode == "host" else "host.docker.internal"
        with HostJudgeMCPServer(self.tool_executor) as judge_server:
            if self._use_litellm_proxy():
                backend_provider = (self.runtime.provider_name or "").strip().lower()
                if backend_provider not in {"azure", "openai"}:
                    raise RuntimeError(
                        "Codex + LiteLLM currently supports only Azure or OpenAI backends. "
                        f"Resolved backend provider was {self.runtime.provider_name!r}."
                    )
                if backend_provider == "azure":
                    proxy_api_key = os.environ["AZURE_OPENAI_API_KEY"]
                    proxy_api_base = self._azure_endpoint_for_proxy()
                    proxy_api_version = _azure_api_version_for_responses_proxy()
                else:
                    proxy_api_key = os.environ["OPENAI_API_KEY"]
                    proxy_api_base = self._openai_base_url_for_proxy()
                    proxy_api_version = None
                with LiteLLMOpenAIProxy(
                    provider_name=backend_provider,
                    model_alias=self.runtime.backend_model or os.getenv("CODEX_MODEL") or "gpt-5.4",
                    backend_model=self.runtime.backend_model or os.getenv("CODEX_MODEL") or "gpt-5.4",
                    api_key=proxy_api_key,
                    api_base=proxy_api_base,
                    api_version=proxy_api_version,
                    bind_host="0.0.0.0",
                    work_dir=self.output_dir,
                ) as proxy:
                    proxy_host = "127.0.0.1" if self.network_mode == "host" else "host.docker.internal"
                    prompt_path = self._prepare_workspace_with_config(
                        judge_mcp_url=judge_server.url_for_host(judge_host),
                        config_text=self._codex_config_text_for_proxy(
                            proxy_base_url=f"{proxy.url_for_host(proxy_host).rstrip('/')}/v1"
                        ),
                    )
                    for attempt in range(1, retry_attempts + 1):
                        remaining_tokens: int | None = None
                        if self.max_tokens > 0:
                            remaining_tokens = self.max_tokens - cumulative_llm_usage["total_tokens"]
                            if remaining_tokens <= 0:
                                token_limit_hit = True
                                break
                        self._reset_final_response_file()
                        attempt_dir = self._attempt_dir(attempt)
                        live_stdout_path = attempt_dir / "stdout.jsonl"
                        live_stderr_path = attempt_dir / "stderr.log"
                        usage_before_attempt = proxy.usage_summary()
                        completed = self._run_codex_exec_to_paths(
                            prompt_path=prompt_path,
                            stdout_path=live_stdout_path,
                            stderr_path=live_stderr_path,
                            remaining_tokens=remaining_tokens,
                            forwarded_env={"OPENAI_API_KEY": proxy.auth_token},
                            usage_before=usage_before_attempt,
                            usage_getter=proxy.usage_summary,
                        )
                        sleep(0.3)
                        finalized_usage = self._usage_delta(usage_before_attempt, proxy.usage_summary())
                        completed.llm_usage = {
                            "call_count": finalized_usage["call_count"],
                            "input_tokens": finalized_usage["input_tokens"],
                            "output_tokens": finalized_usage["output_tokens"],
                            "total_tokens": finalized_usage["total_tokens"],
                            "estimated_cost": float(finalized_usage.get("estimated_cost", 0.0) or 0.0),
                            "raw_non_json_lines": list(finalized_usage.get("raw_non_json_lines", [])),
                        }
                        final_response = self._read_final_response()
                        cumulative_llm_usage["call_count"] += completed.llm_usage.get("call_count", 0)
                        cumulative_llm_usage["input_tokens"] += completed.llm_usage.get("input_tokens", 0)
                        cumulative_llm_usage["output_tokens"] += completed.llm_usage.get("output_tokens", 0)
                        cumulative_llm_usage["total_tokens"] += completed.llm_usage.get("total_tokens", 0)
                        cumulative_llm_usage["estimated_cost"] += completed.llm_usage.get("estimated_cost", 0.0)
                        cumulative_llm_usage["raw_non_json_lines"].extend(completed.llm_usage.get("raw_non_json_lines", []))
                        token_limit_hit = token_limit_hit or completed.token_limit_hit
                        attempt_records.append(
                            self._snapshot_attempt_artifacts(
                                attempt=attempt,
                                completed=completed,
                                final_response=final_response,
                                prompt_path=prompt_path,
                            )
                        )
                        if completed.token_limit_hit:
                            break
                        if self._attempt_has_usable_result(completed):
                            break
                        logger.warning(
                            "Codex run attempt %s/%s did not yield a usable result (returncode=%s, pending=%s).",
                            attempt,
                            retry_attempts,
                            None if completed is None else completed.returncode,
                            self.tool_executor.get_pending_submissions(),
                        )
            else:
                prompt_path = self._prepare_workspace(
                    judge_mcp_url=judge_server.url_for_host(judge_host)
                )
                for attempt in range(1, retry_attempts + 1):
                    remaining_tokens: int | None = None
                    if self.max_tokens > 0:
                        remaining_tokens = self.max_tokens - cumulative_llm_usage["total_tokens"]
                        if remaining_tokens <= 0:
                            token_limit_hit = True
                            break
                    self._reset_final_response_file()
                    attempt_dir = self._attempt_dir(attempt)
                    live_stdout_path = attempt_dir / "stdout.jsonl"
                    live_stderr_path = attempt_dir / "stderr.log"
                    completed = self._run_codex_exec_to_paths(
                        prompt_path=prompt_path,
                        stdout_path=live_stdout_path,
                        stderr_path=live_stderr_path,
                        remaining_tokens=remaining_tokens,
                    )
                    final_response = self._read_final_response()
                    cumulative_llm_usage["call_count"] += completed.llm_usage.get("call_count", 0)
                    cumulative_llm_usage["input_tokens"] += completed.llm_usage.get("input_tokens", 0)
                    cumulative_llm_usage["output_tokens"] += completed.llm_usage.get("output_tokens", 0)
                    cumulative_llm_usage["total_tokens"] += completed.llm_usage.get("total_tokens", 0)
                    cumulative_llm_usage["estimated_cost"] += completed.llm_usage.get("estimated_cost", 0.0)
                    cumulative_llm_usage["raw_non_json_lines"].extend(completed.llm_usage.get("raw_non_json_lines", []))
                    token_limit_hit = token_limit_hit or completed.token_limit_hit
                    attempt_records.append(
                        self._snapshot_attempt_artifacts(
                            attempt=attempt,
                            completed=completed,
                            final_response=final_response,
                            prompt_path=prompt_path,
                        )
                    )
                    if completed.token_limit_hit:
                        break
                    if self._attempt_has_usable_result(completed):
                        break
                    logger.warning(
                        "Codex run attempt %s/%s did not yield a usable result (returncode=%s, pending=%s).",
                        attempt,
                        retry_attempts,
                        None if completed is None else completed.returncode,
                        self.tool_executor.get_pending_submissions(),
                    )
        if completed is None:
            completed = CodexExecResult(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
                token_limit_hit=token_limit_hit,
                llm_usage=self._empty_codex_usage(),
            )
        duration_seconds = time() - started_at

        self.output_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = self.output_dir / "codex_stdout.jsonl"
        stderr_path = self.output_dir / "codex_stderr.log"
        stdout_path.write_text(completed.stdout or "", encoding="utf-8")
        stderr_path.write_text(completed.stderr or "", encoding="utf-8")
        attempts_manifest_path = self.output_dir / "codex_attempts.json"
        attempts_manifest_path.write_text(json.dumps(attempt_records, indent=2), encoding="utf-8")

        events, final_attempt_usage = self._parse_codex_events(completed.stdout or "")
        if completed.llm_usage:
            final_attempt_usage = completed.llm_usage
        final_response_path = self.output_dir / "codex_final_message.txt"
        final_response_path.write_text(final_response, encoding="utf-8")

        parse_error_count = 0
        score_report = self.tool_executor.finalize_scores()

        if token_limit_hit:
            stop_reason = "max_tokens_exceeded"
        elif self.eval_mode == "flag_only" and score_report.level4_flag.score == 25:
            stop_reason = "correct_flag_submitted"
        elif self.eval_mode == "full" and not self.tool_executor.get_pending_submissions():
            stop_reason = "all_submissions_recorded"
        elif self.eval_mode == "flag_only" and completed.returncode == 0 and score_report.level4_flag.submitted:
            stop_reason = "codex_completed_after_submissions"
        elif self.eval_mode == "full" and completed.returncode == 0 and self.tool_executor.tool_call_count > 0:
            stop_reason = "codex_completed_with_partial_submissions"
        elif completed.returncode == -9 and self.tool_executor.tool_call_count > 0:
            stop_reason = "codex_timeout_after_submissions"
        elif completed.returncode == 0:
            stop_reason = "codex_completed_without_submissions"
        else:
            stop_reason = "codex_exec_failed"
        metrics = {
            "model": self.model,
            "eval_mode": self.eval_mode,
            "max_rounds": 0,
            "rounds_used": 0,
            "model_turns": cumulative_llm_usage.get("call_count", 0),
            "max_tokens": self.max_tokens,
            "token_limit_hit": token_limit_hit,
            "parse_error_count": parse_error_count,
            "stop_reason": stop_reason,
            "duration_seconds": duration_seconds,
            "llm_usage": {
                "call_count": cumulative_llm_usage.get("call_count", 0),
                "input_tokens": cumulative_llm_usage.get("input_tokens", 0),
                "output_tokens": cumulative_llm_usage.get("output_tokens", 0),
                "total_tokens": cumulative_llm_usage.get("total_tokens", 0),
                "estimated_cost": 0.0,
                "per_attempt": [record.get("llm_usage", {}) for record in attempt_records],
            },
            "tool_metrics": self.tool_executor.get_metrics(),
            "score": score_report.to_dict(),
            "codex": {
                "backend_model": self.runtime.backend_model or "",
                "exit_code": completed.returncode,
                "final_attempt_llm_usage": final_attempt_usage,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "final_response_path": str(final_response_path),
                "workspace_dir": str(self.workspace_dir),
                "attempts_manifest_path": str(attempts_manifest_path),
                "attempt_count": len(attempt_records),
            },
        }

        conversation = {
            "runner": "codex",
            "events": events,
            "final_response": final_response,
            "judge_state": score_report.to_dict(),
            "attempts": attempt_records,
        }
        return metrics, conversation, events
