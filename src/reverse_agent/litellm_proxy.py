import os
import secrets
import shlex
import shutil
import socket
import http.client
import subprocess
import sys
import time
import json
import threading
from pathlib import Path
from typing import Any


def _reserve_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def _normalize_azure_base_url(endpoint: str) -> str:
    trimmed = endpoint.rstrip("/")
    if trimmed.endswith("/openai/v1"):
        return trimmed
    return f"{trimmed}/openai/v1"


def _normalize_azure_endpoint_root(endpoint: str) -> str:
    trimmed = endpoint.rstrip("/")
    for suffix in ("/openai/v1", "/openai"):
        if trimmed.endswith(suffix):
            return trimmed[: -len(suffix)]
    return trimmed


def _default_remote_num_retries() -> int:
    raw = (os.getenv("REV_LITELLM_REMOTE_NUM_RETRIES") or "").strip()
    if not raw:
        return 5
    try:
        return max(0, int(raw))
    except ValueError:
        return 5


def _default_startup_timeout_seconds() -> float:
    raw = (os.getenv("REV_LITELLM_STARTUP_TIMEOUT_SECS") or "").strip()
    if not raw:
        return 60.0
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 60.0


def _probe_hosts(bind_host: str) -> list[str]:
    hosts: list[str] = []
    normalized = (bind_host or "").strip()
    if normalized in {"", "0.0.0.0", "::"}:
        hosts.extend(["127.0.0.1", "localhost"])
    else:
        hosts.append(normalized)
        if normalized not in {"127.0.0.1", "localhost"}:
            hosts.extend(["127.0.0.1", "localhost"])
    deduped: list[str] = []
    for host in hosts:
        if host not in deduped:
            deduped.append(host)
    return deduped


def _socket_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _http_ready(host: str, port: int) -> bool:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=1.0)
        conn.request("GET", "/")
        response = conn.getresponse()
        response.read()
        return True
    except OSError:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _tail_text(path: Path, max_lines: int = 20) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    return "\n".join(lines[-max_lines:])


def _wait_for_litellm_ready(
    *,
    process: subprocess.Popen[str] | None,
    port: int,
    bind_host: str,
    stderr_path: Path,
) -> None:
    deadline = time.time() + _default_startup_timeout_seconds()
    hosts = _probe_hosts(bind_host)
    last_socket_host = ""
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            stderr_tail = _tail_text(stderr_path)
            detail = f" See {stderr_path}."
            if stderr_tail:
                detail = f" Last stderr lines:\n{stderr_tail}"
            raise RuntimeError(
                f"LiteLLM exited early with code {process.returncode}.{detail}"
            )
        for host in hosts:
            if not _socket_ready(host, port):
                continue
            last_socket_host = host
            if _http_ready(host, port):
                return
        time.sleep(0.2)

    if last_socket_host:
        return

    stderr_tail = _tail_text(stderr_path)
    detail = f" See {stderr_path}."
    if stderr_tail:
        detail = f" Last stderr lines:\n{stderr_tail}"
    raise RuntimeError(
        f"Timed out waiting for LiteLLM to listen on port {port}.{detail}"
    )


class LiteLLMAnthropicProxy:
    def __init__(
        self,
        *,
        model_alias: str,
        backend_model: str,
        azure_api_key: str,
        azure_endpoint: str,
        azure_api_version: str,
        bind_host: str = "0.0.0.0",
        port: int = 0,
        work_dir: Path,
    ) -> None:
        self.model_alias = model_alias
        self.backend_model = backend_model
        self.azure_api_key = azure_api_key
        self.azure_endpoint = azure_endpoint
        self.azure_api_version = azure_api_version
        self.bind_host = bind_host
        self.port = port
        self.work_dir = work_dir
        self.auth_token = secrets.token_hex(16)
        self._process: subprocess.Popen[str] | None = None
        self._config_path = self.work_dir / "litellm_proxy_config.yaml"
        self._stdout_path = self.work_dir / "litellm_proxy_stdout.log"
        self._stderr_path = self.work_dir / "litellm_proxy_stderr.log"
        self._usage_path = self.work_dir / "litellm_usage.jsonl"
        self._trace_path = self.work_dir / "litellm_trace.jsonl"
        self._usage_lock = threading.Lock()
        self._usage_offset = 0
        self._usage_summary_cache = {
            "call_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "events": [],
        }

    @property
    def stdout_path(self) -> Path:
        return self._stdout_path

    @property
    def stderr_path(self) -> Path:
        return self._stderr_path

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def usage_path(self) -> Path:
        return self._usage_path

    @property
    def trace_path(self) -> Path:
        return self._trace_path

    def _litellm_wrapper_script(self) -> Path:
        return Path(__file__).resolve().with_name("litellm_proxy_wrapper.py")

    def _litellm_binary(self) -> str:
        explicit = (os.getenv("LITELLM_BIN") or "").strip()
        if explicit:
            return str(Path(explicit).expanduser().resolve())
        sibling = Path(sys.executable).resolve().parent / "litellm"
        if sibling.exists():
            return str(sibling)
        found = shutil.which("litellm")
        if found:
            return found
        raise RuntimeError("LiteLLM binary not found. Set LITELLM_BIN or install litellm in the active environment.")

    def _litellm_python(self) -> str:
        explicit = (os.getenv("LITELLM_PYTHON") or "").strip()
        if explicit:
            return str(Path(explicit).expanduser().resolve())

        binary_path = Path(self._litellm_binary())
        try:
            with binary_path.open("r", encoding="utf-8", errors="ignore") as handle:
                first_line = handle.readline().strip()
        except OSError:
            first_line = ""

        if first_line.startswith("#!"):
            shebang = first_line[2:].strip()
            parts = shlex.split(shebang)
            if parts:
                if Path(parts[0]).name == "env" and len(parts) >= 2:
                    found = shutil.which(parts[1])
                    if found:
                        return str(Path(found).resolve())
                elif Path(parts[0]).exists():
                    return str(Path(parts[0]).resolve())

        sibling_candidates = [
            binary_path.parent / "python",
            binary_path.parent / f"python{sys.version_info.major}.{sys.version_info.minor}",
            binary_path.parent / "python3",
        ]
        for candidate in sibling_candidates:
            if candidate.exists():
                return str(candidate.resolve())

        current_python = Path(sys.executable).resolve()
        if current_python.exists():
            return str(current_python)
        raise RuntimeError(
            "Unable to resolve a Python interpreter for LiteLLM. Set LITELLM_PYTHON explicitly."
        )

    def _launch_command(self) -> list[str]:
        wrapper_script = self._litellm_wrapper_script()
        if not wrapper_script.exists():
            raise RuntimeError(f"LiteLLM wrapper script not found: {wrapper_script}")
        cmd = [
            self._litellm_python(),
            str(wrapper_script),
            "--host",
            self.bind_host,
            "--port",
            str(self.port),
            "--config",
            str(self._config_path),
            "--telemetry",
            "False",
        ]
        if (os.getenv("REV_LITELLM_DETAILED_DEBUG") or "").strip().lower() in {"1", "true", "yes", "on"}:
            cmd.append("--detailed_debug")
        return cmd

    def _write_config(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._usage_path.write_text("", encoding="utf-8")
        self._trace_path.write_text("", encoding="utf-8")
        self._usage_offset = 0
        self._usage_summary_cache = {
            "call_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "events": [],
        }
        normalized_endpoint = _normalize_azure_endpoint_root(self.azure_endpoint)
        num_retries = _default_remote_num_retries()
        config = (
            "model_list:\n"
            f"  - model_name: {self.model_alias}\n"
            "    litellm_params:\n"
            f"      model: azure/{self.backend_model}\n"
            "      api_key: os.environ/AZURE_OPENAI_API_KEY\n"
            f"      api_base: {normalized_endpoint}\n"
            f"      api_version: {self.azure_api_version or 'v1'}\n"
            f"      num_retries: {num_retries}\n"
            "litellm_settings:\n"
            "  drop_params: true\n"
        )
        self._config_path.write_text(config, encoding="utf-8")

    def _wait_until_ready(self) -> None:
        _wait_for_litellm_ready(
            process=self._process,
            port=self.port,
            bind_host=self.bind_host,
            stderr_path=self._stderr_path,
        )

    def start(self) -> None:
        if self._process is not None:
            return
        self.port = self.port or _reserve_port("127.0.0.1")
        self._write_config()
        normalized_endpoint = _normalize_azure_endpoint_root(self.azure_endpoint)
        env = os.environ.copy()
        env["AZURE_OPENAI_API_KEY"] = self.azure_api_key
        env["AZURE_OPENAI_ENDPOINT"] = normalized_endpoint
        env["AZURE_API_BASE"] = normalized_endpoint
        env["AZURE_OPENAI_API_VERSION"] = self.azure_api_version or "v1"
        env["REV_LITELLM_DEFAULT_MODEL"] = self.model_alias
        env["REV_LITELLM_ENABLE_WS"] = os.getenv("REV_LITELLM_ENABLE_WS", "0")
        env["REV_LITELLM_USAGE_PATH"] = str(self._usage_path)
        env["REV_LITELLM_TRACE_PATH"] = str(self._trace_path)
        env["PYTHONUNBUFFERED"] = "1"
        cmd = self._launch_command()
        stdout_handle = self._stdout_path.open("w", encoding="utf-8")
        stderr_handle = self._stderr_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            cmd,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            env=env,
        )
        try:
            self._wait_until_ready()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self._process is None:
            return
        process = self._process
        self._process = None
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def __enter__(self) -> "LiteLLMAnthropicProxy":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def url_for_host(self, host: str) -> str:
        return f"http://{host}:{self.port}"

    def _refresh_usage_summary(self) -> None:
        if not self._usage_path.exists():
            return
        with self._usage_lock:
            with self._usage_path.open("r", encoding="utf-8") as handle:
                handle.seek(self._usage_offset)
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    input_tokens = int(event.get("input_tokens", 0) or 0)
                    output_tokens = int(event.get("output_tokens", 0) or 0)
                    total_tokens = int(event.get("total_tokens", input_tokens + output_tokens) or 0)
                    estimated_cost = float(event.get("estimated_cost", 0.0) or 0.0)
                    self._usage_summary_cache["call_count"] += 1
                    self._usage_summary_cache["input_tokens"] += input_tokens
                    self._usage_summary_cache["output_tokens"] += output_tokens
                    self._usage_summary_cache["total_tokens"] += total_tokens
                    self._usage_summary_cache["estimated_cost"] += estimated_cost
                    self._usage_summary_cache["events"].append(event)
                self._usage_offset = handle.tell()

    def usage_summary(self) -> dict[str, Any]:
        self._refresh_usage_summary()
        return {
            "call_count": int(self._usage_summary_cache["call_count"]),
            "input_tokens": int(self._usage_summary_cache["input_tokens"]),
            "output_tokens": int(self._usage_summary_cache["output_tokens"]),
            "total_tokens": int(self._usage_summary_cache["total_tokens"]),
            "estimated_cost": float(self._usage_summary_cache["estimated_cost"]),
            "events": list(self._usage_summary_cache["events"]),
        }

    def gateway_events(self) -> list[dict[str, Any]]:
        return []


class LiteLLMOpenAIProxy:
    def __init__(
        self,
        *,
        provider_name: str,
        model_alias: str,
        backend_model: str,
        api_key: str,
        api_base: str,
        api_version: str | None = None,
        bind_host: str = "0.0.0.0",
        port: int = 0,
        work_dir: Path,
    ) -> None:
        self.provider_name = provider_name
        self.model_alias = model_alias
        self.backend_model = backend_model
        self.api_key = api_key
        self.api_base = api_base
        self.api_version = api_version
        self.bind_host = bind_host
        self.port = port
        self.work_dir = work_dir
        self.auth_token = secrets.token_hex(16)
        self._process: subprocess.Popen[str] | None = None
        self._config_path = self.work_dir / "litellm_proxy_config.yaml"
        self._stdout_path = self.work_dir / "litellm_proxy_stdout.log"
        self._stderr_path = self.work_dir / "litellm_proxy_stderr.log"
        self._usage_path = self.work_dir / "litellm_usage.jsonl"
        self._trace_path = self.work_dir / "litellm_trace.jsonl"
        self._usage_lock = threading.Lock()
        self._usage_offset = 0
        self._usage_summary_cache = {
            "call_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "events": [],
        }

    @property
    def stdout_path(self) -> Path:
        return self._stdout_path

    @property
    def stderr_path(self) -> Path:
        return self._stderr_path

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def usage_path(self) -> Path:
        return self._usage_path

    @property
    def trace_path(self) -> Path:
        return self._trace_path

    def _litellm_wrapper_script(self) -> Path:
        return Path(__file__).resolve().with_name("litellm_proxy_wrapper.py")

    def _litellm_binary(self) -> str:
        explicit = (os.getenv("LITELLM_BIN") or "").strip()
        if explicit:
            return str(Path(explicit).expanduser().resolve())
        sibling = Path(sys.executable).resolve().parent / "litellm"
        if sibling.exists():
            return str(sibling)
        found = shutil.which("litellm")
        if found:
            return found
        raise RuntimeError("LiteLLM binary not found. Set LITELLM_BIN or install litellm in the active environment.")

    def _litellm_python(self) -> str:
        explicit = (os.getenv("LITELLM_PYTHON") or "").strip()
        if explicit:
            return str(Path(explicit).expanduser().resolve())

        binary_path = Path(self._litellm_binary())
        try:
            with binary_path.open("r", encoding="utf-8", errors="ignore") as handle:
                first_line = handle.readline().strip()
        except OSError:
            first_line = ""

        if first_line.startswith("#!"):
            shebang = first_line[2:].strip()
            parts = shlex.split(shebang)
            if parts:
                if Path(parts[0]).name == "env" and len(parts) >= 2:
                    found = shutil.which(parts[1])
                    if found:
                        return str(Path(found).resolve())
                elif Path(parts[0]).exists():
                    return str(Path(parts[0]).resolve())

        sibling_candidates = [
            binary_path.parent / "python",
            binary_path.parent / f"python{sys.version_info.major}.{sys.version_info.minor}",
            binary_path.parent / "python3",
        ]
        for candidate in sibling_candidates:
            if candidate.exists():
                return str(candidate.resolve())

        current_python = Path(sys.executable).resolve()
        if current_python.exists():
            return str(current_python)
        raise RuntimeError(
            "Unable to resolve a Python interpreter for LiteLLM. Set LITELLM_PYTHON explicitly."
        )

    def _launch_command(self) -> list[str]:
        wrapper_script = self._litellm_wrapper_script()
        if not wrapper_script.exists():
            raise RuntimeError(f"LiteLLM wrapper script not found: {wrapper_script}")
        cmd = [
            self._litellm_python(),
            str(wrapper_script),
            "--host",
            self.bind_host,
            "--port",
            str(self.port),
            "--config",
            str(self._config_path),
            "--telemetry",
            "False",
        ]
        if (os.getenv("REV_LITELLM_DETAILED_DEBUG") or "").strip().lower() in {"1", "true", "yes", "on"}:
            cmd.append("--detailed_debug")
        return cmd

    def _write_config(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._usage_path.write_text("", encoding="utf-8")
        self._trace_path.write_text("", encoding="utf-8")
        self._usage_offset = 0
        self._usage_summary_cache = {
            "call_count": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
            "events": [],
        }
        num_retries = _default_remote_num_retries()
        if self.provider_name == "azure":
            normalized_endpoint = _normalize_azure_endpoint_root(self.api_base)
            config = (
                "model_list:\n"
                f"  - model_name: {self.model_alias}\n"
                "    litellm_params:\n"
                f"      model: azure/{self.backend_model}\n"
                "      api_key: os.environ/AZURE_OPENAI_API_KEY\n"
                f"      api_base: {normalized_endpoint}\n"
                f"      api_version: {self.api_version or 'v1'}\n"
                f"      num_retries: {num_retries}\n"
                "litellm_settings:\n"
                "  drop_params: true\n"
            )
        elif self.provider_name == "openai":
            normalized_base = self.api_base.rstrip("/")
            config = (
                "model_list:\n"
                f"  - model_name: {self.model_alias}\n"
                "    litellm_params:\n"
                f"      model: openai/{self.backend_model}\n"
                "      api_key: os.environ/OPENAI_API_KEY\n"
                f"      api_base: {normalized_base}\n"
                f"      num_retries: {num_retries}\n"
                "litellm_settings:\n"
                "  drop_params: true\n"
            )
        else:
            raise RuntimeError(f"Unsupported LiteLLM OpenAI proxy backend provider: {self.provider_name!r}")
        self._config_path.write_text(config, encoding="utf-8")

    def _wait_until_ready(self) -> None:
        _wait_for_litellm_ready(
            process=self._process,
            port=self.port,
            bind_host=self.bind_host,
            stderr_path=self._stderr_path,
        )

    def start(self) -> None:
        if self._process is not None:
            return
        self.port = self.port or _reserve_port("127.0.0.1")
        self._write_config()
        env = os.environ.copy()
        if self.provider_name == "azure":
            normalized_endpoint = _normalize_azure_endpoint_root(self.api_base)
            env["AZURE_OPENAI_API_KEY"] = self.api_key
            env["AZURE_OPENAI_ENDPOINT"] = normalized_endpoint
            env["AZURE_API_BASE"] = normalized_endpoint
            env["AZURE_OPENAI_API_VERSION"] = self.api_version or "v1"
        elif self.provider_name == "openai":
            normalized_base = self.api_base.rstrip("/")
            env["OPENAI_API_KEY"] = self.api_key
            env["OPENAI_API_BASE_URL"] = normalized_base
        else:
            raise RuntimeError(f"Unsupported LiteLLM OpenAI proxy backend provider: {self.provider_name!r}")
        env["REV_LITELLM_DEFAULT_MODEL"] = self.model_alias
        env["REV_LITELLM_ENABLE_WS"] = os.getenv("REV_LITELLM_ENABLE_WS", "0")
        env["REV_LITELLM_USAGE_PATH"] = str(self._usage_path)
        env["REV_LITELLM_TRACE_PATH"] = str(self._trace_path)
        env["PYTHONUNBUFFERED"] = "1"
        cmd = self._launch_command()
        stdout_handle = self._stdout_path.open("w", encoding="utf-8")
        stderr_handle = self._stderr_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(
            cmd,
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            env=env,
        )
        try:
            self._wait_until_ready()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self._process is None:
            return
        process = self._process
        self._process = None
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def __enter__(self) -> "LiteLLMOpenAIProxy":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def url_for_host(self, host: str) -> str:
        return f"http://{host}:{self.port}"

    def _refresh_usage_summary(self) -> None:
        if not self._usage_path.exists():
            return
        with self._usage_lock:
            with self._usage_path.open("r", encoding="utf-8") as handle:
                handle.seek(self._usage_offset)
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    input_tokens = int(event.get("input_tokens", 0) or 0)
                    output_tokens = int(event.get("output_tokens", 0) or 0)
                    total_tokens = int(event.get("total_tokens", input_tokens + output_tokens) or 0)
                    estimated_cost = float(event.get("estimated_cost", 0.0) or 0.0)
                    self._usage_summary_cache["call_count"] += 1
                    self._usage_summary_cache["input_tokens"] += input_tokens
                    self._usage_summary_cache["output_tokens"] += output_tokens
                    self._usage_summary_cache["total_tokens"] += total_tokens
                    self._usage_summary_cache["estimated_cost"] += estimated_cost
                    self._usage_summary_cache["events"].append(event)
                self._usage_offset = handle.tell()

    def usage_summary(self) -> dict[str, Any]:
        self._refresh_usage_summary()
        return {
            "call_count": int(self._usage_summary_cache["call_count"]),
            "input_tokens": int(self._usage_summary_cache["input_tokens"]),
            "output_tokens": int(self._usage_summary_cache["output_tokens"]),
            "total_tokens": int(self._usage_summary_cache["total_tokens"]),
            "estimated_cost": float(self._usage_summary_cache["estimated_cost"]),
            "events": list(self._usage_summary_cache["events"]),
        }

    def gateway_events(self) -> list[dict[str, Any]]:
        return []
