import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import time
import base64
import os
import shlex
import uuid
from dataclasses import dataclass

from .config import ChallengeConfig

logger = logging.getLogger(__name__)

MAX_TOOL_OUTPUT_CHARS = 12000
DOCKER_CMD = shlex.split(os.environ.get("DOCKER_CMD", "sudo docker"))


def _docker(*args: str) -> list[str]:
    return [*DOCKER_CMD, *args]

def clean_out(text: bytes) -> str:
    """Decodes bytes to string, handling potential errors."""
    try:
        return text.decode('utf-8', errors='backslashreplace').replace('\r\n', '\n')
    except (TypeError, AttributeError):
        return ""


def _truncate_output(text: str, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> tuple[str, bool]:
    """Truncation disabled: always return the full text."""
    return text, False


def _gdb_failure_reason(output: str, timed_out: bool, returncode: int | None) -> tuple[str | None, str]:
    """Classify common GDB failure modes to make agent traces easier to interpret."""
    if timed_out:
        return "timeout", "GDB execution timed out before the command sequence completed."

    if returncode == 0:
        return None, "GDB completed successfully."

    lowered = output.lower()
    checks = [
        ("invalid_command", "undefined command", "GDB rejected at least one command in the script."),
        ("missing_binary", "no executable file specified", "The requested binary was not available to GDB."),
        ("missing_binary", "not in executable format", "The requested binary could not be executed by GDB."),
        ("permission_denied", "operation not permitted", "GDB was blocked by a permission or ptrace restriction."),
        ("no_symbols", "no symbol table is loaded", "The target has no usable symbol table for that request."),
        ("no_registers", "the program has no registers now", "The command expected a running or stopped process, but no inferior state was available."),
        ("no_stack", "no stack", "Backtrace data was requested when no stack was available."),
        ("program_crash", "program received signal", "The inferior crashed or hit a signal during execution."),
    ]
    for reason, needle, summary in checks:
        if needle in lowered:
            return reason, summary

    return "gdb_error", "GDB returned a non-zero exit code."


def _build_gdb_result(stdout: str, stderr: str, returncode: int | None, timed_out: bool) -> Dict[str, Any]:
    combined = "\n".join(part for part in (stdout, stderr) if part).strip()
    stdout_text, stdout_truncated = _truncate_output(stdout)
    stderr_text, stderr_truncated = _truncate_output(stderr)
    failure_reason, summary = _gdb_failure_reason(combined, timed_out, returncode)
    status = "ok" if failure_reason is None else "error"
    if timed_out:
        status = "timeout"

    return {
        "status": status,
        "failure_reason": failure_reason,
        "summary": summary,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }

class DockerEnvironment:
    @dataclass(frozen=True)
    class ResourceLimits:
        memory: str | None = None
        memory_swap: str | None = None
        cpus: str | None = None
        pids_limit: int | None = None

        def docker_run_args(self) -> list[str]:
            args: list[str] = []
            if self.memory:
                args.extend(["--memory", self.memory])
            if self.memory_swap:
                args.extend(["--memory-swap", self.memory_swap])
            if self.cpus:
                args.extend(["--cpus", self.cpus])
            if self.pids_limit is not None:
                args.extend(["--pids-limit", str(self.pids_limit)])
            return args

        def summary(self) -> str:
            return (
                f"memory={self.memory or 'unlimited'}, "
                f"memory_swap={self.memory_swap or 'unlimited'}, "
                f"cpus={self.cpus or 'unlimited'}, "
                f"pids_limit={self.pids_limit if self.pids_limit is not None else 'unlimited'}"
            )

    @dataclass(frozen=True)
    class VolumeMount:
        source: Path
        target: str
        read_only: bool = True

        def docker_run_args(self) -> list[str]:
            mode = "ro" if self.read_only else "rw"
            return ["--volume", f"{self.source}:{self.target}:{mode}"]

    def __init__(
        self,
        config: ChallengeConfig,
        docker_image: str = "rev-sandbox:latest",
        host_output_dir: Path | None = None,
        resource_limits: "DockerEnvironment.ResourceLimits | None" = None,
        network_mode: str = "bridge",
        extra_mounts: list["DockerEnvironment.VolumeMount"] | None = None,
    ):
        self.config = config
        self.docker_image = docker_image
        unique_suffix = uuid.uuid4().hex[:10]
        self.container_name = f"rev-agent-{self.config.name}-{unique_suffix}"
        self.container_id = None
        self.host_output_dir = host_output_dir
        self.resource_limits = resource_limits or DockerEnvironment.ResourceLimits()
        self.network_mode = network_mode
        self.extra_mounts = list(extra_mounts or [])

    def _require_runtime_tools(self) -> None:
        """Fail fast when the sandbox image is stale or missing advertised tools."""
        checks = {
            "signsrch": "command -v signsrch >/dev/null 2>&1 && test -f /opt/signsrch/signsrch.sig",
        }
        missing: list[str] = []
        for tool_name, check_cmd in checks.items():
            result = subprocess.run(
                _docker("exec", self.container_id, "bash", "-lc", check_cmd),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if result.returncode != 0:
                missing.append(tool_name)
        if missing:
            raise RuntimeError(
                "Sandbox image is missing required runtime tools: "
                + ", ".join(missing)
                + f". Rebuild '{self.docker_image}' from docker/Dockerfile."
            )

    def __enter__(self):
        logger.info(f"Starting docker container '{self.container_name}'...")
        logger.info(f"Container resource limits: {self.resource_limits.summary()}")
        logger.info(f"Container network mode: {self.network_mode}")
        cmd = [
            *_docker("run", "-d"),
            "--name", self.container_name,
            "--platform", "linux/amd64",
            "--network", self.network_mode,
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "seccomp=unconfined",
            *self.resource_limits.docker_run_args(),
            "--volume", f"{self.config.public_path}:/home/ctfplayer/public/:ro",
            *[arg for mount in self.extra_mounts for arg in mount.docker_run_args()],
            "--workdir", "/home/ctfplayer/",
            self.docker_image,
            "sleep", "infinity"
        ]
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
            self.container_id = result.stdout.strip()
            logger.info(f"Container '{self.container_name}' started with ID: {self.container_id[:12]}")
            self._require_runtime_tools()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start docker container: {e.stderr}")
            raise
        except FileNotFoundError:
            logger.error("Docker command not found. Is Docker installed and in your PATH?")
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.container_id:
            logger.info(f"Stopping and removing docker container '{self.container_name}'...")
            subprocess.run(_docker("stop", self.container_id), capture_output=True, check=False)
            subprocess.run(_docker("rm", self.container_id), capture_output=True, check=False)
            logger.info(f"Container '{self.container_name}' removed.")

    def run_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        if not self.container_id:
            return {"error": "Container is not running."}

        logger.info(f"Executing command in container: {command}")

        if timeout > 60:
            return {"error": "Timeout too long. Maximum allowed is 60 seconds."}
        
        cmd = _docker('exec', self.container_id, 'bash', '-c', command)
        
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate(timeout=timeout)
            out = clean_out(stdout)
            err = clean_out(stderr)
            out, out_truncated = _truncate_output(out)
            err, err_truncated = _truncate_output(err)
            
            logger.debug(f"STDOUT: {out}")
            logger.debug(f"STDERR: {err}")
            logger.debug(f"Return Code: {p.returncode}")

            return {
                "stdout": out,
                "stderr": err,
                "returncode": p.returncode,
                "timed_out": False,
                "stdout_truncated": out_truncated,
                "stderr_truncated": err_truncated,
            }

        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            out = clean_out(stdout)
            err = clean_out(stderr)
            out, out_truncated = _truncate_output(out)
            err, err_truncated = _truncate_output(err)
            logger.warning(f"Command timed out: {command}")
            return {
                "stdout": out,
                "stderr": err,
                "returncode": None,
                "timed_out": True,
                "stdout_truncated": out_truncated,
                "stderr_truncated": err_truncated,
            }
        except Exception as e:
            logger.error(f"An unexpected error occurred while running command: {e}")
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }

    def run_gdb(self, binary: str, commands: str, stdin_input: str = "", timeout: int = 60) -> Dict[str, Any]:
        """Run GDB in batch mode using a script file inside the container.

        Args:
            binary:      Path to the binary (absolute or relative to /home/ctfplayer/).
            commands:    GDB commands, one per line (a .gdb script body).
                         To pass stdin to the binary use: run < /tmp/gdb_input.txt
                         (works automatically when stdin_input is also provided).
            stdin_input: Optional text to write to /tmp/gdb_input.txt inside the
                         container before running GDB so commands can reference it.
            timeout:     Seconds to wait for GDB to finish (default 60).
        """
        if not self.container_id:
            return {"status": "error", "failure_reason": "container_not_running", "error": "Container is not running."}
        if not commands.strip():
            return {"status": "error", "failure_reason": "empty_commands", "error": "GDB commands must not be empty."}
        if timeout <= 0:
            return {"status": "error", "failure_reason": "invalid_timeout", "error": "Timeout must be a positive integer."}
        if timeout > 120:
            return {"status": "error", "failure_reason": "invalid_timeout", "error": "Timeout too long. Maximum allowed is 120 seconds."}

        script_path = "/tmp/gdb_batch_script.gdb"

        # Write GDB script into the container
        try:
            b64 = base64.b64encode(commands.encode("utf-8")).decode("ascii")
        except Exception as e:
            return {"status": "error", "failure_reason": "encode_error", "error": f"Failed to encode GDB commands: {e}"}

        write_script = f'printf %s "{b64}" | base64 -d > {script_path}'
        r = subprocess.run(
            _docker("exec", self.container_id, "bash", "-c", write_script),
            capture_output=True, timeout=15,
        )
        if r.returncode != 0:
            return {
                "status": "error",
                "failure_reason": "script_setup_failed",
                "error": f"Failed to write GDB script: {r.stderr.decode(errors='replace')}",
            }

        # Optionally write stdin input
        if stdin_input:
            try:
                b64_in = base64.b64encode(stdin_input.encode("utf-8")).decode("ascii")
            except Exception as e:
                return {"status": "error", "failure_reason": "encode_error", "error": f"Failed to encode stdin_input: {e}"}
            write_stdin = 'printf %s "{b64}" | base64 -d > /tmp/gdb_input.txt'.format(b64=b64_in)
            r_stdin = subprocess.run(
                _docker("exec", self.container_id, "bash", "-c", write_stdin),
                capture_output=True, timeout=15,
            )
            if r_stdin.returncode != 0:
                return {
                    "status": "error",
                    "failure_reason": "stdin_setup_failed",
                    "error": f"Failed to write stdin_input: {r_stdin.stderr.decode(errors='replace')}",
                }

        gdb_cmd = f"gdb -q -batch -x {script_path} -- {binary} 2>&1"
        cmd = _docker("exec", self.container_id, "bash", "-c", gdb_cmd)

        logger.info(f"Running GDB batch on '{binary}' with {len(commands.splitlines())} commands")
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate(timeout=timeout)
            return _build_gdb_result(
                stdout=clean_out(stdout),
                stderr=clean_out(stderr),
                returncode=p.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            return _build_gdb_result(
                stdout=clean_out(stdout),
                stderr=clean_out(stderr),
                returncode=None,
                timed_out=True,
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred while running gdb: {e}")
            return {
                "status": "error",
                "failure_reason": "unexpected_exception",
                "summary": "Unexpected exception while launching GDB.",
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }

    def create_file(self, file_path: str, content: str) -> Dict[str, Any]:
        if not self.container_id:
            return {"error": "Container is not running."}

        logger.info(f"Creating file '{file_path}' directly inside container.")

        # Encode content to base64 to avoid shell quoting issues
        try:
            b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        except Exception as e:
            logger.error(f"Failed to base64-encode content: {e}")
            return {"success": False, "message": f"encode_error: {e}"}

        dest = f"/home/ctfplayer/{file_path}"
        bash_script = (
            "dest=\"" + dest + "\"; "
            "mkdir -p \"$(dirname \"$dest\")\" && "
            "printf %s \"" + b64 + "\" | base64 -d > \"$dest\""
        )

        cmd = _docker("exec", self.container_id, "bash", "-lc", bash_script)

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
            logger.info(f"Successfully created file: {file_path}")
            return {"success": True, "message": f"File '{file_path}' created successfully.", "stderr": result.stderr}
        except subprocess.CalledProcessError as e:
            logger.warning(f"Base64 method failed, falling back to host copy for '{file_path}': {e.stderr}")
            # Fallback: write to host_output_dir then docker cp and fix ownership
            try:
                if self.host_output_dir is None:
                    # As a final fallback, use a temp file on host
                    import tempfile
                    host_file = Path(tempfile.gettempdir()) / (Path(file_path).name)
                else:
                    host_file = Path(self.host_output_dir) / file_path
                host_file.parent.mkdir(parents=True, exist_ok=True)
                host_file.write_text(content, encoding="utf-8")

                # Ensure destination directory exists in container
                dest_dir = f"/home/ctfplayer/{Path(file_path).parent.as_posix()}"
                mkdir_cmd = _docker("exec", self.container_id, "bash", "-lc", f"mkdir -p \"{dest_dir}\"")
                subprocess.run(mkdir_cmd, check=True, capture_output=True, text=True, timeout=30)

                # Copy file
                dest_path = f"/home/ctfplayer/{file_path}"
                cp_cmd = _docker("cp", str(host_file), f"{self.container_id}:{dest_path}")
                subprocess.run(cp_cmd, check=True, capture_output=True, text=True, timeout=30)

                # Fix ownership and permissions (ctfplayer has passwordless sudo)
                fix_cmd = [
                    *_docker("exec", self.container_id, "bash", "-lc"),
                    f"sudo chown ctfplayer:ctfplayer \"{dest_path}\" && chmod 0644 \"{dest_path}\"",
                ]
                subprocess.run(fix_cmd, check=True, capture_output=True, text=True, timeout=30)

                logger.info(f"Successfully created file via fallback: {file_path}")
                return {"success": True, "message": f"File '{file_path}' created via host copy."}
            except subprocess.CalledProcessError as e2:
                logger.error(f"Fallback copy failed for '{file_path}': {e2.stderr}")
                return {"success": False, "message": e2.stderr}
            except Exception as e2:
                logger.error(f"Unexpected error during fallback for '{file_path}': {e2}")
                return {"success": False, "message": str(e2)}
        except Exception as e:
            logger.error(f"An unexpected error occurred while creating file: {e}")
            return {"success": False, "message": str(e)}

    def read_file(self, file_path: str) -> str:
        if not self.container_id:
            raise RuntimeError("Container is not running.")

        normalized = Path(file_path)
        if normalized.is_absolute():
            raise ValueError("file_path must be relative to /home/ctfplayer/")

        source = Path("/home/ctfplayer") / normalized
        cmd = _docker("exec", self.container_id, "bash", "-lc", f"cat {shlex.quote(str(source))}")
        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as e:
            raise FileNotFoundError(f"failed to read container file '{file_path}': {e.stderr.strip()}") from e
        return result.stdout
