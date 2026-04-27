"""
Human-readable conversation transcript recorder.

Produces a clean, structured record of each agent round:
  - Agent's analysis (thinking) separated from action
  - Tool calls shown concisely (no duplication with assistant JSON)
  - Score submissions highlighted
  - Final score summary appended at end
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

# Truncation disabled; keep constants only to preserve call signatures.
MAX_OUTPUT_LINES = 0
MAX_FIELD_CHARS = 0

def _truncate_lines(text: str, max_lines: int = MAX_OUTPUT_LINES) -> str:
    return text


def _truncate_str(text: str, max_chars: int = MAX_FIELD_CHARS) -> str:
    return text


def _format_tool_output(raw: str) -> str:
    """Format tool output for readability."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return _truncate_lines(raw)

    if not isinstance(obj, dict):
        return _truncate_lines(raw)

    lines: list[str] = []

    for key in ("status", "failure_reason", "summary", "error", "message", "correct", "success", "score"):
        if key in obj:
            lines.append(f"{key}: {obj[key]}")

    # stdout/stderr get special treatment
    if "stdout" in obj:
        stdout = obj["stdout"] or ""
        if stdout.strip():
            lines.append(_truncate_lines(stdout.rstrip()))
        else:
            lines.append("(no stdout)")
        if obj.get("stdout_truncated"):
            lines.append("stdout_truncated: True")
    if "stderr" in obj and obj["stderr"] and obj["stderr"].strip():
        lines.append(f"STDERR: {_truncate_lines(obj['stderr'].rstrip())}")
        if obj.get("stderr_truncated"):
            lines.append("stderr_truncated: True")

    # Other fields shown as key=value
    for key, val in obj.items():
        if key in (
            "stdout",
            "stderr",
            "status",
            "failure_reason",
            "summary",
            "error",
            "message",
            "correct",
            "success",
            "score",
            "stdout_truncated",
            "stderr_truncated",
        ):
            continue
        if isinstance(val, str) and len(val) > 200:
            val = _truncate_str(val, 200)
        lines.append(f"{key}: {val}")

    return "\n".join(lines)


def _parse_assistant_json(text: str) -> Optional[dict]:
    """Try to parse the structured JSON from assistant output."""
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(text.strip())
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return None


class ConversationRecorder:
    def __init__(self, record_path: Path):
        self.path = Path(record_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("w", encoding="utf-8")
        self.round_num = 0

    def close(self) -> None:
        try:
            self._fp.flush()
            self._fp.close()
        except Exception:
            pass

    def _write(self, text: str = "") -> None:
        self._fp.write(text + "\n")
        self._fp.flush()

    # --- Round lifecycle ---

    def start_round(self, user: Optional[str] = None) -> None:
        self.round_num += 1
        self._write(f"\n{'='*60}")
        self._write(f"  Round {self.round_num}")
        self._write(f"{'='*60}")
        if user:
            self._write(f"\n[User]\n{user.strip()}")

    def record_system_prompt(self, prompt: str) -> None:
        self._write(f"\n{'='*60}")
        self._write("  Round 0")
        self._write(f"{'='*60}")
        self._write(f"\n[System]\n{prompt.strip()}")

    def end_round(self) -> None:
        pass  # visual separation handled by start_round

    # --- Content recording ---

    def record_assistant(self, text: str) -> None:
        if not text:
            return

        parsed = _parse_assistant_json(text)
        if parsed:
            # Show analysis and action separately for clarity
            analysis = parsed.get("analysis", "")
            if analysis:
                self._write(f"\n[Analysis]\n{analysis}")

            act = parsed.get("action", {})
            tool = act.get("tool") if isinstance(act, dict) else None

            if tool:
                args = act.get("arguments", {})
                self._write(f"\n[Action] {tool}")
                if args:
                    self._format_tool_args(tool, args)
        else:
            # Couldn't parse JSON — show raw (truncated)
            self._write(f"\n[Assistant]\n{_truncate_str(text, 3000)}")

    def _format_tool_args(self, tool: str, args: dict) -> None:
        """Format tool arguments concisely based on tool type."""
        if tool == "run_command":
            cmd = args.get("command", "")
            timeout = args.get("timeout")
            self._write(f"  $ {cmd}")
            if timeout:
                self._write(f"  (timeout: {timeout}s)")

        elif tool == "create_file":
            path = args.get("file_path", "")
            content = args.get("content", "")
            lines = content.count("\n") + 1
            self._write(f"  path: {path} ({lines} lines)")
            # Show first/last few lines of file content
            if lines <= 10:
                for ln in content.splitlines():
                    self._write(f"  | {ln}")
            else:
                content_lines = content.splitlines()
                for ln in content_lines[:5]:
                    self._write(f"  | {ln}")
                self._write(f"  | ... ({lines - 10} lines omitted) ...")
                for ln in content_lines[-5:]:
                    self._write(f"  | {ln}")

        elif tool == "run_gdb":
            binary = args.get("binary", "")
            commands = args.get("commands", "")
            stdin_input = args.get("stdin_input", "")
            timeout = args.get("timeout", 60)
            cmd_lines = commands.strip().splitlines()
            self._write(f"  binary: {binary}  (timeout: {timeout}s)")
            for ln in cmd_lines:
                self._write(f"  (gdb) {ln}")
            if stdin_input:
                self._write(f"  stdin → /tmp/gdb_input.txt ({len(stdin_input)} bytes)")

        elif tool == "submit_algorithm":
            self._write(f"  algorithm: {args.get('algorithm', '')}")

        elif tool in {"submit_key_material", "submit_key", "submit_key_iv"}:
            if "key" in args and "iv" in args:
                self._write(f"  key: {args.get('key', '')}")
                self._write(f"  iv: {args.get('iv', '')}")
            elif "key" in args:
                self._write(f"  key: {args.get('key', '')}")
            else:
                value = args.get("value", args.get("key_material", ""))
                self._write(f"  value: {value}")

        elif tool == "submit_code":
            self._write(f"  file_path: {args.get('file_path', '')}")

        elif tool == "submit_flag":
            self._write(f"  flag: {args.get('flag', '')}")

        else:
            # Generic fallback
            try:
                self._write(f"  {json.dumps(args, ensure_ascii=False)}")
            except Exception:
                self._write(f"  {args}")

    def record_tool_call(self, name: str, args: Dict[str, Any]) -> None:
        # Already handled in record_assistant via _format_tool_args
        # This is kept for backward compatibility but we skip to avoid duplication
        pass

    def record_tool_output(self, output: Any) -> None:
        formatted = _format_tool_output(output if isinstance(output, str) else str(output))
        self._write(f"\n[Output]\n{formatted}")

    # --- Score summary ---

    def record_score_summary(self, summary: str) -> None:
        self._write(f"\n{'='*60}")
        self._write("  Final Score")
        self._write(f"{'='*60}")
        self._write(summary)
