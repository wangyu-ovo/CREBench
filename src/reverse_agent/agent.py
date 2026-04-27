import os
import json
import logging
import re
from time import sleep, time
from typing import List, Dict, Any, Optional
from pathlib import Path
from .tools import ToolExecutor
from .llm import LLMProvider
from .recorder import ConversationRecorder

logger = logging.getLogger(__name__)
MAX_MODEL_FEEDBACK_CHARS = 4000
MAX_MODEL_FEEDBACK_LINES = 40
SUBMISSION_TOOLS = {
    "submit_algorithm",
    "submit_key_material",
    "submit_key",
    "submit_key_iv",
    "submit_code",
    "submit_flag",
}

SYSTEM_PROMPT_FLAG_ONLY = """You are an expert reverse engineer and CTF player.
You are inside a sandboxed environment and have access to a set of tools to help you solve the challenge.
Your goal is to derive an input that makes the target program return True and treat that input as the flag; identify the cryptographic algorithm used by the program and implement the corresponding decryption to recover the flag.
Think step-by-step and use the tools provided to inspect the environment and execute commands.
You can create files to help you solve the challenge.
When you believe you have found the flag, you must call the `submit_flag` tool to check if it's correct.
If you are stuck or want to give up, call the `exit` tool.

Note: Prioritize examining the decompiled code under /home/ctfplayer/public/decompile first before analyzing the raw binary.
Don't use brute-force algorithms; it is unlikely to run in time. Instead, focus on understanding the logic of the program.
Use your interaction budget carefully: prefer high-value actions and avoid repetitive low-yield exploration.

Environment notes (from the challenge container):
- OS: Ubuntu 22.04; working directory: /home/ctfplayer; public files mounted at /home/ctfplayer/public/ (read-only).
- Challenge assets: /home/ctfplayer/public contains 'challenge' (target executable to reverse) and its corresponding decompiled /home/ctfplayer/public/decompile.
- Core CLI: gcc/g++, make, file, jq, vim.
- GDB: use the run_gdb tool (NOT run_command) for GDB debugging — supports both static analysis (disassemble, info functions) and dynamic analysis (breakpoints, run, register inspection). Do NOT launch gdb via run_command as it requires a TTY.
- Dynamic analysis alternatives: angr (Python) for symbolic/concrete execution without ptrace; useful for path exploration and constraint solving.
- Reverse tools: radare2 (r2), signsrch (crypto/constants signature scanner), Ghidra 11.0.1 with helper scripts in /opt/ghidra/customScripts (decompile.sh, disassemble.sh), Sleuthkit.
- When confirming the encryption algorithm, prioritize using `signsrch` first before spending steps on deeper manual analysis.
- Mobile/Java: apktool.
- Scripting: Python 3 (pwntools, angr, chepy, gmpy2), Java 17 (JDK/JRE), Rust (rustc, cargo), SageMath.
- Other security utils: sqlmap, nikto.

"""

SYSTEM_PROMPT_FULL = """You are an expert reverse engineer and CTF player.
You are inside a sandboxed environment and have access to a set of tools to help you solve the challenge.
This binary is a cryptographic serial checker: it takes candidate input, transforms it with an embedded cryptographic routine, and compares the result against an internal target.

You have 4 independent tasks to complete (in any order):

1. **Identify the algorithm** (submit_algorithm): Determine what cryptographic algorithm the binary uses.
   - The environment will only confirm receipt, NOT whether your answer is correct.
   - Submit the algorithm family/name only. You do NOT need to include the full mode or parameterization. For example, `AES` or `DES` are preferred.
   - You can resubmit to update your answer at any time.

{level2_task_block}

3. **Recover a Python implementation** (submit_code): Reconstruct the full challenge program behavior in Python, not just the inner cipher primitive.
   - Build a standalone Python program in the container, then submit it with `submit_code(file_path=...)`.
   - The submitted file path must be relative to `/home/ctfplayer/`.
   - When the evaluator runs `python <your_code>.py <input_hex>`, your program must accept the candidate input from `argv[1]`, reproduce the same encryption/wrapper logic as the challenge binary, and print the resulting ciphertext hex to stdout.
   - The recovered implementation must match the full wrapper-level behavior that produces the checked ciphertext, including key handling and IV handling when present.
   - Do not submit only an internal helper such as `encrypt(...)`; the evaluator will execute your program from the command line.
   - Your code will be tested against hidden test vectors and you will only see the aggregate pass count.
   - You can resubmit to improve your code.

4. **Reverse the flag** (submit_flag): Use your understanding to decrypt and find the correct flag.
   - The environment will tell you whether the flag is correct.

These tasks are independent — you do NOT need to complete one before starting another.
Work through the binary analysis naturally, and submit answers as you gain understanding.

IMPORTANT: You are scored on ALL 4 tasks. Make sure to call submit_algorithm, {level2_tool_name}, and submit_code in addition to submit_flag. Even if you are not 100% certain, submit your best guess — you can always resubmit later. Do NOT exit without attempting all 4 submissions.

Think step-by-step and use the tools provided to inspect the environment and execute commands.
You can create files to help you solve the challenge.
When you have completed all tasks or want to give up, call the `exit` tool.

Note: Prioritize examining the decompiled code under /home/ctfplayer/public/decompile first before analyzing the raw binary.
Don't use brute-force algorithms; it is unlikely to run in time. Instead, focus on understanding the logic of the program.
Use your interaction budget carefully: prefer high-value actions and avoid repetitive low-yield exploration.

Environment notes (from the challenge container):
- OS: Ubuntu 22.04; working directory: /home/ctfplayer; public files mounted at /home/ctfplayer/public/ (read-only).
- Challenge assets: /home/ctfplayer/public contains 'challenge' (target executable to reverse) and its corresponding decompiled /home/ctfplayer/public/decompile.
- Core CLI: gcc/g++, make, file, jq, vim.
- GDB: use the run_gdb tool (NOT run_command) for GDB debugging — supports both static analysis (disassemble, info functions) and dynamic analysis (breakpoints, run, register inspection). Do NOT launch gdb via run_command as it requires a TTY.
- Dynamic analysis alternatives: angr (Python) for symbolic/concrete execution without ptrace; useful for path exploration and constraint solving.
- Reverse tools: radare2 (r2), signsrch (crypto/constants signature scanner), Ghidra 11.0.1 with helper scripts in /opt/ghidra/customScripts (decompile.sh, disassemble.sh), Sleuthkit.
- When confirming the encryption algorithm, prioritize using `signsrch` first before spending steps on deeper manual analysis.
- Mobile/Java: apktool.
- Scripting: Python 3 (pwntools, angr, chepy, gmpy2), Java 17 (JDK/JRE), Rust (rustc, cargo), SageMath.
- Other security utils: sqlmap, nikto.

"""


def build_system_prompt(eval_mode: str, tool_executor: "ToolExecutor") -> str:
    if eval_mode == "full":
        level2_tool_name = tool_executor.level2_submission_tool_name()
        return SYSTEM_PROMPT_FULL.format(
            level2_task_block=tool_executor.level2_task_prompt_block(),
            level2_tool_name=level2_tool_name,
        )
    return SYSTEM_PROMPT_FLAG_ONLY


def build_initial_prompt(eval_mode: str) -> str:
    if eval_mode == "full":
        return """Here is a challenge. The public files for this challenge are mounted at /home/ctfplayer/public/.
Your working directory is /home/ctfplayer. Create and run any scripts or binaries within this directory.

You have 4 tasks: identify the algorithm, recover the encryption key parameter(s), recover a Python implementation of the full program behavior, and find the flag.
Start by exploring the environment and the files.
"""
    return """Here is a challenge. The public files for this challenge are mounted at /home/ctfplayer/public/.
Your working directory is /home/ctfplayer. Create and run any scripts or binaries within this directory.
Your task is to find the flag. Start by exploring the environment and the files.
"""


class ReverseAgent:
    def __init__(self, model: str, tool_executor: ToolExecutor, llm: LLMProvider):
        self.llm = llm
        self.model = model
        self.tool_executor = tool_executor
        self.messages: List[Dict[str, Any]] = []
        self.run_metrics: Dict[str, Any] = {}

    def _get_system_prompt(self) -> str:
        return build_system_prompt(self.tool_executor.eval_mode, self.tool_executor)

    def _truncate_for_model(self, text: str, max_chars: int, max_lines: int = MAX_MODEL_FEEDBACK_LINES) -> str:
        return text

    def _summarize_tool_output_obj(self, obj: Dict[str, Any]) -> str:
        lines: list[str] = []
        for key in ("status", "failure_reason", "summary", "error", "message", "correct", "success", "score", "returncode", "timed_out"):
            if key in obj:
                lines.append(f"{key}: {obj[key]}")

        for stream_name in ("stdout", "stderr"):
            text = obj.get(stream_name)
            if not isinstance(text, str) or not text.strip():
                continue
            truncated = self._truncate_for_model(text.strip(), max_chars=1400, max_lines=24)
            lines.append(f"{stream_name}:\n{truncated}")
            trunc_flag = obj.get(f"{stream_name}_truncated")
            if trunc_flag:
                lines.append(f"{stream_name}_truncated: True")

        for key, value in obj.items():
            if key in {
                "status",
                "failure_reason",
                "summary",
                "error",
                "message",
                "correct",
                "success",
                "score",
                "returncode",
                "timed_out",
                "stdout",
                "stderr",
                "stdout_truncated",
                "stderr_truncated",
            }:
                continue
            rendered = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
            rendered = self._truncate_for_model(rendered, max_chars=400, max_lines=8)
            lines.append(f"{key}: {rendered}")

        summary = "\n".join(lines)
        return self._truncate_for_model(summary, max_chars=MAX_MODEL_FEEDBACK_CHARS)

    def _compress_tool_output_for_model(self, tool_output_str: str) -> str:
        try:
            parsed = json.loads(tool_output_str)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            return self._summarize_tool_output_obj(parsed)

        return self._truncate_for_model(tool_output_str, max_chars=MAX_MODEL_FEEDBACK_CHARS)

    def _build_continue_instructions(self, remaining_steps: int) -> str:
        lines = ["Continue using the same JSON format."]
        pending = self.tool_executor.get_pending_submissions()
        if pending:
            lines.append(f"Pending submissions: {', '.join(pending)}.")
        return " ".join(lines)

    def _strip_json_code_fence(self, text: str) -> str:
        stripped = text.strip()
        fence_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, flags=re.DOTALL | re.IGNORECASE)
        if fence_match:
            return fence_match.group(1).strip()
        return stripped

    def _parse_assistant_action(self, assistant_text: str) -> Dict[str, Any]:
        decoder = json.JSONDecoder()
        normalized = self._strip_json_code_fence(assistant_text)

        try:
            parsed, _ = decoder.raw_decode(normalized)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            return parsed

        for match in re.finditer(r"\{", normalized):
            start = match.start()
            try:
                parsed, _ = decoder.raw_decode(normalized[start:])
            except Exception:
                continue
            if isinstance(parsed, dict):
                return parsed

        raise ValueError("Could not parse a JSON object from model output")

    def run(self, initial_prompt: str,
            max_steps: int = 30,
            record_path: Optional[Path] = None,
            max_tokens: int = 0) -> List[Dict[str, Any]]:
        # Prompt-defined tools + structured output instructions
        system_prompt_base = self._get_system_prompt()
        tool_instructions = self.tool_executor.get_tool_instructions()
        system_prompt = system_prompt_base + "\n\n" + tool_instructions
        messages: List[Dict[str, str]] = [
            {"role": "user", "content": initial_prompt},
        ]
        logger.info("Starting agent run...")

        recorder: Optional[ConversationRecorder] = None
        if record_path is not None:
            recorder = ConversationRecorder(record_path)
            recorder.record_system_prompt(system_prompt)

        try:
            total_token_count = 0
            start_time = time()
            stop_reason = "max_steps_reached"
            parse_error_count = 0
            model_turns = 0
            rounds_used = 0
            while rounds_used < max_steps:
                if max_tokens > 0 and total_token_count >= max_tokens:
                    logger.warning(
                        "Token limit reached before starting the next step: %s tokens used, max is %s.",
                        total_token_count,
                        max_tokens,
                    )
                    stop_reason = "max_tokens_exceeded"
                    break
                step_num = rounds_used + 1
                logger.info(f"--- Step {step_num}/{max_steps} ---")
                self.tool_executor._current_round = step_num
                self.tool_executor._current_step = step_num

                if recorder:
                    recorder.start_round(user=initial_prompt if model_turns == 0 else None)

                # Ask model for a structured JSON action (analysis + action)
                self.llm.set_max_tokens_for_next_call(max_tokens - total_token_count if max_tokens > 0 else None)
                assistant_text, token_count = self.llm.generate(self.model, system_prompt, messages)
                generation_info = dict(getattr(self.llm, "last_generation_info", {}) or {})
                model_turns += 1
                sleep(2)  # brief pause to avoid overwhelming the environment with rapid commands
                total_token_count += token_count
                if recorder and assistant_text:
                    recorder.record_assistant(assistant_text)
                if generation_info.get("token_limit_hit") or (max_tokens > 0 and total_token_count >= max_tokens):
                    logger.warning(
                        "Token limit reached: %s tokens used, max is %s. Ending run.",
                        total_token_count,
                        max_tokens,
                    )
                    stop_reason = "max_tokens_exceeded"
                    break

                # Resolve tool calls immediately until the model returns no tool
                stop_run = False
                # while True:
                    # Parse assistant_text as JSON with top-level analysis and action
                try:
                    action = self._parse_assistant_action(assistant_text)
                except Exception as e:
                    logger.error(f"Failed to parse model output as JSON: {assistant_text}")
                    logger.error(f"Error: {e}")
                    parse_error_count += 1
                    rounds_used += 1
                    continue_instructions = self._build_continue_instructions(max_steps - rounds_used)
                    messages.append({"role": "assistant", "content": assistant_text})
                    messages.append({"role": "user", "content": f"Error parsing your response as JSON: {e}. Please ensure you follow the output format instructions and try again. {continue_instructions}"})
                    continue
                act = action.get("action", {}) if isinstance(action, dict) else {}
                tool_name = act.get("tool")
                arguments = act.get("arguments", {})
                if not tool_name:
                    logger.info("No tool selected by model. Requesting explicit continuation.")
                    rounds_used += 1
                    continue_instructions = self._build_continue_instructions(max_steps - rounds_used)
                    messages.append({"role": "assistant", "content": assistant_text})
                    messages.append({
                        "role": "user",
                        "content": (
                            "No tool was selected. Do not stop by returning action.tool = null. "
                            "Choose the next tool to call, or call exit explicitly if you are truly finished. "
                            + continue_instructions
                        ),
                    })
                    stop_reason = "model_returned_no_tool"
                    continue

                logger.info(f"Executing: {tool_name}({arguments})")
                if recorder:
                    recorder.record_tool_call(tool_name, arguments)
                tool_output_str = self.tool_executor.execute_tool(tool_name, **arguments)
                logger.info(f"Tool output for {tool_name}: {tool_output_str}")
                if recorder:
                    recorder.record_tool_output(tool_output_str)

                # Parse for termination
                try:
                    tool_output_obj = json.loads(tool_output_str)
                except Exception:
                    tool_output_obj = {}

                # Append the raw tool output so the next worker call sees the full environment feedback.
                consumes_round = tool_name not in SUBMISSION_TOOLS
                if consumes_round:
                    rounds_used += 1
                continue_instructions = self._build_continue_instructions(max_steps - rounds_used)
                feedback = f"TOOL {tool_name} RESULT:\n{tool_output_str}"
                messages.append({"role": "assistant", "content": assistant_text})
                messages.append({"role": "user", "content": feedback + "\n\n" + continue_instructions})

                # Termination logic
                if tool_name == "exit":
                    logger.info("Agent decided to exit. Ending run.")
                    stop_reason = "agent_exit"
                    break

                if self.tool_executor.eval_mode == "flag_only":
                    # Legacy mode: stop on correct flag
                    if tool_name == "submit_flag" and tool_output_obj.get("correct"):
                        logger.info("Flag is correct! Ending run.")
                        stop_reason = "correct_flag_submitted"
                        break
                # In full mode, don't stop on correct flag alone —
                # agent can continue to submit other levels or call exit
            else:
                stop_reason = "max_steps_reached"

        finally:
            # Finalize scores (opens sealed envelopes for L1/L2)
            score_report = self.tool_executor.finalize_scores()

            elapsed = time() - start_time
            logger.info("Agent run finished.")
            logger.info(f"Total tokens used: {total_token_count}")
            logger.info(f"Total time elapsed: {elapsed:.2f} seconds")
            logger.info(f"\n{score_report.summary()}")

            self.run_metrics = {
                "model": self.model,
                "eval_mode": self.tool_executor.eval_mode,
                "max_rounds": max_steps,
                "rounds_used": rounds_used,
                "model_turns": model_turns,
                "max_tokens": max_tokens,
                "token_limit_hit": stop_reason == "max_tokens_exceeded",
                "parse_error_count": parse_error_count,
                "stop_reason": stop_reason,
                "duration_seconds": elapsed,
                "llm_usage": self.llm.get_usage_summary(),
                "tool_metrics": self.tool_executor.get_metrics(),
                "score": score_report.to_dict(),
            }

            if recorder:
                recorder.end_round()
                recorder.record_score_summary(score_report.summary())
                recorder.close()

        self.messages = messages
        return messages
