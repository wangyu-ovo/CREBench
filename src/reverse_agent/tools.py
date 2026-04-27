import json
import logging
import os
import re
from collections import Counter
from typing import Any, Callable, Dict, List, Optional
from dotenv import load_dotenv

from .config import ChallengeConfig
from .environment import DockerEnvironment
from .scorer import ScoreReport
from .evaluator import score_algorithm, score_key_material, run_code_tests

load_dotenv()

logger = logging.getLogger(__name__)
MAX_WEB_EXTRACT_CHARS = 8000


class ToolExecutor:
    def __init__(self, environment: DockerEnvironment, config: ChallengeConfig,
                 eval_mode: str = "full"):
        """
        eval_mode: "full" (all 4 levels) or "flag_only" (legacy, only submit_flag).
        """
        self.env = environment
        self.config = config
        self.eval_mode = eval_mode
        self.score_report = ScoreReport()
        self._current_round = 0  # updated by agent loop
        self._current_step = 0  # deprecated alias for current round
        self.tool_call_count = 0
        self.tool_call_counter: Counter[str] = Counter()

        self.tools: Dict[str, Callable] = {
            "run_command": self.env.run_command,
            "run_gdb": self.env.run_gdb,
            "create_file": self.env.create_file,
            "web_search": self.web_search,
            "web_extract": self.web_extract,
            "submit_flag": self.submit_flag,
            "exit": self.exit,
        }

        self.tool_schemas = [
            {
                "type": "function",
                "name": "run_command",
                "description": "Execute a bash command inside the docker container. Returns stdout, stderr, returncode, and timeout status.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The command to execute.",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds for the command. Defaults to 30.",
                            "default": 30,
                        },
                    },
                    "required": ["command"],
                },
            },
            {
                "type": "function",
                "name": "run_gdb",
                "description": (
                    "Run GDB in non-interactive batch mode on a binary inside the container. "
                    "Supports both static analysis (disassemble, info functions, symbol inspection) "
                    "and dynamic analysis (breakpoints, run, step, register/memory inspection at runtime). "
                    "Provide GDB commands as a multi-line script (one command per line). "
                    "The result includes status, failure_reason, summary, stdout, stderr, returncode, and timeout flags. "
                    "Do NOT use run_command to launch gdb — it requires a TTY and will hang. Use this tool instead. "
                    "If the binary reads from stdin during 'run', also provide stdin_input and add "
                    "'run < /tmp/gdb_input.txt' in your commands."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "binary": {
                            "type": "string",
                            "description": "Path to the binary to debug, e.g. '/home/ctfplayer/public/challenge'.",
                        },
                        "commands": {
                            "type": "string",
                            "description": (
                                "GDB commands to execute, one per line. Examples:\n"
                                "  break main\n"
                                "  run arg1 arg2\n"
                                "  x/32xb $rsp\n"
                                "  info registers\n"
                                "  continue\n"
                                "  disassemble main\n"
                                "  print (int)some_var"
                            ),
                        },
                        "stdin_input": {
                            "type": "string",
                            "description": (
                                "Optional text to feed to the binary's stdin. "
                                "Written to /tmp/gdb_input.txt; reference it in commands as: run < /tmp/gdb_input.txt"
                            ),
                            "default": "",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds (default 60, max 120).",
                            "default": 60,
                        },
                    },
                    "required": ["binary", "commands"],
                },
            },
            {
                "type": "function",
                "name": "create_file",
                "description": "Create or overwrite a file in the container's working directory with specified content.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "The path to the file to create, relative to /home/ctfplayer/.",
                        },
                        "content": {
                            "type": "string",
                            "description": "The content to write to the file.",
                        },
                    },
                    "required": ["file_path", "content"],
                },
            },
            {
                "type": "function",
                "name": "web_search",
                "description": (
                    "Search the public web using Tavily. "
                    "Useful for algorithm references, constants, standards, papers, and other external context. "
                    "Returns a compact list of results with title, URL, snippet, and score."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The web search query.",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return. Defaults to 5.",
                            "default": 5,
                        },
                        "search_depth": {
                            "type": "string",
                            "description": "Search depth: 'basic', 'advanced', 'fast', or 'ultra-fast'. Defaults to 'basic'.",
                            "default": "basic",
                        },
                        "topic": {
                            "type": "string",
                            "description": "Optional topic hint: 'general', 'news', or 'finance'. Defaults to 'general'.",
                            "default": "general",
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "type": "function",
                "name": "web_extract",
                "description": (
                    "Extract readable text from a public web page using Tavily. "
                    "Useful when you already know the exact URL and need page content rather than search results."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The public URL to extract.",
                        },
                        "extract_depth": {
                            "type": "string",
                            "description": "Extraction depth: 'basic' or 'advanced'. Defaults to 'basic'.",
                            "default": "basic",
                        },
                        "format": {
                            "type": "string",
                            "description": "Output format: 'text' or 'markdown'. Defaults to 'text'.",
                            "default": "text",
                        },
                        "query": {
                            "type": "string",
                            "description": "Optional focus query to bias extraction toward relevant parts of the page.",
                            "default": "",
                        },
                    },
                    "required": ["url"],
                },
            },
            {
                "type": "function",
                "name": "submit_flag",
                "description": "Submit the flag (Level 4). Returns whether the flag is correct.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "flag": {
                            "type": "string",
                            "description": "The flag to submit.",
                        },
                    },
                    "required": ["flag"],
                },
            },
            {
                "type": "function",
                "name": "exit",
                "description": "Signal that you have finished all tasks or want to give up.",
                "parameters": {"type": "object", "properties": {}},
            },
        ]

        # Add evaluation tools for full mode
        if eval_mode == "full":
            self._register_eval_tools()

    def _level2_has_iv(self) -> bool:
        mode_iv = self.config.resolved_mode_metadata.get("iv")
        if isinstance(mode_iv, str):
            return bool(mode_iv.strip())

        expected = self.config.level2_expected_material or ""
        for label, value in re.findall(r'([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*([0-9a-fA-F]{8,})', expected):
            if label.lower() == "iv" and value.strip():
                return True
        return False

    def level2_submission_tool_name(self) -> str:
        return "submit_key_iv" if self._level2_has_iv() else "submit_key"

    def _level2_expected_labels(self) -> list[str]:
        expected = self.config.level2_expected_material or ""
        named = re.findall(r'([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*([0-9a-fA-F]{8,})', expected)
        if named:
            seen: list[str] = []
            for label, _ in named:
                lowered = label.lower()
                if lowered not in seen:
                    seen.append(lowered)
            return seen
        return []

    def _human_join(self, items: list[str]) -> str:
        if not items:
            return ""
        if len(items) == 1:
            return items[0]
        if len(items) == 2:
            return f"{items[0]} and {items[1]}"
        return f"{', '.join(items[:-1])}, and {items[-1]}"

    def _level2_submit_guidance(self) -> str:
        if self._level2_has_iv():
            return (
                "Submit the actual encryption key and IV used by the program. "
                "Make it explicit which hex value is the key and which hex value is the IV."
            )
        return "Submit the actual encryption key used by the program."

    def level2_task_prompt_block(self) -> str:
        if self._level2_has_iv():
            return (
                "2. **Extract the key and IV** (submit_key_iv): Recover the actual encryption key and IV embedded in the binary.\n"
                "   - The environment will only confirm receipt, NOT whether your answer is correct.\n"
                "   - Submit the actual encryption key and IV used by the program. Make it explicit which hex value is the key and which hex value is the IV.\n"
                "   - You can resubmit to update your answer at any time."
            )
        return (
            "2. **Extract the key** (submit_key): Recover the actual encryption key embedded in the binary.\n"
            "   - The environment will only confirm receipt, NOT whether your answer is correct.\n"
            "   - Submit the actual encryption key used by the program.\n"
            "   - You can resubmit to update your answer at any time."
        )

    def _register_eval_tools(self):
        """Register Level 1-3 evaluation tools."""
        level2_tool_name = self.level2_submission_tool_name()
        self.tools["submit_algorithm"] = self.submit_algorithm
        self.tools[level2_tool_name] = self.submit_level2_material
        self.tools["submit_code"] = self.submit_code

        self.tool_schemas.insert(-1, {  # insert before 'exit'
            "type": "function",
            "name": "submit_algorithm",
            "description": (
                "Submit your identification of the cryptographic algorithm used by the binary (Level 1). "
                "You can call this multiple times; only the last submission counts. "
                "The environment will NOT tell you whether your answer is correct. "
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "algorithm": {
                        "type": "string",
                        "description": "The algorithm family/name, e.g. 'AES', 'DES'",
                    },
                },
                "required": ["algorithm"],
            },
        })
        self.tool_schemas.insert(-1, {
            "type": "function",
            "name": level2_tool_name,
            "description": (
                "Submit the recovered Level 2 parameter(s). "
                "You can call this multiple times; only the last submission counts. "
                "The environment will NOT tell you whether your answer is correct. "
            ),
            "parameters": {
                "type": "object",
                "properties": (
                    {
                        "key": {
                            "type": "string",
                            "description": "Recovered encryption key in hex.",
                        },
                        "iv": {
                            "type": "string",
                            "description": "Recovered IV in hex.",
                        },
                    }
                    if self._level2_has_iv()
                    else {
                        "key": {
                            "type": "string",
                            "description": "Recovered encryption key in hex.",
                        },
                    }
                ),
                "required": ["key", "iv"] if self._level2_has_iv() else ["key"],
            },
        })
        self.tool_schemas.insert(-1, {
            "type": "function",
            "name": "submit_code",
            "description": (
                "Submit the Level 3 Python file for evaluation. "
                "You can call this multiple times; only the last submission counts. "
                "Pass a file path relative to `/home/ctfplayer/`. "
                "The evaluator will read that file and test it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to the Python file under `/home/ctfplayer/`, for example `main.py`.",
                    },
                },
                "required": ["file_path"],
            },
        })

    def get_tool_schema(self) -> List[Dict[str, Any]]:
        return self.tool_schemas

    def get_submission_tool_names(self) -> list[str]:
        names = ["submit_flag"]
        if self.eval_mode == "full":
            names = [
                "submit_algorithm",
                self.level2_submission_tool_name(),
                "submit_code",
                "submit_flag",
            ]
        return names

    def get_submission_tool_schemas(self) -> List[Dict[str, Any]]:
        allowed = set(self.get_submission_tool_names())
        return [spec for spec in self.tool_schemas if spec.get("name") in allowed]

    def get_tool_instructions(self) -> str:
        lines: list[str] = []
        lines.append("Output format (STRICT JSON, no extra text, no code fences):")
        lines.append("{")
        lines.append("  \"analysis\": <string>,   // detailed reasoning, findings, and a short plan for next step")
        lines.append("  \"action\": {")
        lines.append("    \"tool\": <string|null>,  // name of tool to call; call exit explicitly when finished")
        lines.append("    \"arguments\": <object>   // arguments for the selected tool")
        lines.append("  }")
        lines.append("}")
        lines.append("")
        lines.append("Tool catalog:")
        for spec in self.tool_schemas:
            name = spec.get("name")
            desc = spec.get("description", "")
            params = spec.get("parameters", {})
            lines.append(f"- {name}: {desc}")
            if isinstance(params, dict) and params.get("properties"):
                lines.append("  parameters:")
                for pname, pdef in params["properties"].items():
                    pdesc = pdef.get("description", "")
                    ptype = pdef.get("type", "")
                    lines.append(f"    - {pname} ({ptype}): {pdesc}")
        lines.append("")
        lines.append("Response rules:")
        lines.append("- Always return STRICT JSON with keys: analysis and action.")
        lines.append("- Provide meaningful analysis with a clear plan before selecting a tool.")
        lines.append("- If calling a tool, set action.tool to the tool name and include arguments.")
        lines.append("- Do not use action.tool = null to end the run. If you are finished, call exit explicitly.")
        lines.append("- If you still have work to do, choose a concrete tool call instead of returning null.")
        lines.append("- After you return an action with a tool, the environment will reply with the raw tool result. Then produce the next JSON object.")
        return "\n".join(lines)

    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        if tool_name not in self.tools:
            return f"Error: Tool '{tool_name}' not found."

        self.tool_call_count += 1
        self.tool_call_counter[tool_name] += 1
        func: Callable = self.tools[tool_name]
        try:
            result = func(**kwargs)
            return json.dumps(result)
        except Exception as e:
            return f"Error executing tool '{tool_name}': {e}"

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "tool_call_count": self.tool_call_count,
            "tool_calls_by_name": dict(self.tool_call_counter),
            "submission_counts": {
                "submit_algorithm": self.score_report.level1_algorithm.submit_count,
                "submit_key_material": self.score_report.level2_key.submit_count,
                "submit_key": self.score_report.level2_key.submit_count if self.level2_submission_tool_name() == "submit_key" else 0,
                "submit_key_iv": self.score_report.level2_key.submit_count if self.level2_submission_tool_name() == "submit_key_iv" else 0,
                "submit_code": self.score_report.level3_code.submit_count,
                "submit_flag": self.score_report.level4_flag.submit_count,
            },
        }

    def get_pending_submissions(self) -> list[str]:
        pending: list[str] = []
        if self.eval_mode != "full":
            if not self.score_report.level4_flag.submitted:
                pending.append("submit_flag")
            return pending

        if not self.score_report.level1_algorithm.submitted:
            pending.append("submit_algorithm")
        if not self.score_report.level2_key.submitted:
            pending.append(self.level2_submission_tool_name())
        if not self.score_report.level3_code.submitted:
            pending.append("submit_code")
        if not self.score_report.level4_flag.submitted:
            pending.append("submit_flag")
        return pending

    def _get_tavily_client(self):
        try:
            from tavily import TavilyClient  # type: ignore
        except Exception as e:
            raise ImportError("Please install tavily-python in the active environment.") from e

        api_key = os.getenv("TVLY_API_KEY")
        if not api_key:
            raise RuntimeError("TVLY_API_KEY is not configured in the environment.")
        return TavilyClient(api_key=api_key)

    def _truncate_web_text(self, text: Any, max_chars: int = MAX_WEB_EXTRACT_CHARS) -> tuple[str | None, bool]:
        if not isinstance(text, str):
            return None, False
        if len(text) <= max_chars:
            return text, False
        return text[:max_chars], True

    def web_search(
        self,
        query: str,
        max_results: int = 5,
        search_depth: str = "basic",
        topic: str = "general",
    ) -> Dict[str, Any]:
        client = self._get_tavily_client()
        response = client.search(
            query=query,
            max_results=max_results,
            search_depth=search_depth,
            topic=topic,
            include_answer="basic",
            include_raw_content=False,
            include_images=False,
            include_usage=True,
        )
        compact_results = []
        for item in response.get("results", [])[:max_results]:
            compact_results.append({
                "title": item.get("title"),
                "url": item.get("url"),
                "content": item.get("content"),
                "score": item.get("score"),
            })
        return {
            "status": "ok",
            "query": response.get("query", query),
            "answer": response.get("answer"),
            "results": compact_results,
            "response_time": response.get("response_time"),
        }

    def web_extract(
        self,
        url: str,
        extract_depth: str = "basic",
        format: str = "text",
        query: str = "",
    ) -> Dict[str, Any]:
        client = self._get_tavily_client()
        response = client.extract(
            urls=url,
            extract_depth=extract_depth,
            format=format,
            query=query or None,
            include_images=False,
            include_usage=True,
            chunks_per_source=5,
        )
        compact_results = []
        for item in response.get("results", []):
            excerpt, truncated = self._truncate_web_text(item.get("raw_content"))
            compact_results.append({
                "url": item.get("url"),
                "title": item.get("title"),
                "raw_content": excerpt,
                "raw_content_truncated": truncated,
            })
        return {
            "status": "ok",
            "results": compact_results,
            "failed_results": response.get("failed_results", []),
            "response_time": response.get("response_time"),
        }

    # --- Level 1: Algorithm (sealed envelope) ---
    def submit_algorithm(self, algorithm: str) -> Dict[str, Any]:
        report = self.score_report.level1_algorithm
        report.submitted = True
        report.submission = algorithm
        report.submit_count += 1
        report.round = self._current_round
        report.actually_step = self.tool_call_count
        report.submit_step = self._current_step
        logger.info(f"L1 algorithm submission #{report.submit_count}: '{algorithm}'")
        return {
            "status": "recorded",
            "message": (
                "Submission recorded. The environment will not tell you whether it is correct. "
                "Please continue working on the remaining tasks."
            ),
        }

    # --- Level 2: Key extraction (sealed envelope) ---
    def submit_level2_material(self, key: str, iv: str | None = None) -> Dict[str, Any]:
        report = self.score_report.level2_key
        report.submitted = True
        if iv is not None:
            report.submission = {"key": key, "iv": iv}
        else:
            report.submission = {"key": key}
        report.submit_count += 1
        report.round = self._current_round
        report.actually_step = self.tool_call_count
        report.submit_step = self._current_step
        logger.info(f"L2 submission via {self.level2_submission_tool_name()} #{report.submit_count}")
        return {
            "status": "recorded",
            "message": (
                "Submission recorded. The environment will not tell you whether it is correct. "
                "Please continue working on the remaining tasks."
            ),
        }

    # --- Level 3: Code recovery (with feedback) ---
    def submit_code(self, file_path: str) -> Dict[str, Any]:
        report = self.score_report.level3_code
        report.submitted = True
        report.submission = {"file_path": file_path}
        report.submit_count += 1
        report.round = self._current_round
        report.actually_step = self.tool_call_count
        report.submit_step = self._current_step
        logger.info(f"L3 code submission #{report.submit_count}: {file_path}")

        try:
            code = self.env.read_file(file_path)
            score, passed, total = run_code_tests(code, self.config, self.env)
            report.score = score
            report.explanation = f"{score}/25 pts ({passed}/{total} test cases passed)"
            return {
                "status": "tested",
                "score": f"{score}/25 pts ({passed}/{total} test cases passed)",
                "message": (
                    "Code tested. Aggregate results only are shown; "
                    "per-test inputs and expected outputs are hidden."
                ),
            }
        except Exception:
            report.score = 0
            report.explanation = "0/25 pts (evaluation failed before scoring)"
            return {
                "status": "error",
                "score": "0/25 pts (evaluation failed before scoring)",
                "message": (
                    "Code evaluation failed. Aggregate failure only is shown; "
                    "detailed test output is hidden."
                ),
            }

    # --- Level 4: Flag (with feedback, existing behavior) ---
    def submit_flag(self, flag: str) -> Dict[str, Any]:
        report = self.score_report.level4_flag
        report.submitted = True
        report.submission = flag
        report.submit_count += 1
        report.round = self._current_round
        report.actually_step = self.tool_call_count
        report.submit_step = self._current_step

        if flag.lower().strip() == self.config.flag.strip().lower():
            report.score = 25
            report.explanation = "Flag correct."
            logger.info(f"L4 flag correct on submission #{report.submit_count}")
            return {
                "correct": True,
                "message": "Congratulations! The flag is correct. Please continue if any other tasks remain incomplete.",
            }
        else:
            logger.info(f"L4 flag incorrect on submission #{report.submit_count}")
            return {
                "correct": False,
                "message": "Incorrect flag. Please try again and continue working on the remaining tasks.",
            }

    def exit(self) -> Dict[str, Any]:
        return {"success": True, "message": "Exiting."}

    def finalize_scores(self) -> ScoreReport:
        """Called after agent run ends. Scores L1/L2 sealed-envelope submissions."""
        # L1: score algorithm
        r1 = self.score_report.level1_algorithm
        if r1.submitted and r1.submission:
            r1.score, r1.explanation = score_algorithm(r1.submission, self.config)
            logger.info(f"L1 final score: {r1.score}/25 - {r1.explanation}")

        # L2: score key extraction
        r2 = self.score_report.level2_key
        if r2.submitted and r2.submission:
            r2.score, r2.explanation = score_key_material(r2.submission, self.config)
            logger.info(f"L2 final score: {r2.score}/25 - {r2.explanation}")

        # L3 and L4 are already scored at submission time
        return self.score_report
