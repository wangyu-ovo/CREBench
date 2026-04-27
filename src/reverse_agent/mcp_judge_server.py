import json
import logging
import socket
import threading
import time
import uuid
import keyword
from typing import Any

import uvicorn
from fastmcp import FastMCP

from .tools import ToolExecutor

logger = logging.getLogger(__name__)


def _reserve_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


class HostJudgeMCPServer:
    def __init__(self, tool_executor: ToolExecutor, bind_host: str = "0.0.0.0", port: int = 0):
        self.tool_executor = tool_executor
        self.bind_host = bind_host
        self.port = port
        self.server_name = "revbench_judge"
        self.path = f"/mcp/{uuid.uuid4().hex}"
        self._mcp = FastMCP(self.server_name)
        self._tool_events: list[dict[str, Any]] = []
        self._tool_events_lock = threading.Lock()
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._register_tools()

    def _register_tools(self) -> None:
        for spec in self.tool_executor.get_submission_tool_schemas():
            tool_name = spec["name"]
            input_props = (spec.get("parameters") or {}).get("properties") or {}
            required = set((spec.get("parameters") or {}).get("required") or [])
            description = spec.get("description", "")
            tool_fn = self._build_tool_function(tool_name, input_props, required, description)
            self._mcp.tool(name=tool_name, description=description)(tool_fn)

    def _build_tool_function(
        self,
        tool_name: str,
        input_props: dict[str, Any],
        required_fields: set[str],
        description: str,
    ) -> Any:
        params: list[str] = []
        for arg_name in input_props.keys():
            if not arg_name.isidentifier() or keyword.iskeyword(arg_name):
                raise ValueError(f"Unsupported MCP tool argument name: {arg_name}")
            if arg_name in required_fields:
                params.append(f"{arg_name}: str")
            else:
                params.append(f"{arg_name}: str = ''")

        params_src = ", ".join(params)
        args_items = ", ".join(f"'{name}': {name}" for name in input_props.keys())
        source = (
            f"def {tool_name}({params_src}) -> str:\n"
            f"    args = {{{args_items}}}\n"
            f"    return _dispatch(args)\n"
        )
        namespace: dict[str, Any] = {
            "_dispatch": self._make_dispatcher(tool_name, input_props),
        }
        exec(source, namespace)
        fn = namespace[tool_name]
        fn.__doc__ = description
        return fn

    def _make_dispatcher(self, tool_name: str, input_props: dict[str, Any]) -> Any:
        def _dispatch(args: dict[str, Any]) -> str:
            filtered_args = {key: value for key, value in args.items() if key in input_props}
            logger.info("Judge MCP tool call: %s(%s)", tool_name, filtered_args)
            result = self.tool_executor.execute_tool(tool_name, **filtered_args)
            with self._tool_events_lock:
                self._tool_events.append(
                    {
                        "timestamp": time.time(),
                        "tool_name": tool_name,
                        "arguments": filtered_args,
                        "result": result,
                    }
                )
            return result

        return _dispatch

    def start(self) -> None:
        if self._server is not None:
            return

        port = self.port or _reserve_port(self.bind_host)
        app = self._mcp.http_app(path=self.path, transport="streamable-http")
        config = uvicorn.Config(app, host=self.bind_host, port=port, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, name="judge-mcp-server", daemon=True)
        self._thread.start()

        deadline = time.time() + 10
        while time.time() < deadline:
            if self._server.started:
                logger.info("Started host judge MCP server on %s", self.url_for_host("127.0.0.1"))
                return
            time.sleep(0.05)

        raise RuntimeError("Timed out while starting host judge MCP server")

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._thread = None
        self._server = None

    def __enter__(self) -> "HostJudgeMCPServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    @property
    def bound_port(self) -> int:
        if self._server is None:
            raise RuntimeError("judge MCP server is not running")
        return int(self._server.config.port)

    def url_for_host(self, host: str) -> str:
        return f"http://{host}:{self.bound_port}{self.path}"

    def tool_events(self) -> list[dict[str, Any]]:
        with self._tool_events_lock:
            return [dict(item) for item in self._tool_events]
