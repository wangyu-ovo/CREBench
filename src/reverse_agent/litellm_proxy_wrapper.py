import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from starlette.websockets import WebSocket

_REDACTED = "***REDACTED***"
_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "secret",
    "password",
    "token",
)


def _remote_num_retries() -> int:
    raw = (os.getenv("REV_LITELLM_REMOTE_NUM_RETRIES") or "").strip()
    if not raw:
        return 5
    try:
        return max(0, int(raw))
    except ValueError:
        return 5


def _debug_ws(message: str) -> None:
    if (os.getenv("REV_LITELLM_WS_DEBUG") or "").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    print(f"[revbench-ws] {message}", file=sys.stderr, flush=True)


def _responses_ws_enabled() -> bool:
    return (os.getenv("REV_LITELLM_ENABLE_WS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _capture_ws_payload(raw_message: str) -> None:
    capture_path = (os.getenv("REV_LITELLM_WS_CAPTURE_PATH") or "").strip()
    if not capture_path:
        return
    try:
        Path(capture_path).expanduser().resolve().write_text(raw_message, encoding="utf-8")
    except Exception as exc:
        _debug_ws(f"capture-failed {exc}")


def _safe_copy_jsonish(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _safe_copy_jsonish(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_copy_jsonish(item) for item in value]
    return value


def _tighten_read_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    tool_copy = _safe_copy_jsonish(tool)
    if str(tool_copy.get("name") or "") != "Read":
        return tool_copy
    schema = tool_copy.get("input_schema")
    if not isinstance(schema, dict):
        return tool_copy
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return tool_copy
    pages = properties.get("pages")
    if not isinstance(pages, dict):
        return tool_copy
    pages_copy = dict(pages)
    pages_copy["minLength"] = max(1, int(pages_copy.get("minLength", 0) or 0))
    pages_copy["pattern"] = r"^\d+(?:-\d+)?$"
    description = str(pages_copy.get("description") or "").strip()
    extra = " Omit this field entirely for non-PDF files. Never send an empty string."
    if extra.strip() not in description:
        pages_copy["description"] = f"{description}{extra}".strip()
    properties = dict(properties)
    properties["pages"] = pages_copy
    schema = dict(schema)
    schema["properties"] = properties
    tool_copy["input_schema"] = schema
    return tool_copy


def _sanitize_read_tool_input(value: Any, *, tool_name: str = "") -> Any:
    if str(tool_name or "") != "Read":
        return value
    if not isinstance(value, dict):
        return value
    if value.get("pages") != "":
        return value
    sanitized = dict(value)
    sanitized.pop("pages", None)
    return sanitized


def _sanitize_function_call_arguments(tool_name: str, arguments_text: str) -> str:
    if str(tool_name or "") != "Read":
        return arguments_text
    try:
        parsed = json.loads(arguments_text) if arguments_text else {}
    except Exception:
        return arguments_text
    sanitized = _sanitize_read_tool_input(parsed, tool_name=tool_name)
    return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))


def _patch_responses_api_providers_for_azure() -> None:
    from litellm.llms.anthropic.experimental_pass_through.messages import handler

    current = getattr(handler, "_RESPONSES_API_PROVIDERS", frozenset())
    if "azure" in current:
        return
    handler._RESPONSES_API_PROVIDERS = frozenset({*current, "azure"})


def _disable_azure_native_responses_websocket() -> None:
    from litellm.llms.azure.responses.transformation import AzureOpenAIResponsesAPIConfig

    if getattr(AzureOpenAIResponsesAPIConfig, "_revbench_native_ws_disabled", False):
        return

    def supports_native_websocket(self) -> bool:
        return False

    AzureOpenAIResponsesAPIConfig.supports_native_websocket = supports_native_websocket
    AzureOpenAIResponsesAPIConfig._revbench_native_ws_disabled = True


def _patch_managed_responses_ws_provider_injection() -> None:
    from litellm.responses.streaming_iterator import ManagedResponsesWebSocketHandler

    if getattr(ManagedResponsesWebSocketHandler, "_revbench_provider_injection_patch_installed", False):
        return

    original = ManagedResponsesWebSocketHandler._inject_credentials

    def patched_inject_credentials(self, call_kwargs: dict[str, Any], event_model: str | None) -> None:
        original(self, call_kwargs, event_model)
        if self.custom_llm_provider is None:
            return
        if event_model is None or event_model == self.model:
            call_kwargs["custom_llm_provider"] = self.custom_llm_provider

    ManagedResponsesWebSocketHandler._inject_credentials = patched_inject_credentials
    ManagedResponsesWebSocketHandler._revbench_provider_injection_patch_installed = True

    original_run = ManagedResponsesWebSocketHandler.run

    async def patched_run(self) -> None:
        _debug_ws(f"managed-ws-run model={self.model!r} custom_provider={self.custom_llm_provider!r}")
        return await original_run(self)

    ManagedResponsesWebSocketHandler.run = patched_run

    original_parse_message = ManagedResponsesWebSocketHandler._parse_message

    async def patched_parse_message(self, raw_message: str):
        preview = raw_message if len(raw_message) <= 400 else raw_message[:400] + "...<truncated>"
        _debug_ws(f"managed-ws-client-msg {preview}")
        _capture_ws_payload(raw_message)
        return await original_parse_message(self, raw_message)

    ManagedResponsesWebSocketHandler._parse_message = patched_parse_message


def _patch_anthropic_responses_read_tool_handling() -> None:
    from litellm.llms.anthropic.experimental_pass_through.responses_adapters import (
        transformation as responses_transformation,
    )
    from litellm.llms.anthropic.experimental_pass_through.responses_adapters import (
        streaming_iterator as responses_streaming,
    )

    adapter_cls = responses_transformation.LiteLLMAnthropicToResponsesAPIAdapter
    if not getattr(adapter_cls, "_revbench_read_schema_patch_installed", False):
        original_translate_tools = adapter_cls.translate_tools_to_responses_api
        original_translate_response = adapter_cls.translate_response

        def patched_translate_tools_to_responses_api(self, tools):
            tightened_tools = [
                _tighten_read_tool_schema(tool) if isinstance(tool, dict) else tool
                for tool in tools
            ]
            return original_translate_tools(self, tightened_tools)

        def patched_translate_response(self, response):
            translated = original_translate_response(self, response)
            content = translated.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if str(block.get("type") or "") != "tool_use":
                        continue
                    block["input"] = _sanitize_read_tool_input(
                        block.get("input"),
                        tool_name=str(block.get("name") or ""),
                    )
            return translated

        adapter_cls.translate_tools_to_responses_api = patched_translate_tools_to_responses_api
        adapter_cls.translate_response = patched_translate_response
        adapter_cls._revbench_read_schema_patch_installed = True

    stream_cls = responses_streaming.AnthropicResponsesStreamWrapper
    if not getattr(stream_cls, "_revbench_read_stream_patch_installed", False):
        original_init = stream_cls.__init__
        original_process_event = stream_cls._process_event

        def patched_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            self._revbench_tool_name_by_item_id = {}
            self._revbench_tool_arg_buffer = {}

        def patched_process_event(self, event):
            event_type = getattr(event, "type", None)
            if event_type is None and isinstance(event, dict):
                event_type = event.get("type")

            if event_type == "response.output_item.added":
                item = getattr(event, "item", None) or (
                    event.get("item") if isinstance(event, dict) else None
                )
                item_id = getattr(item, "id", None) or (
                    item.get("id") if isinstance(item, dict) else None
                )
                item_type = getattr(item, "type", None) or (
                    item.get("type") if isinstance(item, dict) else None
                )
                if item_id and item_type == "function_call":
                    name = getattr(item, "name", None) or (
                        item.get("name") if isinstance(item, dict) else None
                    )
                    self._revbench_tool_name_by_item_id[item_id] = str(name or "")
                    self._revbench_tool_arg_buffer[item_id] = []
                return original_process_event(self, event)

            if event_type == "response.function_call_arguments.delta":
                item_id = getattr(event, "item_id", None) or (
                    event.get("item_id") if isinstance(event, dict) else None
                )
                tool_name = self._revbench_tool_name_by_item_id.get(item_id or "", "")
                if item_id and tool_name == "Read":
                    delta = getattr(event, "delta", "") or (
                        event.get("delta", "") if isinstance(event, dict) else ""
                    )
                    self._revbench_tool_arg_buffer.setdefault(item_id, []).append(str(delta))
                    return
                return original_process_event(self, event)

            if event_type == "response.output_item.done":
                item = getattr(event, "item", None) or (
                    event.get("item") if isinstance(event, dict) else None
                )
                item_id = getattr(item, "id", None) or (
                    item.get("id") if isinstance(item, dict) else None
                )
                tool_name = self._revbench_tool_name_by_item_id.get(item_id or "", "")
                if item_id and tool_name == "Read":
                    raw_arguments = getattr(item, "arguments", None) or (
                        item.get("arguments") if isinstance(item, dict) else None
                    )
                    if raw_arguments is None:
                        raw_arguments = "".join(self._revbench_tool_arg_buffer.get(item_id, []))
                    sanitized_arguments = _sanitize_function_call_arguments(tool_name, str(raw_arguments or ""))
                    block_idx = self._item_id_to_block_index.get(item_id, self._current_block_index)
                    if sanitized_arguments:
                        self._chunk_queue.append(
                            {
                                "type": "content_block_delta",
                                "index": block_idx,
                                "delta": {"type": "input_json_delta", "partial_json": sanitized_arguments},
                            }
                        )
                    self._chunk_queue.append({"type": "content_block_stop", "index": block_idx})
                    self._revbench_tool_name_by_item_id.pop(item_id, None)
                    self._revbench_tool_arg_buffer.pop(item_id, None)
                    return
                if item_id:
                    self._revbench_tool_name_by_item_id.pop(item_id, None)
                    self._revbench_tool_arg_buffer.pop(item_id, None)
                return original_process_event(self, event)

            return original_process_event(self, event)

        stream_cls.__init__ = patched_init
        stream_cls._process_event = patched_process_event
        stream_cls._revbench_read_stream_patch_installed = True


def _patch_local_websocket_auth() -> None:
    from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
    from litellm.proxy.auth import user_api_key_auth as auth_module

    if getattr(auth_module, "_revbench_local_ws_auth_patch_installed", False):
        return

    original = auth_module.user_api_key_auth_websocket

    async def patched_user_api_key_auth_websocket(websocket: WebSocket):
        _debug_ws(
            f"auth path={getattr(websocket, 'url', '')} auth={bool(websocket.headers.get('authorization'))} "
            f"api-key={bool(websocket.headers.get('api-key'))} subprotocol={websocket.headers.get('sec-websocket-protocol','')!r}"
        )
        authorization = websocket.headers.get("authorization")
        api_key = websocket.headers.get("api-key")
        subprotocols = websocket.headers.get("sec-websocket-protocol", "")
        has_browser_api_key = any(
            protocol.strip().startswith("openai-insecure-api-key.")
            for protocol in subprotocols.split(",")
        )
        if authorization or api_key or has_browser_api_key:
            return await original(websocket)

        if (os.getenv("LITELLM_MASTER_KEY") or "").strip():
            return await original(websocket)

        return UserAPIKeyAuth(
            api_key="revbench-local-proxy",
            user_role=LitellmUserRoles.INTERNAL_USER,
        )

    auth_module.user_api_key_auth_websocket = patched_user_api_key_auth_websocket
    auth_module._revbench_local_ws_auth_patch_installed = True

    try:
        from litellm.proxy.response_api_endpoints import endpoints as response_endpoints
    except Exception:
        response_endpoints = None
    if response_endpoints is not None:
        response_endpoints.user_api_key_auth_websocket = patched_user_api_key_auth_websocket
        for route in getattr(response_endpoints.router, "routes", []):
            if getattr(route, "path", None) not in {"/responses", "/v1/responses"}:
                continue
            dependant = getattr(route, "dependant", None)
            if dependant is None:
                continue
            for dependency in getattr(dependant, "dependencies", []):
                if getattr(dependency.call, "__name__", "") == "user_api_key_auth_websocket":
                    dependency.call = patched_user_api_key_auth_websocket

    try:
        from litellm.proxy import proxy_server
    except Exception:
        return
    proxy_server.user_api_key_auth_websocket = patched_user_api_key_auth_websocket
    for route in getattr(proxy_server.app, "routes", []):
        if getattr(route, "path", None) not in {"/responses", "/v1/responses"}:
            continue
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for dependency in getattr(dependant, "dependencies", []):
            if getattr(dependency.call, "__name__", "") == "user_api_key_auth_websocket":
                dependency.call = patched_user_api_key_auth_websocket


def _install_responses_websocket_model_compat() -> None:
    default_model = (os.getenv("REV_LITELLM_DEFAULT_MODEL") or "").strip()
    _debug_ws(f"install-compat default_model={default_model!r}")
    if not default_model:
        return

    from fastapi.routing import APIWebSocketRoute
    from litellm.proxy.response_api_endpoints import endpoints as response_endpoints
    from litellm.proxy import proxy_server

    if getattr(proxy_server.app.state, "_revbench_responses_ws_model_compat_installed", False):
        return

    async def patched_responses_websocket_endpoint(websocket: WebSocket):
        _debug_ws(
            f"compat-route path={getattr(websocket, 'url', '')} query={dict(websocket.query_params)}"
        )
        model = (websocket.query_params.get("model") or "").strip() or default_model
        user_api_key_dict = await response_endpoints.user_api_key_auth_websocket(websocket)
        return await response_endpoints.responses_websocket_endpoint(
            websocket=websocket,
            model=model,
            user_api_key_dict=user_api_key_dict,
        )

    for path in ("/v1/responses", "/responses"):
        route = APIWebSocketRoute(
            path=path,
            endpoint=patched_responses_websocket_endpoint,
            name=f"revbench_responses_websocket_{path.strip('/').replace('/', '_')}",
        )
        proxy_server.app.router.routes.insert(0, route)
        _debug_ws(f"inserted compat route path={path}")

    proxy_server.app.state._revbench_responses_ws_model_compat_installed = True


def _install_responses_websocket_deny_route() -> None:
    from fastapi.routing import APIWebSocketRoute
    from starlette.responses import PlainTextResponse
    from litellm.proxy import proxy_server

    if getattr(proxy_server.app.state, "_revbench_responses_ws_deny_installed", False):
        return

    async def deny_responses_websocket(websocket: WebSocket):
        response = PlainTextResponse(
            "Responses websocket disabled by RevBench proxy; retry over HTTPS.",
            status_code=403,
        )
        try:
            await websocket.send_denial_response(response)
        except RuntimeError:
            # Older servers may not expose the denial-response extension.
            await websocket.close(code=1008, reason="responses websocket disabled")

    for path in ("/v1/responses", "/responses"):
        route = APIWebSocketRoute(
            path=path,
            endpoint=deny_responses_websocket,
            name=f"revbench_responses_websocket_deny_{path.strip('/').replace('/', '_')}",
        )
        proxy_server.app.router.routes.insert(0, route)

    proxy_server.app.state._revbench_responses_ws_deny_installed = True


def _coerce_usage_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        try:
            return dict(vars(value))
        except Exception:
            return {}
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump()
        except Exception:
            return {}
    if hasattr(value, "dict"):
        try:
            return value.dict()
        except Exception:
            return {}
    return {}


def _extract_response_cost(kwargs: dict[str, Any], response_obj: Any) -> float:
    details = kwargs.get("litellm_params") or {}
    metadata = details.get("metadata") or {}
    hidden = getattr(response_obj, "_hidden_params", None) or {}
    for candidate in (
        kwargs.get("response_cost"),
        metadata.get("response_cost"),
        hidden.get("response_cost"),
    ):
        if candidate is None:
            continue
        try:
            return float(candidate)
        except (TypeError, ValueError):
            continue
    return 0.0


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "model_dump"):
        try:
            return _json_safe(value.model_dump())
        except Exception:
            pass
    if hasattr(value, "dict"):
        try:
            return _json_safe(value.dict())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return _json_safe(vars(value))
        except Exception:
            pass
    return repr(value)


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    redacted = _redact_sensitive(payload)
    rendered = json.dumps(redacted, ensure_ascii=False)
    rendered = _replace_known_secret_values(rendered)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(rendered + "\n")


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _replace_known_secret_values(text: str) -> str:
    for env_name in ("AZURE_OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        value = (os.getenv(env_name) or "").strip()
        if value:
            text = text.replace(value, _REDACTED)
    return text


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _redact_sensitive(value: Any, *, parent_key: str = "") -> Any:
    if _is_sensitive_key(parent_key):
        return _REDACTED
    if isinstance(value, dict):
        return {str(key): _redact_sensitive(item, parent_key=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_sensitive(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive(item, parent_key=parent_key) for item in value]
    return value


def _build_usage_event(kwargs: dict[str, Any], response_obj: Any) -> dict[str, Any]:
    usage = _coerce_usage_dict(getattr(response_obj, "usage", None))
    input_tokens = int(
        usage.get("prompt_tokens")
        or usage.get("input_tokens")
        or usage.get("promptTokens")
        or 0
    )
    output_tokens = int(
        usage.get("completion_tokens")
        or usage.get("output_tokens")
        or usage.get("completionTokens")
        or 0
    )
    total_tokens = int(usage.get("total_tokens") or usage.get("totalTokens") or (input_tokens + output_tokens))
    return {
        "request_id": str(getattr(response_obj, "id", "") or kwargs.get("request_id") or ""),
        "model": str(kwargs.get("model") or getattr(response_obj, "model", "") or ""),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "estimated_cost": _extract_response_cost(kwargs, response_obj),
    }


def _build_trace_request_event(model: str, messages: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": _timestamp_now(),
        "phase": "request",
        "request_id": str(kwargs.get("request_id") or kwargs.get("litellm_call_id") or ""),
        "model": str(model or kwargs.get("model") or ""),
        "messages": _json_safe(messages),
        "kwargs": _json_safe(kwargs),
    }


def _build_trace_response_event(kwargs: dict[str, Any], response_obj: Any) -> dict[str, Any]:
    usage_event = _build_usage_event(kwargs, response_obj)
    return {
        "timestamp": _timestamp_now(),
        "phase": "response",
        "request_id": usage_event.get("request_id") or str(kwargs.get("request_id") or kwargs.get("litellm_call_id") or ""),
        "model": usage_event.get("model") or str(kwargs.get("model") or ""),
        "usage": usage_event,
        "response": _json_safe(response_obj),
    }


def _build_trace_failure_event(kwargs: dict[str, Any], response_obj: Any) -> dict[str, Any]:
    request_id = ""
    if isinstance(kwargs, dict):
        request_id = str(kwargs.get("request_id") or kwargs.get("litellm_call_id") or "")
    return {
        "timestamp": _timestamp_now(),
        "phase": "failure",
        "request_id": request_id,
        "model": str((kwargs or {}).get("model") or ""),
        "kwargs": _json_safe(kwargs),
        "error": _json_safe(response_obj),
    }


def _install_usage_recorder() -> None:
    usage_path_raw = (os.getenv("REV_LITELLM_USAGE_PATH") or "").strip()
    if not usage_path_raw:
        return

    import litellm
    from litellm.integrations.custom_logger import CustomLogger

    usage_path = Path(usage_path_raw).expanduser().resolve()
    usage_path.parent.mkdir(parents=True, exist_ok=True)

    class _UsageRecorder(CustomLogger):
        def _append(self, kwargs: dict[str, Any], response_obj: Any) -> None:
            event = _build_usage_event(kwargs, response_obj)
            with usage_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")

        def log_success_event(self, kwargs, response_obj, start_time, end_time):
            self._append(kwargs, response_obj)

        async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
            self._append(kwargs, response_obj)

    recorder = _UsageRecorder()
    if recorder not in litellm.success_callback:
        litellm.success_callback.append(recorder)
    async_callbacks = getattr(litellm, "_async_success_callback", None)
    if isinstance(async_callbacks, list) and recorder not in async_callbacks:
        async_callbacks.append(recorder)


def _install_trace_recorder() -> None:
    trace_path_raw = (os.getenv("REV_LITELLM_TRACE_PATH") or "").strip()
    if not trace_path_raw:
        return

    import litellm
    from litellm.integrations.custom_logger import CustomLogger

    trace_path = Path(trace_path_raw).expanduser().resolve()
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    class _TraceRecorder(CustomLogger):
        def log_pre_api_call(self, model, messages, kwargs):
            _append_jsonl(trace_path, _build_trace_request_event(model, messages, kwargs))

        def log_success_event(self, kwargs, response_obj, start_time, end_time):
            _append_jsonl(trace_path, _build_trace_response_event(kwargs, response_obj))

        def log_failure_event(self, kwargs, response_obj, start_time, end_time):
            _append_jsonl(trace_path, _build_trace_failure_event(kwargs, response_obj))

        async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
            _append_jsonl(trace_path, _build_trace_response_event(kwargs, response_obj))

        async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
            _append_jsonl(trace_path, _build_trace_failure_event(kwargs, response_obj))

    recorder = _TraceRecorder()
    callbacks = getattr(litellm, "callbacks", None)
    if isinstance(callbacks, list) and recorder not in callbacks:
        callbacks.append(recorder)
    success_callbacks = getattr(litellm, "success_callback", None)
    if isinstance(success_callbacks, list) and recorder not in success_callbacks:
        success_callbacks.append(recorder)
    failure_callbacks = getattr(litellm, "failure_callback", None)
    if isinstance(failure_callbacks, list) and recorder not in failure_callbacks:
        failure_callbacks.append(recorder)
    async_success_callbacks = getattr(litellm, "_async_success_callback", None)
    if isinstance(async_success_callbacks, list) and recorder not in async_success_callbacks:
        async_success_callbacks.append(recorder)
    async_failure_callbacks = getattr(litellm, "_async_failure_callback", None)
    if isinstance(async_failure_callbacks, list) and recorder not in async_failure_callbacks:
        async_failure_callbacks.append(recorder)


def _configure_remote_retry_defaults() -> None:
    import litellm

    litellm.num_retries = _remote_num_retries()


def main() -> int:
    _patch_responses_api_providers_for_azure()
    _patch_anthropic_responses_read_tool_handling()
    _configure_remote_retry_defaults()
    if _responses_ws_enabled():
        _disable_azure_native_responses_websocket()
        _patch_managed_responses_ws_provider_injection()
        _patch_local_websocket_auth()
        _install_responses_websocket_model_compat()
    else:
        _install_responses_websocket_deny_route()
        print(
            "[revbench-ws] responses websocket compatibility disabled; Codex should fall back to HTTPS.",
            file=sys.stderr,
            flush=True,
        )
    _install_usage_recorder()
    _install_trace_recorder()
    from litellm import run_server

    sys.argv[0] = "litellm"
    return int(run_server() or 0)


if __name__ == "__main__":
    raise SystemExit(main())
