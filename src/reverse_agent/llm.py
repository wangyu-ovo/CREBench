import json
import logging
import os
import random
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from time import sleep
from typing import Any, Dict, List

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

PRICE_PER_MILLION_TOKENS = {
    "gpt-4.1": {"input": 2, "output": 8},
    "gpt-5.2": {"input": 1.75, "output": 14},
    "claude-sonnet-4-6": {"input": 3, "output": 15},
    "claude-sonnet-4-6-thinking": {"input": 3, "output": 15},
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    if model in PRICE_PER_MILLION_TOKENS:
        rates = PRICE_PER_MILLION_TOKENS[model]
        return (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000
    logger.warning("Unknown model %s for cost estimation. Returning $0.", model)
    return 0.0


def _safe_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _safe_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_safe_jsonable(item) for item in value]
    if hasattr(value, "model_dump"):
        try:
            return _safe_jsonable(value.model_dump())
        except Exception:
            pass
    if hasattr(value, "dict"):
        try:
            return _safe_jsonable(value.dict())
        except Exception:
            pass
    if hasattr(value, "to_dict"):
        try:
            return _safe_jsonable(value.to_dict())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return _safe_jsonable(vars(value))
        except Exception:
            pass
    return str(value)


def _response_body_from_exception(exc: Exception) -> Any:
    response = getattr(exc, "response", None)
    if response is None:
        return None

    try:
        json_method = getattr(response, "json", None)
        if callable(json_method):
            return _safe_jsonable(json_method())
    except Exception:
        pass

    for attr in ("text", "content"):
        value = getattr(response, attr, None)
        if value is not None:
            return _safe_jsonable(value)
    return None


def _error_payload(exc: Exception, *, provider: str, model: str, attempt: int, retry_times: int) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "provider": provider,
        "model": model,
        "attempt": attempt,
        "retry_times": retry_times,
        "exception_type": exc.__class__.__name__,
        "message": str(exc),
    }

    for attr in ("status_code", "request_id", "code", "param", "type"):
        value = getattr(exc, attr, None)
        if value is not None:
            payload[attr] = _safe_jsonable(value)

    body = _response_body_from_exception(exc)
    if body is not None:
        payload["response_body"] = body

    response = getattr(exc, "response", None)
    if response is not None:
        headers = getattr(response, "headers", None)
        if headers is not None:
            payload["response_headers"] = _safe_jsonable(headers)

    cause = getattr(exc, "__cause__", None)
    if cause is not None:
        payload["cause"] = {
            "exception_type": cause.__class__.__name__,
            "message": str(cause),
        }

    return payload


def _log_generation_error(
    exc: Exception,
    *,
    provider: str,
    model: str,
    attempt: int,
    retry_times: int,
    final: bool,
) -> Dict[str, Any]:
    payload = _error_payload(exc, provider=provider, model=model, attempt=attempt, retry_times=retry_times)
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if final:
        logger.error("LLM generation failed: %s", text)
    else:
        logger.warning("LLM generation error: %s", text)
    return payload


def _extract_openai_usage(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0, 0
    input_tokens = getattr(usage, "prompt_tokens", 0) or 0
    output_tokens = getattr(usage, "completion_tokens", 0) or 0
    if not output_tokens:
        output_tokens = getattr(usage, "output_tokens", 0) or 0
    return input_tokens, output_tokens


def _extract_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                    continue
            text_attr = getattr(item, "text", None)
            if isinstance(text_attr, str):
                parts.append(text_attr)
        return "".join(parts)
    text_attr = getattr(value, "text", None)
    if isinstance(text_attr, str):
        return text_attr
    return str(value)


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    return max(minimum, value)


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except Exception:
        return default
    return max(minimum, value)


def _retry_delay_seconds(attempt: int, *, base_env: str = "REV_RETRY_BASE_DELAY_SEC", max_env: str = "REV_RETRY_MAX_DELAY_SEC") -> float:
    base_delay = _env_float(base_env, 1.5, minimum=0.0)
    max_delay = _env_float(max_env, 20.0, minimum=0.0)
    jitter = random.uniform(0.0, 0.5)
    return min(max_delay, base_delay * (2 ** max(0, attempt - 1))) + jitter


def _is_claude_thinking_model(model: str) -> bool:
    normalized = model.strip().lower()
    return normalized.startswith("claude-") and "thinking" in normalized


def _claude_api_model_name(model: str) -> str:
    normalized = model.strip()
    if not _is_claude_thinking_model(normalized):
        return normalized

    suffixes = ("-thinking", "_thinking", ":thinking", "/thinking")
    lowered = normalized.lower()
    for suffix in suffixes:
        if lowered.endswith(suffix):
            return normalized[: -len(suffix)]

    return normalized.replace("thinking", "").replace("--", "-").strip("-_:/")


def _openai_api_model_name(model: str) -> str:
    normalized = model.strip()
    lowered = normalized.lower()
    for prefix in ("openai/", "openai:"):
        if lowered.startswith(prefix):
            stripped = normalized[len(prefix):].strip()
            return stripped or normalized
    return normalized


def _has_openai_credentials() -> bool:
    return bool((os.getenv("OPENAI_API_KEY") or "").strip())


def _has_azure_credentials() -> bool:
    return bool((os.getenv("AZURE_OPENAI_API_KEY") or "").strip()) and bool((os.getenv("AZURE_OPENAI_ENDPOINT") or "").strip())


def _select_openai_family_provider(*, provider: str | None = None) -> str:
    if provider is not None:
        normalized = provider.strip().lower()
        if normalized not in {"openai", "azure"}:
            raise ValueError(f"Unsupported provider override {provider!r}. Expected 'openai' or 'azure'.")
        return normalized
    if _has_openai_credentials():
        return "openai"
    if _has_azure_credentials():
        return "azure"
    raise ValueError(
        "Unable to resolve provider for OpenAI-family model. "
        "Pass --provider openai|azure, or set OPENAI_API_KEY, or set AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT."
    )


def resolve_provider_for_model(model: str, provider: str | None = None) -> str:
    normalized = model.strip().lower()
    if not normalized:
        raise ValueError("model must be a non-empty string")

    if normalized == "codex" or normalized.startswith("codex-"):
        if provider is not None and provider.strip().lower() not in {"openai", "azure"}:
            raise ValueError(f"Unsupported provider override {provider!r}. Expected 'openai' or 'azure'.")
        return "codex"
    if normalized.startswith("openai/") or normalized.startswith("openai:"):
        return _select_openai_family_provider(provider=provider)
    if normalized.startswith("gpt-") or normalized.startswith("o4-"):
        return _select_openai_family_provider(provider=provider)
    if provider is not None:
        raise ValueError(
            f"Provider override {provider!r} is only supported for OpenAI-family models "
            "(gpt-*, o4-*, openai/... or openai:...)."
        )
    if normalized.startswith("claude-"):
        return "claude"
    if normalized.startswith("qwen-"):
        return "qwen"
    if normalized.startswith("gemini-"):
        return "gemini"
    if normalized.startswith("mimo-"):
        return "mimo"
    if normalized.startswith("doubao"):
        return "doubao"

    raise ValueError(
        "Unable to resolve provider for model "
        f"{model!r}. Expected values/prefixes: codex, gpt-, claude-, qwen-, gemini-, mimo-, doubao."
    )


class LLMProvider(ABC):
    def __init__(self) -> None:
        self.total_cost = 0.0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_tokens = 0
        self.call_count = 0
        self.call_metrics: List[Dict[str, Any]] = []
        self.next_call_max_tokens: int | None = None
        self.last_generation_info: Dict[str, Any] = {}
        self.last_usage: Dict[str, Any] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost": 0.0,
        }

    @abstractmethod
    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        raise NotImplementedError

    def set_max_tokens_for_next_call(self, max_tokens: int | None) -> None:
        self.next_call_max_tokens = max_tokens if max_tokens and max_tokens > 0 else None

    def _record_usage(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        extra: Dict[str, Any] | None = None,
    ) -> int:
        total_tokens = input_tokens + output_tokens
        cost = _estimate_cost(model, input_tokens, output_tokens)

        self.call_count += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_tokens += total_tokens
        self.total_cost += cost
        self.last_usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "estimated_cost": cost,
        }
        if extra:
            self.last_usage.update(extra)
        self.last_generation_info = dict(extra or {})
        self.call_metrics.append({
            "call_index": self.call_count,
            **self.last_usage,
        })

        logger.info(
            "Input tokens: %s, Output tokens: %s, Total tokens: %s",
            input_tokens,
            output_tokens,
            total_tokens,
        )
        logger.info("Estimated cost: $%.6f", cost)
        logger.info("Total cost so far: $%.6f", self.total_cost)
        return total_tokens

    def get_usage_summary(self) -> Dict[str, Any]:
        return {
            "call_count": self.call_count,
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost": self.total_cost,
            "per_call": list(self.call_metrics),
        }


class OpenAICompatibleChatProvider(LLMProvider):
    def __init__(
        self,
        *,
        provider_name: str,
        api_key: str | None = None,
        api_key_env: str,
        base_url: str | None = None,
        base_url_env: str,
        default_base_url: str,
        request_kwargs: dict[str, Any] | None = None,
        retry_times: int = 5,
    ) -> None:
        from openai import OpenAI

        super().__init__()
        self.provider_name = provider_name
        self.client = OpenAI(
            api_key=api_key or os.getenv(api_key_env),
            base_url=base_url or os.getenv(base_url_env, default_base_url),
        )
        self.request_kwargs = dict(request_kwargs or {})
        self.retry_times = retry_times

    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        chat_messages = [{"role": "system", "content": system_prompt}, *messages]
        last_error_payload: Dict[str, Any] | None = None
        for attempt in range(1, self.retry_times + 1):
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=chat_messages,
                    **self.request_kwargs,
                )
                break
            except Exception as exc:
                last_error_payload = _log_generation_error(
                    exc,
                    provider=self.provider_name,
                    model=model,
                    attempt=attempt,
                    retry_times=self.retry_times,
                    final=False,
                )
                sleep(2)
        else:
            if last_error_payload is None:
                raise RuntimeError(f"Failed to generate response after {self.retry_times} retries")
            raise RuntimeError(
                f"Failed to generate response after {self.retry_times} retries: "
                f"{json.dumps(last_error_payload, ensure_ascii=False, sort_keys=True)}"
            )

        content = _extract_text(response.choices[0].message.content)
        input_tokens, output_tokens = _extract_openai_usage(response)
        token_count = self._record_usage(model, input_tokens, output_tokens)
        return content, token_count


class OpenAIChatProvider(OpenAICompatibleChatProvider):
    def __init__(self, api_key: str | None = None, retry_times: int = 5) -> None:
        super().__init__(
            provider_name="openai",
            api_key=api_key,
            api_key_env="OPENAI_API_KEY",
            base_url_env="OPENAI_API_BASE_URL",
            default_base_url="https://api.openai.com/v1",
            retry_times=retry_times,
        )

    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        return super().generate(_openai_api_model_name(model), system_prompt, messages)


class AzureOpenAIChatProvider(LLMProvider):
    def __init__(
        self,
        api_key: str | None = None,
        azure_endpoint: str | None = None,
        api_version: str | None = None,
        retry_times: int = 5,
    ) -> None:
        from openai import AzureOpenAI

        super().__init__()
        self.client = AzureOpenAI(
            api_key=api_key or os.getenv("AZURE_OPENAI_API_KEY"),
            azure_endpoint=azure_endpoint or os.getenv("AZURE_OPENAI_ENDPOINT"),
            api_version=api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),
        )
        self.retry_times = retry_times

    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        chat_messages = [{"role": "system", "content": system_prompt}, *messages]
        last_error_payload: Dict[str, Any] | None = None
        for attempt in range(1, self.retry_times + 1):
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=chat_messages,
                    max_completion_tokens=10000,
                )
                break
            except Exception as exc:
                last_error_payload = _log_generation_error(
                    exc,
                    provider="azure",
                    model=model,
                    attempt=attempt,
                    retry_times=self.retry_times,
                    final=False,
                )
                sleep(2)
        else:
            if last_error_payload is None:
                raise RuntimeError(f"Failed to generate response after {self.retry_times} retries")
            raise RuntimeError(
                f"Failed to generate response after {self.retry_times} retries: "
                f"{json.dumps(last_error_payload, ensure_ascii=False, sort_keys=True)}"
            )

        content = _extract_text(response.choices[0].message.content)
        input_tokens, output_tokens = _extract_openai_usage(response)
        token_count = self._record_usage(model, input_tokens, output_tokens)
        return content, token_count


class ClaudeProvider(LLMProvider):
    def __init__(self, api_key: str | None = None, base_url: str | None = None, retry_times: int = 5) -> None:
        super().__init__()
        try:
            import anthropic  # type: ignore
        except Exception as exc:
            raise ImportError("Please install anthropic: pip install anthropic") from exc

        self.client = anthropic.Anthropic(
            api_key=api_key or os.getenv("CLAUDE_API_KEY"),
            base_url=base_url or os.getenv("CLAUDE_BASE_URL"),
        )
        self.retry_times = retry_times

    def _extract_usage(self, response: Any) -> tuple[int, int]:
        usage = getattr(response, "usage", None)
        if usage is None:
            return 0, 0
        return getattr(usage, "input_tokens", 0) or 0, getattr(usage, "output_tokens", 0) or 0

    def _build_request_kwargs(self, model: str, system_prompt: str, conversation: list[dict[str, str]]) -> dict[str, Any]:
        request: dict[str, Any] = {
            "model": _claude_api_model_name(model),
            "max_tokens": 10000,
            "system": system_prompt,
            "messages": conversation,
        }
        if _is_claude_thinking_model(model):
            request["thinking"] = {
                "type": "enabled",
                "budget_tokens": 5000,
            }
            request["max_tokens"] = 15000
        return request

    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        conversation = []
        for message in messages:
            role = message.get("role", "user")
            if role not in {"user", "assistant"}:
                role = "user"
            conversation.append({"role": role, "content": message.get("content", "")})

        request_kwargs = self._build_request_kwargs(model, system_prompt, conversation)

        last_error_payload: Dict[str, Any] | None = None
        for attempt in range(1, self.retry_times + 1):
            try:
                response = self.client.messages.create(**request_kwargs)
                break
            except Exception as exc:
                last_error_payload = _log_generation_error(
                    exc,
                    provider="claude",
                    model=model,
                    attempt=attempt,
                    retry_times=self.retry_times,
                    final=False,
                )
                sleep(2)
        else:
            if last_error_payload is None:
                raise RuntimeError(f"Failed to generate response after {self.retry_times} retries")
            raise RuntimeError(
                f"Failed to generate response after {self.retry_times} retries: "
                f"{json.dumps(last_error_payload, ensure_ascii=False, sort_keys=True)}"
            )

        if not getattr(response, "content", None):
            return "", 0
        text = _extract_text(response.content)
        input_tokens, output_tokens = self._extract_usage(response)
        token_count = self._record_usage(model, input_tokens, output_tokens)
        return text, token_count


class QwenProvider(OpenAICompatibleChatProvider):
    def __init__(self, api_key: str | None = None, base_url: str | None = None, retry_times: int = 5) -> None:
        super().__init__(
            provider_name="qwen",
            api_key=api_key,
            api_key_env="QWEN_API_KEY",
            base_url=base_url,
            base_url_env="QWEN_BASE_URL",
            default_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
            retry_times=retry_times,
        )


class DoubaoProvider(OpenAICompatibleChatProvider):
    def __init__(self, api_key: str | None = None, base_url: str | None = None, retry_times: int = 5) -> None:
        request_kwargs: dict[str, Any] = {}
        if _env_flag("DOUBAO_ENABLE_THINKING", True):
            request_kwargs["extra_body"] = {"thinking": {"type": "enabled"}}
        super().__init__(
            provider_name="doubao",
            api_key=api_key or os.getenv("ARK_API_KEY"),
            api_key_env="DOUBAO_API_KEY",
            base_url=base_url,
            base_url_env="DOUBAO_BASE_URL",
            default_base_url="https://ark.cn-beijing.volces.com/api/v3",
            request_kwargs=request_kwargs,
            retry_times=retry_times,
        )


class MiMoProvider(OpenAICompatibleChatProvider):
    def __init__(self, api_key: str | None = None, base_url: str | None = None, retry_times: int = 5) -> None:
        super().__init__(
            provider_name="mimo",
            api_key=api_key,
            api_key_env="MIMO_API_KEY",
            base_url=base_url,
            base_url_env="MIMO_BASE_URL",
            default_base_url="https://api.xiaomimimo.com/v1",
            retry_times=retry_times,
        )


class GeminiProvider(LLMProvider):
    def __init__(
        self,
        *,
        project: str | None = None,
        location: str | None = None,
        vertexai: bool | None = None,
        retry_times: int = 5,
    ) -> None:
        super().__init__()
        try:
            from google import genai
            from google.genai import types
        except Exception as exc:
            raise ImportError("Please install google-genai: pip install google-genai") from exc

        self._types = types
        self.retry_times = retry_times
        self.client = genai.Client(
            vertexai=_env_flag("GEMINI_USE_VERTEXAI", True) if vertexai is None else vertexai,
            project=project or os.getenv("GEMINI_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT"),
            location=location or os.getenv("GEMINI_LOCATION", "global"),
        )

    def _extract_usage(self, response: Any) -> tuple[int, int]:
        usage = getattr(response, "usage_metadata", None)
        if usage is None:
            return 0, 0
        prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
        output_tokens = getattr(usage, "candidates_token_count", 0) or 0
        return prompt_tokens, output_tokens

    def generate(self, model: str, system_prompt: str, messages: List[Dict[str, str]]) -> tuple[str, int]:
        contents = []
        for message in messages:
            role = message.get("role", "user")
            if role not in {"user", "assistant"}:
                role = "user"
            contents.append(
                self._types.Content(
                    role="model" if role == "assistant" else "user",
                    parts=[self._types.Part.from_text(text=message.get("content", ""))],
                )
            )

        config = self._types.GenerateContentConfig(
            system_instruction=system_prompt,
            response_mime_type="application/json",
        )
        last_error_payload: Dict[str, Any] | None = None
        for attempt in range(1, self.retry_times + 1):
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=contents,
                    config=config,
                )
                break
            except Exception as exc:
                last_error_payload = _log_generation_error(
                    exc,
                    provider="gemini",
                    model=model,
                    attempt=attempt,
                    retry_times=self.retry_times,
                    final=False,
                )
                sleep(2)
        else:
            if last_error_payload is None:
                raise RuntimeError(f"Failed to generate response after {self.retry_times} retries")
            raise RuntimeError(
                f"Failed to generate response after {self.retry_times} retries: "
                f"{json.dumps(last_error_payload, ensure_ascii=False, sort_keys=True)}"
            )

        text = _extract_text(getattr(response, "text", ""))
        input_tokens, output_tokens = self._extract_usage(response)
        token_count = self._record_usage(model, input_tokens, output_tokens)
        return text, token_count


def build_provider_for_model(model: str, provider: str | None = None) -> tuple[str, LLMProvider]:
    provider = resolve_provider_for_model(model, provider=provider)
    if provider == "codex":
        raise RuntimeError("The codex runner is wired directly in run_reverse.py and does not use LLMProvider.generate().")
    if provider == "azure":
        return provider, AzureOpenAIChatProvider()
    if provider == "claude":
        return provider, ClaudeProvider()
    if provider == "qwen":
        return provider, QwenProvider()
    if provider == "doubao":
        return provider, DoubaoProvider()
    if provider == "gemini":
        return provider, GeminiProvider()
    if provider == "mimo":
        return provider, MiMoProvider()
    if provider == "openai":
        return provider, OpenAIChatProvider()
    raise ValueError(f"Unsupported provider {provider!r} for model {model!r}")
