from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
from typing import Any, Protocol

from .config import AppSettings, LOCAL_ENVIRONMENTS, QuotaMode, TokenizerMode

logger = logging.getLogger("tenant_policy_gateway.metering")


class TokenizerInitializationError(RuntimeError):
    """Raised when the configured production tokenizer cannot be verified."""


class _Encoder(Protocol):
    def count(self, text: str) -> int: ...
    @property
    def source(self) -> str: ...
    @property
    def billing_grade(self) -> bool: ...


class TiktokenEncoder:
    def __init__(self, encoding_name: str) -> None:
        try:
            import tiktoken  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - depends on optional runtime dependency
            raise TokenizerInitializationError("APP_TOKENIZER_MODE=tiktoken requires tiktoken to be installed") from exc
        try:
            self._encoder = tiktoken.get_encoding(encoding_name)
        except Exception as exc:  # pragma: no cover - depends on configured tokenizer name
            raise TokenizerInitializationError(f"Could not initialize tiktoken encoding {encoding_name!r}") from exc
        self._source = f"tiktoken:{encoding_name}"

    def count(self, text: str) -> int:
        return len(self._encoder.encode(text))

    @property
    def source(self) -> str:
        return self._source

    @property
    def billing_grade(self) -> bool:
        return False


class HuggingFaceFastTokenizerEncoder:
    def __init__(self, tokenizer_path: Path) -> None:
        if not tokenizer_path.exists():
            raise TokenizerInitializationError(f"Tokenizer path does not exist: {tokenizer_path}")
        try:
            from tokenizers import Tokenizer  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - optional dependency
            raise TokenizerInitializationError("APP_TOKENIZER_MODE=hf_local requires tokenizers to be installed") from exc
        try:
            if tokenizer_path.is_file():
                self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
                source_path = tokenizer_path
            else:
                candidate = tokenizer_path / "tokenizer.json"
                if not candidate.exists():
                    raise TokenizerInitializationError(f"No tokenizer.json found under {tokenizer_path}")
                self._tokenizer = Tokenizer.from_file(str(candidate))
                source_path = candidate
        except TokenizerInitializationError:
            raise
        except Exception as exc:  # pragma: no cover - depends on tokenizer artifact
            raise TokenizerInitializationError(f"Could not load HuggingFace tokenizer from {tokenizer_path}") from exc
        self._source = f"hf_local:{source_path}"

    def count(self, text: str) -> int:
        return len(self._tokenizer.encode(text).ids)

    @property
    def source(self) -> str:
        return self._source

    @property
    def billing_grade(self) -> bool:
        return False


class Utf8ByteUpperBoundEncoder:
    """Deterministic local/demo safety fallback.

    This deliberately does NOT use len(text)//4. It counts UTF-8 bytes, which is
    deterministic and conservative for quota protection in local/demo mode. It
    is not model-specific and is rejected by settings validation for
    production-like environments when quota enforcement is enabled.
    """

    def count(self, text: str) -> int:
        return len(text.encode("utf-8"))

    @property
    def source(self) -> str:
        return "deterministic_utf8_byte_upper_bound_local_demo"

    @property
    def billing_grade(self) -> bool:
        return False


@dataclass(frozen=True)
class TokenEstimate:
    value: int
    source: str
    billing_grade: bool = False


@dataclass(frozen=True)
class MeteringEvent:
    request_id: str
    tenant_id: str | None
    user_id: str | None
    domain: str | None
    model: str | None
    adapter: str | None
    decision: str
    status_code: int
    reason: str
    latency_ms: float
    estimated_input_tokens: int | None = None
    estimated_input_token_source: str | None = None
    estimated_input_tokens_billing_grade: bool = False
    estimated_output_tokens: int | None = None
    estimated_output_token_source: str | None = None
    estimated_output_tokens_billing_grade: bool = False
    upstream_status_code: int | None = None


_encoder: _Encoder | None = None


def initialize_tokenizer(settings: AppSettings) -> None:
    """Initialize and verify the configured tokenizer during application startup."""

    global _encoder
    production_like = settings.environment.strip().lower() not in LOCAL_ENVIRONMENTS
    if settings.tokenizer_mode == TokenizerMode.TIKTOKEN:
        _encoder = TiktokenEncoder(settings.tokenizer_name)
    elif settings.tokenizer_mode == TokenizerMode.HF_LOCAL:
        assert settings.tokenizer_path is not None
        _encoder = HuggingFaceFastTokenizerEncoder(settings.tokenizer_path)
    elif settings.tokenizer_mode == TokenizerMode.UTF8_BYTES:
        if production_like and not settings.unsafe_allow_mock_auth_outside_local and settings.quota_mode != QuotaMode.DISABLED and settings.require_production_tokenizer:
            raise TokenizerInitializationError(
                "Production-like quota mode requires tiktoken or hf_local tokenizer; utf8_bytes is local/demo only."
            )
        _encoder = Utf8ByteUpperBoundEncoder()
    else:  # pragma: no cover - protected by pydantic enum validation
        raise TokenizerInitializationError(f"Unsupported tokenizer mode: {settings.tokenizer_mode}")
    # Verification pass: fail fast if encode/count is broken.
    if _encoder.count("tokenizer startup verification") <= 0:
        raise TokenizerInitializationError("Tokenizer verification produced a non-positive token count")
    logger.info(json.dumps({"event": "tokenizer_initialized", "source": _encoder.source}, sort_keys=True))


def _get_encoder() -> _Encoder:
    global _encoder
    if _encoder is None:
        # Local-library safe default for direct unit tests. FastAPI lifespan calls
        # initialize_tokenizer(settings), so production paths should never rely
        # on this branch.
        _encoder = Utf8ByteUpperBoundEncoder()
    return _encoder


def _collect_text_parts(request_body: dict[str, Any]) -> list[str]:
    text_parts: list[str] = []
    prompt = request_body.get("prompt")
    if isinstance(prompt, str):
        text_parts.append(prompt)
    elif isinstance(prompt, list):
        text_parts.extend(_text_from_prompt_list(prompt))

    messages = request_body.get("messages")
    if isinstance(messages, list):
        for item in messages:
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            content = item.get("content")
            if isinstance(role, str):
                text_parts.append(f"role:{role}")
            text_parts.extend(_text_from_message_content(content))
            for tool_call in item.get("tool_calls") or []:
                if isinstance(tool_call, dict):
                    text_parts.append(_canonical_json_for_tokenization(tool_call))
            function_call = item.get("function_call")
            if isinstance(function_call, dict):
                text_parts.append(_canonical_json_for_tokenization(function_call))
    return [part for part in text_parts if part]


def _text_from_prompt_list(prompt: list[Any]) -> list[str]:
    parts: list[str] = []
    for item in prompt:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, int):
            # Token-id prompts are already tokenized. Represent the integer
            # sequence deterministically for quota/audit estimation.
            parts.append(f"token_id:{item}")
        elif isinstance(item, list):
            parts.extend(_text_from_prompt_list(item))
        else:
            parts.append(_canonical_json_for_tokenization(item))
    return parts


def _text_from_message_content(content: Any) -> list[str]:
    if isinstance(content, str):
        return [content]
    if content is None:
        return []
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            parts.extend(_text_from_content_part(item))
        return parts
    return [_canonical_json_for_tokenization(content)]


def _text_from_content_part(part: Any) -> list[str]:
    if isinstance(part, str):
        return [part]
    if not isinstance(part, dict):
        return [_canonical_json_for_tokenization(part)]
    part_type = part.get("type")
    if part_type in {"text", "input_text"}:
        text = part.get("text")
        return [text] if isinstance(text, str) else [_canonical_json_for_tokenization(part)]
    if part_type == "image_url":
        image_url = part.get("image_url")
        if isinstance(image_url, dict):
            url = image_url.get("url", "")
            detail = image_url.get("detail", "auto")
            return [f"image_url:url={url};detail={detail}"]
        if isinstance(image_url, str):
            return [f"image_url:url={image_url};detail=auto"]
    if part_type == "input_image":
        image_url = part.get("image_url")
        if isinstance(image_url, str):
            return [f"input_image:url={image_url};detail=auto"]
        if isinstance(image_url, dict):
            return [f"input_image:{_canonical_json_for_tokenization(image_url)}"]
    return [_canonical_json_for_tokenization(part)]


def _canonical_json_for_tokenization(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return repr(value)


def estimate_input_tokens(request_body: dict[str, Any]) -> TokenEstimate | None:
    text_parts = _collect_text_parts(request_body)
    if not text_parts:
        return None
    combined = "\n".join(text_parts)
    encoder = _get_encoder()
    value = max(1, encoder.count(combined))
    return TokenEstimate(value=value, source=encoder.source, billing_grade=encoder.billing_grade)


def estimate_input_tokens_from_upstream(response_body: Any) -> TokenEstimate | None:
    if not isinstance(response_body, dict):
        return None
    usage = response_body.get("usage")
    if isinstance(usage, dict):
        prompt_tokens = usage.get("prompt_tokens")
        if isinstance(prompt_tokens, int) and prompt_tokens >= 0:
            return TokenEstimate(
                value=prompt_tokens,
                source="upstream_usage_prompt_tokens_unverified",
            )
    return None


def estimate_output_tokens(response_body: Any) -> TokenEstimate | None:
    if not isinstance(response_body, dict):
        return None
    usage = response_body.get("usage")
    if isinstance(usage, dict):
        completion_tokens = usage.get("completion_tokens")
        if isinstance(completion_tokens, int) and completion_tokens >= 0:
            return TokenEstimate(
                value=completion_tokens,
                source="upstream_usage_completion_tokens_unverified",
            )
    return None


def event_fields_from_token_estimate(prefix: str, estimate: TokenEstimate | None) -> dict[str, Any]:
    if estimate is None:
        return {
            f"estimated_{prefix}_tokens": None,
            f"estimated_{prefix}_token_source": None,
            f"estimated_{prefix}_tokens_billing_grade": False,
        }
    return {
        f"estimated_{prefix}_tokens": estimate.value,
        f"estimated_{prefix}_token_source": estimate.source,
        f"estimated_{prefix}_tokens_billing_grade": estimate.billing_grade,
    }


def emit_metering_event(event: MeteringEvent) -> None:
    logger.info(json.dumps(asdict(event), sort_keys=True, separators=(",", ":")))
