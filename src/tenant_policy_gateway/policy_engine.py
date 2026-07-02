from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .jwt_validation import AuthenticatedPrincipal
from .tenant_registry import TenantConfig, TenantRegistry


class InvalidRequestError(ValueError):
    """Raised when an incoming LLM request violates the gateway API contract."""

    def __init__(self, reason: str, details: str | None = None) -> None:
        super().__init__(details or reason)
        self.reason = reason
        self.details = details or reason


@dataclass(frozen=True)
class RequestAttributes:
    domain: str | None
    model: str | None
    adapter: str | None


@dataclass(frozen=True)
class ParsedGatewayRequest:
    attributes: RequestAttributes
    body: dict[str, Any]
    endpoint: Literal["chat", "completion"]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    status_code: int
    reason: str
    tenant: TenantConfig | None = None
    tenant_id: str | None = None
    user_id: str | None = None
    model: str | None = None
    adapter: str | None = None


class _StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class FunctionCall(_StrictBaseModel):
    name: str
    arguments: str


class ToolCallFunction(_StrictBaseModel):
    name: str
    arguments: str


class ToolCall(_StrictBaseModel):
    id: str | None = None
    type: Literal["function"] = "function"
    function: ToolCallFunction


class ImageUrlPart(_StrictBaseModel):
    url: str
    detail: Literal["auto", "low", "high"] | None = None


class TextContentPart(_StrictBaseModel):
    type: Literal["text"]
    text: str


class InputTextContentPart(_StrictBaseModel):
    type: Literal["input_text"]
    text: str


class ImageUrlContentPart(_StrictBaseModel):
    type: Literal["image_url"]
    image_url: ImageUrlPart


class InputImageContentPart(_StrictBaseModel):
    type: Literal["input_image"]
    image_url: str | ImageUrlPart


ChatContentPart = TextContentPart | InputTextContentPart | ImageUrlContentPart | InputImageContentPart


class ChatMessage(_StrictBaseModel):
    role: Literal["system", "user", "assistant", "tool", "developer"]
    content: str | list[ChatContentPart] | None = None
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[ToolCall] | None = None
    function_call: FunctionCall | None = None

    @model_validator(mode="after")
    def require_content_or_tool_payload(self) -> "ChatMessage":
        if self.content is None and self.tool_calls is None and self.function_call is None:
            raise ValueError("message must include content, tool_calls, or function_call")
        return self


class ResponseFormat(_StrictBaseModel):
    type: Literal["text", "json_object"]


class ChatCompletionGatewayRequest(_StrictBaseModel):
    """Strict API contract accepted by the gateway for chat completions.

    Unknown vendor-specific fields are rejected instead of forwarded. The only
    adapter selector accepted by this gateway is the canonical `lora_adapter`
    field. This prevents hidden upstream knobs from bypassing the tenant adapter
    policy by being invisible to policy evaluation.
    """

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    lora_adapter: str | None = None
    stream: bool = False
    temperature: float | None = Field(default=None, ge=0)
    top_p: float | None = Field(default=None, ge=0, le=1)
    n: int | None = Field(default=None, ge=1, le=16)
    stop: str | list[str] | None = None
    max_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: int | None = None
    response_format: ResponseFormat | None = None

    @field_validator("model", "lora_adapter")
    @classmethod
    def normalize_non_empty_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("field must not be blank")
        return normalized


CompletionPrompt = str | list[str] | list[int] | list[list[int]]


class CompletionGatewayRequest(_StrictBaseModel):
    model: str
    prompt: CompletionPrompt
    lora_adapter: str | None = None
    stream: bool = False
    suffix: str | None = None
    max_tokens: int | None = Field(default=None, ge=1)
    temperature: float | None = Field(default=None, ge=0)
    top_p: float | None = Field(default=None, ge=0, le=1)
    n: int | None = Field(default=None, ge=1, le=16)
    stop: str | list[str] | None = None
    presence_penalty: float | None = Field(default=None, ge=-2, le=2)
    frequency_penalty: float | None = Field(default=None, ge=-2, le=2)
    seed: int | None = None

    @field_validator("model", "lora_adapter")
    @classmethod
    def normalize_non_empty_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("field must not be blank")
        return normalized


def parse_gateway_request_body(
    *,
    domain: str | None,
    request_body: dict[str, Any],
    upstream_path: str,
) -> ParsedGatewayRequest:
    endpoint = _endpoint_from_path(upstream_path, request_body)
    try:
        if endpoint == "chat":
            parsed = ChatCompletionGatewayRequest.model_validate(request_body)
        else:
            parsed = CompletionGatewayRequest.model_validate(request_body)
    except ValidationError as exc:
        raise InvalidRequestError("invalid_request_schema", _format_validation_error(exc)) from exc

    normalized_body = parsed.model_dump(mode="json", exclude_none=True)
    attributes = RequestAttributes(
        domain=domain.lower() if domain else None,
        model=parsed.model,
        adapter=parsed.lora_adapter,
    )
    return ParsedGatewayRequest(attributes=attributes, body=normalized_body, endpoint=endpoint)


def request_attributes_from_body(domain: str | None, request_body: dict[str, Any]) -> RequestAttributes:
    """Backward-compatible helper for older tests/call sites.

    It now validates the request against the strict schema instead of scavenging
    for vendor-specific fields.
    """

    parsed = parse_gateway_request_body(domain=domain, request_body=request_body, upstream_path="auto")
    return parsed.attributes


def extract_adapter(request_body: dict[str, Any]) -> str | None:
    """Return the canonical adapter field after strict schema validation.

    Only `lora_adapter` is accepted. Legacy aliases such as `adapter`, `lora`,
    `metadata.adapter`, or vendor-specific hidden fields are intentionally not
    supported and will be rejected by `parse_gateway_request_body`.
    """

    parsed = parse_gateway_request_body(domain=None, request_body=request_body, upstream_path="auto")
    return parsed.attributes.adapter


def _endpoint_from_path(upstream_path: str, request_body: dict[str, Any]) -> Literal["chat", "completion"]:
    if upstream_path.endswith("/v1/chat/completions") or upstream_path.endswith("chat/completions"):
        return "chat"
    if upstream_path.endswith("/v1/completions") or upstream_path.endswith("completions"):
        return "completion"
    if "messages" in request_body:
        return "chat"
    if "prompt" in request_body:
        return "completion"
    raise InvalidRequestError("invalid_request_schema", "request must include either messages or prompt")


def _format_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error.get("loc", ())) or "body"
        message = str(error.get("msg", "invalid value"))
        parts.append(f"{location}: {message}")
    return "; ".join(parts[:8])


def evaluate_policy(
    *,
    registry: TenantRegistry | None,
    attributes: RequestAttributes,
    principal: AuthenticatedPrincipal | None,
    auth_error_reason: str | None,
) -> PolicyDecision:
    if registry is None:
        return PolicyDecision(False, 503, "registry_unavailable")

    tenant = registry.resolve_by_host(attributes.domain)
    if tenant is None:
        return PolicyDecision(False, 403, "unknown_tenant", model=attributes.model, adapter=attributes.adapter)

    if principal is None:
        return PolicyDecision(False, 401, auth_error_reason or "missing_token", tenant=tenant, tenant_id=tenant.tenant_id)

    if principal.tenant_id != tenant.tenant_id:
        return PolicyDecision(
            False,
            403,
            "tenant_claim_mismatch",
            tenant=tenant,
            tenant_id=tenant.tenant_id,
            user_id=principal.user_id,
            model=attributes.model,
            adapter=attributes.adapter,
        )

    if attributes.model is None:
        return PolicyDecision(
            False,
            403,
            "unknown_model",
            tenant=tenant,
            tenant_id=tenant.tenant_id,
            user_id=principal.user_id,
            adapter=attributes.adapter,
        )

    model_policy = tenant.allowed_models.get(attributes.model)
    if model_policy is None:
        return PolicyDecision(
            False,
            403,
            "unknown_model",
            tenant=tenant,
            tenant_id=tenant.tenant_id,
            user_id=principal.user_id,
            model=attributes.model,
            adapter=attributes.adapter,
        )

    if attributes.adapter and attributes.adapter not in model_policy.allowed_lora_adapters:
        return PolicyDecision(
            False,
            403,
            "unknown_adapter",
            tenant=tenant,
            tenant_id=tenant.tenant_id,
            user_id=principal.user_id,
            model=attributes.model,
            adapter=attributes.adapter,
        )

    return PolicyDecision(
        True,
        200,
        "allowed",
        tenant=tenant,
        tenant_id=tenant.tenant_id,
        user_id=principal.user_id,
        model=attributes.model,
        adapter=attributes.adapter,
    )
