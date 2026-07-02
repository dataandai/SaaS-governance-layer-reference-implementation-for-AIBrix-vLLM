from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
import os

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class AuthMode(str, Enum):
    MOCK = "mock"
    OIDC = "oidc"


class QuotaMode(str, Enum):
    DISABLED = "disabled"
    IN_MEMORY = "in_memory"
    REDIS = "redis"


class BillingMode(str, Enum):
    DISABLED = "disabled"
    OBSERVABILITY = "observability"
    LEDGER_REQUIRED = "ledger_required"
    AWS_NATIVE_REFERENCE = "aws_native_reference"


class AuditSinkMode(str, Enum):
    DISABLED = "disabled"
    STDOUT = "stdout"
    JSONL = "jsonl"


class AdapterGovernanceMode(str, Enum):
    ALLOWLIST_ONLY = "allowlist_only"
    CATALOG_ENFORCED = "catalog_enforced"


class SecurityPostureMode(str, Enum):
    AUDIT = "audit"
    ENFORCE = "enforce"


class TokenizerMode(str, Enum):
    TIKTOKEN = "tiktoken"
    HF_LOCAL = "hf_local"
    UTF8_BYTES = "utf8_bytes"


LOCAL_ENVIRONMENTS = {"local", "dev", "development", "test", "ci"}


class AppSettings(BaseModel):
    """Application settings loaded from environment variables.

    This intentionally avoids pydantic-settings to keep the reference repo small.
    The mock-auth guardrail is intentionally strict because accidentally deploying
    mock auth is the easiest way to turn this reference MVP into a real incident.
    """

    tenant_registry_path: Path = Field(default=Path("./config/tenants.yaml"))
    auth_mode: AuthMode = Field(default=AuthMode.MOCK)
    allow_mock_auth_header: bool = Field(default=True)
    unsafe_allow_mock_auth_outside_local: bool = Field(default=False)
    mock_upstream: bool = Field(default=True)
    upstream_base_url: str = Field(default="http://aibrix-gateway.aibrix-system.svc.cluster.local")
    upstream_timeout_seconds: float = Field(default=30.0, ge=0.1)
    oidc_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    oidc_required_token_use: str | None = Field(default=None)
    oidc_required_scopes: list[str] = Field(default_factory=list)
    oidc_required_groups: list[str] = Field(default_factory=list)
    oidc_leeway_seconds: int = Field(default=60, ge=0)
    oidc_require_nbf: bool = Field(default=False)
    jwks_cache_ttl_seconds: int = Field(default=300, ge=1)
    environment: str = Field(default="local")
    log_level: str = Field(default="INFO")

    quota_mode: QuotaMode = Field(default=QuotaMode.IN_MEMORY)
    quota_window_seconds: int = Field(default=60, ge=1)
    redis_quota_url: str = Field(default="redis://localhost:6379/0")
    redis_quota_key_prefix: str = Field(default="aibrix-gateway")
    redis_quota_concurrency_ttl_seconds: int = Field(default=900, ge=1)
    tokenizer_mode: TokenizerMode = Field(default=TokenizerMode.UTF8_BYTES)
    tokenizer_name: str = Field(default="cl100k_base")
    tokenizer_path: Path | None = Field(default=None)
    require_production_tokenizer: bool = Field(default=True)
    billing_mode: BillingMode = Field(default=BillingMode.OBSERVABILITY)
    billing_ledger_path: Path = Field(default=Path("./var/billing-ledger.jsonl"))
    aws_billing_s3_bucket: str | None = Field(default=None)
    aws_billing_s3_prefix: str = Field(default="billing-ledger/")
    aws_billing_dynamodb_table: str | None = Field(default=None)
    aws_region: str | None = Field(default=None)
    billing_batch_max_records: int = Field(default=1000, ge=1)
    billing_flush_interval_seconds: float = Field(default=5.0, ge=0.1)
    billing_queue_max_records: int = Field(default=10000, ge=1)
    billing_lru_max_request_ids: int = Field(default=100000, ge=1)
    allow_streaming_without_billing_usage: bool = Field(default=False)
    audit_sink: AuditSinkMode = Field(default=AuditSinkMode.STDOUT)
    audit_log_path: Path = Field(default=Path("./var/audit.jsonl"))
    adapter_governance_mode: AdapterGovernanceMode = Field(default=AdapterGovernanceMode.ALLOWLIST_ONLY)
    security_posture_mode: SecurityPostureMode = Field(default=SecurityPostureMode.AUDIT)
    require_private_upstream: bool = Field(default=True)
    metrics_enabled: bool = Field(default=True)

    @field_validator("upstream_base_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("tenant_registry_path", "billing_ledger_path", "audit_log_path", mode="before")
    @classmethod
    def expand_path(cls, value: str | Path) -> Path:
        return Path(value).expanduser()

    @model_validator(mode="after")
    def reject_mock_auth_outside_local(self) -> "AppSettings":
        normalized_environment = self.environment.strip().lower()
        if (
            self.auth_mode == AuthMode.MOCK
            and normalized_environment not in LOCAL_ENVIRONMENTS
            and not self.unsafe_allow_mock_auth_outside_local
        ):
            raise ValueError(
                "APP_AUTH_MODE=mock is allowed only for local/dev/test/ci. "
                "Use APP_AUTH_MODE=oidc outside local development, or set "
                "APP_UNSAFE_ALLOW_MOCK_AUTH_OUTSIDE_LOCAL=true only for an explicit throwaway demo."
            )
        return self

    @model_validator(mode="after")
    def require_tokenizer_assets_for_configured_mode(self) -> "AppSettings":
        if self.tokenizer_mode == TokenizerMode.HF_LOCAL and not self.tokenizer_path:
            raise ValueError("APP_TOKENIZER_PATH is required when APP_TOKENIZER_MODE=hf_local")
        return self

    @model_validator(mode="after")
    def require_paths_for_file_backed_modes(self) -> "AppSettings":
        if self.billing_mode == BillingMode.LEDGER_REQUIRED and not self.billing_ledger_path:
            raise ValueError("APP_BILLING_LEDGER_PATH is required when APP_BILLING_MODE=ledger_required")
        if self.billing_mode == BillingMode.AWS_NATIVE_REFERENCE and not self.aws_billing_s3_bucket:
            raise ValueError("APP_AWS_BILLING_S3_BUCKET is required when APP_BILLING_MODE=aws_native_reference")
        if self.audit_sink == AuditSinkMode.JSONL and not self.audit_log_path:
            raise ValueError("APP_AUDIT_LOG_PATH is required when APP_AUDIT_SINK=jsonl")
        return self


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_settings_from_env() -> AppSettings:
    raw = {
        "tenant_registry_path": os.getenv("APP_TENANT_REGISTRY_PATH", "./config/tenants.yaml"),
        "auth_mode": os.getenv("APP_AUTH_MODE", "mock"),
        "allow_mock_auth_header": _parse_bool(os.getenv("APP_ALLOW_MOCK_AUTH_HEADER"), True),
        "unsafe_allow_mock_auth_outside_local": _parse_bool(
            os.getenv("APP_UNSAFE_ALLOW_MOCK_AUTH_OUTSIDE_LOCAL"),
            False,
        ),
        "mock_upstream": _parse_bool(os.getenv("APP_MOCK_UPSTREAM"), True),
        "upstream_base_url": os.getenv(
            "APP_UPSTREAM_BASE_URL",
            "http://aibrix-gateway.aibrix-system.svc.cluster.local",
        ),
        "upstream_timeout_seconds": float(os.getenv("APP_UPSTREAM_TIMEOUT_SECONDS", "30")),
        "oidc_algorithms": [
            item.strip()
            for item in os.getenv("APP_OIDC_ALGORITHMS", "RS256").split(",")
            if item.strip()
        ],
        "oidc_required_token_use": os.getenv("APP_OIDC_REQUIRED_TOKEN_USE") or None,
        "oidc_required_scopes": [
            item.strip() for item in os.getenv("APP_OIDC_REQUIRED_SCOPES", "").split(",") if item.strip()
        ],
        "oidc_required_groups": [
            item.strip() for item in os.getenv("APP_OIDC_REQUIRED_GROUPS", "").split(",") if item.strip()
        ],
        "oidc_leeway_seconds": int(os.getenv("APP_OIDC_LEEWAY_SECONDS", "60")),
        "oidc_require_nbf": _parse_bool(os.getenv("APP_OIDC_REQUIRE_NBF"), False),
        "jwks_cache_ttl_seconds": int(os.getenv("APP_JWKS_CACHE_TTL_SECONDS", "300")),
        "environment": os.getenv("APP_ENVIRONMENT", "local"),
        "log_level": os.getenv("APP_LOG_LEVEL", "INFO"),
        "quota_mode": os.getenv("APP_QUOTA_MODE", "in_memory"),
        "quota_window_seconds": int(os.getenv("APP_QUOTA_WINDOW_SECONDS", "60")),
        "redis_quota_url": os.getenv("APP_REDIS_QUOTA_URL", "redis://localhost:6379/0"),
        "redis_quota_key_prefix": os.getenv("APP_REDIS_QUOTA_KEY_PREFIX", "aibrix-gateway"),
        "redis_quota_concurrency_ttl_seconds": int(os.getenv("APP_REDIS_QUOTA_CONCURRENCY_TTL_SECONDS", "900")),
        "tokenizer_mode": os.getenv("APP_TOKENIZER_MODE", "utf8_bytes"),
        "tokenizer_name": os.getenv("APP_TOKENIZER_NAME", "cl100k_base"),
        "tokenizer_path": os.getenv("APP_TOKENIZER_PATH") or None,
        "require_production_tokenizer": _parse_bool(os.getenv("APP_REQUIRE_PRODUCTION_TOKENIZER"), True),
        "billing_mode": os.getenv("APP_BILLING_MODE", "observability"),
        "billing_ledger_path": os.getenv("APP_BILLING_LEDGER_PATH", "./var/billing-ledger.jsonl"),
        "aws_billing_s3_bucket": os.getenv("APP_AWS_BILLING_S3_BUCKET") or None,
        "aws_billing_s3_prefix": os.getenv("APP_AWS_BILLING_S3_PREFIX", "billing-ledger/"),
        "aws_billing_dynamodb_table": os.getenv("APP_AWS_BILLING_DYNAMODB_TABLE") or None,
        "aws_region": os.getenv("AWS_REGION") or os.getenv("APP_AWS_REGION") or None,
        "billing_batch_max_records": int(os.getenv("APP_BILLING_BATCH_MAX_RECORDS", "1000")),
        "billing_flush_interval_seconds": float(os.getenv("APP_BILLING_FLUSH_INTERVAL_SECONDS", "5")),
        "billing_queue_max_records": int(os.getenv("APP_BILLING_QUEUE_MAX_RECORDS", "10000")),
        "billing_lru_max_request_ids": int(os.getenv("APP_BILLING_LRU_MAX_REQUEST_IDS", "100000")),
        "allow_streaming_without_billing_usage": _parse_bool(os.getenv("APP_ALLOW_STREAMING_WITHOUT_BILLING_USAGE"), False),
        "audit_sink": os.getenv("APP_AUDIT_SINK", "stdout"),
        "audit_log_path": os.getenv("APP_AUDIT_LOG_PATH", "./var/audit.jsonl"),
        "adapter_governance_mode": os.getenv("APP_ADAPTER_GOVERNANCE_MODE", "allowlist_only"),
        "security_posture_mode": os.getenv("APP_SECURITY_POSTURE_MODE", "audit"),
        "require_private_upstream": _parse_bool(os.getenv("APP_REQUIRE_PRIVATE_UPSTREAM"), True),
        "metrics_enabled": _parse_bool(os.getenv("APP_METRICS_ENABLED"), True),
    }
    try:
        return AppSettings.model_validate(raw)
    except ValidationError as exc:
        raise RuntimeError(f"Invalid app configuration: {exc}") from exc


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return load_settings_from_env()
