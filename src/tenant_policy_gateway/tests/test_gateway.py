from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tenant_policy_gateway.config import AppSettings, AuthMode, AdapterGovernanceMode, AuditSinkMode, BillingMode, QuotaMode, SecurityPostureMode
from tenant_policy_gateway.main import create_app


TENANT_REGISTRY = """
tenants:
  - tenant_id: tenant-a
    domains: [tenant-a.example.local]
    oidc_issuer: https://issuer.example.local/tenant-a
    oidc_audience: aibrix-gateway
    oidc_jwks_url: https://issuer.example.local/tenant-a/jwks.json
    tenant_claim: tenant_id
    user_claim: sub
    routing_external_filter: tenant={tenant_id}
    config_profile: gold
    user_header_template: "{tenant_id}:{user_id}"
    limits:
      requests_per_minute: 60
      input_tokens_per_minute: 100000
      output_tokens_per_minute: 100000
    runtime_isolation:
      mode: shared_pool_reference
      kv_cache_isolation_required: true
      kv_cache_isolation_proven: false
      evidence: null
    adapter_artifacts:
      tenant-a-support:
        artifact_uri: s3://example-lora-artifacts/tenant-a/support/v1/adapter.safetensors
        sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        signed_by: kms-key-alias/aibrix-lora-signing
        status: active
        compatible_models: [meta-llama/Llama-3.1-8B-Instruct]
      tenant-a-sales:
        artifact_uri: s3://example-lora-artifacts/tenant-a/sales/v1/adapter.safetensors
        sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        signed_by: kms-key-alias/aibrix-lora-signing
        status: active
        compatible_models: [meta-llama/Llama-3.1-8B-Instruct]
    allowed_models:
      meta-llama/Llama-3.1-8B-Instruct:
        allowed_lora_adapters: [tenant-a-support, tenant-a-sales]
      mistral/Mistral-7B-Instruct:
        allowed_lora_adapters: []
  - tenant_id: tenant-b
    domains: [tenant-b.example.local]
    oidc_issuer: https://issuer.example.local/tenant-b
    oidc_audience: aibrix-gateway
    oidc_jwks_url: https://issuer.example.local/tenant-b/jwks.json
    tenant_claim: tenant_id
    user_claim: sub
    routing_external_filter: tenant={tenant_id}
    config_profile: silver
    user_header_template: "{tenant_id}:{user_id}"
    limits:
      requests_per_minute: 30
      input_tokens_per_minute: 50000
      output_tokens_per_minute: 50000
    runtime_isolation:
      mode: shared_pool_reference
      kv_cache_isolation_required: true
      kv_cache_isolation_proven: false
      evidence: null
    adapter_artifacts:
      tenant-b-support:
        artifact_uri: s3://example-lora-artifacts/tenant-b/support/v1/adapter.safetensors
        sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
        signed_by: kms-key-alias/aibrix-lora-signing
        status: active
        compatible_models: [meta-llama/Llama-3.1-8B-Instruct]
    allowed_models:
      meta-llama/Llama-3.1-8B-Instruct:
        allowed_lora_adapters: [tenant-b-support]
"""

@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    path = tmp_path / "tenants.yaml"
    path.write_text(TENANT_REGISTRY, encoding="utf-8")
    return path


@pytest.fixture()
def client(registry_path: Path) -> TestClient:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        allow_mock_auth_header=True,
        mock_upstream=True,
        upstream_base_url="http://mock-aibrix.local",
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _headers(host: str, token: str | None = "mock:tenant-a:user-123", **extra: str) -> dict[str, str]:
    headers = {"host": host, "x-request-id": "test-request-1"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    headers.update(extra)
    return headers


def _chat_body(model: str = "meta-llama/Llama-3.1-8B-Instruct", adapter: str | None = "tenant-a-support") -> dict:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0,
    }
    if adapter is not None:
        body["lora_adapter"] = adapter
    return body


def test_valid_tenant_a_request(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local"),
        json=_chat_body(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["received_headers"]["user"] == "tenant-a:user-123"
    assert payload["received_headers"]["external-filter"] == "tenant=tenant-a"
    assert payload["received_headers"]["config-profile"] == "gold"
    assert payload["received_headers"]["x-internal-tenant-id"] == "tenant-a"


def test_valid_tenant_b_request(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-b.example.local", token="mock:tenant-b:user-777"),
        json=_chat_body(adapter="tenant-b-support"),
    )
    assert response.status_code == 200
    assert response.json()["received_headers"]["external-filter"] == "tenant=tenant-b"


def test_tenant_a_token_sent_to_tenant_b_domain_is_denied(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-b.example.local", token="mock:tenant-a:user-123"),
        json=_chat_body(adapter="tenant-b-support"),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "tenant_claim_mismatch"


def test_forbidden_lora_adapter_is_denied(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local"),
        json=_chat_body(adapter="tenant-b-support"),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "unknown_adapter"


def test_unknown_model_is_denied(client: TestClient) -> None:
    response = client.post(
        "/v1/completions",
        headers=_headers("tenant-a.example.local"),
        json={"model": "unknown/model", "prompt": "hello"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "unknown_model"


def test_spoofed_external_filter_header_is_stripped_and_ignored(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers(
            "tenant-a.example.local",
            **{
                "external-filter": "tenant=tenant-b",
                "user": "tenant-b:evil",
                "x-internal-tenant-id": "tenant-b",
            },
        ),
        json=_chat_body(),
    )
    assert response.status_code == 200
    forwarded = response.json()["received_headers"]
    assert forwarded["external-filter"] == "tenant=tenant-a"
    assert forwarded["user"] == "tenant-a:user-123"
    assert forwarded["x-internal-tenant-id"] == "tenant-a"


def test_missing_token_is_denied(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local", token=None),
        json=_chat_body(),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "missing_token"


def test_metering_event_is_emitted(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="tenant_policy_gateway.metering")
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local"),
        json=_chat_body(),
    )
    assert response.status_code == 200
    metering_records = [record for record in caplog.records if record.name == "tenant_policy_gateway.metering"]
    assert metering_records
    event = json.loads(metering_records[-1].message)
    assert event["request_id"] == "test-request-1"
    assert event["tenant_id"] == "tenant-a"
    assert event["user_id"] == "user-123"
    assert event["decision"] == "allow"
    assert event["upstream_status_code"] == 200
    assert event["estimated_input_tokens"] is not None
    assert event["estimated_input_token_source"] in {"upstream_usage_prompt_tokens_unverified", "deterministic_utf8_byte_upper_bound_local_demo", "tiktoken:cl100k_base"}
    assert event["estimated_input_tokens_billing_grade"] is False


def test_fail_closed_when_tenant_registry_cannot_be_loaded(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"
    settings = AppSettings(
        tenant_registry_path=missing_path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
    )
    with TestClient(create_app(settings)) as test_client:
        ready = test_client.get("/readyz")
        assert ready.status_code == 503
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(),
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "registry_unavailable"


def test_mock_auth_is_rejected_outside_local_by_default(registry_path: Path) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AppSettings(
            tenant_registry_path=registry_path,
            auth_mode=AuthMode.MOCK,
            environment="production",
            mock_upstream=True,
        )
    assert "APP_AUTH_MODE=mock is allowed only" in str(exc_info.value)


def test_explicit_unsafe_override_allows_mock_auth_for_throwaway_demo(registry_path: Path) -> None:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        environment="review-demo",
        unsafe_allow_mock_auth_outside_local=True,
        mock_upstream=True,
    )
    assert settings.auth_mode == AuthMode.MOCK
    assert settings.unsafe_allow_mock_auth_outside_local is True


def test_in_memory_quota_enforces_requests_per_minute(tmp_path: Path) -> None:
    limited_registry = TENANT_REGISTRY.replace("requests_per_minute: 60", "requests_per_minute: 1", 1)
    path = tmp_path / "limited-tenants.yaml"
    path.write_text(limited_registry, encoding="utf-8")
    settings = AppSettings(
        tenant_registry_path=path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        quota_mode=QuotaMode.IN_MEMORY,
    )
    with TestClient(create_app(settings)) as test_client:
        first = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(),
        )
        second = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(),
        )
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "request_quota_exceeded"
    assert "Retry-After" in second.headers


def test_catalog_enforced_adapter_governance_allows_signed_active_adapter(registry_path: Path) -> None:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        adapter_governance_mode=AdapterGovernanceMode.CATALOG_ENFORCED,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(adapter="tenant-a-support"),
        )
    assert response.status_code == 200


def test_catalog_enforced_adapter_governance_denies_adapter_without_catalog(tmp_path: Path) -> None:
    registry_without_catalog = TENANT_REGISTRY.replace("    adapter_artifacts:\n      tenant-a-support:", "    adapter_artifacts: {}\n    unused_adapter_artifacts:\n      tenant-a-support:", 1)
    path = tmp_path / "tenants-no-catalog.yaml"
    path.write_text(registry_without_catalog, encoding="utf-8")
    settings = AppSettings(
        tenant_registry_path=path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        adapter_governance_mode=AdapterGovernanceMode.CATALOG_ENFORCED,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(adapter="tenant-a-support"),
        )
    # extra=forbid makes the malformed registry fail closed before request policy can allow anything.
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "registry_unavailable"



def test_catalog_enforced_adapter_governance_denies_quarantined_adapter(tmp_path: Path) -> None:
    quarantined_registry = TENANT_REGISTRY.replace("status: active", "status: quarantined", 1)
    path = tmp_path / "tenants-quarantined.yaml"
    path.write_text(quarantined_registry, encoding="utf-8")
    settings = AppSettings(
        tenant_registry_path=path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        adapter_governance_mode=AdapterGovernanceMode.CATALOG_ENFORCED,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(adapter="tenant-a-support"),
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "adapter_quarantined"

def test_jsonl_audit_sink_writes_decision_event(registry_path: Path, tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        audit_sink=AuditSinkMode.JSONL,
        audit_log_path=audit_path,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(),
        )
    assert response.status_code == 200
    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    event = json.loads(lines[-1])
    assert event["request_id"] == "test-request-1"
    assert event["decision"] == "allow"
    assert event["security_boundary_claim"] == "gateway_policy_not_downstream_security_boundary"


def test_billing_ledger_required_writes_usage_record(registry_path: Path, tmp_path: Path) -> None:
    ledger_path = tmp_path / "billing-ledger.jsonl"
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        billing_mode=BillingMode.LEDGER_REQUIRED,
        billing_ledger_path=ledger_path,
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json=_chat_body(),
        )
    assert response.status_code == 200
    entries = ledger_path.read_text(encoding="utf-8").strip().splitlines()
    assert entries
    entry = json.loads(entries[-1])
    assert entry["request_id"] == "test-request-1"
    assert entry["prompt_tokens"] == 1
    assert entry["completion_tokens"] == 1
    assert entry["total_tokens"] == 2
    assert entry["billing_grade_reference"] is True


def test_metrics_endpoint_exposes_request_counter(client: TestClient) -> None:
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local"),
        json=_chat_body(),
    )
    assert response.status_code == 200
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "tenant_policy_gateway_requests_total" in metrics.text
    assert 'tenant_id="tenant-a"' in metrics.text


def test_security_posture_enforce_blocks_insecure_production_posture(registry_path: Path) -> None:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.OIDC,
        mock_upstream=True,
        environment="production",
        security_posture_mode=SecurityPostureMode.ENFORCE,
        quota_mode=QuotaMode.DISABLED,
        billing_mode=BillingMode.DISABLED,
        audit_sink=AuditSinkMode.DISABLED,
    )
    with TestClient(create_app(settings)) as test_client:
        ready = test_client.get("/readyz")
        response = test_client.post(
            "/v1/chat/completions",
            headers={"host": "tenant-a.example.local", "x-request-id": "blocked-prod"},
            json=_chat_body(),
        )
    assert ready.status_code == 503
    assert ready.json()["reason"] == "security_posture_blocked"
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "security_posture_blocked"


def test_streaming_request_emits_sse_and_ttft_metrics(client: TestClient) -> None:
    with client.stream(
        "POST",
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local", **{"accept": "text/event-stream"}),
        json={**_chat_body(), "stream": True},
    ) as response:
        body = "".join(response.iter_text())
    assert response.status_code == 200
    assert "data:" in body
    assert "[DONE]" in body
    metrics = client.get("/metrics")
    assert "tenant_policy_gateway_ttft_ms_count" in metrics.text
    assert "tenant_policy_gateway_stream_completion_token_hints_total" in metrics.text


def test_oidc_claim_hardening_rejects_wrong_token_use(registry_path: Path) -> None:
    from tenant_policy_gateway.jwt_validation import AuthError, _enforce_required_oidc_claims
    from tenant_policy_gateway.tenant_registry import TenantRegistry

    registry = TenantRegistry.load(registry_path)
    tenant = registry.tenants_by_id["tenant-a"]
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.OIDC,
        oidc_required_token_use="id",
    )
    with pytest.raises(AuthError) as exc_info:
        _enforce_required_oidc_claims(
            claims={"token_use": "access", tenant.tenant_claim: "tenant-a"},
            tenant=tenant,
            settings=settings,
        )
    assert exc_info.value.reason == "invalid_token_use"


def test_oidc_claim_hardening_accepts_required_scope_and_group(registry_path: Path) -> None:
    from tenant_policy_gateway.jwt_validation import _enforce_required_oidc_claims
    from tenant_policy_gateway.tenant_registry import TenantRegistry

    registry = TenantRegistry.load(registry_path)
    tenant = registry.tenants_by_id["tenant-a"]
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.OIDC,
        oidc_required_token_use="id",
        oidc_required_scopes=["gateway.invoke"],
        oidc_required_groups=["tenant-a-users"],
    )
    _enforce_required_oidc_claims(
        claims={
            "token_use": "id",
            "scope": "openid gateway.invoke",
            "cognito:groups": ["tenant-a-users"],
            tenant.tenant_claim: "tenant-a",
        },
        tenant=tenant,
        settings=settings,
    )


def test_security_posture_enforce_blocks_in_memory_quota_in_production(registry_path: Path) -> None:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.OIDC,
        mock_upstream=False,
        environment="production",
        upstream_base_url="http://aibrix.envoy-gateway-system.svc.cluster.local",
        security_posture_mode=SecurityPostureMode.ENFORCE,
        quota_mode=QuotaMode.IN_MEMORY,
        billing_mode=BillingMode.OBSERVABILITY,
        audit_sink=AuditSinkMode.STDOUT,
        adapter_governance_mode=AdapterGovernanceMode.CATALOG_ENFORCED,
    )
    with TestClient(create_app(settings)) as test_client:
        ready = test_client.get("/readyz")
    assert ready.status_code == 503
    assert "quota_in_memory_not_distributed" in ready.json()["findings"]


def test_adapter_artifact_verifier_checks_local_sha256(tmp_path: Path) -> None:
    from hashlib import sha256
    from tenant_policy_gateway.adapter_artifact_verifier import verify_adapter_artifact
    from tenant_policy_gateway.tenant_registry import AdapterArtifactPolicy

    artifact = tmp_path / "adapter.safetensors"
    artifact.write_bytes(b"adapter-bytes")
    digest = sha256(b"adapter-bytes").hexdigest()
    policy = AdapterArtifactPolicy(
        artifact_uri=str(artifact),
        sha256=digest,
        signed_by="kms-key-alias/reference",
        compatible_models=["meta-llama/Llama-3.1-8B-Instruct"],
    )
    result = verify_adapter_artifact(policy)
    assert result.ok is True
    assert result.reason == "sha256_match"


def test_aws_native_billing_mode_requires_bucket(registry_path: Path) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AppSettings(
            tenant_registry_path=registry_path,
            auth_mode=AuthMode.OIDC,
            billing_mode=BillingMode.AWS_NATIVE_REFERENCE,
        )
    assert "APP_AWS_BILLING_S3_BUCKET" in str(exc_info.value)


def test_streaming_is_denied_when_billing_requires_usage(registry_path: Path, tmp_path: Path) -> None:
    settings = AppSettings(
        tenant_registry_path=registry_path,
        auth_mode=AuthMode.MOCK,
        mock_upstream=True,
        billing_mode=BillingMode.LEDGER_REQUIRED,
        billing_ledger_path=tmp_path / "ledger.jsonl",
    )
    with TestClient(create_app(settings)) as test_client:
        response = test_client.post(
            "/v1/chat/completions",
            headers=_headers("tenant-a.example.local"),
            json={**_chat_body(), "stream": True},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "streaming_billing_not_supported"


def test_redis_quota_enforcer_uses_atomic_lua_scripts() -> None:
    source = Path("src/tenant_policy_gateway/quota_enforcer.py").read_text(encoding="utf-8")
    assert "_REDIS_CHECK_AND_RECORD_LUA" in source
    assert "tenant_concurrency_quota_exceeded" in source
    assert "evalsha" in source
    assert "ZADD" in source
    assert "ZREMRANGEBYSCORE" in source
    assert "fixed window" not in source.lower()


def test_aws_native_billing_uses_boto3_and_dynamodb_idempotency(tmp_path: Path) -> None:
    from tenant_policy_gateway.billing_ledger import BillingLedger, UsageTokens

    class FakeS3:
        def __init__(self) -> None:
            self.objects = []
        def put_object(self, **kwargs):
            self.objects.append(kwargs)
            return {}

    class FakeDynamo:
        def __init__(self) -> None:
            self.items = []
            self.updates = []
        def put_item(self, **kwargs):
            self.items.append(kwargs)
            return {}
        def update_item(self, **kwargs):
            self.updates.append(kwargs)
            return {}

    ledger = BillingLedger(
        mode=BillingMode.AWS_NATIVE_REFERENCE,
        aws_s3_bucket="billing-bucket",
        aws_s3_prefix="billing-ledger/",
        aws_dynamodb_table="billing-idempotency",
        aws_region="eu-west-1",
    )
    fake_s3 = FakeS3()
    fake_dynamo = FakeDynamo()
    ledger._s3_client = fake_s3
    ledger._dynamodb_client = fake_dynamo
    usage = UsageTokens(prompt_tokens=1, completion_tokens=2, total_tokens=3, source="upstream_usage_required")
    ledger.append(request_id="req-1", tenant_id="tenant-a", user_id="u", model="m", adapter=None, usage=usage)
    ledger.append(request_id="req-1", tenant_id="tenant-a", user_id="u", model="m", adapter=None, usage=usage)
    ledger.flush()
    assert len(fake_dynamo.items) == 1
    assert len(fake_dynamo.updates) == 1
    assert len(fake_s3.objects) == 1
    assert fake_s3.objects[0]["Bucket"] == "billing-bucket"


def test_unknown_vendor_adapter_field_is_rejected(client: TestClient) -> None:
    body = _chat_body(adapter=None)
    body["adapter"] = "tenant-a-support"
    response = client.post(
        "/v1/chat/completions",
        headers=_headers("tenant-a.example.local"),
        json=body,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request_schema"


def test_deterministic_token_estimator_does_not_use_chars_div_4() -> None:
    from tenant_policy_gateway.metering import estimate_input_tokens, initialize_tokenizer
    from tenant_policy_gateway.config import AppSettings

    initialize_tokenizer(AppSettings())
    estimate = estimate_input_tokens({"model": "m", "prompt": "éééé"})
    assert estimate is not None
    assert estimate.source == "deterministic_utf8_byte_upper_bound_local_demo"
    assert estimate.value == len("éééé".encode("utf-8"))


def test_billing_lru_is_bounded(tmp_path: Path) -> None:
    from tenant_policy_gateway.billing_ledger import BillingLedger, UsageTokens

    ledger = BillingLedger(
        mode=BillingMode.LEDGER_REQUIRED,
        jsonl_path=tmp_path / "ledger.jsonl",
        lru_max_request_ids=3,
        batch_max_records=10,
        flush_interval_seconds=100,
    )
    usage = UsageTokens(prompt_tokens=1, completion_tokens=1, total_tokens=2, source="upstream_usage_required")
    for idx in range(5):
        ledger.append(request_id=f"req-{idx}", tenant_id="tenant-a", user_id="u", model="m", adapter=None, usage=usage)
    assert len(ledger._seen_request_ids) == 3
    ledger.close()
