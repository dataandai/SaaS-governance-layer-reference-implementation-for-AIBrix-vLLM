from __future__ import annotations

from contextlib import asynccontextmanager
import logging
import time
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from .adapter_governance import evaluate_adapter_governance
from .audit import AuditSink, audit_event_from_metering
from .billing_ledger import BillingLedger, BillingLedgerError
from .config import AppSettings, AuthMode, BillingMode, get_settings
from .header_sanitizer import (
    inject_trusted_headers,
    routing_headers_were_supplied,
    sanitize_inbound_headers,
)
from .jwt_validation import AuthError, AuthenticatedPrincipal, validate_request_auth
from .metering import (
    MeteringEvent,
    TokenEstimate,
    emit_metering_event,
    estimate_input_tokens,
    initialize_tokenizer,
    estimate_input_tokens_from_upstream,
    estimate_output_tokens,
)
from .policy_engine import InvalidRequestError, PolicyDecision, evaluate_policy, parse_gateway_request_body
from .proxy import forward_to_upstream, open_upstream_stream
from .quota_enforcer import QuotaEnforcer, create_quota_enforcer
from .security_posture import emit_security_posture, enforce_security_posture, evaluate_security_posture
from .slo_metrics import SloMetrics
from .tenant_registry import RegistryLoadError, TenantRegistry

LOG = logging.getLogger("tenant_policy_gateway")


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level.upper(), format="%(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: AppSettings = app.state.settings
    configure_logging(settings.log_level)

    findings = evaluate_security_posture(settings)
    emit_security_posture(findings)
    app.state.security_posture_block = enforce_security_posture(settings, findings)
    app.state.audit_sink = AuditSink(mode=settings.audit_sink, jsonl_path=settings.audit_log_path)
    app.state.slo_metrics = SloMetrics()

    if app.state.security_posture_block:
        # In enforce mode, fail readiness and requests without initializing
        # expensive/runtime-sensitive dependencies such as production tokenizers,
        # Redis, or AWS ledger clients. This preserves a useful /readyz finding.
        app.state.quota_enforcer = None
        app.state.billing_ledger = BillingLedger(mode=BillingMode.DISABLED)
    else:
        initialize_tokenizer(settings)
        app.state.quota_enforcer = create_quota_enforcer(settings)
        app.state.billing_ledger = BillingLedger(
            mode=settings.billing_mode,
            jsonl_path=settings.billing_ledger_path,
            aws_s3_bucket=settings.aws_billing_s3_bucket,
            aws_s3_prefix=settings.aws_billing_s3_prefix,
            aws_dynamodb_table=settings.aws_billing_dynamodb_table,
            aws_region=settings.aws_region,
            batch_max_records=settings.billing_batch_max_records,
            flush_interval_seconds=settings.billing_flush_interval_seconds,
            queue_max_records=settings.billing_queue_max_records,
            lru_max_request_ids=settings.billing_lru_max_request_ids,
        )

    if settings.auth_mode == AuthMode.MOCK:
        LOG.warning(
            '{"event":"mock_auth_enabled","environment":"%s","production_secure":false}',
            settings.environment.replace('"', "'"),
        )
    try:
        app.state.registry = TenantRegistry.load(settings.tenant_registry_path)
        app.state.registry_error = None
        LOG.info(
            '{"event":"registry_loaded","path":"%s","tenants":%d}',
            settings.tenant_registry_path,
            len(app.state.registry.tenants_by_id),
        )
    except RegistryLoadError as exc:
        app.state.registry = None
        app.state.registry_error = str(exc)
        LOG.error('{"event":"registry_load_failed","reason":"%s"}', str(exc).replace('"', "'"))
    try:
        yield
    finally:
        ledger = getattr(app.state, "billing_ledger", None)
        if ledger is not None:
            ledger.close()


def create_app(settings: AppSettings | None = None, registry: TenantRegistry | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    app = FastAPI(title="AIBrix Multitenant Tenant Policy Gateway", version="0.3.0", lifespan=lifespan)
    app.state.settings = resolved_settings
    if registry is not None:
        app.state.registry = registry
        app.state.registry_error = None

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        posture_block = getattr(app.state, "security_posture_block", None)
        if posture_block:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "security_posture_blocked", "findings": posture_block},
            )
        if getattr(app.state, "registry", None) is None:
            return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "registry_unavailable"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    @app.get("/metrics")
    async def metrics() -> Response:
        settings: AppSettings = app.state.settings
        if not settings.metrics_enabled:
            return JSONResponse(status_code=404, content={"error": "metrics_disabled"})
        collector: SloMetrics = app.state.slo_metrics
        return PlainTextResponse(collector.prometheus_text(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        return await _handle_llm_request(request=request, upstream_path="/v1/chat/completions")

    @app.post("/v1/completions")
    async def completions(request: Request) -> Response:
        return await _handle_llm_request(request=request, upstream_path="/v1/completions")

    async def _handle_llm_request(request: Request, upstream_path: str) -> Response:
        start = time.perf_counter()
        request_id = request.headers.get("x-request-id") or str(uuid4())
        settings: AppSettings = app.state.settings
        registry: TenantRegistry | None = getattr(app.state, "registry", None)
        domain = request.headers.get("host")

        posture_block = getattr(app.state, "security_posture_block", None)
        if posture_block:
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=PolicyDecision(False, 503, "security_posture_blocked"),
                domain=domain,
                response_body={"error": {"code": "security_posture_blocked", "message": posture_block}},
                input_token_estimate=None,
            )

        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise ValueError("JSON body must be an object")
        except Exception:
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=PolicyDecision(False, 400, "invalid_json"),
                domain=domain,
                response_body={"error": {"code": "invalid_json", "message": "JSON body must be an object"}},
                input_token_estimate=None,
            )

        try:
            parsed_request = parse_gateway_request_body(domain=domain, request_body=body, upstream_path=upstream_path)
            attributes = parsed_request.attributes
            body = parsed_request.body
        except InvalidRequestError as exc:
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=PolicyDecision(False, 400, exc.reason),
                domain=domain,
                response_body={"error": {"code": exc.reason, "message": exc.details}},
                input_token_estimate=None,
            )
        tenant = registry.resolve_by_host(domain) if registry else None
        principal: AuthenticatedPrincipal | None = None
        auth_error_reason: str | None = None
        if tenant is not None:
            try:
                principal = validate_request_auth(
                    authorization=request.headers.get("authorization"),
                    mock_auth_header=request.headers.get("x-mock-auth"),
                    tenant=tenant,
                    settings=settings,
                )
            except AuthError as exc:
                auth_error_reason = exc.reason

        decision = evaluate_policy(registry=registry, attributes=attributes, principal=principal, auth_error_reason=auth_error_reason)
        input_token_estimate = estimate_input_tokens(body)
        if not decision.allowed:
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=decision,
                domain=domain,
                response_body={"error": {"code": decision.reason, "message": decision.reason}},
                input_token_estimate=input_token_estimate,
            )

        assert decision.tenant is not None
        assert decision.tenant_id is not None
        assert decision.user_id is not None
        assert decision.model is not None

        adapter_decision = evaluate_adapter_governance(
            tenant=decision.tenant,
            model=decision.model,
            adapter=decision.adapter,
            mode=settings.adapter_governance_mode,
        )
        if not adapter_decision.allowed:
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=PolicyDecision(
                    False,
                    adapter_decision.status_code,
                    adapter_decision.reason,
                    tenant=decision.tenant,
                    tenant_id=decision.tenant_id,
                    user_id=decision.user_id,
                    model=decision.model,
                    adapter=decision.adapter,
                ),
                domain=domain,
                response_body={"error": {"code": adapter_decision.reason, "message": adapter_decision.reason}},
                input_token_estimate=input_token_estimate,
            )

        if _streaming_billing_is_blocked(settings=settings, body=body):
            return _emit_and_respond(
                request_id=request_id,
                start=start,
                decision=PolicyDecision(
                    False,
                    400,
                    "streaming_billing_not_supported",
                    tenant=decision.tenant,
                    tenant_id=decision.tenant_id,
                    user_id=decision.user_id,
                    model=decision.model,
                    adapter=decision.adapter,
                ),
                domain=domain,
                response_body={
                    "error": {
                        "code": "streaming_billing_not_supported",
                        "message": "Streaming is disabled when billing mode requires upstream usage tokens.",
                    }
                },
                input_token_estimate=input_token_estimate,
            )

        quota_enforcer: QuotaEnforcer | None = app.state.quota_enforcer
        quota_recorded = False
        if quota_enforcer is not None:
            quota_decision = quota_enforcer.check_and_record(
                tenant_id=decision.tenant_id,
                user_id=decision.user_id,
                limits=decision.tenant.limits,
                estimated_input_tokens=input_token_estimate.value if input_token_estimate else None,
                request_id=request_id,
            )
            if not quota_decision.allowed:
                headers = {}
                if quota_decision.retry_after_seconds is not None:
                    headers["Retry-After"] = str(quota_decision.retry_after_seconds)
                return _emit_and_respond(
                    request_id=request_id,
                    start=start,
                    decision=PolicyDecision(
                        False,
                        quota_decision.status_code,
                        quota_decision.reason,
                        tenant=decision.tenant,
                        tenant_id=decision.tenant_id,
                        user_id=decision.user_id,
                        model=decision.model,
                        adapter=decision.adapter,
                    ),
                    domain=domain,
                    response_body={"error": {"code": quota_decision.reason, "message": quota_decision.reason}},
                    input_token_estimate=input_token_estimate,
                    headers=headers,
                )
            quota_recorded = True

        outbound_headers = _build_outbound_headers(request=request, decision=decision, request_id=request_id)

        if bool(body.get("stream")):
            return await _streaming_response(
                request_id=request_id,
                start=start,
                decision=decision,
                domain=domain,
                body=body,
                upstream_path=upstream_path,
                outbound_headers=outbound_headers,
                input_token_estimate=input_token_estimate,
                quota_recorded=quota_recorded,
            )

        try:
            upstream = await forward_to_upstream(path=upstream_path, body=body, headers=outbound_headers, settings=settings)
        finally:
            if quota_recorded and quota_enforcer is not None:
                quota_enforcer.finish_request(tenant_id=decision.tenant_id, user_id=decision.user_id, request_id=request_id)

        ledger: BillingLedger = app.state.billing_ledger
        ledger_usage = ledger.require_usage_tokens(upstream.body)
        if settings.billing_mode in {BillingMode.LEDGER_REQUIRED, BillingMode.AWS_NATIVE_REFERENCE}:
            if ledger_usage is None:
                return _emit_and_respond(
                    request_id=request_id,
                    start=start,
                    decision=PolicyDecision(
                        False,
                        502,
                        "billing_usage_missing",
                        tenant=decision.tenant,
                        tenant_id=decision.tenant_id,
                        user_id=decision.user_id,
                        model=decision.model,
                        adapter=decision.adapter,
                    ),
                    domain=domain,
                    response_body={
                        "error": {
                            "code": "billing_usage_missing",
                            "message": "Upstream response did not include required usage tokens",
                        }
                    },
                    input_token_estimate=input_token_estimate,
                    upstream_status_code=upstream.status_code,
                )
            try:
                ledger.append(
                    request_id=request_id,
                    tenant_id=decision.tenant_id,
                    user_id=decision.user_id,
                    model=decision.model,
                    adapter=decision.adapter,
                    usage=ledger_usage,
                )
            except BillingLedgerError as exc:
                return _emit_and_respond(
                    request_id=request_id,
                    start=start,
                    decision=PolicyDecision(
                        False,
                        503,
                        str(exc),
                        tenant=decision.tenant,
                        tenant_id=decision.tenant_id,
                        user_id=decision.user_id,
                        model=decision.model,
                        adapter=decision.adapter,
                    ),
                    domain=domain,
                    response_body={"error": {"code": str(exc), "message": str(exc)}},
                    input_token_estimate=input_token_estimate,
                    upstream_status_code=upstream.status_code,
                )

        upstream_input_estimate = estimate_input_tokens_from_upstream(upstream.body)
        output_token_estimate = estimate_output_tokens(upstream.body)
        latency_ms = round((time.perf_counter() - start) * 1000, 3)
        _emit_observability(
            MeteringEvent(
                request_id=request_id,
                tenant_id=decision.tenant_id,
                user_id=decision.user_id,
                domain=domain,
                model=decision.model,
                adapter=decision.adapter,
                decision="allow",
                status_code=upstream.status_code,
                reason=decision.reason,
                latency_ms=latency_ms,
                estimated_input_tokens=(upstream_input_estimate or input_token_estimate).value
                if (upstream_input_estimate or input_token_estimate)
                else None,
                estimated_input_token_source=(upstream_input_estimate or input_token_estimate).source
                if (upstream_input_estimate or input_token_estimate)
                else None,
                estimated_input_tokens_billing_grade=False,
                estimated_output_tokens=output_token_estimate.value if output_token_estimate else None,
                estimated_output_token_source=output_token_estimate.source if output_token_estimate else None,
                estimated_output_tokens_billing_grade=False,
                upstream_status_code=upstream.status_code,
            )
        )
        return JSONResponse(status_code=upstream.status_code, content=upstream.body)

    def _build_outbound_headers(*, request: Request, decision: PolicyDecision, request_id: str) -> dict[str, str]:
        assert decision.tenant is not None
        assert decision.tenant_id is not None
        assert decision.user_id is not None
        sanitized_headers = sanitize_inbound_headers(request.headers)
        trusted_user = decision.tenant.user_header_template.format(tenant_id=decision.tenant_id, user_id=decision.user_id)
        trusted_external_filter = decision.tenant.routing_external_filter.format(tenant_id=decision.tenant_id)
        outbound_headers = inject_trusted_headers(
            headers=sanitized_headers,
            tenant_id=decision.tenant_id,
            user_id=decision.user_id,
            user_header_value=trusted_user,
            external_filter=trusted_external_filter,
            config_profile=decision.tenant.config_profile,
        )
        outbound_headers["x-request-id"] = request_id
        outbound_headers["x-internal-kv-cache-isolation-required"] = str(
            decision.tenant.runtime_isolation.kv_cache_isolation_required
        ).lower()
        outbound_headers["x-internal-runtime-isolation-mode"] = decision.tenant.runtime_isolation.mode
        if routing_headers_were_supplied(request.headers):
            LOG.info(
                '{"event":"spoofable_routing_headers_stripped","request_id":"%s","tenant_id":"%s"}',
                request_id,
                decision.tenant_id,
            )
        return outbound_headers

    async def _streaming_response(
        *,
        request_id: str,
        start: float,
        decision: PolicyDecision,
        domain: str | None,
        body: dict[str, Any],
        upstream_path: str,
        outbound_headers: dict[str, str],
        input_token_estimate: TokenEstimate | None,
        quota_recorded: bool,
    ) -> StreamingResponse:
        settings: AppSettings = app.state.settings
        upstream_stream = await open_upstream_stream(
            path=upstream_path,
            body=body,
            headers=outbound_headers,
            settings=settings,
        )

        async def iterator():
            first_token_ms: float | None = None
            token_hint_total = 0
            try:
                async for chunk in upstream_stream.chunks:
                    if chunk.is_first_token and first_token_ms is None:
                        first_token_ms = round((time.perf_counter() - start) * 1000, 3)
                    token_hint_total += chunk.token_count_hint
                    yield chunk.data
            finally:
                quota_enforcer: QuotaEnforcer | None = app.state.quota_enforcer
                if quota_recorded and quota_enforcer is not None:
                    quota_enforcer.finish_request(tenant_id=decision.tenant_id, user_id=decision.user_id, request_id=request_id)
                latency_ms = round((time.perf_counter() - start) * 1000, 3)
                metrics: SloMetrics = app.state.slo_metrics
                metrics.record_stream(tenant_id=decision.tenant_id, ttft_ms=first_token_ms, token_count_hint=token_hint_total)
                _emit_observability(
                    MeteringEvent(
                        request_id=request_id,
                        tenant_id=decision.tenant_id,
                        user_id=decision.user_id,
                        domain=domain,
                        model=decision.model,
                        adapter=decision.adapter,
                        decision="allow" if upstream_stream.status_code < 400 else "deny",
                        status_code=upstream_stream.status_code,
                        reason="stream_allowed" if upstream_stream.status_code < 400 else "upstream_stream_error",
                        latency_ms=latency_ms,
                        estimated_input_tokens=input_token_estimate.value if input_token_estimate else None,
                        estimated_input_token_source=input_token_estimate.source if input_token_estimate else None,
                        estimated_input_tokens_billing_grade=False,
                        estimated_output_tokens=token_hint_total or None,
                        estimated_output_token_source="stream_token_hint_not_billing_grade" if token_hint_total else None,
                        estimated_output_tokens_billing_grade=False,
                        upstream_status_code=upstream_stream.status_code,
                    )
                )
                LOG.info(
                    '{"event":"stream_completed","request_id":"%s","tenant_id":"%s","status_code":%d,"ttft_ms":%s,"token_hint_total":%d}',
                    request_id,
                    decision.tenant_id,
                    upstream_stream.status_code,
                    "null" if first_token_ms is None else first_token_ms,
                    token_hint_total,
                )

        return StreamingResponse(
            iterator(),
            status_code=upstream_stream.status_code,
            media_type=upstream_stream.headers.get("content-type", "text/event-stream"),
            headers={"x-request-id": request_id},
        )

    def _streaming_billing_is_blocked(*, settings: AppSettings, body: dict[str, Any]) -> bool:
        if not bool(body.get("stream")):
            return False
        if settings.allow_streaming_without_billing_usage:
            return False
        return settings.billing_mode in {BillingMode.LEDGER_REQUIRED, BillingMode.AWS_NATIVE_REFERENCE}

    def _emit_and_respond(
        *,
        request_id: str,
        start: float,
        decision: PolicyDecision,
        domain: str | None,
        response_body: dict[str, Any],
        input_token_estimate: TokenEstimate | None,
        headers: dict[str, str] | None = None,
        upstream_status_code: int | None = None,
    ) -> JSONResponse:
        latency_ms = round((time.perf_counter() - start) * 1000, 3)
        _emit_observability(
            MeteringEvent(
                request_id=request_id,
                tenant_id=decision.tenant_id,
                user_id=decision.user_id,
                domain=domain,
                model=decision.model,
                adapter=decision.adapter,
                decision="allow" if decision.allowed else "deny",
                status_code=decision.status_code,
                reason=decision.reason,
                latency_ms=latency_ms,
                estimated_input_tokens=input_token_estimate.value if input_token_estimate else None,
                estimated_input_token_source=input_token_estimate.source if input_token_estimate else None,
                estimated_input_tokens_billing_grade=False,
                estimated_output_tokens=None,
                estimated_output_token_source=None,
                estimated_output_tokens_billing_grade=False,
                upstream_status_code=upstream_status_code,
            )
        )
        return JSONResponse(status_code=decision.status_code, content=response_body, headers=headers)

    def _emit_observability(event: MeteringEvent) -> None:
        settings: AppSettings = app.state.settings
        emit_metering_event(event)
        audit_sink: AuditSink = app.state.audit_sink
        audit_sink.emit(
            audit_event_from_metering(
                request_id=event.request_id,
                tenant_id=event.tenant_id,
                user_id=event.user_id,
                domain=event.domain,
                model=event.model,
                adapter=event.adapter,
                decision=event.decision,
                status_code=event.status_code,
                reason=event.reason,
                auth_mode=settings.auth_mode.value,
                quota_mode=settings.quota_mode.value,
                adapter_governance_mode=settings.adapter_governance_mode.value,
                billing_mode=settings.billing_mode.value,
                upstream_status_code=event.upstream_status_code,
            )
        )
        metrics: SloMetrics = app.state.slo_metrics
        metrics.record(
            tenant_id=event.tenant_id,
            decision=event.decision,
            reason=event.reason,
            latency_ms=event.latency_ms,
            upstream_status_code=event.upstream_status_code,
        )

    return app


app = create_app()
