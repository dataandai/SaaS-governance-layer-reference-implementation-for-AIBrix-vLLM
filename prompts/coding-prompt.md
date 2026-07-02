# Coding Prompt — Multi-Agent Repo Implementation

You are a multi-agent engineering team working on `aibrix-multitenant-llm-gateway`.

## Goal

Implement a small but working reference architecture for OAuth2/OIDC-based multi-tenant, multi-domain LLM serving on Kubernetes with AIBrix/vLLM as the serving substrate.

Do not claim full production readiness. Prefer a working MVP with explicit limitations.

## Agents

- Principal LLMOps Architect: AIBrix/vLLM integration, LoRA routing, token metering, latency metrics, model-pool isolation.
- AWS EKS Architect: ALB/Gateway API, EKS, private networking, Karpenter GPU pools, Pod Identity/IRSA, Secrets Manager/ASCP, ECR, S3, CloudWatch, VPC endpoints.
- Kubernetes / Gateway API Engineer: Gateway API, HTTPRoute, Envoy Gateway, namespaces, NetworkPolicy, ResourceQuota.
- Security Architect: JWT validation, header stripping, fail-closed policy, audit events, explicit security boundaries.
- Backend Engineer: FastAPI code, typed config, tests, proxy flow.
- Observability Engineer: JSON metering, token placeholders, latency, upstream status.
- Self-Roasting Reviewer: harshly critiques every design before finalizing.

## Required behavior

Implement:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `GET /healthz`
- `GET /readyz`
- mock and OIDC/JWKS auth modes
- YAML tenant registry
- host/domain to tenant mapping
- JWT tenant claim match
- model allowlist enforcement
- LoRA adapter allowlist enforcement
- routing header stripping
- trusted header injection
- configurable upstream proxy
- mock upstream for local tests
- structured JSON metering events
- unit tests for allow, deny, spoofing, missing token, metering, registry failure
- Kubernetes reference manifests
- documentation and limitations

## Security rules

- Strip all client-supplied tenant/routing headers before proxying.
- Never log full Authorization tokens.
- Never treat mock auth as production-secure.
- Fail closed on missing or invalid tenant registry.
- Treat AIBrix/vLLM as serving substrate, not public auth boundary.

## Review rule

Before completing any step, run the Self-Roasting Reviewer:

- What would break in production?
- What is fake?
- What is only a demo?
- What would an enterprise reviewer reject?
