# Eval Prompt — Repository Review

Evaluate the `aibrix-multitenant-llm-gateway` repository as if you are an enterprise LLMOps, Kubernetes, AWS EKS, and security review board.

## Required checks

1. Does the gateway fail closed if tenant config is missing or invalid?
2. Are client-supplied routing headers stripped before proxying?
3. Are trusted routing headers injected only after policy allow?
4. Does Host domain map to exactly one tenant?
5. Does JWT tenant claim have to match the resolved tenant?
6. Are unknown tenants denied?
7. Are missing/invalid tokens denied with 401?
8. Are unknown models denied?
9. Are forbidden LoRA adapters denied?
10. Are logs structured and free of full Authorization tokens?
11. Is mock auth clearly documented as local-only?
12. Is AIBrix/vLLM described as serving substrate, not auth boundary?
13. Are Kubernetes manifests minimal, clear, and honest about being examples?
14. Are AWS/EKS gaps and guardrails documented?
15. Are limitations explicit and not hidden?

## Score dimensions

- Correctness of policy enforcement.
- Security clarity and fail-closed behavior.
- Local runnable MVP quality.
- Test coverage.
- Kubernetes manifest clarity.
- AWS/EKS realism.
- Observability usefulness.
- Honesty of limitations.

## Required output

- Overall score from 1 to 10.
- Must-fix issues.
- Should-fix issues.
- Production gaps.
- Best parts of the repo.
- Final self-roast.
