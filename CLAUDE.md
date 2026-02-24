# Agent-Safe — Development Conventions

## Project Overview
Agent-Safe is an open-source governance/control layer for AI agents and non-human identities (NHIs).
It is NOT an agent. It is the system that restricts and governs what agents are allowed to do.

Core product: A policy decision sidecar — Action Registry + Policy Decision Point (PDP) + Audit Log + Execution Tickets + Rate Limiting + Approval Workflows + Credential Gating + Multi-Agent Delegation + Cumulative Risk Scoring + Ticket/Incident Linkage + Before/After State Capture + Rollback Pairing + Runner/Executor (DryRun, Subprocess, K8s, AWS) + SDK/CLI.

## Key Decisions (Locked)
- **Deployment**: Sidecar / library (runs in customer's environment, no cloud dependency)
- **Target environment**: Kubernetes first + AWS (K8s actions + 13 AWS actions across EC2, ECS, Lambda, S3, IAM)
- **Enforcement model**: Advisory + ticket-based. PDP returns ALLOW/DENY/REQUIRE_APPROVAL. ALLOW decisions include signed execution tickets. Rate limiting + circuit breaker protect against misbehaving agents. Cumulative risk scoring escalates decisions when action chaining accumulates too much risk.
- **GTM**: Open-source core (Apache 2.0), future paid tier (hosted dashboard, enterprise features)
- **Tech stack**: Python (most agent frameworks are Python)
- **License**: Apache 2.0

## Architecture (Phase 2 — Current)
```
Agent → SDK → Rate Limiter → PDP → Policy Decision
                                         │
                                         ▼
                                  Risk Tracker (post-policy escalation)
                                    ├─ ALLOW + signed Execution Ticket
                                    │    ├──→ Credential Resolver (JIT vault)
                                    │    └──→ Delegation (chain in JWT)
                                    ├─ REQUIRE_APPROVAL → Approval Store
                                    └─ Cumulative risk context in audit
                                         │
                                         ▼
                                   Audit Logger → Local file (source of truth)
                                         ├──→ FilesystemShipper (backup file)
                                         ├──→ WebhookShipper (SIEM/log aggregator)
                                         └──→ S3Shipper (immutable storage)
```
Agents execute actions themselves. Agent-Safe decides, issues tickets, manages credentials, handles approvals, tracks cumulative risk, and logs. Delegation chains tracked in JWT (stateless PDP preserved).

## Code Conventions
- Python 3.11+
- Use `pyproject.toml` for project config (no setup.py)
- Formatter: `ruff format`
- Linter: `ruff check`
- Type hints on all public APIs
- Tests: `pytest`, aim for >80% coverage on PDP logic
- Docstrings only on public API functions (not internal helpers)
- Keep dependencies minimal — stdlib where possible

## File Structure
```
agent-safe/
├── CLAUDE.md
├── README.md
├── CHANGELOG.md
├── LICENSE
├── pyproject.toml
├── src/
│   └── agent_safe/
│       ├── __init__.py
│       ├── registry/       # Action Registry loader, validator
│       ├── pdp/            # Policy Decision Point
│       ├── audit/          # Audit logging + external shippers
│       │   ├── logger.py   # Hash-chained JSONL logger
│       │   └── shipper.py  # AuditShipper protocol + backends
│       ├── inventory/      # Target inventory
│       ├── identity/       # Agent identity (JWT) + delegation
│       ├── tickets/        # Execution ticket issuer + validator
│       ├── ratelimit/      # Per-caller rate limiting + circuit breaker
│       ├── credentials/    # Credential vault protocol + resolver
│       ├── approval/       # Approval workflows (store + notifiers)
│       ├── runner/         # Runner/Executor framework
│       │   ├── runner.py        # Runner orchestrator
│       │   ├── executor.py      # Executor protocol + DryRunExecutor
│       │   ├── subprocess_executor.py  # SubprocessExecutor (kubectl)
│       │   ├── k8s_executor.py  # K8sExecutor (kubernetes Python client)
│       │   └── aws_executor.py  # AwsExecutor (boto3)
│       ├── sdk/            # Public SDK interface (AgentSafe class)
│       └── cli/            # CLI entry point
├── actions/                # YAML action definitions (K8s + AWS)
├── policies/               # Policy definitions
├── tests/
├── docs/
│   ├── MVP-PLAN.md
│   ├── ROADMAP.md
│   ├── ARCHITECTURE.md
│   ├── FUTURE-BACKLOG.md
│   ├── THREAT-MODEL.md
│   ├── CREDENTIAL-SCOPING.md
│   ├── GETTING-STARTED.md
│   └── WRITING-ACTIONS.md / WRITING-POLICIES.md
└── examples/
```

## Key Principles
1. **No raw shell execution** — actions are declared, validated, policy-checked
2. **Audit everything** — every request, every decision, every reason
3. **Policy is context-aware** — risk = f(action, target, caller, time, state), not just action type
4. **Sidecar, not SaaS** — decisions and data stay in the customer's environment
5. **Advisory before enforced** — log and decide now, gate credentials later

## What NOT to Build Yet (Phase 2.5 and beyond)
- No cloud infrastructure (sidecar/library only)
- No dashboard (Phase 2.5)
- No agent supervisor (separate product decision)

## Documentation
- `docs/MVP-PLAN.md` — 6–8 week detailed build plan (Phase 1)
- `docs/ROADMAP.md` — Full multi-phase roadmap (Phase 1 ✅, Phase 1.5 ✅, Phase 2.1 ✅, Phase 2 ✅)
- `docs/ARCHITECTURE.md` — Architecture decisions and diagrams
- `docs/GETTING-STARTED.md` — Installation, quick start, SDK usage, all features
- `docs/CREDENTIAL-SCOPING.md` — Vault-based credential gating design (implemented)
- `docs/FUTURE-BACKLOG.md` — Cut items and future ideas (parking lot)
- `docs/THREAT-MODEL.md` — Threat model and abuse cases (16 threats catalogued)
