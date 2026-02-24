# Agent-Safe — Development Conventions

## Project Overview
Agent-Safe is an open-source governance/control layer for AI agents and non-human identities (NHIs).
It is NOT an agent. It is the system that restricts and governs what agents are allowed to do.

Core product: A policy decision sidecar — Action Registry + Policy Decision Point (PDP) + Audit Log + Execution Tickets + Rate Limiting + SDK/CLI.

## Key Decisions (Locked)
- **Deployment**: Sidecar / library (runs in customer's environment, no cloud dependency)
- **Target environment**: Kubernetes first (all action catalogues scoped to K8s API)
- **Enforcement model**: Advisory + ticket-based. PDP returns ALLOW/DENY/REQUIRE_APPROVAL. ALLOW decisions include signed execution tickets. Rate limiting + circuit breaker protect against misbehaving agents.
- **GTM**: Open-source core (Apache 2.0), future paid tier (hosted dashboard, enterprise features)
- **Tech stack**: Python (most agent frameworks are Python)
- **License**: Apache 2.0

## Architecture (Phase 1.5 — Current)
```
Agent → SDK → Rate Limiter → PDP → ALLOW + signed Execution Ticket
                               │         │
                               │         ▼
                               │  Executor validates ticket
                               │  (TicketValidator: sig, expiry, nonce)
                               ▼
                         Audit Logger → Local file (source of truth)
                               │
                               ├──→ FilesystemShipper (backup file)
                               ├──→ WebhookShipper (SIEM/log aggregator)
                               └──→ S3Shipper (immutable storage)
```
No Runner/Executor, no cloud infra, no credential management yet (Phase 2).
Agents execute actions themselves. Agent-Safe decides, issues tickets, and logs.

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
│       ├── identity/       # Agent identity (JWT)
│       ├── tickets/        # Execution ticket issuer + validator
│       ├── ratelimit/      # Per-caller rate limiting + circuit breaker
│       ├── sdk/            # Public SDK interface (AgentSafe class)
│       └── cli/            # CLI entry point
├── actions/                # YAML action definitions (K8s)
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

## What NOT to Build Yet (Phase 2 and beyond)
- No Runner/Executor (agents execute, we decide + issue tickets)
- No cloud infrastructure (sidecar/library only)
- No credential/secrets management (design doc done, implementation Phase 2)
- No approval workflow UI (PDP returns REQUIRE_APPROVAL, handling is the caller's job)
- No rollback automation
- No multi-agent supervisor
- No dashboard (Phase 2.5)

## Documentation
- `docs/MVP-PLAN.md` — 6–8 week detailed build plan (Phase 1)
- `docs/ROADMAP.md` — Full multi-phase roadmap (Phase 1 ✅, Phase 1.5 ✅, Phase 2 next)
- `docs/ARCHITECTURE.md` — Architecture decisions and diagrams
- `docs/GETTING-STARTED.md` — Installation, quick start, SDK usage, all features
- `docs/CREDENTIAL-SCOPING.md` — Vault-based credential gating design (Phase 2 implementation)
- `docs/FUTURE-BACKLOG.md` — Cut items and future ideas (parking lot)
- `docs/THREAT-MODEL.md` — Threat model and abuse cases (13 threats catalogued)
