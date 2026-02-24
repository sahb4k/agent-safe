# Agent-Safe — Development Conventions

## Project Overview
Agent-Safe is an open-source governance/control layer for AI agents and non-human identities (NHIs).
It is NOT an agent. It is the system that restricts and governs what agents are allowed to do.

Core product: A policy decision sidecar — Action Registry + Policy Decision Point (PDP) + Audit Log + SDK/CLI.

## Key Decisions (Locked)
- **Deployment**: Sidecar / library (runs in customer's environment, no cloud dependency)
- **Target environment**: Kubernetes first (all action catalogues scoped to K8s API)
- **Enforcement model (MVP)**: Advisory — PDP returns ALLOW/DENY/REQUIRE_APPROVAL, agent should respect it, audit logs everything. No credential gating yet.
- **GTM**: Open-source core (Apache 2.0), future paid tier (hosted dashboard, enterprise features)
- **Tech stack**: Python (most agent frameworks are Python)
- **License**: Apache 2.0

## Architecture (MVP)
```
Agent → agent-safe SDK → PDP (local) → decision + audit log
         ↓
   Action Registry (YAML, versioned, signed)
   Target Inventory (static YAML)
   Audit Log (hash-chained JSON lines)
```
The MVP has NO Runner/Executor, NO cloud infra, NO credential management.
Agents execute actions themselves. Agent-Safe decides and logs.

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
├── LICENSE
├── pyproject.toml
├── src/
│   └── agent_safe/
│       ├── __init__.py
│       ├── registry/       # Action Registry loader, validator
│       ├── pdp/            # Policy Decision Point
│       ├── audit/          # Audit logging
│       ├── inventory/      # Target inventory
│       ├── identity/       # Agent identity (JWT)
│       ├── sdk/            # Public SDK interface
│       └── cli/            # CLI entry point
├── actions/                # YAML action definitions
├── policies/               # Policy definitions
├── tests/
├── docs/
│   ├── MVP-PLAN.md
│   ├── ROADMAP.md
│   ├── ARCHITECTURE.md
│   ├── FUTURE-BACKLOG.md
│   └── THREAT-MODEL.md
└── examples/
```

## Key Principles
1. **No raw shell execution** — actions are declared, validated, policy-checked
2. **Audit everything** — every request, every decision, every reason
3. **Policy is context-aware** — risk = f(action, target, caller, time, state), not just action type
4. **Sidecar, not SaaS** — decisions and data stay in the customer's environment
5. **Advisory before enforced** — log and decide now, gate credentials later

## What NOT to Build (MVP)
- No Runner/Executor (agents execute, we decide)
- No cloud infrastructure
- No credential/secrets management
- No approval workflow UI (PDP returns REQUIRE_APPROVAL, handling is the caller's job)
- No rollback automation
- No multi-agent supervisor
- No dashboard (post-MVP)

## Documentation
- `docs/MVP-PLAN.md` — 6–8 week detailed build plan
- `docs/ROADMAP.md` — Full multi-phase roadmap
- `docs/ARCHITECTURE.md` — Architecture decisions and diagrams
- `docs/FUTURE-BACKLOG.md` — Cut items and future ideas (parking lot)
- `docs/THREAT-MODEL.md` — Threat model and abuse cases
