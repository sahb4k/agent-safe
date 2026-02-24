# Agent-Safe — Architecture Decisions

## Decision Log

| # | Decision | Chosen | Alternatives Considered | Rationale |
|---|----------|--------|------------------------|-----------|
| D1 | Deployment model | Sidecar / Library | SaaS API, Hybrid, CLI-only | Regulated buyers won't send action metadata to a third-party cloud. Sidecar keeps decisions local. Simplest to build solo. |
| D2 | Target environment | Kubernetes first | AWS, Azure, Linux/SSH | K8s has a well-defined API, strong RBAC model, and is where most AI-deploying companies run. Smaller surface area than multi-cloud. |
| D3 | Enforcement model (MVP) | Advisory | Credential gating, Proxy | Advisory ships in weeks, not months. No vault or proxy infra needed. Still provides audit trail and compliance evidence. Enforcement comes in Phase 1.5/2. |
| D4 | GTM | Open-source core (Apache 2.0) | Closed-source, AGPL/BSL | Security tool from unknown vendor needs trust through transparency. OSS adoption creates inbound pipeline. Action catalogue benefits from community contributions. |
| D5 | Language | Python | Go, TypeScript, Rust | Most agent frameworks are Python. SDK adoption is frictionless if same language. Performance is not the bottleneck (PDP is <5ms). |
| D6 | Policy engine | Custom rule engine | OPA/Rego, Cedar, Casbin | OPA is powerful but heavy dependency for MVP. Custom engine is ~300 lines, fully understood, fully testable. Migrate to OPA later if rule complexity demands it. |
| D7 | Audit log format | Hash-chained JSON lines | SQLite, Postgres, structured logs | JSON lines is append-only by nature, no database dependency, trivially parseable, easy to ship to external stores. Hash chain adds tamper evidence. |
| D8 | Agent identity | JWT (HMAC-SHA256) | mTLS, SPIFFE, API keys | JWT is simple, widely understood, and works for advisory model. HMAC-SHA256 is fine when the PDP and agent share an environment. Move to asymmetric/SPIFFE for cross-trust-boundary enforcement. |
| D9 | Action definitions | YAML files in repo | Database, API, OCI artifacts | YAML in a git repo is versionable, diffable, reviewable (PRs), and requires no infrastructure. |
| D10 | No Runner in MVP | Decided | Runner was in original plan | Runner is the most complex, most dangerous component. Building a secure general-purpose executor is multi-quarter. Advisory model eliminates the need for MVP. |

---

## MVP Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AGENT PROCESS                         │
│                                                          │
│   from agent_safe import AgentSafe                       │
│   safe = AgentSafe(...)                                  │
│   decision = safe.check("restart-deployment",            │
│       target="prod/api", caller="deploy-bot", ...)       │
│                                                          │
│   if decision.result == ALLOW:                           │
│       # agent executes the action itself                 │
│   elif decision.result == DENY:                          │
│       # agent logs reason, skips action                  │
│   elif decision.result == REQUIRE_APPROVAL:              │
│       # agent queues for human review                    │
└───────────────────┬─────────────────────────────────────┘
                    │ in-process call (no network hop)
                    ▼
┌─────────────────────────────────────────────────────────┐
│              AGENT-SAFE (library / sidecar)               │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Action      │  │   Target     │  │    Agent     │   │
│  │   Registry    │  │   Inventory  │  │   Identity   │   │
│  │              │  │              │  │   Validator  │   │
│  │  actions/     │  │  YAML file   │  │   JWT check  │   │
│  │  *.yaml       │  │  id, type,   │  │   agent_id,  │   │
│  │  name,version │  │  env, sens.  │  │   roles,     │   │
│  │  params,risk  │  │  owner,labels│  │   groups     │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                  │            │
│         └────────┬────────┴──────────┬───────┘            │
│                  ▼                   │                    │
│  ┌──────────────────────────────┐    │                    │
│  │   Policy Decision Point      │◄───┘                    │
│  │   (PDP)                      │                        │
│  │                              │                        │
│  │   Input:                     │                        │
│  │     action (from registry)   │                        │
│  │     target (from inventory)  │                        │
│  │     caller (from identity)   │                        │
│  │     params (from request)    │                        │
│  │     timestamp                │                        │
│  │                              │                        │
│  │   Evaluation:                │                        │
│  │     1. Validate action exists│                        │
│  │     2. Validate params       │                        │
│  │     3. Resolve target context│                        │
│  │     4. Match policies        │                        │
│  │     5. Compute effective risk│                        │
│  │     6. Return decision       │                        │
│  │                              │                        │
│  │   Output:                    │                        │
│  │     Decision(ALLOW/DENY/     │                        │
│  │       REQUIRE_APPROVAL,      │                        │
│  │       reason, audit_id)      │                        │
│  └──────────────┬───────────────┘                        │
│                 │                                        │
│                 ▼                                        │
│  ┌──────────────────────────────┐                        │
│  │   Audit Log                  │                        │
│  │                              │                        │
│  │   Hash-chained JSON lines    │                        │
│  │   {event_id, timestamp,      │                        │
│  │    prev_hash, action, target,│                        │
│  │    caller, params, decision, │                        │
│  │    reason, policy_matched}   │                        │
│  │                              │                        │
│  │   Append-only, file-locked   │                        │
│  │   Verification: check chain  │                        │
│  └──────────────────────────────┘                        │
└─────────────────────────────────────────────────────────┘
```

---

## Data Flow

```
1. Agent calls safe.check(action, target, caller, params)
2. Registry: validate action exists, validate params against schema
3. Inventory: resolve target → (environment, sensitivity, owner, labels)
4. Identity: validate caller JWT → (agent_id, roles, groups)
5. PDP: load policies, match (action, target_context, caller_context, time)
         compute effective_risk = f(action.risk_class, target.sensitivity)
         apply most-specific matching rule → decision
6. Audit: log {request + decision + context + hash_chain}
7. Return Decision to agent
```

---

## Key Design Principles

### Default-Deny
If no policy matches, the answer is DENY. This is non-negotiable. An unconfigured system blocks everything.

### Stateless PDP
The PDP holds no state between calls. All context comes from the request + registry + inventory + policies. This means:
- No database required
- Easy to test (pure function: inputs → output)
- Easy to scale (any instance gives the same answer)

### Context-Aware Risk
Risk is not a property of the action alone. It's computed from:
```
effective_risk = risk_matrix[action.risk_class][target.sensitivity]

                    Target Sensitivity
                    public  internal  restricted  critical
Action Risk  low  │  low      low       medium     high
            med  │  low      medium    high       critical
           high  │  medium   high      critical   critical
       critical  │  high     critical  critical   critical
```
Policies can match on `effective_risk` rather than raw action risk.

### Separation of Concerns
- **Registry** knows *what* actions exist and their properties
- **Inventory** knows *what* targets exist and their properties
- **Identity** knows *who* the caller is
- **PDP** knows *the rules* and makes decisions
- **Audit** knows *what happened*

No component does more than one job.

---

## Future Architecture (Post-MVP)

When enforcement is added (Phase 1.5+), the architecture extends:

```
Agent → SDK → PDP → ALLOW + signed Execution Ticket
                       │
                       ▼
              Executor validates ticket
              Executor retrieves creds from vault (JIT)
              Executor runs action on target
              Executor reports result to audit log
```

The PDP design does not change. The Execution Ticket and Executor are additive. This is why the MVP architecture is correct — it doesn't need to be rewritten when enforcement is added.

---

## Technology Choices

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.11+ | Agent ecosystem, developer familiarity |
| Package manager | pip / pyproject.toml | Standard Python packaging |
| Schema validation | Pydantic v2 | Fast, Python-native, good error messages |
| YAML parsing | PyYAML or ruamel.yaml | Standard, handles all YAML features |
| JWT | PyJWT | Lightweight, widely used |
| Hashing | hashlib (stdlib) | SHA-256, no external dependency |
| CLI | Click or Typer | Clean CLI framework |
| Testing | pytest | Standard Python testing |
| Linting | ruff | Fast, replaces flake8+isort+black |
| CI | GitHub Actions | Free for open-source |
