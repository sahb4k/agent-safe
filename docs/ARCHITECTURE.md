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
| D11 | Execution ticket signing | HMAC-SHA256 (PyJWT) | RSA/ECDSA, PASETO | Symmetric signing is simple and correct when PDP and validator share an environment. `type: "execution-ticket"` claim prevents cross-use with identity JWTs. Move to asymmetric for cross-trust-boundary enforcement. |
| D12 | Rate limit enforcement point | Inside PDP (before policy eval) | SDK wrapper, middleware | Placing rate limiting inside PDP ensures all paths are protected, including `check_plan()`. Record denials after policy eval (not rate-limited denials) for circuit breaker. |
| D13 | Audit log shipping model | Synchronous fire-and-forget | Background thread, async | Local file is source of truth. Shippers run synchronously after local write, exceptions caught and warned. Simplest correct approach. CLI replay command handles catch-up. |
| D14 | Shipper interface | `typing.Protocol` | ABC, callable | Protocol is the modern Python approach. `runtime_checkable` enables `isinstance()` checks. Any object with `ship(event)` satisfies the protocol -- no inheritance required. |

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

## Phase 1.5 Architecture (Current)

Phase 1.5 extends the MVP with ticket-based authorization, rate limiting, and external audit shipping:

```
Agent → SDK → Rate Limiter → PDP → ALLOW + signed Execution Ticket
                               │         │
                               │         ▼
                               │  Executor validates ticket
                               │  (TicketValidator: sig, expiry, nonce)
                               │
                               ▼
                         Audit Logger → Local file (source of truth)
                               │
                               ├──→ FilesystemShipper (backup file)
                               ├──→ WebhookShipper (SIEM/log aggregator)
                               └──→ S3Shipper (immutable storage)
```

**What's new vs MVP:**
- **Rate Limiter** sits before policy evaluation — per-caller sliding window + circuit breaker
- **Execution Tickets** are issued on ALLOW — signed JWT with action, target, nonce, expiry
- **Ticket Validator** is a standalone library — executors validate without full AgentSafe
- **Audit Shippers** fire after each local write — pluggable via `AuditShipper` protocol

The PDP design does not change. These features are additive.

## Phase 2.1 Architecture: Delegation + Credentials + Approvals

Phase 2.1 adds multi-agent delegation, credential gating, and approval workflows:

```
Orchestrator → SDK.delegate(parent_token, child_id, roles=[...])
                    │
                    └→ Delegation JWT (chain: [orchestrator])
                         │
                         └→ Worker calls SDK.check(caller=delegation_jwt)
                              │
                              └→ PDP evaluates with delegation context from JWT
                                   ├─ Checks delegated_from, max_depth, require_delegation
                                   ├─ ALLOW → Execution Ticket
                                   │           └→ resolve_credentials(ticket) → scoped cred from vault
                                   ├─ REQUIRE_APPROVAL → Approval Store → webhook/Slack notification
                                   └─ Audit event includes full delegation chain in context
```

**What's new vs Phase 1.5:**
- **Delegation chains** carried in JWT payload — PDP inspects provenance statelessly
- **CallerSelector** extended with `delegated_from`, `max_delegation_depth`, `require_delegation`
- **Credential Resolver** fetches scoped credentials from vault after ticket validation
- **Approval Store** persists REQUIRE_APPROVAL decisions with notification dispatch
- **Audit context** carries delegation chain for provenance tracking

The PDP design does not change. These features are additive.

| # | Decision | Chosen | Alternatives Considered | Rationale |
|---|----------|--------|------------------------|-----------|
| D15 | Delegation chain storage | In JWT payload | External delegation store, database | Stateless PDP preserved — no external store needed. Chain integrity guaranteed by JWT HMAC signature. Matches existing identity pattern. |
| D16 | Scope narrowing enforcement | At token creation time | At PDP evaluation time | Strict subset check when creating delegation token prevents privilege escalation. PDP can additionally verify via policy. |
| D17 | Credential vault interface | `typing.Protocol` | ABC, callable | Consistent with existing AuditShipper pattern. `runtime_checkable` enables `isinstance()` checks. |

## Phase 2 Architecture: Cumulative Risk Scoring

Phase 2 adds session-level risk tracking to prevent privilege escalation via action chaining (Threat T7):

```
Agent → SDK → Rate Limiter → PDP → Policy Decision
                                         │
                                         ▼
                                  Risk Tracker (post-policy)
                                    ├─ Record effective_risk score for caller
                                    ├─ Compute cumulative score in sliding window
                                    ├─ If score >= escalation_threshold: ALLOW → REQUIRE_APPROVAL
                                    ├─ If score >= deny_threshold: any non-DENY → DENY
                                    └─ Annotate Decision + audit context with cumulative info
```

**What's new vs Phase 2.1:**
- **CumulativeRiskTracker** sits after policy evaluation — escalates decisions based on accumulated risk
- **Per-caller sliding window** tracks risk scores with configurable duration (default 1 hour)
- **Decision annotation** — `cumulative_risk_score`, `cumulative_risk_class`, `escalated_from` on every non-DENY decision
- **Audit context** carries cumulative risk info, merged with delegation context

The PDP design does not change. Cumulative risk is an additive post-policy layer.

| # | Decision | Chosen | Alternatives Considered | Rationale |
|---|----------|--------|------------------------|-----------|
| D18 | Cumulative risk placement | Post-policy escalation | Policy match field, pre-policy check | Post-policy keeps policy rules simple (each evaluates one action in isolation) while adding session awareness as a separate concern. Escalation only goes UP, never DOWN. |
| D19 | Risk recording trigger | Non-DENY decisions only | All decisions, ALLOW only | Only non-DENY decisions represent actions the agent was approved to execute. Recording DENY would let denial-spam inflate scores artificially. |
| D20 | Risk tracker module location | `pdp/risk_tracker.py` | Extend rate limiter, inline in engine | Separate module follows rate limiter pattern for consistency. Different concern despite similar structure. |
| D21 | Ticket ID as first-class audit field | Dedicated `ticket_id` field on AuditEvent | In `context` dict, in `params` | First-class field is queryable, filterable, and visible in audit exports. Same pattern as `correlation_id`. Compliance auditors need to answer "was there a ticket?" without parsing nested dicts. |

## Future Architecture (Phase 2+)

When enforcement is added:

```
Agent → SDK → PDP → ALLOW + signed Execution Ticket
                       │
                       ▼
              Runner validates ticket
              Runner retrieves creds from vault (JIT)
              Runner runs action on target
              Runner reports result to audit log
```

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
