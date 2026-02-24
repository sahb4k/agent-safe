# Agent-Safe — Full Roadmap

## Vision
Agent-Safe becomes the standard governance layer for AI agents operating on infrastructure — the "IAM for non-human identities" that every regulated enterprise deploys before letting agents touch production.

## Roadmap Sequence
```
Phase 1 (MVP)     → Policy Sidecar        (6-8 weeks)   ✅ COMPLETE
Phase 1.5         → Execution Tickets      (4-6 weeks)   ✅ COMPLETE
Phase 2.1         → Delegation + Creds     (4 weeks)     ✅ COMPLETE
Phase 2           → Change Control         (8-12 weeks)  ← WE ARE HERE
Phase 2.5         → Dashboard + SaaS tier  (6-8 weeks)
Phase 3           → Agent Supervisor       (separate product decision)
```

---

## Phase 1: Policy Sidecar (MVP) — Weeks 1–8
**Status**: Complete (v0.1.0)
**Detailed plan**: [MVP-PLAN.md](MVP-PLAN.md)

**Deliverables**:
- Action Registry (YAML, versioned, integrity-checked)
- Policy Decision Point (stateless, context-aware, default-deny)
- Audit Log (hash-chained, append-only)
- Python SDK + CLI
- 20+ curated Kubernetes action definitions
- One demo integration with a real agent framework
- Published to PyPI, Apache 2.0

**Enforcement model**: Advisory — PDP decides and logs, agent executes.

---

## Phase 1.5: Execution Tickets — Weeks 9–14
**Status**: Complete (v0.2.0)

**Goal**: Bridge from advisory to enforceable decisions without building a full Runner.

**Deliverables**:
- [x] **Signed Execution Tickets**: PDP issues a signed, time-limited, single-use JWT on ALLOW. Encodes action, target, params, nonce, expiry. HMAC-SHA256 with `type: "execution-ticket"` claim.
- [x] **Ticket Validator**: Standalone validator with signature, expiry, issuer, action/target match, and single-use nonce checks. Thread-safe.
- [x] **Policy Testing Framework**: `agent-safe test <path>` runs table-driven YAML test suites against policy definitions.
- [x] **Rate Limiting + Circuit Breakers**: Per-caller sliding window rate limiting. Circuit breaker auto-pauses agents exceeding DENY thresholds. Thread-safe, injectable clock.
- [x] **External Audit Log Shipping**: Pluggable shipper protocol with FilesystemShipper, WebhookShipper (stdlib), S3Shipper (optional boto3). Fire-and-forget after local write.
- [x] **Credential Scoping Design**: Architecture document for vault-based credential gating ([CREDENTIAL-SCOPING.md](CREDENTIAL-SCOPING.md)).
- [x] **Second target environment actions**: AWS — 12 actions (EC2, ECS, Lambda, S3, IAM) with AwsExecutor (v0.9.0).

**Enforcement model**: Ticket-based — agent receives a signed ticket, must present it to the executor. Executor validates before acting. Agent still holds some credentials, but the ticket provides an audit-verified authorization chain.

---

## Phase 2.1: Delegation + Credentials + Approvals
**Status**: Complete (v0.3.0)

**Goal**: Multi-agent delegation, credential gating, and approval workflows.

**Deliverables**:
- [x] **Multi-Agent Delegation**: JWT-based delegation chains. Orchestrator delegates to worker with scope narrowing (child roles ⊆ parent roles). Configurable max depth. TTL inheritance (child cannot outlive parent). Delegation context in audit trail.
- [x] **Delegation-Aware Policies**: `CallerSelector` extended with `delegated_from`, `max_delegation_depth`, `require_delegation`. Policies control delegation at the policy level.
- [x] **Credential Gating**: `CredentialVault` protocol with `EnvVarVault` dev/test backend. `CredentialResolver` resolves scoped credentials from vault after ticket validation. `{{ params.xyz }}` template engine for credential scope fields.
- [x] **Approval Workflows**: `FileApprovalStore` with JSONL persistence. `ApprovalNotifier` protocol with webhook and Slack notifiers. SDK orchestration: `wait_for_approval()`, `resolve_approval()`.
- [x] **New CLI commands**: `delegation create/verify`, `credential resolve/test-vault`, `approval list/show/approve/deny`.
- [x] **540 tests** (up from 376).

**Enforcement model**: Credential gating — agents no longer hold target credentials. Credentials are retrieved JIT via vault after ticket validation. Delegation provides provenance tracking for multi-agent workflows.

---

## Phase 2: Change Control — Weeks 15–26
**Depends on**: Phase 1.5, design partner feedback, early community adoption

**Goal**: Add human-in-the-loop approval, state capture, and rollback for governed agent actions.

**Deliverables**:
- [x] **Cumulative Risk Scoring**: Per-caller session-level risk tracking with sliding time window. Configurable risk scores, escalation threshold (ALLOW → REQUIRE_APPROVAL), and deny threshold (any → DENY). Post-policy escalation layer. Thread-safe, injectable clock. Addresses Threat T7.
- [x] **Ticket/Incident Linkage**: Actions reference an external ticket ID via `ticket_id` parameter. First-class audit field. Policy `require_ticket` condition controls per-rule ticket requirements. CLI `--ticket-id` option. Policy test cases support `ticket_id`.
- [x] **Before/After State Capture**: Executors record target state before/after execution via SDK. State data (before, after, diff) stored as `state_capture` audit events linked to original decisions. Advisory `state_fields` in action YAML. CLI `audit show-state` and `audit state-coverage` commands.
- [x] **Rollback Pairing (K8s only)**: Declarative `rollback_params` mapping in action YAML. `generate_rollback()` and `check_rollback()` SDK methods. `rollback show` and `rollback check` CLI commands. Convention-based fallback for undeclared mappings. Rollback goes through PDP with `correlation_id` linking to original decision.
- [x] **Runner (Single Backend — K8s only)**: Runner/Executor framework with `Executor` protocol, `DryRunExecutor`, and `SubprocessExecutor` (kubectl). Runner orchestrates: ticket validation → credential resolution → prechecks → before-state → execute → after-state → audit → revoke. SDK `execute()` convenience method. CLI `runner execute` and `runner dry-run` commands.
- [x] **K8sExecutor (Python-native)**: Python-native Kubernetes executor using the `kubernetes` client library. Maps 17 actions to API calls (AppsV1Api, CoreV1Api, AutoscalingV1Api, NetworkingV1Api). No kubectl binary required. Multi-step drain-node. Optional dependency: `pip install agent-safe[k8s]`.
- [x] **AWS Actions + AwsExecutor**: 12 curated AWS action definitions (EC2, ECS, Lambda, S3, IAM) with AwsExecutor using boto3. Request builders, state extractors, credential handling (access key, profile, default chain). Optional dependency: `pip install agent-safe[aws]`.

**Enforcement model**: Enforced for K8s (via Runner/K8sExecutor) and AWS (via AwsExecutor), advisory + tickets for other targets.

---

## Phase 2.5: Dashboard + Commercial Tier — Weeks 24–32
**Depends on**: Phase 2, sufficient open-source adoption to justify investment

**Goal**: Monetisation layer. A hosted control plane that adds centralized visibility without replacing the local PDP.

**Deliverables**:
- **Web Dashboard** (read-only for free tier):
  - Audit log viewer (search, filter, timeline)
  - Action catalogue browser
  - Policy visualizer (which rules match which targets)
  - Agent activity feed
- **Team/Org Features** (paid tier):
  - Multi-cluster policy management (push policies to multiple sidecars)
  - Centralized audit aggregation (sidecars ship logs to dashboard)
  - Role-based access to dashboard
  - Compliance report generation (SOC2, ISO 27001 evidence)
  - SSO integration
- **Hosted Policy Sync**: Edit policies in the dashboard, sync to local sidecars.
- **Alert Rules**: Define anomaly thresholds in the dashboard, push to sidecars.

**Business model**: Open-source core remains free. Dashboard + team features are the paid product. Pricing: per-agent or per-cluster.

---

## Phase 3: Agent Supervisor — SEPARATE PRODUCT DECISION
**Depends on**: Revenue from Phase 2.5, explicit market demand, probably a second engineer

**This is not a guaranteed phase.** It is a different product with different technical requirements. Do not let it distort Phases 1–2 architecture.

**What it would be (if built)**:
- Observe multiple agents across multiple clusters
- Correlate agent behaviour (action sequences, timing, targets)
- Detect anomalies (agent doing something it never did before, action volume spike, target drift)
- Auto-pause agents that exhibit suspicious patterns
- Compliance-grade reporting (who did what, when, why, and was it approved)
- Integration with SIEM/SOAR platforms

**Technical requirements (different from Phases 1–2)**:
- Streaming telemetry ingestion
- Statistical/ML anomaly detection models
- Real-time correlation engine
- Much higher infrastructure cost

**Decision criteria for starting Phase 3**:
- [ ] At least 10 paying customers on Phase 2.5
- [ ] At least 3 customers explicitly requesting supervision capabilities
- [ ] Second engineer hired
- [ ] Architecture design validated with security researchers

---

## Roadmap Principles
1. **Each phase ships a usable product** — not a partial system that only works when everything is done.
2. **Advisory before enforced** — earn trust by logging, then gate by controlling credentials.
3. **Kubernetes first, expand later** — depth over breadth. Own one environment completely.
4. **Open-source core, commercial layer** — adoption fuels the business, not the other way around.
5. **Don't build the Supervisor until the market demands it** — it's a different company.
