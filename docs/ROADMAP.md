# Agent-Safe — Full Roadmap

## Vision
Agent-Safe becomes the standard governance layer for AI agents operating on infrastructure — the "IAM for non-human identities" that every regulated enterprise deploys before letting agents touch production.

## Roadmap Sequence
```
Phase 1 (MVP)     → Policy Sidecar        (6-8 weeks)   ← WE ARE HERE
Phase 1.5         → Execution Tickets      (4-6 weeks)
Phase 2           → Change Control         (8-12 weeks)
Phase 2.5         → Dashboard + SaaS tier  (6-8 weeks)
Phase 3           → Agent Supervisor       (separate product decision)
```

---

## Phase 1: Policy Sidecar (MVP) — Weeks 1–8
**Status**: In progress
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
**Depends on**: Phase 1 complete, at least one real-world deployment/design partner

**Goal**: Bridge from advisory to enforceable decisions without building a full Runner.

**Deliverables**:
- **Signed Execution Tickets**: PDP issues a signed, time-limited, single-use token when it returns ALLOW. The token encodes the approved action, target, params, and expiry.
- **Ticket Validator**: A lightweight library/sidecar that existing executors (Ansible, Terraform, K8s controllers) can use to validate a ticket before executing.
- **Credential Scoping Design**: Document the architecture for credential gating (vault integration, just-in-time credential retrieval). Don't build it yet — design and validate the approach with a design partner.
- **External Audit Log Shipping**: Push audit logs to immutable external storage (S3 Object Lock, GCS retention-locked bucket).
- **Rate Limiting + Circuit Breakers**: Per-agent request rate limits. Auto-pause agents that exceed thresholds.
- **Policy Testing Framework**: `agent-safe test policies/` — run a test suite against policy definitions (table-driven: input → expected decision).
- **Second target environment actions** (based on design partner needs — likely AWS EC2/Lambda or generic Linux/SSH).

**Enforcement model**: Ticket-based — agent receives a signed ticket, must present it to the executor. Executor validates before acting. Agent still holds some credentials, but the ticket provides an audit-verified authorization chain.

---

## Phase 2: Change Control — Weeks 15–26
**Depends on**: Phase 1.5, design partner feedback, early community adoption

**Goal**: Add human-in-the-loop approval, state capture, and rollback for governed agent actions.

**Deliverables**:
- **Approval Workflows**: When PDP returns REQUIRE_APPROVAL, trigger a webhook. Integrate with:
  - Slack (bot that posts approval request, human clicks approve/deny)
  - Generic webhook (for PagerDuty, Teams, email, custom systems)
  - CLI approval (for testing: `agent-safe approve <request_id>`)
- **Approval Policies**: Define who can approve what (role-based, target-based, risk-based).
- **Before/After State Capture**: For supported actions, capture target state before execution and after. Store diffs in audit log.
- **Rollback Pairing (K8s only first)**:
  - Each reversible action has a paired rollback action
  - `agent-safe rollback <audit_id>` — execute the compensating action for a previous action
  - Only for actions marked `reversible: true`
  - Rollback itself goes through PDP (no unaudited rollbacks)
- **Cumulative Risk Scoring**: Track action sequences per agent session. Escalate to REQUIRE_APPROVAL when cumulative risk exceeds threshold (prevents privilege escalation via action chaining — see Threat Model T7).
- **Ticket/Incident Linkage**: Actions can reference an external ticket ID. Audit log includes it. Policy can require a ticket for certain action/target combinations.
- **Runner (Single Backend — K8s only)**: Optional sandboxed executor for K8s actions. Runs as a controller/operator. Retrieves credentials via K8s RBAC (not vault yet). Validates execution tickets before acting.

**Enforcement model**: Enforced for K8s (via Runner), advisory + tickets for other targets.

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
