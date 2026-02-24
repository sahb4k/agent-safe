# Agent-Safe — Future Backlog (Parking Lot)

Items cut from MVP that are good ideas for later. Each entry includes why it was cut and when it should be reconsidered.

---

## Execution & Enforcement

### Runner / Executor
**What**: A sandboxed execution engine that runs actions on behalf of agents. Agent never touches the target directly.
**Why cut**: Most complex and dangerous component. Building a secure, general-purpose executor is multi-quarter work. The advisory model eliminates the need for MVP.
**When to reconsider**: Phase 2, after design partner validates the advisory model and asks for enforcement. Start with K8s-only Runner (K8s operator pattern).
**Risk if delayed too long**: Advisory-only may not satisfy enterprise buyers who need provable enforcement. Phase 1.5 Execution Tickets are the bridge.

### Credential Gating
**What**: Agents never hold target credentials. Credentials live in a vault (HashiCorp Vault, AWS Secrets Manager). Only the Runner retrieves them after PDP approval.
**Why cut**: Requires vault integration, changes agent deployment model, adds operational complexity.
**Status**: Design document completed in Phase 1.5 ([CREDENTIAL-SCOPING.md](CREDENTIAL-SCOPING.md)). Implementation deferred to Phase 2.
**When to reconsider**: Phase 2, when Runner is built and enforcement becomes the priority.

### Enforcement Proxy
**What**: Network-level enforcement — all agent traffic to targets routes through a proxy that checks PDP decisions inline.
**Why cut**: Building a protocol-aware proxy is a product in itself. Overkill for early stage.
**When to reconsider**: Phase 3+, or never. Ticket-based enforcement may be sufficient.

---

## Approval & Workflow

### Human Approval Workflow
**What**: When PDP returns REQUIRE_APPROVAL, trigger a notification (Slack, webhook, email) and wait for human response.
**Why cut**: UX + integration work with no core IP. The PDP returns the decision; handling it is the caller's job in MVP.
**When to reconsider**: Phase 2. This is the first thing enterprise buyers will ask for after seeing the audit log.
**Design note**: MVP PDP already returns REQUIRE_APPROVAL with a `request_id`. Phase 2 just needs to add: (a) webhook dispatch, (b) approval API endpoint, (c) Slack bot.

### Approval Policies
**What**: Define who can approve what (role-based, target-based, risk-based). Two-person approval for critical actions.
**Why cut**: Depends on approval workflow existing first.
**When to reconsider**: Phase 2, alongside approval workflow.

---

## Rollback & Safety

### Rollback Pairing
**What**: Every reversible action has a paired compensating action. `agent-safe rollback <audit_id>` executes the reverse.
**Why cut**: Many actions aren't truly reversible. Promising rollback creates false confidence. Requires the Runner to execute rollback actions.
**When to reconsider**: Phase 2, K8s only. K8s has good rollback semantics (rollout undo, uncordon, etc.). Start there.
**Design note**: Action YAML schema already includes `reversible: bool`. Phase 2 adds `rollback_action: <action_name>` field.

### Before/After State Capture
**What**: Capture target state before and after action execution. Store diffs in audit log.
**Why cut**: Requires talking to the K8s API to read state, which means the sidecar needs K8s credentials. Adds complexity to advisory model.
**When to reconsider**: Phase 2, when the Runner exists and already has K8s access.

### Dry Run / Simulation Mode
**What**: `agent-safe simulate <action>` — run the full PDP evaluation but also show what the action *would* do (K8s dry-run).
**Why cut**: K8s dry-run is action-specific and requires API access. Nice-to-have, not core.
**When to reconsider**: Phase 2, alongside Runner.

---

## Observability & Reporting

### Dashboard / Web UI
**What**: Read-only web UI showing audit log, action catalogue, policy matches, agent activity.
**Why cut**: Frontend development is a separate skill set and time sink. CLI + log files are sufficient for MVP.
**When to reconsider**: Phase 2.5. This is the monetization layer — free dashboard for OSS users, paid features for teams.

### ~~External Audit Log Shipping~~ — COMPLETED (Phase 1.5, v0.2.0)
**What**: Push audit logs to immutable external storage (S3 Object Lock, GCS retention lock, WORM).
**Status**: Implemented. Pluggable `AuditShipper` protocol with three built-in backends: `FilesystemShipper`, `WebhookShipper` (stdlib), `S3Shipper` (optional boto3). Fire-and-forget after local write. CLI `agent-safe audit ship` for backfill.

### Compliance Report Generation
**What**: Generate SOC2 / ISO 27001 evidence reports from audit logs. "Here's everything agents did, all decisions, all reasons."
**Why cut**: Report formatting is not core IP. The data is there; report generation is a presentation layer.
**When to reconsider**: Phase 2.5, as a paid dashboard feature.

### SIEM/SOAR Integration
**What**: Ship audit events to Splunk, Sentinel, XSOAR, etc.
**Status**: Partially addressed in Phase 1.5 — `WebhookShipper` can POST events to any HTTP endpoint (SIEM ingest URLs, webhook-based SOAR triggers). Native integrations (Splunk HEC, Sentinel connector) deferred.
**When to reconsider**: Phase 2+, when enterprise customers demand native connectors beyond webhook.

---

## Multi-Environment & Scale

### Multi-Cloud Support (AWS, Azure, GCP)
**What**: Action catalogues for cloud provider APIs (EC2, Lambda, RDS, Azure VMs, GCP Compute, etc.).
**Why cut**: Massive surface area. Each cloud provider is essentially a separate product's worth of action definitions.
**When to reconsider**: Post-MVP, driven by demand. Add one cloud provider at a time. AWS is likely first (biggest market).

### Linux/SSH Target Support
**What**: Action catalogue for classic sysadmin actions (service management, file ops, user management) via SSH.
**Why cut**: Different execution model, different credential model, different risk profile than K8s.
**When to reconsider**: Post-MVP, if design partners are managing legacy infrastructure.

### Multi-Cluster Policy Sync
**What**: Manage policies centrally, push to multiple K8s clusters running agent-safe sidecars.
**Why cut**: Requires a control plane (hosted service or hub-spoke model). Not needed for single-cluster MVP.
**When to reconsider**: Phase 2.5, as part of the commercial dashboard.

---

## Advanced Policy

### OPA/Rego Policy Engine
**What**: Replace the custom rule engine with OPA (Open Policy Agent) using Rego policies.
**Why cut**: OPA is powerful but adds dependency complexity. Custom engine is simpler, faster to iterate, and sufficient for MVP policy needs.
**When to reconsider**: When policy complexity outgrows the custom engine (>50 rules, complex cross-references, data-dependent policies). Likely Phase 2.

### Cumulative Risk Scoring
**What**: Track action sequences per agent session. Escalate when cumulative risk exceeds a threshold (prevents privilege escalation via action chaining).
**Why cut**: Requires stateful PDP (tracks sessions), which contradicts the stateless design. Complex to get right.
**When to reconsider**: Phase 2. The audit log captures sequences; cumulative scoring can be computed from log data.

### Time-Window Policies
**What**: Policies that vary by time (e.g., "allow prod restarts only during maintenance windows").
**Why cut from initial scope**: Actually, this IS in MVP scope — the PDP receives a timestamp and policies can match on time windows. Included in Phase 1a.

---

## Agent Supervisor (Phase 3 — Separate Product)

### Multi-Agent Observation
**What**: Monitor multiple agents across clusters, correlate behaviour, detect anomalies.
**Why cut**: Different product with different technical requirements (streaming telemetry, ML models, real-time correlation).
**When to reconsider**: Only after revenue from Phases 1–2, at least 10 paying customers requesting it, and a second engineer.

### Anomaly Detection
**What**: Detect agents doing things they've never done before, unusual action volumes, target drift.
**Why cut**: ML/statistical models are a different engineering discipline. Don't dilute focus.
**When to reconsider**: Phase 3, if Phase 3 is greenlit.

### Auto-Pause / Escalation
**What**: Automatically pause an agent exhibiting suspicious behaviour. Escalate to human.
**Why cut**: Requires the Supervisor (Phase 3) and enforcement (Phase 2).
**When to reconsider**: Phase 3.

---

## Developer Experience

### ~~`agent-safe init` Scaffolding~~ — COMPLETED (Phase 1, v0.1.0)
**What**: `agent-safe init` generates a starter project with example actions, policies, inventory.
**Status**: Implemented in MVP.

### Action Marketplace / Community Registry
**What**: A shared repository of community-contributed action definitions (like Ansible Galaxy or Terraform Registry).
**Why cut**: Requires hosting, review process, trust model for community contributions.
**When to reconsider**: Post-launch, once there's a community. GitHub repo with contributed actions is the MVP version of this.

### IDE Integration
**What**: VSCode extension for authoring actions and policies with validation, autocomplete, and testing.
**Why cut**: Nice-to-have, not core.
**When to reconsider**: Post-launch, if action/policy authoring becomes a pain point.
