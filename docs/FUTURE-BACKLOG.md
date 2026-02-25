# Agent-Safe — Future Backlog (Parking Lot)

Items cut from MVP that are good ideas for later. Each entry includes why it was cut and when it should be reconsidered.

---

## Execution & Enforcement

### ~~Runner / Executor~~ — COMPLETED (v0.8.0–v0.9.0, Phase 2)
**What**: A sandboxed execution engine that runs actions on behalf of agents. Agent never touches the target directly.
**Status**: Implemented. Runner/Executor framework with `Executor` protocol, `DryRunExecutor`, `SubprocessExecutor` (kubectl), `K8sExecutor` (python-native, 17 K8s actions), and `AwsExecutor` (boto3, 13 AWS actions). Full lifecycle: ticket validation → credential resolution → prechecks → before-state → execute → after-state → audit.

### ~~Credential Gating~~ — COMPLETED (v0.3.0, Phase 2.1)
**What**: Agents never hold target credentials. Credentials live in a vault (HashiCorp Vault, AWS Secrets Manager). Only the Runner retrieves them after PDP approval.
**Status**: Implemented. `CredentialVault` protocol with `EnvVarVault` dev/test backend. `CredentialResolver` resolves scoped credentials from vault after ticket validation. Template engine for credential scope fields. Design doc: [CREDENTIAL-SCOPING.md](CREDENTIAL-SCOPING.md).

### Enforcement Proxy
**What**: Network-level enforcement — all agent traffic to targets routes through a proxy that checks PDP decisions inline.
**Why cut**: Building a protocol-aware proxy is a product in itself. Overkill for early stage.
**When to reconsider**: Phase 3+, or never. Ticket-based enforcement may be sufficient.

---

## Approval & Workflow

### ~~Human Approval Workflow~~ — COMPLETED (v0.3.0, Phase 2.1)
**What**: When PDP returns REQUIRE_APPROVAL, trigger a notification (Slack, webhook, email) and wait for human response.
**Status**: Implemented. `FileApprovalStore` with JSONL persistence. `ApprovalNotifier` protocol with webhook and Slack notifiers. SDK orchestration: `wait_for_approval()`, `resolve_approval()`. CLI: `approval list/show/approve/deny`.

### ~~Approval Policies~~ — COMPLETED (v0.3.0, Phase 2.1)
**What**: Define who can approve what (role-based, target-based, risk-based). Two-person approval for critical actions.
**Status**: Implemented alongside approval workflows. Delegation-aware policies control who can approve.

---

## Rollback & Safety

### ~~Rollback Pairing~~ — COMPLETED (v0.7.0, Phase 2)
**What**: Every reversible action has a paired compensating action. `agent-safe rollback <audit_id>` executes the reverse.
**Status**: Implemented. Declarative `rollback_params` mapping in action YAML. `generate_rollback()` and `check_rollback()` SDK methods. CLI: `rollback show` and `rollback check`. Rollback goes through full PDP evaluation.

### ~~Before/After State Capture~~ — COMPLETED (v0.6.0, Phase 2)
**What**: Capture target state before and after action execution. Store diffs in audit log.
**Status**: Implemented. Executors record state via SDK. State data (before, after, diff) stored as `state_capture` audit events. CLI: `audit show-state` and `audit state-coverage`.

### ~~Dry Run / Simulation Mode~~ — COMPLETED (v0.8.0, Phase 2)
**What**: `agent-safe simulate <action>` — run the full PDP evaluation but also show what the action *would* do.
**Status**: Implemented. `DryRunExecutor` simulates execution without side effects. CLI: `runner dry-run <token>`.

---

## Observability & Reporting

### ~~Dashboard / Web UI~~ — COMPLETED (v0.10.0, Phase 2.5)
**What**: Read-only web UI showing audit log, action catalogue, policy matches, agent activity.
**Status**: Implemented. FastAPI backend + React/TypeScript/Tailwind frontend. `agent-safe dashboard` CLI command. Optional dependency: `pip install agent-safe[dashboard]`.

### ~~External Audit Log Shipping~~ — COMPLETED (Phase 1.5, v0.2.0)
**What**: Push audit logs to immutable external storage (S3 Object Lock, GCS retention lock, WORM).
**Status**: Implemented. Pluggable `AuditShipper` protocol with three built-in backends: `FilesystemShipper`, `WebhookShipper` (stdlib), `S3Shipper` (optional boto3). Fire-and-forget after local write. CLI `agent-safe audit ship` for backfill.

### ~~Compliance Report Generation~~ — COMPLETED (v0.13.0, Phase 2.5 Paid)
**What**: Generate SOC2 / ISO 27001 evidence reports from audit logs. "Here's everything agents did, all decisions, all reasons."
**Status**: Implemented as a paid dashboard feature. Reports page with SOC2 and ISO 27001 export, date range filtering, and per-cluster scoping.

### ~~Alert Rules~~ — COMPLETED (v0.16.0, Phase 2.5 Paid)
**What**: Define alert conditions in the dashboard (match on risk_class, decision, action patterns, event types). When ingested events match, fire notifications via webhook or Slack.
**Status**: Implemented. Alert rules engine with configurable conditions, thresholds (N events in time window), cooldown periods, and webhook/Slack notification channels. Alert history logged for audit.

### SIEM/SOAR Integration
**What**: Ship audit events to Splunk, Sentinel, XSOAR, etc.
**Status**: Partially addressed in Phase 1.5 — `WebhookShipper` can POST events to any HTTP endpoint (SIEM ingest URLs, webhook-based SOAR triggers). Native integrations (Splunk HEC, Sentinel connector) deferred.
**When to reconsider**: Phase 2+, when enterprise customers demand native connectors beyond webhook.

---

## Multi-Environment & Scale

### Multi-Cloud Support (~~AWS~~, Azure, GCP)
**What**: Action catalogues for cloud provider APIs (EC2, Lambda, RDS, Azure VMs, GCP Compute, etc.).
**AWS status**: COMPLETED (v0.9.0). 13 AWS actions (EC2, ECS, Lambda, S3, IAM) with AwsExecutor using boto3.
**Azure/GCP**: Not started. Add driven by demand.

### Linux/SSH Target Support
**What**: Action catalogue for classic sysadmin actions (service management, file ops, user management) via SSH.
**Why cut**: Different execution model, different credential model, different risk profile than K8s.
**When to reconsider**: Post-MVP, if design partners are managing legacy infrastructure.

### ~~Multi-Cluster Policy Sync~~ — COMPLETED (v0.14.0–v0.15.0, Phase 2.5 Paid)
**What**: Manage policies centrally, push to multiple K8s clusters running agent-safe sidecars.
**Status**: Implemented. Multi-cluster management with centralized audit aggregation (v0.14.0). Hosted managed policies with `PolicySyncClient` SDK for sidecar-side polling (v0.15.0).

---

## Advanced Policy

### OPA/Rego Policy Engine
**What**: Replace the custom rule engine with OPA (Open Policy Agent) using Rego policies.
**Why cut**: OPA is powerful but adds dependency complexity. Custom engine is simpler, faster to iterate, and sufficient for MVP policy needs.
**When to reconsider**: When policy complexity outgrows the custom engine (>50 rules, complex cross-references, data-dependent policies). Likely Phase 2.

### ~~Cumulative Risk Scoring~~ — COMPLETED (v0.4.0, Phase 2)
**What**: Track action sequences per agent session. Escalate when cumulative risk exceeds a threshold (prevents privilege escalation via action chaining).
**Status**: Implemented. Per-caller sliding time window with configurable risk scores, escalation threshold (ALLOW → REQUIRE_APPROVAL), and deny threshold (any → DENY). Post-policy escalation layer. Addresses Threat T7.

### Time-Window Policies
**What**: Policies that vary by time (e.g., "allow prod restarts only during maintenance windows").
**Why cut from initial scope**: Actually, this IS in MVP scope — the PDP receives a timestamp and policies can match on time windows. Included in Phase 1a.

---

## Authentication & Identity

### ~~SSO / OIDC Integration~~ — COMPLETED (v0.16.0, Phase 2.5 Paid)
**What**: Enterprise SSO via OpenID Connect. Users authenticate via their identity provider (Google, Azure AD, Okta, Keycloak, Auth0).
**Status**: Implemented. OIDC Authorization Code Flow (stdlib only, no authlib). Auto-provisioning of local accounts from OIDC claims. Configurable default role for SSO users. Optional password auth disable when SSO is the sole auth method. Enterprise tier only.

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

### ~~`agent-safe init` Scaffolding~~ — COMPLETED (v0.1.0, enhanced v0.12.0)
**What**: `agent-safe init` generates a starter project with example actions, policies, inventory.
**Status**: Implemented in MVP (v0.1.0). Enhanced in v0.12.0: scaffolds 9 files including `agent-safe.yaml` with auto-generated signing key, `.gitignore`, 5 diverse actions (LOW to HIGH risk, K8s + AWS), default policy, and inventory with 4 targets. Zero-config SDK and CLI work immediately after `init`.

### Action Marketplace / Community Registry
**What**: A shared repository of community-contributed action definitions (like Ansible Galaxy or Terraform Registry).
**Why cut**: Requires hosting, review process, trust model for community contributions.
**When to reconsider**: Post-launch, once there's a community. GitHub repo with contributed actions is the MVP version of this.

### IDE Integration
**What**: VSCode extension for authoring actions and policies with validation, autocomplete, and testing.
**Why cut**: Nice-to-have, not core.
**When to reconsider**: Post-launch, if action/policy authoring becomes a pain point.
