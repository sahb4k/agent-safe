# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - 2026-02-25

Commercial tier Phase D: Alert rules and SSO/OIDC authentication.

### Added

- **Alert rules**: Admins define alert conditions (risk_class, decision, event_type, action glob patterns) with configurable thresholds (N events in time window), cooldown periods, and notification channels (webhook, Slack). `POST /api/alerts/rules` creates rules; `GET/PUT/DELETE` for full CRUD. Soft-delete preserves audit history.

- **Alert engine**: Ingested events are evaluated against active rules via `BackgroundTasks` — non-blocking, fires after the HTTP response. Matching events trigger webhook and/or Slack notifications using stdlib `urllib.request`. Alert history logged to `alert_history` table for audit.

- **Alert history**: `GET /api/alerts/history` returns fired alerts with rule name, cluster ID, trigger event IDs, notification status (sent/failed), and error messages. Filterable by rule_id and cluster_id. Frontend auto-refreshes every 15 seconds.

- **Threshold and cooldown**: Threshold rules (e.g., "5 critical denies in 10 minutes") use SQL COUNT with a composite index on `cluster_events(cluster_id, risk_class, decision, timestamp)`. In-memory cooldown cache with DB fallback (survives restart) prevents alert spam.

- **SSO/OIDC authentication** (enterprise tier): OpenID Connect Authorization Code Flow using stdlib only — no new dependencies. Supports Google, Azure AD, Okta, Keycloak, Auth0, and any OIDC-compliant provider. Cached `.well-known/openid-configuration` discovery with 1-hour TTL.

- **SSOService**: Generates state + nonce for CSRF protection (stored in `oidc_auth_states` table, 10-minute TTL, single-use). Exchanges authorization code at token endpoint, decodes id_token payload (safe per OIDC Core spec 3.1.3.7 — received over TLS from token endpoint), validates nonce/issuer/audience, auto-provisions local user from OIDC claims.

- **SSO user provisioning**: Users provisioned by `external_id` (OIDC `sub` claim) with `auth_provider = "oidc"` and empty password hash/salt (SSO users cannot password-login). Username derived from email or name with collision suffix. Configurable default role via `AGENT_SAFE_DASHBOARD_OIDC_DEFAULT_ROLE`.

- **SSO API endpoints**: `GET /api/auth/sso/config` (public SSO info for login page), `GET /api/auth/sso/authorize` (returns OIDC redirect URL), `POST /api/auth/sso/token` (exchanges code + state for JWT session), `GET /api/auth/sso/callback` (browser redirect fallback).

- **Password auth toggle**: `AGENT_SAFE_DASHBOARD_PASSWORD_AUTH_ENABLED=false` disables password login when SSO is the sole auth method. `POST /api/auth/login` returns 403 when disabled. `GET /api/auth/tier` response extended with `sso_enabled` and `password_auth_enabled` fields.

- **SQLite migration v4**: `alert_rules` and `alert_history` tables, composite index on `cluster_events` for threshold queries, `auth_provider` and `external_id` columns on `users`, `oidc_auth_states` table for CSRF state.

- **Alerts dashboard page**: React page with two tabs — Rules (CRUD table with AlertRuleEditor form for conditions, thresholds, channels) and History (read-only table with status badges, auto-refresh). "Alerts" nav item in paid tier sidebar.

- **SSO login page**: "Sign in with SSO" button when SSO is enabled. "or" divider between SSO and password form. Password form conditionally shown. SSOCallbackPage handles OIDC redirect and token exchange.

- **54 new tests**: `test_alerts.py` (46 tests covering service CRUD, history, engine matching, evaluation, cooldown, notifications, API endpoints, tier gating) and SSO tests in `test_dashboard_auth.py` (8 tests covering SSO user creation, external_id lookup, password login prevention, default/custom roles, password_auth_disabled). Total: 1,363 tests.

### Changed

- **DashboardConfig**: 7 new OIDC fields — `oidc_provider_url`, `oidc_client_id`, `oidc_client_secret`, `oidc_default_role`, `oidc_enabled`, `password_auth_enabled`, `oidc_scopes`. All configurable via `AGENT_SAFE_DASHBOARD_*` env vars.

- **AuthService**: New `create_sso_user()` and `get_user_by_external_id()` methods. `_row_to_user()` extracts `auth_provider` and `external_id` with backward-compatible fallback for pre-v4 schemas.

- **Auth tier**: `"alerts"` feature added to team and enterprise tiers.

- **Event ingestion**: `POST /api/clusters/ingest` now fires `AlertEngine.evaluate_batch()` as a background task when events are accepted.

- Schema version bumped from 3 to 4.

## [0.15.0] - 2026-02-25

Commercial tier Phase C: Hosted policy sync and policy editor.

### Added

- **Managed policy service**: Full CRUD for centrally managed policies via `POST/GET/PUT/DELETE /api/policies/managed`. Policies stored in SQLite with priority, decision, reason, and match conditions (actions, targets, callers, risk_classes, require_ticket). Admin-only write access, authenticated read access.

- **Policy publishing**: `POST /api/policies/publish` snapshots active managed policies into an immutable revision with notes and publisher tracking. `GET /api/policies/revisions` lists all published revisions.

- **Policy bundle pull**: `GET /api/clusters/policy-bundle` authenticated via cluster API key (same as event ingestion). Returns the latest (or specific) published revision as a structured bundle. Records per-cluster sync status.

- **Policy sync client** (`agent_safe.sync.policy_sync.PolicySyncClient`): Sidecars poll the dashboard for policy bundles, write to local YAML, and track the synced revision. Configurable poll interval, stdlib-only (`urllib.request`), zero new dependencies.

- **Cluster sync status**: `GET /api/policies/sync-status` shows which clusters have synced and whether they're on the latest revision. Displayed in the dashboard Policies page.

- **Policy editor frontend**: React component for creating and editing managed policies with match condition builder (actions, targets, callers, risk classes, ticket requirement), priority, decision, and reason fields.

- **Policies page tabs**: Policies page split into three tabs — Local Rules (existing file-based), Managed Policies (CRUD table + editor), and Sync Status (cluster sync tracking with revision info).

- **SQLite migration v3**: `managed_policies`, `policy_revisions`, and `cluster_sync_status` tables.

- **59 new tests**: `test_managed_policies.py` (38 tests covering service CRUD, publishing, bundle, sync status, API endpoints) and `test_policy_sync.py` (21 tests covering sync client, bundle parsing, file writing, revision tracking). Total: 1,309 tests.

### Changed

- **Public exports**: New `PolicySyncClient` export from `agent_safe`.
- Schema version bumped from 2 to 3.

## [0.14.0] - 2026-02-25

Commercial tier Phase B: Multi-cluster registration and audit aggregation.

### Added

- **Cluster registration**: Register remote clusters via `POST /api/clusters/` — returns a one-time API key for sidecar authentication. SHA-256 hashed key storage, prefix-based display. Admin-only CRUD: list, get, deactivate clusters.

- **DashboardShipper**: New `AuditShipper` implementation in the core library (`agent_safe.audit.dashboard_shipper`). Sidecars POST audit events to a central dashboard using stdlib `urllib.request` — zero new dependencies. Configurable via `build_shippers()` with `dashboard_url` and `dashboard_api_key` keys.

- **Event ingestion endpoint**: `POST /api/clusters/ingest` accepts batches of audit events authenticated via cluster API key (Bearer token). Deduplication by `(cluster_id, event_id)`. Tracks `last_seen` timestamp per cluster.

- **Aggregated audit views**: `GET /api/clusters/events` and `GET /api/clusters/{id}/events` with full filtering (event_type, action, target, risk_class, decision, date range) and pagination. `GET /api/clusters/stats` and `GET /api/clusters/{id}/stats` for per-cluster and aggregated statistics.

- **SQLite migration v2**: `clusters` and `cluster_events` tables with foreign key constraints and indexes on `cluster_id` and `timestamp`.

- **Clusters dashboard page**: React page with cluster registration form, cluster table (status, event count, last seen, API key prefix), and per-cluster event viewer.

- **Team tier clusters**: "clusters" feature added to team tier (previously enterprise-only). Both team and enterprise tiers can now manage clusters.

### Changed

- Schema version bumped from 1 to 2 (migrations run automatically on startup).

## [0.13.0] - 2026-02-25

Commercial tier Phase A: Dashboard authentication and compliance reports.

### Added

- **Dashboard authentication**: JWT-based login with RBAC roles (admin/editor/viewer). PBKDF2-SHA256 password hashing (stdlib, zero new dependencies). Session tokens reuse existing PyJWT infrastructure with `type: "dashboard-session"` claim.

- **SQLite user store**: Thread-safe database layer with WAL mode. Version-tracked schema migrations. User CRUD: create, list, update, deactivate, password reset.

- **Tier gating**: `AGENT_SAFE_DASHBOARD_TIER` env var controls feature access. `free` (default) = no auth, existing behavior unchanged. `team` = auth + reports + user management. `enterprise` = team + SSO + clusters (future).

- **Bootstrap admin**: Set `AGENT_SAFE_DASHBOARD_ADMIN_PASSWORD` to auto-create an admin user on first startup. No manual setup needed.

- **Compliance report generation**: `POST /api/reports/generate` produces SOC2 and ISO 27001 evidence reports from audit data. SOC2 sections: Access Control (CC6.1), Change Management (CC8.1), Risk Assessment (CC3.2), Audit Trail Integrity (CC7.2), Incident Response (CC7.4). ISO 27001 sections: Security Events (A.12.4), Access Management (A.9.2), Change Control (A.12.1), Monitoring & Review (A.12.4).

- **User management API**: Admin-only CRUD for dashboard users. `GET/POST /api/users`, `PUT/DELETE /api/users/{id}`, `POST /api/users/{id}/reset-password`.

- **Frontend auth layer**: Login page, AuthContext with token persistence, ProtectedRoute wrapper, automatic Bearer token injection, 401 redirect to login.

- **Frontend pages**: Reports page with SOC2/ISO 27001 generation form and tabular output. Users page with create/list for admin.

- **Conditional navigation**: Sidebar shows Reports and Users only for paid tiers. User info and logout button in sidebar footer.

- **72 new tests**: `test_dashboard_db.py` (11), `test_dashboard_auth.py` (35), `test_dashboard_reports.py` (15), `test_dashboard_tier.py` (11). Total: 1,174 tests.

### Changed

- **DashboardConfig**: 5 new fields — `db_path`, `signing_key`, `tier`, `admin_username`, `admin_password`. All configurable via `AGENT_SAFE_DASHBOARD_*` env vars.

- **App factory**: Conditionally initializes SQLite, auth service, and paid-tier routers based on tier setting. Free tier is unmodified.

## [0.12.2] - 2026-02-25

Documentation and PyPI metadata refresh.

### Changed

- **PyPI metadata**: Added keywords (aws, rbac, zero-trust, guardrails). Updated README (PyPI long description) with correct version and test counts.
- **Roadmap**: Phase 2.5 free tier marked complete. Split into free/paid tiers. Added zero-config and CI/CD milestones.
- **Future Backlog**: Marked 10 completed items with version references.

## [0.12.1] - 2026-02-25

CI pipeline and cross-platform test fixes.

### Added

- **GitHub Actions CI**: Lint + test matrix on Python 3.11, 3.12, 3.13 with pip caching and coverage reporting. Lints `src/`, `tests/`, `examples/`, and `dashboard/`.

- **Trusted PyPI publishing**: `publish.yml` workflow triggers on GitHub releases. Builds, tests across all Python versions, and publishes to PyPI via trusted publishing (no API token needed).

### Fixed

- **Cross-platform test portability**: Replaced hardcoded Windows paths in all 24 test files with `Path(__file__).resolve().parent.parent`-based relative paths. Tests now pass on Linux, macOS, and Windows.

- **Click 8.2+ compatibility**: Removed deprecated `mix_stderr=False` from `CliRunner()`. Changed `result.stderr` assertions to `result.output` for mixed-mode output.

- **Dashboard test isolation**: Added `pytest.importorskip("fastapi")` guard so dashboard tests skip gracefully when FastAPI is not installed (e.g., in CI without `[dashboard]` extras).

## [0.12.0] - 2026-02-24

Zero-config new user experience.

### Added

- **`agent-safe.yaml` config file**: Project-level configuration with auto-discovery. CLI and SDK walk parent directories to find the config file (like `.gitignore` or `pyproject.toml`). All paths resolved relative to the YAML file's location.

- **Config loader module** (`agent_safe.config`): `find_config()`, `load_config()`, `generate_signing_key()`, `AgentSafeConfig` dataclass. New public exports from `agent_safe`.

- **Zero-config SDK**: `AgentSafe()` with no arguments now works — auto-discovers `agent-safe.yaml` for registry, policies, inventory, audit log, and signing key. New `config=` and `auto_discover=` parameters. Explicit args always override.

- **Config-aware CLI**: All 14 CLI commands fall back to `agent-safe.yaml` values. `--signing-key` is no longer `required=True` on 6 commands (ticket verify, delegation create/verify, runner execute/dry-run, credential resolve) — reads from config instead.

- **Richer `init` scaffolding**: `agent-safe init` now creates 9 files: `agent-safe.yaml` (with auto-generated 256-bit HMAC signing key), `.gitignore` (excludes config and secrets), 5 example actions spanning LOW to HIGH risk and K8s + AWS platforms, default policy, and inventory with 4 targets (3 K8s + 1 AWS).

- **19 new config tests** + 2 new init tests. **1,102 total unit tests**.

### Fixed

- Scaffolded `restart-deployment.yaml` now correctly has `reversible: false` (was `true`).

## [0.11.0] - 2026-02-24

Phase 2.5 -- Community Readiness.

### Added

- **Demo Suite**: 5 new runnable demos covering all major features. `demo_rate_limit.py` (rate limiting + circuit breaker), `demo_cumulative_risk.py` (risk scoring + escalation), `demo_delegation.py` (multi-agent delegation), `demo_approval_workflow.py` (approval lifecycle), `demo_execution_pipeline.py` (full ticket → credentials → execute → rollback pipeline).

- **Integration Test Suite**: 27 tests against real infrastructure. K8sExecutor against Kind (scale, restart, logs, delete-pod, state capture, prechecks). AwsExecutor against LocalStack (EC2 stop/start, S3 operations, IAM attach/detach). SubprocessExecutor against Kind (kubectl operations). Full pipeline: check() → ticket → credential → execute (real) → state → audit.

- **Integration Test Infrastructure**: Docker Compose for LocalStack, Kind cluster config (3 nodes), Kubernetes bootstrap manifests (namespace, deployment, configmap, secret). One-command setup (`bash infra/setup.sh`) and teardown (`bash infra/teardown.sh`).

- **AwsExecutor `endpoint_url`**: Backward-compatible parameter to redirect boto3 calls to custom endpoints (e.g., LocalStack). Enables local testing without real AWS credentials.

- **pytest integration markers**: `@pytest.mark.integration`, `@pytest.mark.kind`, `@pytest.mark.localstack` with `addopts = "-m 'not integration'"` so `pytest tests/` continues to run only fast unit tests.

- **PEP 561 `py.typed` marker**: Package now declares inline type stubs.

- **1,108 total tests** (1,081 unit + 27 integration).

## [0.10.0] - 2026-02-24

Phase 2.5 -- Governance Dashboard.

### Added

- **Web Dashboard**: Read-only governance dashboard served locally via `agent-safe dashboard`. FastAPI backend with React/TypeScript/Tailwind frontend. Browse audit events, actions, policies, and live activity.

- **Dashboard Backend**: 5 API routers (audit, actions, policies, activity, health) with 4 services. Paginated/filterable audit events, aggregate stats, event timeline, action detail, policy match analysis, real-time activity feed. Lightweight TTL-based caching.

- **Dashboard Frontend**: React 18 SPA with Vite, TanStack Query, Recharts, and Tailwind CSS. 6 pages: Dashboard (overview stats + timeline chart), Audit (filterable event table), Actions (grid with risk badges), ActionDetail (full definition view), Policies (priority-sorted table with match analysis), Activity (auto-refresh live feed).

- **CLI `dashboard` command**: `agent-safe dashboard [--dev] [--port 8420]`. Launches uvicorn serving the FastAPI app with built frontend static files. `--dev` enables CORS for Vite dev server.

- **Optional dependency**: `pip install agent-safe[dashboard]` for FastAPI + uvicorn. Core package works without dashboard deps.

- **74 new tests** across 2 files (test_dashboard_api.py, test_dashboard_services.py). **1081 total tests**.

## [0.9.0] - 2026-02-24

Phase 2 -- Multi-Environment Executors.

### Added

- **K8sExecutor**: Python-native Kubernetes executor using the `kubernetes` client library. Maps 17 K8s actions to API calls (AppsV1Api, CoreV1Api, AutoscalingV1Api, NetworkingV1Api). No kubectl binary required. Multi-step drain-node (cordon + evict). Body builders for all mutation actions. Supports kubeconfig, bearer token, and in-cluster credentials.

- **AwsExecutor**: AWS executor using boto3. Maps 13 AWS actions across 5 services (EC2, ECS, Lambda, S3, IAM). Request builders, state extractors, and datetime serialization. Supports access key, profile, and default credential chain.

- **13 AWS action definitions**: ec2-stop-instance, ec2-start-instance, ec2-reboot-instance, ec2-terminate-instance, ecs-update-service, ecs-stop-task, ecs-scale-service, lambda-update-function-config, lambda-invoke-function, s3-delete-object, s3-put-bucket-policy, iam-attach-role-policy, iam-detach-role-policy. All include credential scoping, risk classes, reversibility, and rollback params where applicable.

- **Optional dependencies**: `pip install agent-safe[k8s]` for kubernetes, `pip install agent-safe[aws]` for boto3, `pip install agent-safe[all]` for both. Lazy import guards — core package works without optional deps.

- **CLI executor options**: `--executor k8s` and `--executor aws` on `runner execute`. New options: `--aws-region`, `--aws-profile`, `--in-cluster`.

- **AWS inventory targets**: 4 example AWS targets (EC2 instance, ECS service, Lambda function, S3 bucket) in inventory.yaml.

- **SubprocessExecutor temp file cleanup**: Temp kubeconfig files created from credential payloads are now cleaned up after each execute/get_state call.

- **~130 new tests** across 5 files (test_k8s_executor.py, test_aws_executor.py, test_aws_actions.py, plus additions to test_runner_sdk.py and test_runner_cli.py). **1007 total tests**.

## [0.8.0] - 2026-02-24

Phase 2 -- Runner/Executor Framework.

### Added

- **Runner/Executor Framework**: Orchestrated governed action execution. The Runner validates execution tickets, resolves credentials, runs prechecks, captures before/after state, delegates to an Executor, audits the result, and revokes credentials — all in one lifecycle.

- **Executor protocol**: `typing.Protocol` with `execute()`, `get_state()`, and `run_prechecks()` methods. Any object satisfying the protocol works as a backend.

- **DryRunExecutor**: Built-in executor that simulates execution without side effects. Useful for testing, CI/CD dry-runs, and SDK integration tests.

- **SubprocessExecutor**: Runs kubectl commands via `subprocess.run`. Maps 17 K8s action names to kubectl command templates. Handles kubeconfig from credential payloads, custom kubectl paths, and command timeouts.

- **ExecutionResult model**: Structured outcome with status (SUCCESS/FAILURE/TIMEOUT/SKIPPED/ERROR), output, error, duration, precheck results, before/after state, and executor type.

- **SDK execute()**: `safe.execute(ticket_token)` convenience method. Creates a Runner internally with the SDK's components. Defaults to DryRunExecutor.

- **CLI runner commands**: `runner execute <token>` validates and executes. `runner dry-run <token>` shows what would happen. Both support `--executor`, `--json-output`, `--timeout`.

- **AuditLogger.log_execution()**: Logs execution results as `execution` events in the hash-chained audit log.

- **~87 new tests** across 4 files (test_runner.py, test_subprocess_executor.py, test_runner_sdk.py, test_runner_cli.py). **870 total tests**.

## [0.7.0] - 2026-02-24

Phase 2 -- Rollback Pairing.

### Added

- **Rollback Pairing**: Reversible actions can now generate compensating rollback plans from state capture data. The rollback itself goes through full PDP evaluation — no unaudited rollbacks.

- **RollbackPlan model**: Structured output describing how to reverse a previous action, including original/rollback params, before_state, and advisory warnings.

- **Declarative rollback_params in YAML**: Each reversible action declares how to derive rollback parameters using `source: params.<name>` or `source: before_state.<name>` dot-path syntax. Convention-based fallback when undeclared.

- **RollbackPlanner**: Core engine that resolves rollback parameters from original decision params + before_state via declared mappings or convention-based fallback. Produces advisory warnings for missing fields.

- **SDK rollback API**: `generate_rollback(audit_id)` returns a `RollbackPlan`. `check_rollback(audit_id, caller=None)` runs the rollback action through PDP with `correlation_id` linking to the original decision.

- **New CLI commands**: `rollback show <audit_id>` displays the rollback plan. `rollback check <audit_id>` generates the plan and evaluates it through PDP. Both support `--json-output`.

- **Action YAML extensions**: `rollback_params` added to 7 reversible actions (`scale-deployment`, `update-configmap`, `scale-hpa`, `update-hpa-limits`, `cordon-node`, `update-image`, `create-namespace`). `state_fields` added to 4 actions that previously lacked them.

- **AuditLogger.get_decision_event()**: New helper to look up a decision event by audit_id.

- **783 tests** (up from 689), covering rollback models, source resolution, planner (self-reversible, paired, convention, errors, warnings), SDK, CLI, and end-to-end flows.

## [0.6.0] - 2026-02-24

Phase 2 -- Before/After State Capture.

### Added

- **Before/After State Capture**: Executors can record target state before and after action execution. State data (before, after, diff) is stored in the audit log as `state_capture` events, linked to the original decision via `audit_id`. Enables compliance auditing of "what changed?" for every governed action.

- **StateCapture model**: Structured Pydantic model for state data with `before_state`, `after_state`, `diff`, `capture_duration_ms`, `state_fields_declared`, and `state_fields_captured` fields.

- **StateFieldSpec model**: Advisory state field declarations in action YAML. Tells executors what fields to capture per action type. Non-enforced — executors can capture any fields.

- **AuditEvent.event_type**: New field distinguishing `decision` events from `state_capture` events. Default `"decision"` for backward compatibility.

- **SDK state capture API**: `record_before_state()`, `record_after_state()`, `record_state()` (convenience), and `get_state_capture()` methods on `AgentSafe`.

- **Diff utility**: `compute_state_diff()` computes shallow dict diffs with added/removed/changed/unchanged categorization.

- **New CLI commands**: `audit show-state <audit_id>` displays state capture for a decision. `audit state-coverage` reports what percentage of decisions have state captures. `audit show --event-type` filters by event type.

- **Action YAML extensions**: `state_fields` block added to `scale-deployment`, `restart-deployment`, and `update-configmap` actions.

- **689 tests** (up from 610), covering state capture models, diff utility, audit logger, SDK, CLI, and end-to-end flows.

## [0.5.0] - 2026-02-24

Phase 2 -- Ticket/Incident Linkage.

### Added

- **Ticket/Incident Linkage**: Actions can reference an external change management ticket ID (JIRA, ServiceNow, PagerDuty, etc.) via `ticket_id` parameter. The ticket ID flows through the entire pipeline: SDK → PDP → policy matching → Decision → audit log. First-class audit field for compliance tracing.

- **Policy-level ticket requirement**: New `require_ticket` field on policy match conditions. Three-state matching: `true` (action must have a ticket), `false` (action must NOT have a ticket), `null`/omitted (don't care). Different rules can have different ticket requirements.

- **Decision.ticket_id**: Every Decision includes the ticket ID when provided, available via `to_dict()` and JSON output.

- **AuditEvent.ticket_id**: First-class audit field (like `correlation_id`), queryable and filterable in audit exports.

- **New CLI option**: `--ticket-id` on `check` command.

- **Policy testing support**: Test cases can include `ticket_id` in YAML, passed through to policy evaluation.

- **610 tests** (up from 577), covering ticket linkage models, PDP matching, SDK integration, CLI, and policy testing.

## [0.4.0] - 2026-02-24

Phase 2 -- Cumulative Risk Scoring.

### Added

- **Cumulative Risk Scoring**: Per-caller session-level risk tracking with sliding time window. Addresses Threat T7 (privilege escalation via action chaining). Configurable risk scores per risk class, escalation threshold (ALLOW → REQUIRE_APPROVAL), and deny threshold (any → DENY). Post-policy escalation layer -- policies evaluate individual actions, cumulative risk provides session awareness. Thread-safe, injectable clock for testing.

- **Decision annotations**: Every non-DENY decision includes `cumulative_risk_score` and `cumulative_risk_class` fields when cumulative risk is configured. `escalated_from` field shows the original decision result when escalation occurs.

- **Audit context enrichment**: Cumulative risk info (score, class, entry count, window) included in audit event context. Merged with delegation context when both are present.

- **New SDK parameter**: `cumulative_risk` (dict or `CumulativeRiskConfig`) on `AgentSafe.__init__`.

- **CLI enhancement**: `check` command output shows cumulative risk score and escalation info.

- **577 tests** (up from 540), covering cumulative risk config, scoring, sliding window, escalation, PDP integration, SDK integration, and thread safety.

## [0.3.0] - 2026-02-24

Phase 2.1 -- Multi-Agent Delegation, Credential Gating, and Approval Workflows.

### Added

- **Multi-Agent Delegation**: Orchestrator agents can delegate sub-tasks to worker agents with full governance tracking. Delegation chains are carried in the JWT (stateless PDP preserved). Strict scope narrowing -- child roles must be a subset of parent's. TTL inheritance -- child token cannot outlive parent. Configurable max delegation depth (default 5).

- **Delegation-Aware Policies**: New `CallerSelector` fields: `delegated_from` (match by chain origin), `max_delegation_depth` (limit chain depth), `require_delegation` (match only delegated or direct callers). Policies control who can delegate to whom.

- **Delegation Audit Trail**: Full delegation chain (agent IDs, roles, timestamps) recorded in audit event `context` field. Original caller tracked for provenance.

- **Credential Gating**: Agents never hold target credentials. Credentials are retrieved just-in-time via `resolve_credentials()` after ticket validation. `CredentialVault` protocol with `EnvVarVault` dev/test backend. Template engine (`{{ params.xyz }}`) resolves credential scopes from ticket parameters.

- **Approval Workflows**: `REQUIRE_APPROVAL` decisions create trackable approval requests. `FileApprovalStore` with JSONL persistence. `ApprovalNotifier` protocol with webhook and Slack notifiers. SDK orchestration via `wait_for_approval()` and `resolve_approval()`.

- **New models**: `DelegationLink`, `DelegationRequest`, `DelegationResult`, `CredentialScope`, `Credential`, `CredentialResult`, `ApprovalRequest`.

- **New SDK methods**: `delegate()`, `verify_delegation()`, `resolve_credentials()`, `revoke_credential()`, `wait_for_approval()`, `resolve_approval()`.

- **New CLI commands**:
  - `agent-safe delegation create` -- create a delegation token for a sub-agent
  - `agent-safe delegation verify` -- verify a delegation token and display the chain
  - `agent-safe credential resolve` -- resolve credentials for a valid execution ticket
  - `agent-safe credential test-vault` -- test vault connectivity
  - `agent-safe approval list/show/approve/deny` -- manage approval requests

- **540 tests** (up from 376), covering delegation, credentials, approvals, and all existing functionality.

## [0.2.0] - 2026-02-24

Phase 1.5 -- bridges advisory enforcement to ticket-based authorization.

### Added

- **Signed Execution Tickets**: ALLOW decisions include a signed, time-limited, single-use JWT token encoding the approved action, target, params, and expiry. Tokens use HMAC-SHA256 with a `type: "execution-ticket"` claim to prevent cross-use with identity JWTs. Configurable TTL (default 5 min), unique nonce per ticket.

- **Ticket Validator**: Standalone library for executors to validate tickets without a full AgentSafe instance. Validates JWT signature, expiry, issuer, type claim, action/target match, and single-use nonce tracking. Thread-safe via lock.

- **Rate Limiting + Circuit Breakers**: Per-caller sliding window rate limiting with configurable max requests and window duration. Circuit breaker auto-pauses agents that trigger too many DENY decisions within a window. Configurable threshold, window, and cooldown. Thread-safe, injectable clock for testing.

- **External Audit Log Shipping**: Pluggable shipper system dispatches audit events to external backends after each local write. Built-in shippers: FilesystemShipper (JSON lines to file), WebhookShipper (POST to URL, stdlib only), S3Shipper (upload to S3, optional boto3). Custom shippers via `AuditShipper` protocol. Fire-and-forget -- shipping failures warn but never block logging.

- **Policy Testing Framework**: `agent-safe test <path>` runs table-driven test cases against policy definitions. YAML test files specify action/target/caller/params and expected decision. Test suite reports pass/fail with reasons.

- **New CLI commands**:
  - `agent-safe test` -- run policy test cases
  - `agent-safe audit ship` -- ship audit events to filesystem, webhook, or S3
  - `agent-safe ticket verify` -- verify a signed execution ticket
  - `--signing-key` option on `check` command for ticket issuance

- **New SDK parameters**: `signing_key` (execution tickets), `rate_limit` (rate limiting config or dict), `audit_shippers` (shipper list or config dict).

- **New public exports**: `ExecutionTicket`, `TicketValidationResult`, `TicketValidator`.

- **Optional dependency**: `pip install agent-safe[s3]` installs boto3 for S3 audit shipping.

- **Claude Agent SDK demo**: `examples/claude_agent_demo.py` showing 4 policy scenarios.

- **376 tests** (up from 243), covering tickets, rate limiting, circuit breakers, shipping, and policy testing.

## [0.1.0] - 2026-02-24

Initial alpha release.

### Added

- **Action Registry**: YAML-based action definitions with parameter schemas, type constraints (string, integer, number, boolean, array), value constraints (min/max, pattern, enum, string length), risk classes (low/medium/high/critical), target types, reversibility flags, required privileges, and tags. SHA-256 integrity hashing per file.

- **Policy Decision Point (PDP)**: Stateless policy evaluator with default-deny model. Supports matching on action names (exact and glob patterns), target selectors (environment, sensitivity, type, labels), caller selectors (agent_id, roles, groups), effective risk class, and time windows (with midnight wrap). Priority-based evaluation -- highest priority first, first match wins.

- **Context-Aware Risk Matrix**: Effective risk computed from action risk class x target sensitivity. A medium-risk action on a critical-sensitivity target becomes critical effective risk.

- **Audit Log**: Hash-chained JSON lines format. Append-only, thread-safe writes. Chain verification for tamper detection. Chain resumption across logger restarts. Every `check()` call auto-logged.

- **Target Inventory**: YAML-based target definitions with id, type, environment, sensitivity, owner, and labels. O(1) lookup by target id.

- **Agent Identity**: JWT-based identity with HMAC-SHA256 signing. Claims include agent_id, roles, groups. Token creation and validation via IdentityManager. Automatic caller resolution in SDK (string, AgentIdentity, or JWT token).

- **Python SDK**: `AgentSafe` class wiring all components. `check()` for single action evaluation. `check_plan()` for batch evaluation. `list_actions()` and `verify_audit()` utilities.

- **CLI**: `agent-safe` command with subcommands:
  - `init` -- scaffold a new project with example actions, policies, and inventory
  - `check` -- evaluate a policy decision (colored output or JSON)
  - `list-actions` -- show registered actions with --tag and --risk filters
  - `validate` -- validate config files (registry, policies, inventory)
  - `audit verify` -- verify audit hash chain integrity
  - `audit show` -- show recent audit entries

- **K8s Action Catalogue**: 20 curated Kubernetes action definitions covering deployments (restart, scale, rollout-status, rollout-undo, update-image), pods (delete, get-logs, exec, port-forward), nodes (cordon, uncordon, drain), namespaces (create, delete), config (get-configmap, update-configmap, get-secret), HPA (scale, update-limits), and network policy.

- **Example Policies**: Default policy set with safety rails (deny critical risk, deny namespace deletion in prod), environment rules (require approval for prod), role-based rules (deployer access to staging), and catch-all (allow dev).

- **Demo**: End-to-end demo script (`examples/demo_agent.py`) showing 5 scenarios: dev unrestricted, staging role-based, prod locked down, dangerous operations, and batch plan checking.

- **Documentation**: Getting Started guide, Writing Actions guide, Writing Policies guide, Architecture decisions and data flow.

- **CI**: GitHub Actions workflow with ruff lint and pytest across Python 3.11, 3.12, 3.13.

- **243 tests** covering models, registry, inventory, identity, PDP, audit, SDK, CLI, edge cases, and malformed input handling.
