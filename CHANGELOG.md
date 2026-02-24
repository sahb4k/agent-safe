# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
