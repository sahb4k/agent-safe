# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
