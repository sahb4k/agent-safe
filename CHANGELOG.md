# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
