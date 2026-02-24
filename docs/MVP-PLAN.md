# Agent-Safe MVP Plan (6–8 Weeks)

## Goal
Ship a credible, usable open-source policy decision sidecar for AI agents operating on Kubernetes.

**What the MVP is**: An Action Registry + PDP + Audit Log + Python SDK + CLI that any agent framework can integrate with. Advisory enforcement — decides and logs, does not execute.

**What the MVP is not**: An execution engine, an approval workflow, a dashboard, a multi-cloud platform.

## Success Criteria
- [ ] An agent using the SDK can submit action requests and get ALLOW/DENY/REQUIRE_APPROVAL decisions
- [ ] All decisions are logged in hash-chained, append-only audit log
- [ ] 20+ curated K8s action definitions ship with the project
- [ ] Policies are human-readable and testable
- [ ] One demo integration with a real agent framework (Claude Agent SDK or LangGraph)
- [ ] Published to PyPI, usable via `pip install agent-safe`
- [ ] README, docs, and examples are good enough for a developer to self-serve

---

## Phase 0: Foundation (Week 1–2)

### Week 1: Project Scaffolding
- [ ] Initialize Python project with `pyproject.toml` (ruff, pytest, Python 3.11+)
- [ ] Set up CI (GitHub Actions: lint, test, type-check)
- [ ] Create directory structure (see CLAUDE.md)
- [ ] Define and document the **Action Schema** (YAML spec for action definitions)
  - Fields: `name`, `version`, `description`, `parameters` (with types + constraints), `risk_class` (low/medium/high/critical), `target_types`, `prechecks`, `reversible` (bool), `required_privileges`, `tags`
- [ ] Define and document the **Policy Schema** (how rules reference actions, targets, callers)
  - Rule structure: `match` (action, target_selector, caller_selector, time_window) → `decision` (allow/deny/require_approval) + `reason`
  - Evaluation order: most-specific-match wins, default-deny
- [ ] Define and document the **Audit Event Schema** (JSON structure for log entries)
  - Fields: `event_id`, `timestamp`, `prev_hash`, `action`, `target`, `caller`, `params`, `decision`, `reason`, `policy_matched`, `context`
- [ ] Write the schema validation tests first (TDD)

### Week 2: Target Inventory + Identity Model
- [ ] Define **Target Inventory Schema** (YAML)
  - Fields: `id`, `type` (k8s-cluster, namespace, deployment, etc.), `environment` (prod/staging/dev), `sensitivity` (public/internal/restricted/critical), `owner`, `labels`
- [ ] Implement inventory loader + validator
- [ ] Define **Agent Identity Model**
  - JWT claims: `agent_id`, `agent_name`, `roles`, `groups`, `issued_at`, `expires_at`
  - Signing: HMAC-SHA256 for MVP (asymmetric later)
  - Identity validator: check signature, expiry, extract claims
- [ ] Write tests for inventory and identity

**Phase 0 Deliverable**: All schemas defined, validated, tested. No business logic yet, but the data model is solid.

---

## Phase 1a: Policy Core (Week 3–5)

### Week 3: Action Registry
- [ ] Implement YAML action loader (load all `actions/*.yaml` files)
- [ ] Schema validation on load (reject malformed actions)
- [ ] Version tracking (action `name@version`)
- [ ] Integrity checking (SHA-256 hash per action file, manifest of hashes)
- [ ] Registry API: `get_action(name)`, `list_actions()`, `validate_params(action, params)`
- [ ] Parameter validation (type checking, required fields, allowed values)
- [ ] Write 5 initial K8s action definitions:
  - `restart-deployment`
  - `scale-deployment`
  - `delete-pod`
  - `cordon-node`
  - `get-pod-logs`

### Week 4: Policy Decision Point
- [ ] Implement policy loader (YAML policy files from `policies/` directory)
- [ ] Policy rule matching engine:
  - Match on: action name, target selectors (env, sensitivity, labels), caller selectors (roles, groups, agent_id), time windows
  - Wildcards and glob patterns in selectors
  - Evaluation: collect all matching rules, most-specific wins, default-deny
- [ ] Decision output: `Decision(result, reason, matched_policy, risk_class, audit_id)`
- [ ] Context injection: PDP receives `(action, target, caller, params, timestamp)` and enriches from registry + inventory
- [ ] Risk evaluation: combine action `risk_class` with target `sensitivity` for effective risk
- [ ] Write policy evaluation tests (table-driven: input → expected decision)
- [ ] Create example policies:
  - "Allow low-risk actions on staging for any agent"
  - "Deny all actions on prod targets without approval"
  - "Allow deploy-agent to restart deployments in prod during maintenance windows"

### Week 5: Audit Log
- [ ] Implement hash-chained JSON-lines logger
  - Each entry: `{event_id, timestamp, prev_hash, sha256(entry), ...fields}`
  - Append-only file writer with file locking
  - Verification function: read log, check chain integrity
- [ ] Log every PDP request + decision (even for unknown actions)
- [ ] Correlation ID support (caller can pass `correlation_id` for request tracing)
- [ ] Log rotation support (new file per day/size, chain continues via cross-file reference)
- [ ] Integration: wire PDP → Audit so every `check()` call auto-logs

**Phase 1a Deliverable**: Working policy engine. `check(action, target, caller, params)` → `Decision` with full audit logging.

---

## Phase 1b: Integration Surface (Week 5–7)

### Week 5–6: SDK + CLI
- [ ] Python SDK — the public API:
  ```python
  from agent_safe import AgentSafe
  safe = AgentSafe(registry=..., policies=..., inventory=..., audit_log=...)
  decision = safe.check(action, target, caller, params)
  ```
- [ ] Decision object: `.result` (enum), `.reason` (str), `.risk_class`, `.audit_id`, `.to_dict()`
- [ ] Batch check: `safe.check_plan([list of actions])` → list of decisions (for agents planning multi-step operations)
- [ ] CLI entry point (`agent-safe` command):
  - `agent-safe check <action> --target <t> --caller <c> --params '{}'`
  - `agent-safe list-actions` (show registry)
  - `agent-safe validate-policy <policy_file>` (dry-run policy check)
  - `agent-safe audit verify <log_file>` (verify log chain integrity)
  - `agent-safe audit show --last 50` (show recent log entries)
- [ ] Configuration: `agent-safe.yaml` config file for paths and defaults

### Week 6–7: K8s Action Catalogue + Demo
- [ ] Write remaining K8s action definitions (target: 20+):
  - Deployment: `restart-deployment`, `scale-deployment`, `rollout-status`, `rollout-undo`, `update-image`
  - Pods: `delete-pod`, `get-pod-logs`, `exec-pod` (high risk), `port-forward`
  - Nodes: `cordon-node`, `uncordon-node`, `drain-node`
  - Namespace: `create-namespace`, `delete-namespace`
  - Config: `get-configmap`, `update-configmap`, `get-secret` (high risk)
  - HPA: `scale-hpa`, `update-hpa-limits`
  - Network: `apply-network-policy`
- [ ] Each action definition includes: params with types/constraints, risk class, prechecks (what to verify), reversibility flag, required privileges (K8s RBAC verbs)
- [ ] Write one end-to-end demo:
  - A simple agent (using Claude Agent SDK or LangGraph) that manages K8s deployments
  - Agent uses `agent-safe` SDK to check every action before executing
  - Show: action allowed in staging, denied in prod, require_approval for drain-node
  - Script or notebook that runs the full flow

**Phase 1b Deliverable**: Installable package, working CLI, 20+ actions, one real demo.

---

## Phase 1c: Ship It (Week 7–8)

### Week 7: Hardening
- [ ] Edge case testing: malformed inputs, unknown actions, empty inventory, conflicting policies
- [ ] Policy conflict detection: warn when two rules match with different decisions
- [ ] Performance: benchmark PDP decision time (target: <5ms per check)
- [ ] Error messages: clear, actionable errors for misconfigured registry/policies
- [ ] `agent-safe init` command: scaffold a new project with example actions/policies/inventory

### Week 8: Release
- [ ] Write developer guide (docs/GETTING-STARTED.md): install, configure, first check, integrate with agent
- [ ] Write action authoring guide (docs/WRITING-ACTIONS.md): how to define new actions
- [ ] Write policy authoring guide (docs/WRITING-POLICIES.md): how to write rules
- [ ] Publish to PyPI (`pip install agent-safe`)
- [ ] Build + publish container image (for sidecar deployment)
- [ ] GitHub release with changelog
- [ ] Write a launch post / blog-style README section explaining the "why"

**Phase 1c Deliverable**: Published, documented, usable open-source tool.

---

## Non-Goals for MVP (Explicitly Deferred)
These are documented in [FUTURE-BACKLOG.md](FUTURE-BACKLOG.md) with rationale:
- Runner/Executor
- Credential gating / enforcement
- Human approval workflows (UI/Slack)
- Rollback automation
- Dashboard / web UI
- Multi-cloud support
- Agent Supervisor
- OPA/Rego integration (start with simpler rule engine)
- Ticket/incident linkage
