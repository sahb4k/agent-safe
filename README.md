# Agent-Safe

**A governance and policy enforcement layer for AI agents and non-human identities.**

Agent-Safe is not an agent. It's the system that controls what agents are allowed to do.

[![CI](https://github.com/sahb4k/agent-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/sahb4k/agent-safe/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-safe)](https://pypi.org/project/agent-safe/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/agent-safe)](https://pypi.org/project/agent-safe/)

---

## The Problem

AI agents are getting access to production infrastructure. They restart deployments, scale services, modify configs, and drain nodes. But there's no standard way to answer:

- **Is this agent allowed to do this?** Not just "does it have credentials" but "should it?"
- **What did it do?** A tamper-proof record of every action request and decision.
- **How risky is this?** A `restart-deployment` in dev is fine. The same action in prod on a critical service is not.

Agent-Safe answers all three.

## How It Works

When an AI agent wants to perform an infrastructure action, Agent-Safe:

1. **Checks the action** against a versioned registry of known, approved actions
2. **Evaluates policy** -- is this caller allowed to do this action on this target, right now?
3. **Returns a decision** -- `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` with a reason
4. **Logs everything** -- append-only, hash-chained audit trail of every request and decision

```
Agent: "I want to restart-deployment on prod/api-server"
                    |
                    v
            +---------------+
            |  Agent-Safe   |
            |               |
            |  1. Action?   |-- restart-deployment (medium risk)
            |  2. Target?   |-- prod/api-server (critical sensitivity)
            |  3. Policy?   |-- "prod requires approval"
            |  4. Risk?     |-- medium x critical = CRITICAL
            |  5. Decision  |-- REQUIRE_APPROVAL
            |  6. Audit log |-- logged with hash chain
            +---------------+
                    |
                    v
Agent: "OK, I'll queue this for human review."
```

## Quick Start

### Install

```bash
pip install agent-safe            # Core (policy engine, DryRun/Subprocess executors)
pip install agent-safe[k8s]       # + K8sExecutor (kubernetes Python client)
pip install agent-safe[aws]       # + AwsExecutor (boto3)
pip install agent-safe[all]       # Everything
```

### Scaffold a project

```bash
agent-safe init myproject
cd myproject
```

This creates example actions, policies, and an inventory file.

### Check an action (CLI)

```bash
# Dev target -- should be ALLOW
agent-safe check restart-deployment \
    --target dev/test-app \
    --caller deploy-agent \
    --params '{"namespace": "dev", "deployment": "app"}' \
    --registry ./actions --policies ./policies --inventory ./inventory.yaml

# Prod target -- should be REQUIRE_APPROVAL
agent-safe check restart-deployment \
    --target prod/api-server \
    --caller deploy-agent \
    --params '{"namespace": "prod", "deployment": "api"}' \
    --registry ./actions --policies ./policies --inventory ./inventory.yaml
```

### Check an action (Python SDK)

```python
from agent_safe import AgentSafe

safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    inventory="./inventory.yaml",
    audit_log="./audit.jsonl",
)

decision = safe.check(
    action="restart-deployment",
    target="prod/api-server",
    caller="deploy-agent-01",
    params={"namespace": "prod", "deployment": "api-server"},
)

print(decision.result)         # REQUIRE_APPROVAL
print(decision.reason)         # "Production actions require explicit approval"
print(decision.effective_risk) # critical
print(decision.audit_id)       # evt-a1b2c3d4...
```

### Integrate with your agent

```python
from agent_safe import AgentSafe
from agent_safe.models import DecisionResult

safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    inventory="./inventory.yaml",
    audit_log="./audit.jsonl",
)

def agent_step(action, target, params):
    decision = safe.check(
        action=action,
        target=target,
        caller="my-agent",
        params=params,
    )

    if decision.result == DecisionResult.ALLOW:
        execute_action(action, target, params)
    elif decision.result == DecisionResult.REQUIRE_APPROVAL:
        queue_for_review(decision.reason)
    else:
        log_blocked(decision.reason)
```

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Action Registry** | YAML definitions of approved actions -- parameters, risk class, prechecks, target types |
| **Policy Decision Point (PDP)** | Evaluates (action, target, caller, time) -> decision. Stateless, local, fast. |
| **Audit Log** | Hash-chained JSON lines. Every request + decision + reason. Append-only, tamper-evident. |
| **Target Inventory** | What infrastructure exists, its environment (prod/staging/dev), sensitivity class |
| **Agent Identity** | JWT-based caller identity -- agent_id, roles, groups. HMAC-SHA256 signed. |
| **Execution Tickets** | Signed, time-limited, single-use tokens issued on ALLOW decisions. Bridges advisory to enforceable authorization. |
| **Rate Limiting** | Per-caller request throttling with sliding window. Circuit breaker auto-pauses agents that trigger too many denials. |
| **Audit Shipping** | Ship audit events to external immutable storage (S3, webhooks, filesystem) in real-time. |
| **Credential Gating** | Agents never hold target credentials. JIT scoped credentials via vault after ticket validation. |
| **Approval Workflows** | REQUIRE_APPROVAL triggers trackable requests with webhook/Slack notifications. |
| **Multi-Agent Delegation** | Orchestrator agents delegate to workers with chain tracking, scope narrowing, and delegation-aware policies. |
| **Cumulative Risk Scoring** | Per-caller session risk tracking. Escalates decisions when action chaining accumulates too much risk (T7 mitigation). |
| **Ticket/Incident Linkage** | Link actions to external change tickets (JIRA, ServiceNow, etc.). Policies can require tickets. First-class audit field for compliance. |
| **Before/After State Capture** | Record target state before and after action execution. Diffs stored in audit log for compliance. Advisory `state_fields` in action YAML. |
| **Rollback Pairing** | Generate compensating rollback plans from state capture data. Declarative `rollback_params` in YAML. Rollback goes through PDP — no unaudited rollbacks. |
| **Runner/Executor** | Orchestrated action execution: validate ticket → resolve credentials → prechecks → state capture → execute → audit → revoke. Pluggable `Executor` protocol with DryRunExecutor, SubprocessExecutor (kubectl), K8sExecutor (kubernetes Python client), and AwsExecutor (boto3). |
| **Context-Aware Risk** | Risk = f(action risk, target sensitivity). A medium action on a critical target = critical effective risk. |

## Key Design Decisions

- **Default-deny**: If no policy matches, the answer is DENY. An unconfigured system blocks everything.
- **Advisory + tickets**: Agent-Safe decides and logs. ALLOW decisions include a signed execution ticket that executors can validate before acting.
- **Stateless PDP**: No database. All context comes from the request + config files. Pure function: inputs -> output.
- **Context-aware risk**: Risk is not a property of the action alone. `restart-deployment` is medium risk. `restart-deployment` on `prod/payments` (critical sensitivity) is critical risk.

## K8s Action Catalogue

Agent-Safe ships with 20 curated Kubernetes action definitions:

| Category | Actions |
|----------|---------|
| **Deployments** | restart-deployment, scale-deployment, rollout-status, rollout-undo, update-image |
| **Pods** | delete-pod, get-pod-logs, exec-pod, port-forward |
| **Nodes** | cordon-node, uncordon-node, drain-node |
| **Namespaces** | create-namespace, delete-namespace |
| **Config** | get-configmap, update-configmap, get-secret |
| **HPA** | scale-hpa, update-hpa-limits |
| **Network** | apply-network-policy |

Each definition includes parameters with type constraints, risk class, reversibility flag, required K8s RBAC privileges, and tags.

## AWS Action Catalogue

Agent-Safe also ships with 13 curated AWS action definitions:

| Category | Actions |
|----------|---------|
| **EC2** | ec2-stop-instance, ec2-start-instance, ec2-reboot-instance, ec2-terminate-instance |
| **ECS** | ecs-update-service, ecs-stop-task, ecs-scale-service |
| **Lambda** | lambda-update-function-config, lambda-invoke-function |
| **S3** | s3-delete-object, s3-put-bucket-policy |
| **IAM** | iam-attach-role-policy, iam-detach-role-policy |

Each definition includes parameters, risk class, credential scoping (IAM actions + resources), reversibility, and rollback params where applicable.

## Batch Plan Checking

If your agent plans multi-step operations, check them all at once:

```python
plan = [
    {"action": "scale-deployment", "target": "staging/api", "params": {"namespace": "staging", "deployment": "api", "replicas": 3}},
    {"action": "update-image", "target": "staging/api", "params": {"namespace": "staging", "deployment": "api", "container": "api", "image": "api:v2"}},
    {"action": "restart-deployment", "target": "staging/api", "params": {"namespace": "staging", "deployment": "api"}},
]

decisions = safe.check_plan(plan)
# Returns a list of Decision objects, one per step
```

## Agent Identity (JWT)

For role-based access control, use JWT tokens:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    signing_key="shared-secret-key",
)

token = safe.identity.create_token(
    agent_id="deploy-agent-01",
    roles=["deployer"],
    groups=["platform-team"],
)

# Pass the token as the caller -- JWT is validated automatically
decision = safe.check(action="restart-deployment", caller=token, ...)
```

## Execution Tickets

When `signing_key` is set, ALLOW decisions include a signed execution ticket -- a JWT that executors can validate before acting:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    signing_key="shared-secret-key",
    audit_log="./audit.jsonl",
)

decision = safe.check(action="restart-deployment", target="dev/test-app",
                       caller="agent-01", params={"namespace": "dev", "deployment": "app"})

if decision.result == DecisionResult.ALLOW:
    print(decision.ticket.token)      # Signed JWT
    print(decision.ticket.nonce)      # Single-use nonce
    print(decision.ticket.expires_at) # Short TTL (5 min default)
```

Validate tickets on the executor side:

```python
from agent_safe import TicketValidator

validator = TicketValidator(signing_key="shared-secret-key")
result = validator.validate(token, expected_action="restart-deployment")
print(result.valid)   # True/False
print(result.reason)  # Human-readable reason
```

## Rate Limiting

Throttle per-agent request rates and auto-pause misbehaving agents:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    rate_limit={
        "max_requests": 50,              # Per caller, per window
        "window_seconds": 60,            # Sliding window
        "circuit_breaker_threshold": 10,  # DENY count to trip breaker
        "circuit_breaker_cooldown_seconds": 300,
    },
)
```

## Audit Log

Every `check()` call is logged to an append-only, hash-chained audit file:

```bash
# Verify the audit chain hasn't been tampered with
agent-safe audit verify ./audit.jsonl

# Show the last 10 entries
agent-safe audit show ./audit.jsonl --last 10

# Ship audit log to external storage
agent-safe audit ship ./audit.jsonl --backend filesystem --path ./backup.jsonl
agent-safe audit ship ./audit.jsonl --backend s3 --bucket my-audit-bucket
```

Ship events to external backends in real-time via the SDK:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    audit_log="./audit.jsonl",
    audit_shippers={"webhook_url": "https://siem.example.com/ingest"},
)
```

## Multi-Agent Delegation

When orchestrator agents delegate sub-tasks to workers, delegation chains track provenance:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    signing_key="shared-secret-key",
)

# Create parent identity
parent_token = safe.identity.create_token(
    agent_id="orchestrator-01",
    roles=["deployer", "reader"],
)

# Delegate to a worker with narrowed scope
result = safe.delegate(
    parent_token=parent_token,
    child_agent_id="worker-01",
    child_roles=["deployer"],  # Must be subset of parent's roles
)

# Worker uses delegation token for checks
decision = safe.check(
    action="restart-deployment",
    target="dev/test-app",
    caller=result.token,  # Carries full delegation chain
)
```

Delegation-aware policies control who can delegate and to what depth:

```yaml
rules:
  - name: allow-delegated-from-orchestrator
    match:
      callers:
        delegated_from: [orchestrator-01]
        max_delegation_depth: 2
    decision: allow
    reason: Delegated from trusted orchestrator
```

## Cumulative Risk Scoring

Prevent privilege escalation via action chaining by tracking per-caller risk over time:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    inventory="./inventory.yaml",
    cumulative_risk={
        "window_seconds": 3600,             # 1 hour sliding window
        "escalation_threshold": 30,          # ALLOW → REQUIRE_APPROVAL
        "deny_threshold": 75,                # Any → DENY
        "risk_scores": {"low": 1, "medium": 5, "high": 15, "critical": 50},
    },
)

# Individual low-risk actions are fine
d1 = safe.check("get-configmap", target="dev/test-app", caller="agent-01",
                 params={"namespace": "dev", "configmap": "cfg"})
# d1.result = ALLOW, d1.cumulative_risk_score = 1

# But chaining high-risk actions triggers escalation
d2 = safe.check("exec-pod", target="dev/debug-pod", caller="agent-01",
                 params={"namespace": "dev", "pod": "p", "command": ["ls"]})
d3 = safe.check("get-secret", target="dev/test-app", caller="agent-01",
                 params={"namespace": "dev", "secret": "db-creds"})
# d3.escalated_from = ALLOW → REQUIRE_APPROVAL due to cumulative risk
```

## Ticket/Incident Linkage

Link actions to external change management tickets for compliance:

```python
# SDK — pass ticket_id to check()
decision = safe.check(
    action="restart-deployment",
    target="prod/api-server",
    caller="deploy-agent-01",
    params={"namespace": "prod", "deployment": "api-server"},
    ticket_id="JIRA-1234",  # Links to external ticket
)
print(decision.ticket_id)  # "JIRA-1234" — also in audit log
```

```bash
# CLI — use --ticket-id
agent-safe check restart-deployment \
    --target prod/api-server \
    --params '{"namespace": "prod", "deployment": "api"}' \
    --ticket-id JIRA-1234
```

Policies can require a ticket for certain actions:

```yaml
rules:
  - name: require-ticket-prod
    priority: 500
    match:
      targets:
        environments: [prod]
      require_ticket: true
    decision: allow
    reason: Production changes allowed with ticket
```

## Policy Testing

Validate your policies against expected outcomes:

```bash
agent-safe test ./tests/ --registry ./actions --policies ./policies
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `agent-safe init [dir]` | Scaffold a new project with example config |
| `agent-safe check <action>` | Evaluate a policy decision |
| `agent-safe test <path>` | Run policy test cases |
| `agent-safe list-actions` | Show registered actions (with --tag/--risk filters) |
| `agent-safe validate` | Validate config files |
| `agent-safe audit verify <log>` | Verify audit hash chain integrity |
| `agent-safe audit show <log>` | Show audit entries |
| `agent-safe audit ship <log>` | Ship audit events to external backend |
| `agent-safe ticket verify <token>` | Verify a signed execution ticket |
| `agent-safe credential resolve <token>` | Resolve credentials for a valid ticket |
| `agent-safe credential test-vault` | Test vault connectivity |
| `agent-safe approval list/show/approve/deny` | Manage approval requests |
| `agent-safe runner execute <token>` | Execute an action via Runner (--executor dry-run/subprocess/k8s/aws) |
| `agent-safe runner dry-run <token>` | Dry-run an action (validate ticket, show what would happen) |
| `agent-safe delegation create <token>` | Create a delegation token for a sub-agent |
| `agent-safe delegation verify <token>` | Verify a delegation token and display chain |

## Docker (Sidecar)

```bash
docker build -t agent-safe .
docker run -v ./config:/config agent-safe check restart-deployment \
    --target prod/api-server \
    --registry /config/actions \
    --policies /config/policies \
    --inventory /config/inventory.yaml
```

## Documentation

- [Getting Started](docs/GETTING-STARTED.md) -- install, configure, first check, integrate with agent
- [Writing Actions](docs/WRITING-ACTIONS.md) -- define custom action definitions
- [Writing Policies](docs/WRITING-POLICIES.md) -- write policy rules
- [Architecture](docs/ARCHITECTURE.md) -- design decisions and data flow

## Project Status

**Alpha** (v0.9.0) -- core policy engine, SDK, CLI, audit log, K8s action catalogue (20 actions), AWS action catalogue (13 actions), execution tickets, rate limiting, audit shipping, approval workflows, credential gating, multi-agent delegation, cumulative risk scoring, ticket/incident linkage, before/after state capture, rollback pairing, Runner/Executor framework with DryRunExecutor, SubprocessExecutor, K8sExecutor, and AwsExecutor. 1007 tests passing.

What's next:
- Web dashboard (Phase 2.5)

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full roadmap.

## Contributing

Contributions welcome. The easiest way to start:

```bash
git clone https://github.com/sahb4k/agent-safe.git
cd agent-safe
pip install -e ".[dev]"
pytest tests/ -v
ruff check src/ tests/ examples/
```

Add new K8s actions in `actions/`, write policies in `policies/`, and run `agent-safe validate` to check your work.

## License

Apache 2.0
