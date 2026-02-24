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
pip install agent-safe
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
| **Context-Aware Risk** | Risk = f(action risk, target sensitivity). A medium action on a critical target = critical effective risk. |

## Key Design Decisions

- **Default-deny**: If no policy matches, the answer is DENY. An unconfigured system blocks everything.
- **Advisory enforcement**: Agent-Safe decides and logs. The agent executes (or doesn't). No credential gating in MVP.
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

## Audit Log

Every `check()` call is logged to an append-only, hash-chained audit file:

```bash
# Verify the audit chain hasn't been tampered with
agent-safe audit verify ./audit.jsonl

# Show the last 10 entries
agent-safe audit show ./audit.jsonl --last 10

# JSON output for piping
agent-safe audit show ./audit.jsonl --json-output
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `agent-safe init [dir]` | Scaffold a new project with example config |
| `agent-safe check <action>` | Evaluate a policy decision |
| `agent-safe list-actions` | Show registered actions (with --tag/--risk filters) |
| `agent-safe validate` | Validate config files |
| `agent-safe audit verify <log>` | Verify audit hash chain integrity |
| `agent-safe audit show <log>` | Show audit entries |

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

**Alpha** (v0.1.0) -- the core policy engine, SDK, CLI, audit log, and K8s action catalogue are complete and tested. Advisory enforcement only (decides + logs, does not execute).

What's next (post-MVP):
- Enforcement mode with signed execution tickets
- Human approval workflows
- OPA/Rego policy backend option
- Multi-cloud action catalogues (AWS, Azure, GCP)
- Web dashboard for audit trail

See [docs/MVP-PLAN.md](docs/MVP-PLAN.md) for the full roadmap.

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
