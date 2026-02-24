# Getting Started with Agent-Safe

## Installation

```bash
pip install agent-safe
```

Or from source:

```bash
git clone https://github.com/sahb4k/agent-safe.git
cd agent-safe
pip install -e ".[dev]"
```

## Quick Start

### 1. Scaffold a project

```bash
agent-safe init myproject
cd myproject
```

This creates:
- `actions/restart-deployment.yaml` - example action definition
- `policies/default.yaml` - example policies (allow dev, require approval for prod)
- `inventory.yaml` - example target inventory

### 2. Validate your config

```bash
agent-safe validate --registry ./actions --policies ./policies --inventory ./inventory.yaml
```

### 3. Check an action from the CLI

```bash
# Dev target - should be ALLOW
agent-safe check restart-deployment \
    --target dev/test-app \
    --caller deploy-agent \
    --params '{"namespace": "dev", "deployment": "app"}' \
    --registry ./actions \
    --policies ./policies \
    --inventory ./inventory.yaml

# Prod target - should be REQUIRE_APPROVAL
agent-safe check restart-deployment \
    --target prod/api-server \
    --caller deploy-agent \
    --params '{"namespace": "prod", "deployment": "api"}' \
    --registry ./actions \
    --policies ./policies \
    --inventory ./inventory.yaml
```

### 4. Use the Python SDK

```python
from agent_safe import AgentSafe

safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    inventory="./inventory.yaml",
    audit_log="./audit.jsonl",     # optional: enables audit logging
    signing_key="your-secret-key", # optional: enables JWT identity
)

# Check a single action
decision = safe.check(
    action="restart-deployment",
    target="prod/api-server",
    caller="deploy-agent-01",
    params={"namespace": "prod", "deployment": "api-server"},
)

print(decision.result)        # ALLOW, DENY, or REQUIRE_APPROVAL
print(decision.reason)        # Human-readable explanation
print(decision.audit_id)      # Unique event ID for tracing
print(decision.risk_class)    # Action's base risk class
print(decision.effective_risk) # Risk after considering target sensitivity
```

### 5. Integrate with your agent

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
    """Before executing any action, check with Agent-Safe."""
    decision = safe.check(
        action=action,
        target=target,
        caller="my-agent",
        params=params,
    )

    if decision.result == DecisionResult.ALLOW:
        execute_action(action, target, params)
    elif decision.result == DecisionResult.REQUIRE_APPROVAL:
        print(f"Needs approval: {decision.reason}")
        # Queue for human review
    else:
        print(f"Blocked: {decision.reason}")
        # Skip or retry with different params
```

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

# Create a token for an agent
token = safe.identity.create_token(
    agent_id="deploy-agent-01",
    roles=["deployer"],
    groups=["platform-team"],
)

# Pass the token as the caller
decision = safe.check(
    action="restart-deployment",
    caller=token,  # JWT is validated automatically
    params={"namespace": "staging", "deployment": "api"},
)
```

## Audit Log

Every `check()` call is logged to an append-only, hash-chained audit file:

```bash
# Verify the audit chain hasn't been tampered with
agent-safe audit verify ./audit.jsonl

# Show the last 10 entries
agent-safe audit show ./audit.jsonl --last 10

# JSON output for piping to other tools
agent-safe audit show ./audit.jsonl --json-output
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `agent-safe init [dir]` | Scaffold a new project |
| `agent-safe check <action>` | Evaluate a policy decision |
| `agent-safe list-actions` | Show registered actions |
| `agent-safe validate` | Validate config files |
| `agent-safe audit verify <log>` | Verify audit chain |
| `agent-safe audit show <log>` | Show audit entries |

## Next Steps

- [Writing Actions](WRITING-ACTIONS.md) - define custom action definitions
- [Writing Policies](WRITING-POLICIES.md) - write policy rules
- [Architecture](ARCHITECTURE.md) - understand how it all fits together
