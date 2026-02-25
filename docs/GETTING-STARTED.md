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
- `agent-safe.yaml` - project config with auto-generated signing key
- `.gitignore` - excludes secrets and runtime files
- `actions/` - 5 example actions (LOW to HIGH risk, K8s + AWS)
- `policies/default.yaml` - example policies (allow dev, require approval for prod/critical)
- `inventory.yaml` - 4 example targets (dev, staging, prod K8s + prod AWS)

The generated `agent-safe.yaml` looks like:

```yaml
# Paths (relative to this file)
registry: ./actions
policies: ./policies
inventory: ./inventory.yaml
audit_log: ./audit.jsonl

# HMAC signing key for execution tickets and identity tokens.
signing_key: "a1b2c3...64-hex-chars..."
```

All CLI commands and the SDK auto-discover this file, so you don't need to pass `--registry`, `--policies`, `--inventory`, or `--signing-key` flags.

### 2. Validate your config

```bash
agent-safe validate
```

### 3. List available actions

```bash
agent-safe list-actions
```

### 4. Check an action from the CLI

```bash
# Dev target - should be ALLOW
agent-safe check restart-deployment \
    --target dev/test-app \
    --caller deploy-agent \
    --params '{"namespace": "dev", "deployment": "app"}'

# Prod target - should be REQUIRE_APPROVAL
agent-safe check restart-deployment \
    --target prod/api-server \
    --caller deploy-agent \
    --params '{"namespace": "prod", "deployment": "api"}'
```

No `--registry` or `--policies` needed — they're read from `agent-safe.yaml`.

### 5. Use the Python SDK

```python
from agent_safe import AgentSafe

# Zero-config — auto-discovers agent-safe.yaml
safe = AgentSafe()

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

You can also pass paths explicitly — explicit args always override the config file:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    inventory="./inventory.yaml",
    audit_log="./audit.jsonl",
    signing_key="your-secret-key",
)
```

### 6. Integrate with your agent

```python
from agent_safe import AgentSafe
from agent_safe.models import DecisionResult

safe = AgentSafe()

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

## Config File (`agent-safe.yaml`)

Agent-Safe looks for `agent-safe.yaml` in the current directory and parent directories (like `.gitignore` or `pyproject.toml`). All paths in the config are resolved relative to the YAML file's location.

Supported fields:

```yaml
registry: ./actions          # Path to actions directory
policies: ./policies         # Path to policies directory
inventory: ./inventory.yaml  # Path to inventory file
audit_log: ./audit.jsonl     # Path to audit log
signing_key: "hex-string"    # HMAC signing key (256-bit)
issuer: agent-safe           # JWT issuer name
```

**Precedence:** explicit args > config file > built-in defaults (`./actions`, `./policies`, etc.)

**Security:** The config file contains your signing key. Add it to `.gitignore` (the `init` command does this automatically).

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
safe = AgentSafe()  # signing_key loaded from agent-safe.yaml

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

## Execution Tickets

When `signing_key` is set, ALLOW decisions include a signed execution ticket that executors can validate:

```python
safe = AgentSafe()

decision = safe.check(
    action="restart-deployment", target="dev/test-app",
    caller="agent-01", params={"namespace": "dev", "deployment": "app"},
)

# ALLOW decisions include a ticket
if decision.ticket:
    print(decision.ticket.token)       # Signed JWT
    print(decision.ticket.expires_at)  # Short TTL (5 min default)
```

Validate tickets on the executor side:

```python
from agent_safe import TicketValidator

validator = TicketValidator(signing_key="shared-secret-key")
result = validator.validate(token, expected_action="restart-deployment")
if result.valid:
    execute_action(result.ticket.action, result.ticket.params)
```

Or from the CLI:

```bash
agent-safe ticket verify "$TOKEN"
```

The `--signing-key` flag is only needed if you don't have an `agent-safe.yaml`.

## Rate Limiting

Throttle per-agent request rates and auto-pause misbehaving agents:

```python
safe = AgentSafe(
    rate_limit={
        "max_requests": 50,               # Per caller, per window
        "window_seconds": 60,             # Sliding window
        "circuit_breaker_threshold": 10,   # DENY count to trip breaker
        "circuit_breaker_cooldown_seconds": 300,
    },
)
```

When a caller exceeds the rate limit, `check()` returns DENY with a reason like `"Rate limit exceeded for caller 'agent-01': 50 requests per 60s window."` The circuit breaker auto-pauses agents that trigger too many denials.

## Cumulative Risk Scoring

Prevent privilege escalation via action chaining (Threat T7). When an agent chains individually low-risk actions to achieve a high-risk outcome, cumulative risk scoring escalates decisions:

```python
safe = AgentSafe(
    cumulative_risk={
        "window_seconds": 3600,             # 1 hour sliding window
        "escalation_threshold": 30,          # ALLOW -> REQUIRE_APPROVAL
        "deny_threshold": 75,                # Any non-DENY -> DENY
        "risk_scores": {                     # Points per risk class
            "low": 1, "medium": 5, "high": 15, "critical": 50,
        },
    },
)
```

How it works:
- Each non-DENY `check()` call records the effective risk score for the caller
- Scores accumulate within a sliding time window
- When cumulative score reaches `escalation_threshold`, ALLOW decisions become REQUIRE_APPROVAL
- When cumulative score reaches `deny_threshold`, all non-DENY decisions become DENY
- Every decision includes `cumulative_risk_score` and `cumulative_risk_class` for visibility
- DENY decisions do not accumulate risk (the action wasn't approved)

```python
decision = safe.check("exec-pod", target="dev/debug-pod", caller="agent-01",
                       params={"namespace": "dev", "pod": "p", "command": ["ls"]})
print(decision.cumulative_risk_score)   # Current score in window
print(decision.cumulative_risk_class)   # low/medium/high/critical
print(decision.escalated_from)          # Original decision if escalated (e.g., "allow")
```

Note: Cumulative risk is tracked in-memory per SDK instance. It's designed for long-running agent processes, not one-shot CLI calls.

## Ticket/Incident Linkage

Link actions to external change management tickets (JIRA, ServiceNow, PagerDuty) for compliance tracing:

```python
# Pass a ticket ID with any check
decision = safe.check(
    action="restart-deployment",
    target="prod/api-server",
    caller="deploy-agent-01",
    params={"namespace": "prod", "deployment": "api-server"},
    ticket_id="JIRA-1234",
)

print(decision.ticket_id)  # "JIRA-1234"
# Also recorded in the audit log as a first-class field
```

Policies can require a ticket for specific actions or environments:

```yaml
rules:
  # Production changes require a ticket
  - name: allow-prod-with-ticket
    priority: 500
    match:
      targets:
        environments: [prod]
      require_ticket: true
    decision: allow
    reason: Production changes allowed with change ticket

  # Without a ticket, deny prod
  - name: deny-prod-no-ticket
    priority: 400
    match:
      targets:
        environments: [prod]
      require_ticket: false
    decision: deny
    reason: Production changes require a change ticket
```

The `require_ticket` field supports three states:
- `true` -- rule only matches when `ticket_id` is provided
- `false` -- rule only matches when `ticket_id` is NOT provided
- `null`/omitted -- rule matches regardless of ticket presence

From the CLI:

```bash
agent-safe check restart-deployment \
    --target prod/api-server \
    --params '{"namespace": "prod", "deployment": "api"}' \
    --ticket-id JIRA-1234
```

Ticket IDs also work in batch plan checking:

```python
decisions = safe.check_plan([
    {
        "action": "restart-deployment",
        "target": "prod/api-server",
        "params": {"namespace": "prod", "deployment": "api"},
        "ticket_id": "JIRA-1234",  # Per-step ticket ID
    },
])
```

The ticket ID is opaque to Agent-Safe -- it can be a JIRA key, ServiceNow incident number, URL, or any string. Validation of the ticket's existence is the caller's responsibility.

## Before/After State Capture

Record target state before and after action execution for audit and compliance:

```python
safe = AgentSafe()

# 1. Get a decision
decision = safe.check(
    action="scale-deployment",
    target="dev/test-app",
    caller="agent-01",
    params={"namespace": "dev", "deployment": "app", "replicas": 5},
)

if decision.result == DecisionResult.ALLOW:
    # 2. Capture state before execution
    safe.record_before_state(decision.audit_id, {
        "replicas": 2,
        "available_replicas": 2,
    })

    # 3. Execute the action
    # kubectl scale deployment app --replicas=5 -n dev

    # 4. Capture state after execution
    capture = safe.record_after_state(
        decision.audit_id,
        {"replicas": 5, "available_replicas": 3},
        action="scale-deployment",
        target="dev/test-app",
        caller="agent-01",
    )

    print(capture.diff)  # {"changed": {"replicas": {"old": 2, "new": 5}}, ...}
```

Or use the convenience method for one-shot capture:

```python
capture = safe.record_state(
    decision.audit_id,
    before={"replicas": 2},
    after={"replicas": 5},
    action="scale-deployment",
)
```

Inspect state captures from the CLI:

```bash
# Show state capture for a specific decision
agent-safe audit show-state evt-abc123 --log-file ./audit.jsonl

# Show state capture coverage across all decisions
agent-safe audit state-coverage ./audit.jsonl

# Filter audit log by event type
agent-safe audit show ./audit.jsonl --event-type state_capture
```

## Rollback Pairing

When a reversible action has state capture data, generate a rollback plan:

```python
# After executing and recording state for a scale-deployment...
plan = safe.generate_rollback(decision.audit_id)
print(f"Rollback: {plan.rollback_action}")
print(f"Params: {plan.rollback_params}")
# -> Rollback: scale-deployment
# -> Params: {"namespace": "dev", "deployment": "api", "replicas": 2}

# Run the rollback through PDP (no unaudited rollbacks)
rb_decision = safe.check_rollback(decision.audit_id)
if rb_decision.result.value == "ALLOW":
    # Agent executes the rollback action
    pass
```

Rollback from the CLI:

```bash
# Show the rollback plan for a decision
agent-safe rollback show evt-abc123

# Generate plan and evaluate through PDP
agent-safe rollback check evt-abc123

# JSON output
agent-safe rollback show evt-abc123 --json-output
```

Rollback parameters are declared in action YAML using `source:` syntax:

```yaml
rollback_params:
  namespace:
    source: params.namespace      # Copy from original params
  replicas:
    source: before_state.replicas  # Restore from captured state
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
agent-safe audit ship ./audit.jsonl --backend webhook --url https://siem.example.com/ingest
agent-safe audit ship ./audit.jsonl --backend s3 --bucket my-audit-bucket
```

### Real-time Audit Shipping

Ship events to external backends automatically as they're logged:

```python
safe = AgentSafe(
    audit_shippers={"webhook_url": "https://siem.example.com/ingest"},
)
# Every check() now ships events to the webhook after local write
```

Multiple backends can be configured simultaneously:

```python
safe = AgentSafe(
    audit_shippers={
        "filesystem_path": "/mnt/nfs/audit-backup.jsonl",
        "webhook_url": "https://siem.example.com/ingest",
        "s3_bucket": "my-audit-bucket",
    },
)
```

For S3 shipping, install the optional dependency: `pip install agent-safe[s3]`

## Multi-Agent Delegation

When an orchestrator agent needs to delegate sub-tasks to worker agents, use delegation tokens:

```python
safe = AgentSafe()  # signing_key loaded from agent-safe.yaml

# Create orchestrator identity
parent_token = safe.identity.create_token(
    agent_id="orchestrator-01",
    roles=["deployer", "reader"],
    groups=["infra-team"],
)

# Delegate to a worker with narrowed scope
result = safe.delegate(
    parent_token=parent_token,
    child_agent_id="worker-01",
    child_roles=["deployer"],  # Subset of parent's roles
)

if result.success:
    # Worker uses the delegation token
    decision = safe.check(
        action="restart-deployment",
        target="dev/test-app",
        caller=result.token,
        params={"namespace": "dev", "deployment": "app"},
    )
    # Audit log includes full delegation chain
```

From the CLI:

```bash
# Create a delegation token
agent-safe delegation create "$PARENT_TOKEN" \
    --child-id worker-01 \
    --roles deployer

# Verify a delegation token
agent-safe delegation verify "$CHILD_TOKEN"
```

## Policy Testing

Validate your policies against expected outcomes with table-driven test cases:

```bash
agent-safe test ./tests/
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `agent-safe init [dir]` | Scaffold a new project (config, actions, policies, inventory) |
| `agent-safe check <action>` | Evaluate a policy decision |
| `agent-safe test <path>` | Run policy test cases |
| `agent-safe list-actions` | Show registered actions |
| `agent-safe validate` | Validate config files |
| `agent-safe audit verify <log>` | Verify audit chain |
| `agent-safe audit show <log>` | Show audit entries |
| `agent-safe audit ship <log>` | Ship audit events to external backend |
| `agent-safe ticket verify <token>` | Verify execution ticket |
| `agent-safe credential resolve <token>` | Resolve credentials for a valid ticket |
| `agent-safe credential test-vault` | Test vault connectivity |
| `agent-safe approval list/show/approve/deny` | Manage approval requests |
| `agent-safe delegation create <token>` | Create a delegation token |
| `agent-safe delegation verify <token>` | Verify delegation token and chain |

All commands auto-discover `agent-safe.yaml`. Use `--registry`, `--policies`, etc. to override.

## Web Dashboard

Agent-Safe includes a web dashboard for visualizing audit logs, actions, policies, and agent activity.

### Free Tier (read-only)

```bash
pip install agent-safe[dashboard]
agent-safe dashboard
```

Opens a browser at `http://localhost:8000` with:
- Audit log viewer (search, filter, timeline)
- Action catalogue browser
- Policy visualizer
- Agent activity feed

### Paid Tier (team / enterprise)

The paid tier adds multi-cluster management, auth, reports, alert rules, and SSO. Configure via environment variables:

```bash
# Required for paid tier
export AGENT_SAFE_DASHBOARD_TIER=team          # or "enterprise"
export AGENT_SAFE_DASHBOARD_SIGNING_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Initial admin user (created on first boot)
export AGENT_SAFE_DASHBOARD_ADMIN_USERNAME=admin
export AGENT_SAFE_DASHBOARD_ADMIN_PASSWORD=changeme

agent-safe dashboard
```

**Team tier features:**
- JWT authentication with role-based access (admin / viewer)
- User management (admin CRUD)
- Multi-cluster management (register clusters, API key rotation)
- Centralized audit aggregation (sidecars ship events via ingest API)
- Compliance reports (SOC2, ISO 27001 evidence export)
- Managed policies (create/edit/version policies, sync to sidecars)
- Alert rules (conditions, thresholds, cooldowns, webhook/Slack notifications)

**Enterprise tier adds:**
- SSO via OIDC (Google, Azure AD, Okta, Keycloak, Auth0)
- Auto-provisioning of SSO users with configurable default roles

### SSO Configuration (Enterprise)

```bash
export AGENT_SAFE_DASHBOARD_TIER=enterprise
export AGENT_SAFE_DASHBOARD_OIDC_ENABLED=true
export AGENT_SAFE_DASHBOARD_OIDC_PROVIDER_URL=https://accounts.google.com
export AGENT_SAFE_DASHBOARD_OIDC_CLIENT_ID=your-client-id
export AGENT_SAFE_DASHBOARD_OIDC_CLIENT_SECRET=your-client-secret
export AGENT_SAFE_DASHBOARD_OIDC_DEFAULT_ROLE=viewer

# Optionally disable password auth when SSO is the sole auth method
export AGENT_SAFE_DASHBOARD_PASSWORD_AUTH_ENABLED=false
```

### Alert Rules

Alert rules let you get notified when critical events occur across your clusters. Configure in the dashboard UI:

1. **Conditions**: Match on risk class (high, critical), decision (deny), event type, or action patterns (glob syntax)
2. **Threshold**: "5 matching events in 10 minutes" or "every matching event" (threshold=1)
3. **Channels**: Webhook URL and/or Slack webhook
4. **Cooldown**: Minimum time between repeated alerts for the same rule (default 5 minutes)

Alert history is logged and visible in the dashboard.

### Policy Sync (Sidecar Integration)

Sidecars can pull managed policies from the dashboard:

```python
from agent_safe import PolicySyncClient

sync = PolicySyncClient(
    dashboard_url="https://dashboard.example.com",
    api_key="cluster-api-key",
    policies_dir="./policies",
    poll_interval=60,
)
sync.start()  # Polls for policy updates in a background thread
```

## Next Steps

- [Writing Actions](WRITING-ACTIONS.md) - define custom action definitions
- [Writing Policies](WRITING-POLICIES.md) - write policy rules
- [Architecture](ARCHITECTURE.md) - understand how it all fits together
- [Credential Scoping](CREDENTIAL-SCOPING.md) - credential gating design
