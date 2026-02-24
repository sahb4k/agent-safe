# Writing Policies

Policies are YAML files that define who can do what, where, and when. Agent-Safe uses a **default-deny** model: if no rule matches a request, it is denied.

## File Location

Place policy files in your policies directory (default: `./policies/`). Files must have a `.yaml` or `.yml` extension. Each file must have a top-level `rules:` key.

## How Evaluation Works

1. Rules are sorted by **priority** (highest first)
2. For each rule, all conditions in `match` must be true (AND logic)
3. Within a condition's list, any value can match (OR logic)
4. **First matching rule wins** - its decision is returned
5. If no rule matches: **DENY** (default-deny)

## Minimal Example

```yaml
rules:
  - name: allow-dev-all
    match:
      targets:
        environments:
          - dev
    decision: allow
    reason: Development environment is unrestricted
```

## Full Example

```yaml
rules:
  # High priority: safety rails
  - name: require-approval-critical-risk
    description: Critical effective risk requires human approval
    priority: 1000
    match:
      risk_classes:
        - critical
    decision: require_approval
    reason: Critical-risk actions always require human approval

  - name: deny-delete-namespace-prod
    description: Never allow namespace deletion in production
    priority: 900
    match:
      actions:
        - delete-namespace
      targets:
        environments:
          - prod
    decision: deny
    reason: Production namespace deletion is prohibited

  # Medium priority: operational rules
  - name: allow-deployer-staging
    description: Deploy agents can manage staging deployments
    priority: 100
    match:
      actions:
        - restart-deployment
        - scale-deployment
        - delete-pod
      targets:
        environments:
          - staging
      callers:
        roles:
          - deployer
    decision: allow
    reason: Deployer agents are authorized for staging

  # Low priority: catch-all
  - name: allow-dev-all
    priority: 10
    match:
      targets:
        environments:
          - dev
    decision: allow
    reason: Development environment is unrestricted
```

## Rule Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Unique rule name |
| `description` | string | `""` | What this rule does |
| `priority` | int | `50` | Higher = evaluated first |
| `match` | object | `{}` | Conditions (all must be true) |
| `decision` | string | required | `allow`, `deny`, or `require_approval` |
| `reason` | string | required | Human-readable explanation |

## Match Conditions

All conditions are optional. Omitted conditions match everything.

### Actions

Match by action name using exact names or glob patterns:

```yaml
match:
  actions:
    - restart-deployment       # exact match
    - "scale-*"                # glob: scale-deployment, scale-hpa, etc.
    - "*-deployment"           # glob: restart-deployment, scale-deployment, etc.
    - "*"                      # matches everything
```

### Target Selectors

Filter by target properties from the inventory:

```yaml
match:
  targets:
    environments:
      - prod
      - staging
    sensitivities:
      - critical
      - restricted
    types:
      - k8s-deployment
    labels:
      tier: backend
      team: platform
```

### Caller Selectors

Filter by agent identity (from JWT or bare ID):

```yaml
match:
  callers:
    agent_ids:
      - deploy-agent-01
      - deploy-agent-02
    roles:
      - deployer          # any of these roles
      - admin
    groups:
      - platform-team     # any of these groups
```

### Risk Classes

Match on the **effective risk** (action risk x target sensitivity):

```yaml
match:
  risk_classes:
    - critical
    - high
```

### Time Windows

Restrict when the rule applies:

```yaml
match:
  time_windows:
    - days: [5, 6]          # Saturday, Sunday (0=Monday)
      start_hour: 2
      end_hour: 6
    - start_hour: 22         # Overnight window (wraps midnight)
      end_hour: 4
```

## Priority Guidelines

| Range | Use For |
|-------|---------|
| 900-1000 | Safety rails (deny critical operations) |
| 500-899 | Environment-wide rules (require approval for prod) |
| 100-499 | Role-based operational rules |
| 10-99 | Catch-all / default rules |
| 1-9 | Absolute fallback |

## Common Patterns

### Lock down production

```yaml
- name: require-approval-prod
  priority: 500
  match:
    targets:
      environments: [prod]
  decision: require_approval
  reason: Production actions require explicit approval
```

### Allow read-only everywhere

```yaml
- name: allow-reads
  priority: 200
  match:
    actions:
      - "get-*"
      - rollout-status
  decision: allow
  reason: Read-only actions are always allowed
```

### Deny specific dangerous actions

```yaml
- name: deny-exec-prod
  priority: 900
  match:
    actions: [exec-pod]
    targets:
      environments: [prod]
  decision: deny
  reason: Pod exec is never allowed in production
```

### Time-based maintenance window

```yaml
- name: allow-maintenance
  priority: 600
  match:
    targets:
      environments: [prod]
    time_windows:
      - days: [5, 6]
        start_hour: 2
        end_hour: 6
  decision: allow
  reason: Production changes allowed during weekend maintenance
```

### Require a change ticket for production

```yaml
- name: allow-prod-with-ticket
  priority: 500
  match:
    targets:
      environments: [prod]
    require_ticket: true
  decision: allow
  reason: Production changes allowed with change ticket

- name: deny-prod-no-ticket
  priority: 400
  match:
    targets:
      environments: [prod]
    require_ticket: false
  decision: deny
  reason: Production changes require a change ticket
```

### Allow untracked changes in dev

```yaml
- name: allow-dev-no-ticket
  priority: 10
  match:
    targets:
      environments: [dev]
  decision: allow
  reason: Dev does not require a ticket
```

`require_ticket` supports three states:
- `true` — rule only matches when `ticket_id` is provided
- `false` — rule only matches when no `ticket_id`
- `null`/omitted (default) — matches regardless of ticket presence

## Delegation Policies

Control multi-agent delegation with CallerSelector fields:

### Restrict delegation depth

```yaml
- name: deny-deep-delegation
  description: Reject delegation chains deeper than 2
  priority: 900
  match:
    callers:
      max_delegation_depth: 2
  decision: deny
  reason: Delegation chain too deep (max 2 hops)
```

Note: `max_delegation_depth` matches when `depth <= value`. To deny depths > 2, use a deny rule with `max_delegation_depth: 2` at low priority, or use separate allow/deny rules.

### Require delegation from specific orchestrator

```yaml
- name: allow-from-orchestrator
  description: Allow actions delegated from trusted orchestrator
  priority: 500
  match:
    callers:
      delegated_from: [orchestrator-01, orchestrator-02]
  decision: allow
  reason: Delegated from trusted orchestrator
```

### Deny delegated callers for critical actions

```yaml
- name: deny-delegated-critical
  description: Critical actions must come from direct callers
  priority: 950
  match:
    risk_classes: [critical]
    callers:
      require_delegation: false
  decision: deny
  reason: Critical actions require direct (non-delegated) identity
```

Note: `require_delegation: true` matches only delegated callers, `false` matches only direct callers, and omitting it (or `null`) matches both.

## Cumulative Risk Scoring

Cumulative risk scoring operates as a **post-policy escalation layer** — it is not a policy match condition. Policies evaluate each action individually and return a decision. Then, if cumulative risk is configured, the risk tracker may escalate that decision based on accumulated risk within the caller's session window.

This means:
- You don't write cumulative risk rules in your policy files
- Policy rules control individual action decisions
- Cumulative risk adds session-level awareness on top
- Escalation only goes UP: ALLOW → REQUIRE_APPROVAL, REQUIRE_APPROVAL → DENY

Configure cumulative risk thresholds in the SDK:

```python
safe = AgentSafe(
    registry="./actions",
    policies="./policies",
    cumulative_risk={
        "escalation_threshold": 30,   # ALLOW → REQUIRE_APPROVAL
        "deny_threshold": 75,         # Any → DENY
    },
)
```

See [GETTING-STARTED.md](GETTING-STARTED.md#cumulative-risk-scoring) for full configuration.

## Validation

```bash
agent-safe validate --policies ./policies
```

## Tips

- Start with high-priority deny/require-approval rules, then add allow rules
- Use glob patterns (`*-deployment`) to cover action families
- Keep reasons clear and actionable - they appear in the audit log
- Test policies with `agent-safe check` before deploying
- Use priority spacing (10, 100, 500, 1000) to leave room for future rules
