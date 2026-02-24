# Writing Action Definitions

Action definitions are YAML files that describe what agents can do. Each file defines one action with its parameters, risk class, and metadata.

## File Location

Place action files in your actions directory (default: `./actions/`). Files must have a `.yaml` or `.yml` extension.

## Minimal Example

```yaml
name: restart-deployment
version: "1.0.0"
description: Restart a Kubernetes deployment.

parameters:
  - name: namespace
    type: string
    required: true
    description: Kubernetes namespace

risk_class: medium
target_types:
  - k8s-deployment
```

## Full Example

```yaml
name: scale-deployment
version: "1.0.0"
description: >
  Scale a Kubernetes deployment to a specified replica count.
  Can scale up or down.

parameters:
  - name: namespace
    type: string
    required: true
    description: Kubernetes namespace containing the deployment
  - name: deployment
    type: string
    required: true
    description: Name of the deployment to scale
  - name: replicas
    type: integer
    required: true
    description: Target replica count
    constraints:
      min_value: 0
      max_value: 100

risk_class: medium
target_types:
  - k8s-deployment

prechecks:
  - name: deployment-exists
    description: Verify the deployment exists
  - name: hpa-check
    description: Warn if HPA is active (scaling may be overridden)

reversible: true
rollback_action: scale-deployment
required_privileges:
  - "apps/deployments:patch"
  - "apps/deployments:get"
tags:
  - kubernetes
  - deployment
  - scaling
```

## Field Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique action name. Must match `^[a-z][a-z0-9-]*$` |
| `version` | string | Semantic version (e.g. `"1.0.0"`) |
| `description` | string | What this action does |
| `risk_class` | string | `low`, `medium`, `high`, or `critical` |
| `target_types` | list | Target types this action operates on (min 1) |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `parameters` | list | `[]` | Parameter definitions |
| `prechecks` | list | `[]` | Pre-execution checks |
| `reversible` | bool | `false` | Whether the action can be undone |
| `rollback_action` | string | `null` | Action to call for rollback |
| `required_privileges` | list | `[]` | K8s RBAC privileges needed |
| `tags` | list | `[]` | Searchable tags |
| `state_fields` | list | `[]` | Expected fields for before/after state capture |

## State Capture Fields

Actions can optionally declare what state fields executors should capture before and after execution. These declarations are advisory — they document what's expected but don't enforce it.

```yaml
state_fields:
  - name: replicas
    description: Current replica count
    type: integer
    required: true
  - name: available_replicas
    description: Number of available replicas
    type: integer
  - name: ready_replicas
    description: Number of ready replicas
    type: integer
```

Each state field has:
- `name` (required): Field name
- `description`: What the field represents
- `type`: Type hint (`string`, `integer`, `object`, `array`, `any`)
- `required`: Whether executors should always capture this field (default `false`)

State fields are used by the SDK's `record_after_state()` to report which declared fields were actually captured, enabling coverage analysis via `audit state-coverage`.

## Parameter Types

| Type | Python | Example |
|------|--------|---------|
| `string` | `str` | `"production"` |
| `integer` | `int` | `3` |
| `number` | `int` or `float` | `3.14` |
| `boolean` | `bool` | `true` |
| `array` | `list` | `["a", "b"]` |

## Parameter Constraints

```yaml
parameters:
  - name: replicas
    type: integer
    required: true
    constraints:
      min_value: 0       # minimum numeric value
      max_value: 100     # maximum numeric value

  - name: namespace
    type: string
    required: true
    constraints:
      min_length: 1      # minimum string length
      max_length: 63     # maximum string length
      pattern: "^[a-z][a-z0-9-]*$"  # regex pattern (fullmatch)

  - name: strategy
    type: string
    required: false
    constraints:
      enum:              # allowed values
        - "rolling"
        - "recreate"
```

## Risk Classes

Choose the risk class based on the worst-case impact of the action:

| Risk Class | When to Use | Examples |
|------------|-------------|---------|
| `low` | Read-only, no state change | get-pod-logs, rollout-status |
| `medium` | Reversible state change | restart-deployment, scale-deployment |
| `high` | Significant impact, may be hard to reverse | update-image, exec-pod, cordon-node |
| `critical` | Destructive or very high blast radius | drain-node, delete-namespace |

The PDP combines the action risk class with the target's sensitivity to compute an **effective risk**:

```
effective_risk = risk_matrix[action.risk_class][target.sensitivity]
```

This means a `medium` risk action on a `critical` sensitivity target becomes `critical` effective risk.

## Validation

Validate your action files:

```bash
agent-safe validate --registry ./actions
```

The registry loader validates:
- YAML syntax
- Schema compliance (required fields, types, patterns)
- Name uniqueness across all files
- SHA-256 integrity hash per file

## Tips

- Keep action names lowercase with hyphens: `restart-deployment`, not `RestartDeployment`
- One action per file
- Use descriptive parameter names and descriptions
- Set `reversible: true` and `rollback_action` when applicable
- Tag actions for filtering: `agent-safe list-actions --tag kubernetes`
- Start with `medium` risk and adjust based on blast radius
