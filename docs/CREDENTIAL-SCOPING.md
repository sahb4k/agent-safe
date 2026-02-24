# Agent-Safe — Credential Scoping Design

## Status
**Design document only** — Phase 1.5 deliverable. Implementation planned for Phase 2 alongside the K8s Runner.

---

## Problem

In the current advisory + ticket model (Phase 1.5), agents hold their own credentials to targets (e.g., K8s kubeconfig, cloud IAM keys). Even when the PDP issues a DENY, the agent technically *can* still act — it just shouldn't. The execution ticket adds accountability but not enforcement.

True enforcement requires **credential gating**: the agent never holds target credentials. Credentials are retrieved just-in-time by an authorized executor (the Runner) only after validating a PDP-issued execution ticket.

---

## Goals

1. **Agents never hold long-lived target credentials** — they cannot bypass the PDP.
2. **Credentials are scoped to the approved action** — a ticket for "restart-deployment" cannot be used to "delete-namespace".
3. **Credentials are short-lived** — JIT retrieval with automatic expiry. No standing access.
4. **Credential retrieval is audited** — who got what credential, for which ticket, at what time.
5. **Vault-agnostic interface** — support HashiCorp Vault, AWS Secrets Manager, K8s Secrets, and custom backends.

---

## Architecture

```
Agent → SDK → PDP → ALLOW + Execution Ticket
                         │
                         ▼
                    Runner / Executor
                         │
                    1. Validate ticket (sig, expiry, nonce, action match)
                    2. Resolve credential scope from action definition
                    3. Retrieve scoped credential from vault (JIT)
                    4. Execute action with scoped credential
                    5. Revoke / let credential expire
                    6. Report result to audit log
```

### Key Insight

The **action definition** declares what credential scope is needed. The **Runner** maps that scope to a vault path and retrieves the credential. The agent never sees the credential.

---

## Action Definition Extension

Action YAML gains a `credentials` block:

```yaml
name: restart-deployment
version: "1.0"
risk_class: medium
credentials:
  type: kubernetes        # Credential type (kubernetes, aws-iam, ssh, custom)
  scope:
    verbs: ["get", "patch"]
    resources: ["deployments"]
    namespaces: ["{{ params.namespace }}"]   # Templated from action params
  ttl: 300                # Max credential lifetime in seconds
```

The `scope` block is type-specific:

| Credential Type | Scope Fields |
|----------------|-------------|
| `kubernetes` | `verbs`, `resources`, `namespaces`, `api_groups` |
| `aws-iam` | `actions` (IAM actions), `resources` (ARNs), `conditions` |
| `ssh` | `hosts`, `user`, `commands` (allowed command patterns) |
| `custom` | Arbitrary key-value pairs passed to the vault backend |

---

## Vault Interface

```python
class CredentialVault(Protocol):
    """Retrieve scoped, time-limited credentials."""

    def get_credential(
        self,
        scope: CredentialScope,
        ticket: ExecutionTicket,
        ttl: int = 300,
    ) -> Credential:
        """Retrieve a credential scoped to the given action.

        Args:
            scope: The credential scope from the action definition.
            ticket: The validated execution ticket (for audit correlation).
            ttl: Maximum credential lifetime in seconds.

        Returns:
            A Credential with the access token/kubeconfig/key and expiry.

        Raises:
            CredentialError: If the vault cannot issue a credential for this scope.
        """
        ...

    def revoke(self, credential_id: str) -> None:
        """Revoke a previously issued credential (best-effort)."""
        ...
```

### Credential Model

```python
@dataclass
class Credential:
    credential_id: str          # Unique ID for audit
    type: str                   # kubernetes, aws-iam, ssh, custom
    payload: dict[str, Any]     # Type-specific (kubeconfig, access key, SSH key, etc.)
    expires_at: datetime        # Absolute expiry
    scope: CredentialScope      # What this credential is authorized to do
    ticket_id: str              # Execution ticket that authorized this credential
```

### Credential Scope Model

```python
@dataclass
class CredentialScope:
    type: str                           # kubernetes, aws-iam, ssh, custom
    fields: dict[str, Any]              # Type-specific scope fields
    ttl: int = 300                      # Requested TTL in seconds
```

---

## Vault Backends

### HashiCorp Vault (Primary)

Uses Vault's dynamic secrets engines:
- **Kubernetes**: Vault K8s secrets engine creates a short-lived ServiceAccount token with a scoped Role/ClusterRole.
- **AWS**: Vault AWS secrets engine generates temporary IAM credentials with an inline policy scoped to the action.
- **SSH**: Vault SSH secrets engine signs a short-lived SSH certificate with principal and command restrictions.

```python
class HashiCorpVault:
    def __init__(self, addr: str, token: str | None = None, role: str | None = None):
        """Connect to HashiCorp Vault.

        Auth methods: token, kubernetes (in-cluster), approle.
        """

    def get_credential(self, scope, ticket, ttl=300):
        # Map scope.type to Vault secrets engine
        # POST to Vault API with scoped parameters
        # Return Credential with lease_id for revocation
```

### AWS Secrets Manager

For AWS-native deployments without HashiCorp Vault:
- Uses `sts:AssumeRole` with an inline session policy scoped to the action.
- Short-lived STS credentials (min 900s, max controlled by role).

### Kubernetes Secrets (Minimal)

For simple K8s-only deployments:
- Creates a short-lived ServiceAccount token via `TokenRequest` API.
- Binds to a Role with only the verbs/resources the action needs.
- Requires pre-created Roles per action (or a controller that creates them dynamically).

---

## Runner Credential Flow

```
1. Runner receives execution ticket from agent
2. Runner validates ticket (TicketValidator — already implemented in Phase 1.5)
3. Runner reads action definition from registry
4. Runner resolves credential scope:
   a. Read `credentials.scope` from action definition
   b. Template any parameter references (e.g., {{ params.namespace }})
   c. Build CredentialScope object
5. Runner calls vault.get_credential(scope, ticket, ttl)
6. Vault creates a scoped, short-lived credential
7. Runner executes action using the scoped credential
8. Runner logs result to audit (including credential_id)
9. Runner calls vault.revoke(credential_id) — best-effort cleanup
10. Credential auto-expires after TTL regardless
```

---

## Security Properties

### Least Privilege
Each credential is scoped to exactly the verbs, resources, and namespaces the action requires. A "restart-deployment" credential cannot list secrets or delete namespaces.

### Time-Limited
Credentials expire after a short TTL (default 5 minutes). Even if leaked, the window of exposure is bounded.

### Single-Use (via Ticket)
The credential is tied to a specific execution ticket. The ticket's nonce ensures it can only be used once. A second request with the same ticket gets no credential.

### Auditable
Every credential issuance is logged: who requested it, which ticket authorized it, what scope was granted, when it expires, and when it was revoked.

### Defense in Depth
Even if an agent obtains a credential through a bug, the credential is scoped and short-lived. Combined with the audit trail, exposure is detectable and limited.

---

## Migration Path

### Phase 1.5 (Current) → Phase 2

1. **No breaking changes** to the SDK. `AgentSafe.check()` continues to return decisions with tickets.
2. **Runner is additive** — it's a new component that consumes tickets, not a change to existing components.
3. **Agents can migrate incrementally**:
   - Start with advisory model (agent executes, ticket provides audit trail)
   - Move to Runner model (agent passes ticket to Runner, Runner executes)
   - Both modes can coexist in the same deployment

### Action Definition Backward Compatibility

The `credentials` block in action YAML is optional. Actions without it work exactly as they do today (advisory + ticket). Only actions with `credentials` defined can use the Runner's credential gating.

---

## What This Design Does NOT Cover

- **Vault cluster setup and operations** — this is the customer's responsibility
- **Network policies** to prevent agents from reaching targets directly — complementary but separate
- **Credential rotation** for the vault authentication itself (Runner's own Vault token)
- **Multi-vault configurations** — one vault per deployment for Phase 2
- **Credential caching** — always fetch fresh. Caching scoped credentials adds complexity and risk.

---

## Implementation Status

Steps 1-2, 6-8 are **implemented** in v0.3.0 with `EnvVarVault` as the dev/test backend:

1. ~~`CredentialScope` and `Credential` models (Pydantic)~~ ✅
2. ~~`CredentialVault` protocol~~ ✅
3. `KubernetesSecretsVault` backend — **future**
4. Runner skeleton — **future**
5. `HashiCorpVault` backend — **future**
6. ~~Audit integration~~ ✅
7. ~~CLI: `agent-safe credential resolve/test-vault`~~ ✅
8. ~~Documentation and examples~~ ✅

## Delegation and Credential Scoping

When orchestrator agents delegate to workers, credential scope is automatically narrowed through two layers:

1. **Identity layer**: Delegation tokens carry a strict subset of the parent's roles (enforced at creation time by `create_delegation_token()`). Workers cannot request roles the parent doesn't hold.

2. **Policy layer**: Delegation-aware policies (`delegated_from`, `max_delegation_depth`, `require_delegation`) control which delegated callers can access which actions. The PDP evaluates the worker's identity with delegation context.

3. **Credential layer**: The credential resolver resolves credentials based on the action definition's `CredentialScope`, not the caller's identity. Since the PDP already approved the action for the delegated caller, the credential scope is implicitly narrowed — workers only get credentials for actions they were approved to execute.

This layered approach means the credential resolver does not need delegation awareness. Scope narrowing is enforced by identity (subset roles) + policy (delegation-aware matching) + credential resolver (action-scoped credentials).
