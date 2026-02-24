# Agent-Safe — Threat Model

## Scope
This threat model covers the agent-safe system as deployed in advisory mode (MVP) and notes how threats evolve when enforcement is added later.

## Trust Boundaries

```
┌─ Trust Boundary 1: Agent Process ────────────────────────┐
│  Agent (untrusted: may be misaligned, prompt-injected,   │
│         or compromised)                                   │
│  agent-safe SDK (trusted: runs in-process)                │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌─ Trust Boundary 2: Policy Data ──────────────────────────┐
│  Action Registry (trusted if integrity-checked)           │
│  Policies (trusted if version-controlled)                 │
│  Target Inventory (trusted if maintained)                 │
│  Audit Log (trusted if append-only + hash-chained)        │
└──────────────────────────────────────────────────────────┘
         │
         ▼
┌─ Trust Boundary 3: Targets ──────────────────────────────┐
│  Kubernetes API, infrastructure                           │
│  (agent has direct access in advisory mode)               │
└──────────────────────────────────────────────────────────┘
```

**Key insight for MVP**: In advisory mode, Trust Boundary 3 is not protected by agent-safe. The agent can bypass the PDP entirely. The value is audit trail and compliance evidence, not enforcement.

---

## Threat Catalogue

### T1: PDP Bypass — Agent Ignores Decision
- **Preconditions**: Advisory mode. Agent has direct credentials/network access to targets.
- **Attack**: Agent calls `safe.check()`, gets DENY, executes the action anyway. Or agent skips calling `safe.check()` entirely.
- **Impact**: Complete governance bypass. Audit log is incomplete (if agent skips the check) or shows a DENY followed by the action happening anyway.
- **Likelihood**: HIGH in advisory mode (by design — this is the known limitation).
- **MVP Control**: Audit log records the DENY. If paired with K8s audit logs, the discrepancy is detectable. Document this as a known limitation.
- **Future Control (Phase 1.5+)**: Credential gating — agent never holds target credentials. Can't act without PDP approval. Execution tickets make bypass impossible.

### T2: Prompt Injection → Policy Evasion
- **Preconditions**: LLM-based agent receives adversarial input (from a ticket, email, log message, user input) that manipulates it into requesting a dangerous action framed as benign.
- **Attack**: Agent is tricked into calling `safe.check("get-pod-logs", target="prod/api", ...)` but then using the result to exfiltrate data, or into misrepresenting the action (calling check for action A but executing action B).
- **Impact**: PDP approves based on the stated action, but the actual execution differs.
- **Likelihood**: MEDIUM — depends on agent architecture and input handling.
- **MVP Control**: PDP evaluates the *declared action + target + caller*, not the agent's reasoning. If the agent lies about what it's going to do, advisory PDP can't prevent it. Audit log creates a paper trail.
- **Future Control**: Runner executes *exactly* the approved action (not whatever the agent wants). Execution ticket specifies precise action + params.

### T3: Action Registry Poisoning
- **Preconditions**: Attacker gains write access to the action registry (YAML files in the git repo, or the filesystem where they're stored).
- **Attack**: Modify an existing action definition (lower its risk class, remove prechecks, widen allowed targets) or add a new malicious action.
- **Impact**: PDP makes incorrect decisions based on poisoned definitions.
- **Likelihood**: LOW-MEDIUM (requires repo/filesystem access).
- **MVP Control**: Registry files are integrity-checked (SHA-256 hashes in a manifest). Git-based registry means changes require PRs/review. CI validates action schemas on every commit.
- **Future Control**: Signed action definitions (GPG-signed YAML). Runtime integrity verification against signed manifest.

### T4: Policy Tampering
- **Preconditions**: Attacker gains write access to policy files.
- **Attack**: Add a permissive policy (`allow * on * for *`), modify risk thresholds, or delete restrictive policies.
- **Impact**: PDP allows actions that should be denied.
- **Likelihood**: LOW-MEDIUM (same access requirements as T3).
- **MVP Control**: Policies in git with PR review. `agent-safe validate-policy` in CI catches syntax errors. Policy change audit (git log).
- **Future Control**: Policy signing. Policy change requires multi-party approval. Dashboard shows policy diff history.

### T5: Audit Log Tampering
- **Preconditions**: Attacker has write access to the host filesystem where audit logs are stored.
- **Attack**: Delete log entries, modify decisions (change DENY to ALLOW), truncate the log, or corrupt the hash chain.
- **Impact**: Compliance evidence is destroyed. Attacker covers their tracks.
- **Likelihood**: MEDIUM (if attacker has host access, they likely have file access).
- **MVP Control**: Hash-chained entries — any modification breaks the chain and is detectable via `agent-safe audit verify`. Log verification should be run periodically.
- **Future Control (Phase 1.5)**: Real-time log shipping to external immutable storage (S3 Object Lock). Separate verification process that detects gaps/tampering independently.

### T6: Denial of Service via Request Flooding
- **Preconditions**: Compromised or misconfigured agent sends high volume of check requests.
- **Attack**: Flood the PDP with requests, causing CPU/memory exhaustion on the sidecar, which may impact the agent process (since SDK runs in-process).
- **Impact**: Agent process degrades. Legitimate checks are delayed or fail.
- **Likelihood**: LOW-MEDIUM.
- **MVP Control**: SDK-level rate limiting (configurable max requests per second). Fast-fail on obviously invalid requests (unknown action, malformed params) before full policy evaluation.
- **Future Control**: Per-agent rate limits. Circuit breaker that auto-denies when rate exceeded. Alert on anomalous request volume.

### T7: Privilege Escalation via Action Chaining
- **Preconditions**: Individual actions are low-risk, but combining them achieves a high-risk outcome.
- **Attack**: Agent chains: `get-configmap` (read DB creds) → `exec-pod` (connect to DB) → data exfiltration. Each action may be individually approved.
- **Impact**: Agent achieves something no single policy would allow.
- **Likelihood**: MEDIUM — depends on action catalogue breadth and policy granularity.
- **MVP Control**: Risk classification should account for sensitive actions regardless of target (e.g., `exec-pod` is always HIGH risk, `get-secret` is always HIGH risk). Policy can match on action risk class.
- **Future Control (Phase 2)**: Cumulative risk scoring. Session-level policy evaluation tracks action sequences and escalates when cumulative risk exceeds threshold.

### T8: TOCTOU — State Changes Between Check and Action
- **Preconditions**: Advisory mode — agent checks, then acts. Time gap between check and action.
- **Attack**: Conditions change between PDP check and action execution. E.g., PDP allows "restart deployment" because it's not in a deploy window, but a deploy starts between check and restart.
- **Impact**: Action executes against unexpected state.
- **Likelihood**: LOW in practice (time gap is usually milliseconds to seconds).
- **MVP Control**: Accept this risk for MVP. Document it. Recommend agents check() and act() as close together as possible.
- **Future Control**: Execution tickets with short TTL (30s–5min). Runner re-validates prechecks at execution time.

### T9: Data Exfiltration via Read Actions
- **Preconditions**: Agent has legitimate access to read actions (get-configmap, get-pod-logs, get-secret).
- **Attack**: Agent uses read actions to extract sensitive data (secrets, credentials, PII) and exfiltrates via its own communication channels (LLM context, external API calls, logs).
- **Impact**: Data breach via authorized read path.
- **Likelihood**: MEDIUM — read actions are often under-policed.
- **MVP Control**: Read actions on sensitive resources (secrets, configmaps in sensitive namespaces) should be classified as HIGH risk. Policy should restrict `get-secret` as aggressively as write actions.
- **Future Control**: Output filtering/redaction. Runner can mask sensitive values in returned data. Data classification tags on action outputs.

### T10: Supply Chain — Malicious Action Implementation
- **Preconditions**: Actions reference external implementations (scripts, container images, Ansible playbooks).
- **Attack**: Attacker compromises the implementation (malicious code in a referenced script or image).
- **Impact**: Runner (when it exists) executes compromised code with production credentials.
- **Likelihood**: LOW for MVP (no Runner). MEDIUM for Phase 2+.
- **MVP Control**: Not applicable — no Runner in MVP. Action definitions are data (YAML), not executable code.
- **Future Control**: Pin implementations to specific versions/hashes. Verify integrity before execution. Run in isolated, ephemeral environments.

### T11: Agent Identity Spoofing
- **Preconditions**: Weak agent authentication (shared API key, predictable JWT, no signature verification).
- **Attack**: Malicious process crafts a JWT claiming to be a trusted agent with broader permissions.
- **Impact**: PDP grants access based on spoofed identity.
- **Likelihood**: LOW-MEDIUM (depends on JWT signing key management).
- **MVP Control**: JWT signed with HMAC-SHA256. Signing key stored securely (env var or file with restricted permissions). Validate signature, issuer, and expiry on every check.
- **Future Control**: Asymmetric signing (RSA/ECDSA). SPIFFE/SPIRE workload identity. Short-lived tokens with automatic rotation.

### T12: Rollback to Vulnerable State
- **Preconditions**: Rollback mechanism exists (Phase 2+). Previous state had known vulnerabilities.
- **Attack**: Trigger rollback to revert to a known-insecure configuration (old K8s config, old image with CVE).
- **Impact**: System is "safely" rolled back to an insecure state.
- **Likelihood**: LOW (requires rollback capability + knowledge of vulnerable state).
- **MVP Control**: Not applicable — no rollback in MVP.
- **Future Control**: Rollback targets go through PDP. Policy checks whether the rollback target state meets current security requirements.

---

## Risk Summary

| Threat | MVP Likelihood | MVP Impact | Post-Enforcement Likelihood | Priority |
|--------|---------------|------------|---------------------------|----------|
| T1: PDP Bypass | HIGH | HIGH | LOW (cred gating) | Accept for MVP |
| T2: Prompt Injection | MEDIUM | HIGH | MEDIUM (Runner helps) | Monitor |
| T3: Registry Poison | LOW-MED | HIGH | LOW-MED | Mitigate (integrity checks) |
| T4: Policy Tamper | LOW-MED | HIGH | LOW-MED | Mitigate (git + review) |
| T5: Audit Tamper | MEDIUM | HIGH | LOW (external shipping) | Mitigate (hash chain) |
| T6: DoS Flooding | LOW-MED | MEDIUM | LOW (rate limits) | Mitigate (rate limits) |
| T7: Action Chaining | MEDIUM | HIGH | MEDIUM | Mitigate (risk classification) |
| T8: TOCTOU | LOW | MEDIUM | LOW (tickets) | Accept for MVP |
| T9: Data Exfil | MEDIUM | HIGH | MEDIUM | Mitigate (policy on reads) |
| T10: Supply Chain | N/A (MVP) | N/A | MEDIUM | Future |
| T11: Identity Spoof | LOW-MED | HIGH | LOW (SPIFFE) | Mitigate (JWT signing) |
| T12: Rollback Vuln | N/A (MVP) | N/A | LOW | Future |
