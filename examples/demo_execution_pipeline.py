#!/usr/bin/env python3
"""Demo: Full Governed Execution Pipeline.

Walks through the complete execution lifecycle: policy check, ticket
issuance, credential resolution, state capture, DryRun execution,
audit logging, and rollback generation. Shows every layer working
together in a single flow.

Run from the project root:
    python examples/demo_execution_pipeline.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_safe import AgentSafe
from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.models import DecisionResult

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _mask(value: str, visible: int = 8) -> str:
    """Mask a string, showing only the first N characters."""
    if len(value) <= visible:
        return value
    return value[:visible] + "****"


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    # Clean up from previous runs
    audit_file = project_root / "examples" / "demo_pipeline_audit.jsonl"
    audit_file.unlink(missing_ok=True)

    # Create a vault with mock credentials
    vault = EnvVarVault(credentials={
        "kubernetes": {
            "token": "k8s-demo-token-xK9mP2nQ",
            "cluster": "staging-cluster.example.com",
        },
    })

    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=audit_file,
        signing_key="demo-signing-key-exec-pipeline-32b",
        credential_vault=vault,
    )

    deployer_token = safe.identity.create_token(
        agent_id="deploy-agent-01",
        agent_name="Deploy Agent",
        roles=["deployer"],
        groups=["platform-team"],
    )

    print(f"\n{BOLD}{'=' * 70}")
    print("  Agent-Safe Demo: Full Execution Pipeline")
    print(f"{'=' * 70}{RESET}")

    # --- Phase 1: Policy check + ticket issuance ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 1: Policy Check + Ticket Issuance")
    print(f"{'-' * 70}{RESET}")

    decision = safe.check(
        action="scale-deployment",
        target="staging/api-server",
        caller=deployer_token,
        params={
            "namespace": "staging",
            "deployment": "api-server",
            "replicas": 5,
        },
    )

    print("  Action:    scale-deployment")
    print("  Target:    staging/api-server (internal)")
    print(f"  Decision:  {GREEN}{decision.result.value.upper()}{RESET}")
    print(f"  Policy:    {decision.policy_matched or 'default'}")

    if decision.result != DecisionResult.ALLOW or decision.ticket is None:
        print(f"\n  {RED}Expected ALLOW with ticket but got "
              f"{decision.result.value}{RESET}")
        return

    ticket = decision.ticket
    print(f"\n  {CYAN}Execution Ticket:{RESET}")
    print(f"    Token:     {DIM}{ticket.token[:40]}...{RESET}")
    print(f"    Action:    {ticket.action}")
    print(f"    Target:    {ticket.target}")
    print(f"    Nonce:     {ticket.nonce}")
    print(f"    Issued:    {ticket.issued_at.isoformat()[:19]}")
    print(f"    Expires:   {ticket.expires_at.isoformat()[:19]} (5 min TTL)")

    # --- Phase 2: Credential resolution ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 2: JIT Credential Resolution")
    print(f"{'-' * 70}{RESET}")

    cred_result = safe.resolve_credentials(ticket)

    if cred_result.success:
        cred = cred_result.credential
        print(f"  Status:      {GREEN}Resolved{RESET}")
        print(f"  Cred Type:   {cred.scope.type}")
        print("  Scope:")
        for field_name, field_val in cred.scope.fields.items():
            print(f"    {field_name:<12} {field_val}")
        print(f"  Expires:     {cred.expires_at.isoformat()[:19]}")
        print("  Payload:")
        for k, v in cred.payload.items():
            print(f"    {k:<12} {_mask(str(v))}")
    else:
        print(f"  Status:      {YELLOW}No credentials configured for this action{RESET}")
        print(f"  {DIM}(Credential resolution is optional - proceeding){RESET}")

    # --- Phase 3: Before-state capture ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 3: Before-State Capture")
    print(f"{'-' * 70}{RESET}")

    before_state = {
        "replicas": 2,
        "available_replicas": 2,
        "ready_replicas": 2,
    }

    safe.record_before_state(decision.audit_id, before_state)

    for k, v in before_state.items():
        print(f"  {k:<25} {v}")

    # --- Phase 4: Execute via ticket ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 4: Governed Execution")
    print(f"{'-' * 70}{RESET}")

    exec_result = safe.execute(ticket.token)

    print(f"  Ticket:     {GREEN}VALID{RESET}")
    print("  Executor:   DryRunExecutor")
    print(f"  Status:     {exec_result.status.value}")
    print(f"  Output:     {DIM}{exec_result.output}{RESET}")

    # --- Phase 5: After-state capture + diff ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 5: After-State Capture + Diff")
    print(f"{'-' * 70}{RESET}")

    after_state = {
        "replicas": 5,
        "available_replicas": 5,
        "ready_replicas": 5,
    }

    safe.record_after_state(
        decision.audit_id,
        after_state,
        action="scale-deployment",
        target="staging/api-server",
        caller="deploy-agent-01",
    )

    print(f"  {'FIELD':<25} {'BEFORE':>8} {'AFTER':>8}  CHANGE")
    print(f"  {'-' * 55}")
    for key in before_state:
        bv = before_state.get(key, "-")
        av = after_state.get(key, "-")
        changed = bv != av
        change_str = f"{YELLOW}modified{RESET}" if changed else f"{DIM}unchanged{RESET}"
        print(f"  {key:<25} {str(bv):>8} {str(av):>8}  {change_str}")

    # --- Phase 6: Rollback generation ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 6: Rollback Generation")
    print(f"{'-' * 70}{RESET}")

    try:
        rollback = safe.generate_rollback(decision.audit_id)

        print(f"  {CYAN}Rollback Plan:{RESET}")
        print(f"    Original:  {rollback.original_action} "
              f"(replicas: 2 -> 5)")
        print(f"    Rollback:  {rollback.rollback_action} "
              f"(replicas: 5 -> {rollback.rollback_params.get('replicas', '?')})")
        print(f"    Params:    {rollback.rollback_params}")

        # Check rollback through PDP
        rb_decision = safe.check_rollback(
            decision.audit_id, caller=deployer_token,
        )
        rb_color = GREEN if rb_decision.result == DecisionResult.ALLOW else YELLOW
        print("\n  Rollback policy check:")
        print(f"    Decision:  {rb_color}{rb_decision.result.value.upper()}{RESET}")
        print(f"    Reason:    {rb_decision.reason}")
    except Exception as e:
        print(f"  {YELLOW}Rollback: {e}{RESET}")
        print(f"  {DIM}(Rollback requires state capture with matching "
              f"rollback_params in action YAML){RESET}")

    # --- Phase 7: Audit trail ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 7: Audit Trail")
    print(f"{'-' * 70}{RESET}")

    is_valid, errors = safe.verify_audit()
    events = safe.audit.read_events()
    print(f"  Audit log: {'VALID' if is_valid else 'INVALID'} "
          f"({len(events)} events, chain {'intact' if is_valid else 'broken'})")

    print("\n  Event flow:")
    for event in events:
        ts = event.timestamp.isoformat()[:19]
        etype = event.event_type if hasattr(event, "event_type") else "?"
        dec = event.decision
        dec_str = dec.value.upper() if dec else "-"
        color = GREEN if dec == DecisionResult.ALLOW else (
            YELLOW if dec == DecisionResult.REQUIRE_APPROVAL else DIM
        )
        print(f"    {ts}  {etype:<18} {color}{dec_str:<12}{RESET} "
              f"{event.action}")

    print(f"\n{BOLD}{'=' * 70}")
    print("  Demo complete. Full lifecycle:")
    print("  check -> ticket -> credential -> execute -> state -> rollback")
    print(f"{'=' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
