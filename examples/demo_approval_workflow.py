#!/usr/bin/env python3
"""Demo: Approval Workflow (Human-in-the-Loop).

Shows the complete approval lifecycle: an agent requests a production
action, gets blocked with REQUIRE_APPROVAL, a simulated human reviewer
approves it, and the agent proceeds to execute via a signed ticket.

Run from the project root:
    python examples/demo_approval_workflow.py
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_safe import AgentSafe
from agent_safe.models import DecisionResult

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

COLORS = {
    DecisionResult.ALLOW: GREEN,
    DecisionResult.DENY: RED,
    DecisionResult.REQUIRE_APPROVAL: YELLOW,
}


def _tag(result: DecisionResult) -> str:
    color = COLORS.get(result, "")
    return f"{color}{result.value.upper()}{RESET}"


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    # Clean up from previous runs
    audit_file = project_root / "examples" / "demo_approval_audit.jsonl"
    approval_file = project_root / "examples" / "demo_approval_store.jsonl"
    audit_file.unlink(missing_ok=True)
    approval_file.unlink(missing_ok=True)

    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=audit_file,
        signing_key="demo-signing-key-approval-wf-32bytes",
        approval_store=approval_file,
        approval_ttl=300,
    )

    deployer_token = safe.identity.create_token(
        agent_id="deploy-agent-01",
        agent_name="Deploy Agent",
        roles=["deployer"],
        groups=["platform-team"],
    )

    print(f"\n{BOLD}{'=' * 70}")
    print("  Agent-Safe Demo: Approval Workflow (Human-in-the-Loop)")
    print(f"{'=' * 70}{RESET}")
    print(f"\n  {CYAN}Registry:{RESET} {len(safe.list_actions())} actions loaded")
    print(f"  {CYAN}Approval store:{RESET} {approval_file.name}")

    # --- Phase 1: Request production action ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 1: Agent Requests Production Scale-Up")
    print(f"{'-' * 70}{RESET}")

    decision = safe.check(
        action="scale-deployment",
        target="prod/api-server",
        caller=deployer_token,
        params={"namespace": "prod", "deployment": "api-server", "replicas": 5},
    )

    print("  Action:    scale-deployment")
    print("  Target:    prod/api-server (critical)")
    print(f"  Decision:  {_tag(decision.result)}")
    print(f"  Reason:    {decision.reason}")
    print(f"  Request:   {CYAN}{decision.request_id}{RESET}")

    if decision.result != DecisionResult.REQUIRE_APPROVAL:
        print(f"\n  {RED}Expected REQUIRE_APPROVAL but got "
              f"{decision.result.value}{RESET}")
        return

    request_id = decision.request_id

    # --- Phase 2: Show pending approvals ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 2: Pending Approval Queue")
    print(f"{'-' * 70}{RESET}")

    pending = safe.list_pending_approvals()
    print(f"  {'REQUEST':<20} {'ACTION':<22} {'TARGET':<22} STATUS")
    print(f"  {'-' * 66}")
    for req in pending:
        print(f"  {req.request_id:<20} {req.action:<22} "
              f"{req.target:<22} {YELLOW}PENDING{RESET}")

    # --- Phase 3: Simulate human approval in background ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 3: Waiting for Human Approval...")
    print(f"{'-' * 70}{RESET}")

    def simulate_human_approval() -> None:
        """Simulate a human reviewing and approving after 3 seconds."""
        time.sleep(3)
        safe.resolve_approval(
            request_id=request_id,
            action="approve",
            resolved_by="ops-lead-alice",
            reason="Reviewed scaling plan, approved for peak traffic",
        )

    # Start background approval
    approval_thread = threading.Thread(target=simulate_human_approval)
    approval_thread.start()

    # Agent waits for approval with visual feedback
    print("  Polling for approval", end="", flush=True)
    approved_decision = safe.wait_for_approval(
        request_id=request_id,
        timeout=10,
        poll_interval=1,
    )
    approval_thread.join()

    print()  # newline after polling
    if approved_decision.result == DecisionResult.ALLOW:
        print(f"\n  {GREEN}{BOLD}APPROVED{RESET} by ops-lead-alice")
        print("  Reason: Reviewed scaling plan, approved for peak traffic")
        if approved_decision.ticket:
            token_preview = approved_decision.ticket.token[:40] + "..."
            print(f"  Ticket: {DIM}{token_preview}{RESET}")
            print(f"  Expires: {approved_decision.ticket.expires_at.isoformat()[:19]} "
                  f"(5 min TTL)")
    else:
        print(f"\n  {RED}DENIED{RESET}")
        print(f"  Reason: {approved_decision.reason}")
        return

    # --- Phase 4: Execute with ticket ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 4: Executing Governed Action")
    print(f"{'-' * 70}{RESET}")

    exec_result = safe.execute(approved_decision.ticket.token)

    print(f"  Ticket:     {GREEN}VALID{RESET}")
    print("  Executor:   DryRunExecutor")
    print(f"  Status:     {exec_result.status.value}")
    print(f"  Output:     {DIM}{exec_result.output}{RESET}")

    # --- Phase 5: Verify audit trail ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 5: Audit Trail Verification")
    print(f"{'-' * 70}{RESET}")

    is_valid, errors = safe.verify_audit()
    events = safe.audit.read_events()
    print(f"  Audit log: {'VALID' if is_valid else 'INVALID'} "
          f"({len(events)} events, chain {'intact' if is_valid else 'broken'})")

    print("\n  Event timeline:")
    for event in events:
        ts = event.timestamp.isoformat()[:19]
        dec_color = COLORS.get(event.decision, "")
        dec_str = event.decision.value.upper() if event.decision else "N/A"
        etype = event.event_type if hasattr(event, "event_type") else ""
        suffix = f" ({etype})" if etype and etype != "decision" else ""
        print(f"    {ts}  {dec_color}{dec_str:<18}{RESET} "
              f"{event.action:<22}{suffix}")

    print(f"\n{BOLD}{'=' * 70}")
    print("  Demo complete. Approval workflow:")
    print("  request -> review -> approve -> execute -> audit")
    print(f"{'=' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
