#!/usr/bin/env python3
"""Demo: Multi-Agent Delegation with Scope Narrowing.

Shows how an orchestrator agent delegates authority to specialized
worker agents. Demonstrates scope narrowing (child roles ⊆ parent),
delegation chains tracked in JWT, and policy enforcement on delegated
identities.

Run from the project root:
    python examples/demo_delegation.py
"""

from __future__ import annotations

import sys
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
    return f"{color}{result.value.upper():<18}{RESET}"


def _print_chain(chain: list) -> None:
    """Print a delegation chain as an indented tree."""
    for i, link in enumerate(chain):
        roles = ", ".join(link.roles) if hasattr(link, "roles") else str(link.get("roles", []))
        agent_id = link.agent_id if hasattr(link, "agent_id") else link.get("agent_id", "?")
        prefix = "    " + "  " * i + ("+- " if i > 0 else "")
        print(f"{prefix}[{i}] {CYAN}{agent_id}{RESET} (roles: {roles})")


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    # Clean up from previous runs
    audit_file = project_root / "examples" / "demo_delegation_audit.jsonl"
    audit_file.unlink(missing_ok=True)

    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=audit_file,
        signing_key="demo-signing-key-delegation-32bytes",
    )

    # Create orchestrator identity
    orchestrator_token = safe.identity.create_token(
        agent_id="orchestrator-01",
        agent_name="Orchestrator",
        roles=["deployer", "reader"],
        groups=["platform-team"],
    )

    print(f"\n{BOLD}{'=' * 70}")
    print("  Agent-Safe Demo: Multi-Agent Delegation")
    print(f"{'=' * 70}{RESET}")
    print(f"\n  {CYAN}Orchestrator:{RESET} orchestrator-01 "
          f"(roles: deployer, reader)")

    # --- Phase 1: Orchestrator acts directly ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 1: Orchestrator Acts Directly")
    print(f"{'-' * 70}{RESET}")

    d = safe.check(
        action="scale-deployment",
        target="staging/api-server",
        caller=orchestrator_token,
        params={"namespace": "staging", "deployment": "api-server", "replicas": 3},
    )
    print("  orchestrator-01 -> scale-deployment staging/api-server")
    print(f"  Decision: {_tag(d.result)} | {d.reason}")

    # --- Phase 2: Delegate to deployment worker ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 2: Delegate to Deployment Worker")
    print(f"{'-' * 70}{RESET}")

    deploy_result = safe.delegate(
        parent_token=orchestrator_token,
        child_agent_id="deploy-worker-01",
        child_agent_name="Deploy Worker",
        child_roles=["deployer"],
        child_groups=["platform-team"],
        ttl=1800,
    )

    print("  Delegation: orchestrator-01 -> deploy-worker-01")
    print(f"  Roles:      {YELLOW}[deployer]{RESET}  "
          f"(narrowed from [deployer, reader])")
    print(f"  Success:    {GREEN if deploy_result.success else RED}"
          f"{deploy_result.success}{RESET}")

    if deploy_result.success:
        # Verify the chain
        identity = safe.verify_delegation(deploy_result.token)
        print(f"  Depth:      {identity.delegation_depth}")
        print("  Chain:")
        _print_chain(identity.delegation_chain)

        # Worker checks an action
        d = safe.check(
            action="scale-deployment",
            target="staging/api-server",
            caller=deploy_result.token,
            params={"namespace": "staging", "deployment": "api-server",
                    "replicas": 5},
        )
        print("\n  deploy-worker-01 -> scale-deployment staging/api-server")
        print(f"  Decision: {_tag(d.result)} | {d.reason}")

    # --- Phase 3: Delegate to reader worker (scope narrowing) ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 3: Delegate to Reader Worker (Scope Narrowing)")
    print(f"{'-' * 70}{RESET}")

    reader_result = safe.delegate(
        parent_token=orchestrator_token,
        child_agent_id="log-reader-01",
        child_agent_name="Log Reader",
        child_roles=["reader"],
        child_groups=["platform-team"],
    )

    print("  Delegation: orchestrator-01 -> log-reader-01")
    print(f"  Roles:      {YELLOW}[reader]{RESET}  "
          f"(narrowed from [deployer, reader])")

    if reader_result.success:
        # Reader can read logs
        d = safe.check(
            action="get-pod-logs",
            target="staging/api-server",
            caller=reader_result.token,
            params={"namespace": "staging", "pod": "api-server-1"},
        )
        print("\n  log-reader-01 -> get-pod-logs staging/api-server")
        print(f"  Decision: {_tag(d.result)} | {d.reason}")

        # Reader CANNOT deploy
        d = safe.check(
            action="restart-deployment",
            target="staging/api-server",
            caller=reader_result.token,
            params={"namespace": "staging", "deployment": "api-server"},
        )
        print("\n  log-reader-01 -> restart-deployment staging/api-server")
        print(f"  Decision: {_tag(d.result)} | {d.reason}")
        print(f"  {DIM}(reader role cannot deploy -- scope narrowing enforced){RESET}")

    # --- Phase 4: Chain delegation (depth=2) ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 4: Chain Delegation (depth=2)")
    print(f"{'-' * 70}{RESET}")

    sub_result = safe.delegate(
        parent_token=deploy_result.token,
        child_agent_id="sub-worker-01",
        child_agent_name="Sub Worker",
        child_roles=["deployer"],
        child_groups=["platform-team"],
        max_depth=5,
    )

    print("  Delegation: deploy-worker-01 -> sub-worker-01")

    if sub_result.success:
        identity = safe.verify_delegation(sub_result.token)
        print(f"  Depth:      {identity.delegation_depth}")
        print("  Chain:")
        _print_chain(identity.delegation_chain)

        d = safe.check(
            action="scale-deployment",
            target="staging/api-server",
            caller=sub_result.token,
            params={"namespace": "staging", "deployment": "api-server",
                    "replicas": 2},
        )
        print("\n  sub-worker-01 -> scale-deployment staging/api-server")
        print(f"  Decision: {_tag(d.result)} | {d.reason}")
    else:
        print(f"  {RED}Failed: {sub_result.error}{RESET}")

    # --- Phase 5: Scope escalation blocked ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 5: Scope Escalation Blocked")
    print(f"{'-' * 70}{RESET}")

    escalate_result = safe.delegate(
        parent_token=orchestrator_token,
        child_agent_id="sneaky-agent",
        child_agent_name="Sneaky Agent",
        child_roles=["deployer", "admin"],  # admin not in parent's roles!
    )

    print("  Attempt:  delegate [deployer, admin] from orchestrator-01")
    print(f"  Result:   {RED if not escalate_result.success else GREEN}"
          f"{'FAILED' if not escalate_result.success else 'SUCCESS'}{RESET}")
    if not escalate_result.success:
        print(f"  Error:    {RED}{escalate_result.error}{RESET}")

    # --- Phase 6: Depth limit enforcement ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 6: Depth Limit Enforcement")
    print(f"{'-' * 70}{RESET}")

    # Build a chain to max depth
    current_token = orchestrator_token
    chain_tokens = []
    for i in range(1, 5):
        r = safe.delegate(
            parent_token=current_token,
            child_agent_id=f"chain-agent-{i:02d}",
            child_roles=["deployer"],
            max_depth=3,
        )
        if r.success:
            chain_tokens.append(r.token)
            current_token = r.token
            depth = safe.verify_delegation(r.token).delegation_depth
            print(f"  chain-agent-{i:02d}: depth={depth} "
                  f"{GREEN}OK{RESET}")
        else:
            print(f"  chain-agent-{i:02d}: "
                  f"{RED}BLOCKED -{r.error}{RESET}")
            break

    # --- Audit summary ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Audit Summary")
    print(f"{'-' * 70}{RESET}")

    is_valid, errors = safe.verify_audit()
    events = safe.audit.read_events()
    print(f"  Audit log: {'VALID' if is_valid else 'INVALID'} "
          f"({len(events)} events, chain {'intact' if is_valid else 'broken'})")

    # Count by caller
    callers: dict[str, int] = {}
    for e in events:
        callers[e.caller] = callers.get(e.caller, 0) + 1
    print("\n  Decisions by agent:")
    for caller, count in sorted(callers.items()):
        print(f"    {caller:<25} {count} decisions")

    print(f"\n{BOLD}{'=' * 70}")
    print("  Demo complete. Delegation: create, narrow, chain, enforce limits.")
    print(f"{'=' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
