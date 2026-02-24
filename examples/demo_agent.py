#!/usr/bin/env python3
"""Demo: An AI deployment agent governed by Agent-Safe.

This script simulates an AI agent that manages Kubernetes deployments.
Every action the agent wants to take is checked against Agent-Safe's
policy engine before execution. The agent respects the decision.

Run from the project root:
    python examples/demo_agent.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to path for running without install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_safe import AgentSafe
from agent_safe.models import AgentIdentity, DecisionResult


def main() -> None:
    # --- Setup ---
    project_root = Path(__file__).resolve().parent.parent

    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=project_root / "examples" / "demo_audit.jsonl",
        signing_key="demo-signing-key-not-for-production",
    )

    # Create agent identities
    deployer_token = safe.identity.create_token(
        agent_id="deploy-agent-01",
        agent_name="Deploy Agent",
        roles=["deployer", "reader"],
        groups=["platform-team"],
    )

    reader_token = safe.identity.create_token(
        agent_id="monitoring-agent",
        agent_name="Monitoring Agent",
        roles=["reader"],
        groups=["monitoring"],
    )

    rogue_agent = AgentIdentity(
        agent_id="unknown-agent",
        roles=[],
        groups=[],
    )

    print("=" * 70)
    print("  Agent-Safe Demo: AI Deployment Agent")
    print("=" * 70)
    print(f"\n  Registry: {len(safe.list_actions())} actions loaded")
    print(f"  Actions:  {', '.join(safe.list_actions()[:5])}...")
    print()

    # --- Scenario 1: Dev environment (anything goes) ---
    print("-" * 70)
    print("  Scenario 1: Deploy Agent operates in DEV environment")
    print("-" * 70)

    steps = [
        ("restart-deployment", "dev/test-app", deployer_token,
         {"namespace": "dev", "deployment": "test-app"}),
        ("scale-deployment", "dev/test-app", deployer_token,
         {"namespace": "dev", "deployment": "test-app", "replicas": 5}),
        ("get-pod-logs", "dev/test-app", deployer_token,
         {"namespace": "dev", "pod": "test-app-abc123"}),
    ]

    for action, target, caller, params in steps:
        decision = safe.check(
            action=action, target=target, caller=caller, params=params
        )
        _print_decision(action, target, decision)

    # --- Scenario 2: Staging with role-based access ---
    print()
    print("-" * 70)
    print("  Scenario 2: Role-based access in STAGING")
    print("-" * 70)

    # Deployer can restart in staging
    d = safe.check(
        action="restart-deployment",
        target="staging/api-server",
        caller=deployer_token,
        params={"namespace": "staging", "deployment": "api-server"},
    )
    _print_decision("restart-deployment", "staging/api-server", d)

    # Reader can only read logs in staging
    d = safe.check(
        action="get-pod-logs",
        target="staging/api-server",
        caller=reader_token,
        params={"namespace": "staging", "pod": "api-server-xyz"},
    )
    _print_decision("get-pod-logs (reader)", "staging/api-server", d)

    # Reader CANNOT restart in staging
    d = safe.check(
        action="restart-deployment",
        target="staging/api-server",
        caller=reader_token,
        params={"namespace": "staging", "deployment": "api-server"},
    )
    _print_decision("restart-deployment (reader)", "staging/api-server", d)

    # --- Scenario 3: Production (locked down) ---
    print()
    print("-" * 70)
    print("  Scenario 3: Production targets (locked down)")
    print("-" * 70)

    # Even deployer needs approval for prod
    d = safe.check(
        action="restart-deployment",
        target="prod/api-server",
        caller=deployer_token,
        params={"namespace": "prod", "deployment": "api-server"},
    )
    _print_decision("restart-deployment", "prod/api-server", d)

    # Reading logs in prod also needs approval
    d = safe.check(
        action="get-pod-logs",
        target="prod/api-server",
        caller=deployer_token,
        params={"namespace": "prod", "pod": "api-server-abc"},
    )
    _print_decision("get-pod-logs", "prod/api-server", d)

    # --- Scenario 4: Dangerous operations ---
    print()
    print("-" * 70)
    print("  Scenario 4: Dangerous and unknown operations")
    print("-" * 70)

    # Unknown action → always denied
    d = safe.check(
        action="drop-database",
        target="prod/api-server",
        caller=deployer_token,
    )
    _print_decision("drop-database (unknown)", "prod/api-server", d)

    # Invalid params → denied
    d = safe.check(
        action="scale-deployment",
        target="dev/test-app",
        caller=deployer_token,
        params={"namespace": "dev", "deployment": "test-app", "replicas": 999},
    )
    _print_decision("scale-deployment (replicas=999)", "dev/test-app", d)

    # Rogue agent in prod → denied
    d = safe.check(
        action="delete-namespace",
        target="prod/api-server",
        caller=rogue_agent,
        params={"namespace": "prod"},
    )
    _print_decision("delete-namespace (rogue)", "prod/api-server", d)

    # --- Scenario 5: Batch plan evaluation ---
    print()
    print("-" * 70)
    print("  Scenario 5: Agent submits a multi-step plan")
    print("-" * 70)

    plan = [
        {
            "action": "scale-deployment",
            "target": "staging/api-server",
            "caller": deployer_token,
            "params": {"namespace": "staging", "deployment": "api-server", "replicas": 3},
        },
        {
            "action": "update-image",
            "target": "staging/api-server",
            "caller": deployer_token,
            "params": {
                "namespace": "staging", "deployment": "api-server",
                "container": "api", "image": "api-server:v2.1.0",
            },
        },
        {
            "action": "restart-deployment",
            "target": "staging/api-server",
            "caller": deployer_token,
            "params": {"namespace": "staging", "deployment": "api-server"},
        },
    ]

    decisions = safe.check_plan(plan)
    for step, decision in zip(plan, decisions, strict=True):
        _print_decision(step["action"], step.get("target", "?"), decision)

    # --- Verify audit trail ---
    print()
    print("-" * 70)
    print("  Audit Trail Verification")
    print("-" * 70)

    is_valid, errors = safe.verify_audit()
    events = safe.audit.read_events()
    if is_valid:
        print(f"  Audit log: VALID ({len(events)} events, chain intact)")
    else:
        print(f"  Audit log: INVALID ({len(errors)} errors)")
        for e in errors:
            print(f"    - {e}")

    print()
    print("  Last 5 audit entries:")
    for event in events[-5:]:
        print(
            f"    {event.timestamp.isoformat()[:19]}  "
            f"{event.decision.value.upper():<17} "
            f"{event.action:<25} target={event.target}"
        )

    print()
    print("=" * 70)
    print("  Demo complete. Audit log: examples/demo_audit.jsonl")
    print("=" * 70)


def _print_decision(action: str, target: str, decision) -> None:
    """Pretty-print a decision."""
    colors = {
        DecisionResult.ALLOW: "\033[92m",       # green
        DecisionResult.DENY: "\033[91m",         # red
        DecisionResult.REQUIRE_APPROVAL: "\033[93m",  # yellow
    }
    reset = "\033[0m"
    color = colors.get(decision.result, "")
    result = decision.result.value.upper()

    print(
        f"  {action:<40} -> "
        f"{color}{result:<17}{reset} "
        f"| {decision.reason}"
    )


if __name__ == "__main__":
    main()
