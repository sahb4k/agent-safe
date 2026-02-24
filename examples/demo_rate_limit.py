#!/usr/bin/env python3
"""Demo: Rate Limiting + Circuit Breaker Protection.

Shows how Agent-Safe protects against misbehaving agents that flood
requests. The rate limiter throttles per-caller, and the circuit breaker
locks out agents that accumulate too many DENY decisions.

Run from the project root:
    python examples/demo_rate_limit.py
"""

from __future__ import annotations

import sys
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


def _tag(decision: DecisionResult) -> str:
    color = COLORS.get(decision, "")
    return f"{color}{decision.value.upper():<18}{RESET}"


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    # Clean up from previous runs
    audit_file = project_root / "examples" / "demo_rate_limit_audit.jsonl"
    audit_file.unlink(missing_ok=True)

    # Use a short rate limit window so cooldown demo doesn't take forever
    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=audit_file,
        signing_key="demo-signing-key-rate-limit-32by",
        rate_limit={
            "max_requests": 8,
            "window_seconds": 8,
            "circuit_breaker_threshold": 5,
            "circuit_breaker_cooldown_seconds": 6,
        },
    )

    flood_token = safe.identity.create_token(
        agent_id="flood-agent-01",
        agent_name="Flood Agent",
        roles=["deployer"],
        groups=["platform-team"],
    )

    good_token = safe.identity.create_token(
        agent_id="good-agent-01",
        agent_name="Good Agent",
        roles=["deployer"],
        groups=["platform-team"],
    )

    print(f"\n{BOLD}{'=' * 70}")
    print("  Agent-Safe Demo: Rate Limiting + Circuit Breaker")
    print(f"{'=' * 70}{RESET}")
    print(f"\n  {CYAN}Config:{RESET} max_requests=8/8s  "
          f"circuit_breaker=5 denies -> 6s cooldown")

    # --- Phase 1: Normal operation ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 1: Normal Operation (Both Agents)")
    print(f"{'-' * 70}{RESET}")

    flood_count = 0
    good_count = 0

    phase1_actions = [
        ("restart-deployment", {"namespace": "dev", "deployment": "test-app"}),
        ("scale-deployment", {"namespace": "dev", "deployment": "test-app", "replicas": 3}),
        ("get-pod-logs", {"namespace": "dev", "pod": "test-app-1"}),
    ]

    for action, params in phase1_actions:
        d = safe.check(
            action=action, target="dev/test-app",
            caller=flood_token, params=params,
        )
        flood_count += 1
        print(f"  flood-agent-01 -> {action:<25} {_tag(d.result)} ({flood_count}/8)")

    for action, params in phase1_actions:
        d = safe.check(
            action=action, target="dev/test-app",
            caller=good_token, params=params,
        )
        good_count += 1
        print(f"  good-agent-01  -> {action:<25} {_tag(d.result)} ({good_count}/8)")

    # --- Phase 2: Flood begins ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 2: Agent Floods Requests — Rate Limit Hit")
    print(f"{'-' * 70}{RESET}")

    for _i in range(10):
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller=flood_token,
            params={"namespace": "dev", "deployment": "test-app"},
        )
        flood_count += 1

        if d.result == DecisionResult.DENY and "Circuit breaker" in d.reason:
            print(f"  flood-agent-01 -> request {flood_count:<4} "
                  f"{_tag(d.result)} {RED}{BOLD}CIRCUIT BREAKER OPEN{RESET}")
        elif d.result == DecisionResult.DENY:
            print(f"  flood-agent-01 -> request {flood_count:<4} "
                  f"{_tag(d.result)} {DIM}Rate limit exceeded{RESET}")
        else:
            print(f"  flood-agent-01 -> request {flood_count:<4} "
                  f"{_tag(d.result)} ({min(flood_count, 8)}/8)")

    # --- Phase 3: Circuit breaker confirmation ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 3: Circuit Breaker Confirmed")
    print(f"{'-' * 70}{RESET}")

    for _i in range(3):
        d = safe.check(
            action="get-pod-logs", target="dev/test-app",
            caller=flood_token,
            params={"namespace": "dev", "pod": "test-app-1"},
        )
        flood_count += 1

        if "Circuit breaker" in d.reason:
            print(f"  flood-agent-01 -> request {flood_count:<4} "
                  f"{_tag(d.result)} {RED}{BOLD}CIRCUIT BREAKER OPEN{RESET}")
        else:
            print(f"  flood-agent-01 -> request {flood_count:<4} "
                  f"{_tag(d.result)} {DIM}{d.reason[:50]}{RESET}")

    # --- Phase 4: Per-caller isolation ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 4: Per-Caller Isolation")
    print(f"{'-' * 70}{RESET}")

    d_good = safe.check(
        action="get-pod-logs", target="dev/test-app",
        caller=good_token,
        params={"namespace": "dev", "pod": "test-app-1"},
    )
    good_count += 1
    print(f"  good-agent-01  -> get-pod-logs              "
          f"{_tag(d_good.result)} {GREEN}(unaffected){RESET}")

    d_good = safe.check(
        action="scale-deployment", target="dev/test-app",
        caller=good_token,
        params={"namespace": "dev", "deployment": "test-app", "replicas": 3},
    )
    good_count += 1
    print(f"  good-agent-01  -> scale-deployment          "
          f"{_tag(d_good.result)} {GREEN}(unaffected){RESET}")

    d_flood = safe.check(
        action="scale-deployment", target="dev/test-app",
        caller=flood_token,
        params={"namespace": "dev", "deployment": "test-app", "replicas": 3},
    )
    flood_count += 1
    print(f"  flood-agent-01 -> scale-deployment          "
          f"{_tag(d_flood.result)} {RED}(still locked){RESET}")

    # --- Phase 5: Cooldown recovery ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 5: Cooldown Recovery")
    print(f"{'-' * 70}{RESET}")

    # Wait for both circuit breaker cooldown (6s) and rate limit window (8s)
    wait_secs = 9
    print(f"  Waiting for cooldown ({wait_secs}s)...", end="", flush=True)
    for i in range(wait_secs):
        time.sleep(1)
        bar = "#" * (i + 1) + "-" * (wait_secs - 1 - i)
        print(f"\r  Waiting for cooldown ({wait_secs}s)... [{bar}] {i + 1}/{wait_secs}s",
              end="", flush=True)
    print()

    d = safe.check(
        action="get-pod-logs", target="dev/test-app",
        caller=flood_token,
        params={"namespace": "dev", "pod": "test-app-1"},
    )
    flood_count += 1

    if d.result == DecisionResult.ALLOW:
        print(f"\n  flood-agent-01 -> get-pod-logs              "
              f"{_tag(d.result)} {GREEN}{BOLD}Agent recovered!{RESET}")
    else:
        print(f"\n  flood-agent-01 -> get-pod-logs              "
              f"{_tag(d.result)} {DIM}{d.reason[:60]}{RESET}")

    # --- Phase 6: Audit summary ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 6: Audit Summary")
    print(f"{'-' * 70}{RESET}")

    events = safe.audit.read_events()
    flood_allow = sum(
        1 for e in events
        if e.caller == "flood-agent-01" and e.decision == DecisionResult.ALLOW
    )
    flood_deny = sum(
        1 for e in events
        if e.caller == "flood-agent-01" and e.decision == DecisionResult.DENY
    )
    good_allow = sum(
        1 for e in events
        if e.caller == "good-agent-01" and e.decision == DecisionResult.ALLOW
    )
    good_deny = sum(
        1 for e in events
        if e.caller == "good-agent-01" and e.decision == DecisionResult.DENY
    )

    print(f"  flood-agent-01:  {GREEN}{flood_allow} ALLOW{RESET}, "
          f"{RED}{flood_deny} DENY{RESET}")
    print(f"  good-agent-01:   {GREEN}{good_allow} ALLOW{RESET}, "
          f"{RED}{good_deny} DENY{RESET}")

    is_valid, errors = safe.verify_audit()
    print(f"\n  Audit log: {'VALID' if is_valid else 'INVALID'} "
          f"({len(events)} events, chain {'intact' if is_valid else 'broken'})")

    print(f"\n{BOLD}{'=' * 70}")
    print("  Demo complete. Misbehaving agents get rate-limited,")
    print("  then circuit-broken. Well-behaved agents are unaffected.")
    print(f"{'=' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
