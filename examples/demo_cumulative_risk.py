#!/usr/bin/env python3
"""Demo: Cumulative Risk Scoring and Escalation.

Shows how Agent-Safe tracks cumulative risk across a sequence of
individually-allowed actions. When the accumulated risk crosses
configurable thresholds, decisions escalate from ALLOW to
REQUIRE_APPROVAL, and eventually to DENY.

This protects against "action chaining" attacks (Threat T7) where
an agent performs many small actions that individually look safe
but collectively represent a dangerous pattern.

Run from the project root:
    python examples/demo_cumulative_risk.py
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

ESCALATION_THRESHOLD = 20
DENY_THRESHOLD = 40


def _risk_bar(score: int) -> str:
    """Render a visual risk meter."""
    max_display = DENY_THRESHOLD + 5
    filled = min(score, max_display)
    bar_width = 20
    fill = int((filled / max_display) * bar_width)
    empty = bar_width - fill

    if score >= DENY_THRESHOLD:
        char = "!"
        color = RED
    elif score >= ESCALATION_THRESHOLD:
        char = "#"
        color = YELLOW
    else:
        char = "#"
        color = GREEN

    return f"{color}[{char * fill}{'-' * empty}]{RESET} {score}/{DENY_THRESHOLD}"


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent

    # Clean up from previous runs
    audit_file = project_root / "examples" / "demo_cumulative_risk_audit.jsonl"
    audit_file.unlink(missing_ok=True)

    safe = AgentSafe(
        registry=project_root / "actions",
        policies=project_root / "policies",
        inventory=project_root / "inventory.yaml",
        audit_log=audit_file,
        signing_key="demo-signing-key-cumul-risk-32bytes",
        cumulative_risk={
            "window_seconds": 3600,
            "escalation_threshold": ESCALATION_THRESHOLD,
            "deny_threshold": DENY_THRESHOLD,
            "risk_scores": {
                "low": 1,
                "medium": 5,
                "high": 15,
                "critical": 50,
            },
        },
    )

    deployer_token = safe.identity.create_token(
        agent_id="deploy-agent-01",
        agent_name="Deploy Agent",
        roles=["deployer", "reader"],
        groups=["platform-team"],
    )

    print(f"\n{BOLD}{'=' * 70}")
    print("  Agent-Safe Demo: Cumulative Risk Scoring")
    print(f"{'=' * 70}{RESET}")
    print(f"\n  {CYAN}Thresholds:{RESET} escalation={ESCALATION_THRESHOLD} "
          f"(ALLOW->REQUIRE_APPROVAL)  deny={DENY_THRESHOLD} (->DENY)")
    print(f"  {CYAN}Scores:{RESET} low=1  medium=5  high=15  critical=50")
    print(f"  {CYAN}Window:{RESET} 3600s (1 hour)")

    # Track all decisions for summary
    timeline: list[dict] = []
    step = 0

    def do_check(action: str, target: str, params: dict) -> None:
        nonlocal step
        step += 1
        d = safe.check(
            action=action, target=target,
            caller=deployer_token, params=params,
        )

        score = d.cumulative_risk_score or 0
        tag_color = COLORS.get(d.result, "")
        tag = f"{tag_color}{d.result.value.upper():<18}{RESET}"
        escalated = d.escalated_from is not None

        risk_str = d.effective_risk if hasattr(d.effective_risk, 'value') else d.effective_risk
        if hasattr(risk_str, 'value'):
            risk_str = risk_str.value

        # Compute the per-action score from the risk class
        risk_scores = {"low": 1, "medium": 5, "high": 15, "critical": 50}
        action_score = risk_scores.get(risk_str, 0)

        print(f"  [{step:>2}] {action:<25} {target:<22} "
              f"risk={risk_str:<8} +{action_score}")
        print(f"       {tag} {_risk_bar(score)}")

        if escalated:
            orig = d.escalated_from.value.upper()
            print(f"       {YELLOW}{BOLD}*** ESCALATED from {orig} "
                  f"- cumulative risk exceeded threshold{RESET}")

        timeline.append({
            "step": step,
            "action": action,
            "risk": risk_str,
            "score": action_score,
            "cumulative": score,
            "decision": d.result.value.upper(),
            "escalated": escalated,
        })

    # --- Phase 1: Low-risk warm-up ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 1: Low-Risk Warm-Up")
    print(f"{'-' * 70}{RESET}")

    do_check("get-pod-logs", "dev/test-app",
             {"namespace": "dev", "pod": "test-app-1"})
    do_check("get-pod-logs", "staging/api-server",
             {"namespace": "staging", "pod": "api-server-1"})

    # --- Phase 2: Risk builds through staging ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 2: Risk Accumulates - Escalation Triggered")
    print(f"{'-' * 70}{RESET}")

    do_check("scale-deployment", "dev/test-app",
             {"namespace": "dev", "deployment": "test-app", "replicas": 3})
    do_check("restart-deployment", "dev/test-app",
             {"namespace": "dev", "deployment": "test-app"})
    do_check("scale-deployment", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server", "replicas": 3})
    do_check("update-image", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server",
              "container": "api", "image": "api:v2.0.0"})

    # --- Phase 3: Push past deny threshold ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Phase 3: Hard Deny - Agent Locked Out")
    print(f"{'-' * 70}{RESET}")

    do_check("restart-deployment", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server"})
    do_check("scale-deployment", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server", "replicas": 5})
    do_check("restart-deployment", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server"})
    do_check("scale-deployment", "staging/api-server",
             {"namespace": "staging", "deployment": "api-server", "replicas": 2})

    # --- Summary ---
    print(f"\n{BOLD}{'-' * 70}")
    print("  Summary Timeline")
    print(f"{'-' * 70}{RESET}")

    print(f"  {'#':<4} {'ACTION':<25} {'RISK':<9} {'SCORE':>6} "
          f"{'CUM':>5}  DECISION")
    print(f"  {'-' * 66}")

    for t in timeline:
        dec = t["decision"]
        if t["escalated"] and dec == "DENY":
            dec_str = f"{RED}{dec} (escalated){RESET}"
        elif t["escalated"]:
            dec_str = f"{YELLOW}{dec} (escalated){RESET}"
        elif dec == "ALLOW":
            dec_str = f"{GREEN}{dec}{RESET}"
        elif dec == "DENY":
            dec_str = f"{RED}{dec}{RESET}"
        else:
            dec_str = f"{YELLOW}{dec}{RESET}"

        print(f"  {t['step']:<4} {t['action']:<25} {t['risk']:<9} "
              f"+{t['score']:<5} {t['cumulative']:>4}  {dec_str}")

    print(f"\n{BOLD}{'=' * 70}")
    print("  Demo complete. The agent was safe action-by-action,")
    print("  but cumulative risk chaining was caught and escalated.")
    print(f"{'=' * 70}{RESET}\n")


if __name__ == "__main__":
    main()
