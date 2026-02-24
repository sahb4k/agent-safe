"""Claude Agent SDK + Agent-Safe integration demo.

Shows how to build an AI agent that checks every K8s action with Agent-Safe
before executing. The agent uses custom MCP tools that wrap agent-safe checks.

Requirements:
    pip install agent-safe claude-agent-sdk

Usage:
    # Set your Anthropic API key
    export ANTHROPIC_API_KEY=sk-...

    # Run the demo
    python examples/claude_agent_demo.py

What this demo does:
    1. Defines K8s operation tools (restart, scale, get-logs)
    2. Each tool checks agent-safe BEFORE executing
    3. If agent-safe says DENY or REQUIRE_APPROVAL, the tool refuses
    4. The agent plans and executes a multi-step deployment update
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

# --- Agent-Safe setup ---
from agent_safe import AgentSafe
from agent_safe.models import DecisionResult

SCRIPT_DIR = Path(__file__).parent.parent
safe = AgentSafe(
    registry=SCRIPT_DIR / "actions",
    policies=SCRIPT_DIR / "policies",
    inventory=SCRIPT_DIR / "inventory.yaml",
)

CALLER = "claude-deploy-agent"


def check_and_execute(
    action: str,
    target: str,
    params: dict[str, Any],
    execute_fn: str = "simulated",
) -> dict[str, Any]:
    """Check an action with agent-safe, then execute if allowed.

    This is the core pattern: every tool calls this before doing anything.
    """
    decision = safe.check(
        action=action,
        target=target,
        caller=CALLER,
        params=params,
    )

    result = {
        "action": action,
        "target": target,
        "decision": decision.result.value,
        "reason": decision.reason,
        "risk": decision.effective_risk,
        "audit_id": decision.audit_id,
    }

    if decision.result == DecisionResult.ALLOW:
        result["executed"] = True
        result["output"] = f"[simulated] {action} executed successfully on {target}"
    elif decision.result == DecisionResult.REQUIRE_APPROVAL:
        result["executed"] = False
        result["output"] = (
            f"Action blocked: requires human approval. "
            f"Reason: {decision.reason}. "
            f"Audit ID: {decision.audit_id} (use this to request approval)"
        )
    else:
        result["executed"] = False
        result["output"] = f"Action denied: {decision.reason}"

    return result


# --- Standalone demo (no Claude API needed) ---


def run_standalone_demo() -> None:
    """Run the demo without requiring Claude API or claude-agent-sdk."""
    print("=" * 70)
    print("Agent-Safe + AI Agent Integration Demo")
    print("=" * 70)
    print()

    # Simulate what a Claude agent would do: plan and check actions
    scenarios = [
        {
            "description": "Scenario 1: Staging reads allowed, writes need deployer role",
            "steps": [
                {
                    "action": "get-pod-logs",
                    "target": "staging/api-server",
                    "params": {"namespace": "staging", "pod": "api-server-abc"},
                },
                {
                    "action": "scale-deployment",
                    "target": "staging/api-server",
                    "params": {"namespace": "staging", "deployment": "api", "replicas": 3},
                },
            ],
        },
        {
            "description": "Scenario 2: Deploy to dev (should be ALLOWED)",
            "steps": [
                {
                    "action": "restart-deployment",
                    "target": "dev/test-app",
                    "params": {"namespace": "dev", "deployment": "test-app"},
                },
                {
                    "action": "get-pod-logs",
                    "target": "dev/test-app",
                    "params": {"namespace": "dev", "pod": "test-app-xyz"},
                },
            ],
        },
        {
            "description": "Scenario 3: Deploy to production (should REQUIRE APPROVAL)",
            "steps": [
                {
                    "action": "scale-deployment",
                    "target": "prod/api-server",
                    "params": {"namespace": "prod", "deployment": "api", "replicas": 5},
                },
                {
                    "action": "restart-deployment",
                    "target": "prod/api-server",
                    "params": {"namespace": "prod", "deployment": "api"},
                },
            ],
        },
        {
            "description": "Scenario 4: Dangerous operation (should be BLOCKED)",
            "steps": [
                {
                    "action": "delete-namespace",
                    "target": "prod/payments-ns",
                    "params": {"namespace": "payments"},
                },
            ],
        },
    ]

    for scenario in scenarios:
        print(f"\n--- {scenario['description']} ---\n")

        for step in scenario["steps"]:
            result = check_and_execute(
                action=step["action"],
                target=step["target"],
                params=step["params"],
            )

            decision = result["decision"].upper()
            if decision == "ALLOW":
                marker = "[ALLOW]"
            elif decision == "REQUIRE_APPROVAL":
                marker = "[APPROVAL NEEDED]"
            else:
                marker = "[DENIED]"

            print(f"  {marker} {step['action']} on {step['target']}")
            print(f"    Risk: {result['risk']} | {result['reason']}")
            if result["executed"]:
                print(f"    -> Executed: {result['output']}")
            else:
                print(f"    -> Blocked: {result['output']}")
            print()

    # Show batch plan check
    print("\n--- Batch Plan Check ---\n")
    plan = [
        {"action": "scale-deployment", "target": "staging/api-server",
         "params": {"namespace": "staging", "deployment": "api", "replicas": 3}},
        {"action": "restart-deployment", "target": "staging/api-server",
         "params": {"namespace": "staging", "deployment": "api"}},
        {"action": "get-pod-logs", "target": "staging/api-server",
         "params": {"namespace": "staging", "pod": "api-server-abc"}},
    ]
    decisions = safe.check_plan(plan)
    for step, decision in zip(plan, decisions, strict=True):
        print(f"  {decision.result.value.upper():<18} {step['action']}")

    print(f"\n  Plan: {len(decisions)} step(s), "
          f"{sum(1 for d in decisions if d.result == DecisionResult.ALLOW)} allowed, "
          f"{sum(1 for d in decisions if d.result == DecisionResult.DENY)} denied, "
          f"{sum(1 for d in decisions if d.result == DecisionResult.REQUIRE_APPROVAL)}"
          f" require approval")

    print("\n" + "=" * 70)
    print("All decisions logged to audit trail. Verify with:")
    print("  agent-safe audit verify ./audit.jsonl")
    print("=" * 70)


# --- Claude Agent SDK integration (requires API key) ---


async def run_claude_agent() -> None:
    """Run the demo with the real Claude Agent SDK.

    Requires: pip install claude-agent-sdk
    Requires: ANTHROPIC_API_KEY environment variable
    """
    try:
        from claude_agent_sdk import (
            AssistantMessage,
            ClaudeAgentOptions,
            ResultMessage,
            TextBlock,
            create_sdk_mcp_server,
            query,
            tool,
        )
    except ImportError:
        print("Error: claude-agent-sdk not installed.")
        print("Install with: pip install claude-agent-sdk")
        sys.exit(1)

    # Define tools that wrap agent-safe checks

    @tool(
        "k8s_restart_deployment",
        "Restart a Kubernetes deployment. Checks agent-safe policies first.",
        {"namespace": str, "deployment": str, "target": str},
    )
    async def k8s_restart(args: dict[str, Any]) -> dict[str, Any]:
        result = check_and_execute(
            action="restart-deployment",
            target=args["target"],
            params={"namespace": args["namespace"], "deployment": args["deployment"]},
        )
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    @tool(
        "k8s_scale_deployment",
        "Scale a Kubernetes deployment. Checks agent-safe policies first.",
        {"namespace": str, "deployment": str, "replicas": int, "target": str},
    )
    async def k8s_scale(args: dict[str, Any]) -> dict[str, Any]:
        result = check_and_execute(
            action="scale-deployment",
            target=args["target"],
            params={
                "namespace": args["namespace"],
                "deployment": args["deployment"],
                "replicas": args["replicas"],
            },
        )
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    @tool(
        "k8s_get_logs",
        "Get pod logs. Checks agent-safe policies first.",
        {"namespace": str, "pod": str, "target": str},
    )
    async def k8s_logs(args: dict[str, Any]) -> dict[str, Any]:
        result = check_and_execute(
            action="get-pod-logs",
            target=args["target"],
            params={"namespace": args["namespace"], "pod": args["pod"]},
        )
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    # Create MCP server with k8s tools
    k8s_server = create_sdk_mcp_server(
        name="k8s-ops",
        version="1.0.0",
        tools=[k8s_restart, k8s_scale, k8s_logs],
    )

    options = ClaudeAgentOptions(
        system_prompt=(
            "You are a Kubernetes operations agent. You have tools for "
            "restarting deployments, scaling deployments, and getting pod logs. "
            "Each tool checks Agent-Safe policies before executing. "
            "If a tool returns 'require_approval', tell the user the action "
            "needs human approval and provide the audit ID. "
            "If it returns 'deny', explain that the action is blocked by policy."
        ),
        mcp_servers={"k8s": k8s_server},
        allowed_tools=[
            "mcp__k8s__k8s_restart_deployment",
            "mcp__k8s__k8s_scale_deployment",
            "mcp__k8s__k8s_get_logs",
        ],
    )

    prompt = (
        "I need you to deploy a new version of our API. Please:\n"
        "1. Check the current logs on staging/api-server (namespace: staging, pod: api-pod)\n"
        "2. Scale staging/api-server to 3 replicas (namespace: staging, deployment: api)\n"
        "3. Then try to restart prod/api-server (namespace: prod, deployment: api)\n"
        "Report what happened with each step."
    )

    print("Sending task to Claude agent...\n")

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text)
        elif isinstance(message, ResultMessage):
            print("\n[Agent task completed]")


if __name__ == "__main__":
    if "--claude" in sys.argv:
        asyncio.run(run_claude_agent())
    else:
        run_standalone_demo()
