"""agent-safe CLI — command-line interface for Agent-Safe.

Commands:
    init            Scaffold a new Agent-Safe project
    check           Evaluate a policy decision for an action
    test            Run policy test cases
    list-actions    Show all registered actions
    validate        Validate config files (actions, policies, inventory)
    audit verify    Verify audit log chain integrity
    audit show      Show recent audit log entries
    audit ship      Ship audit log events to an external backend
    ticket verify   Verify a signed execution ticket
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from agent_safe.audit.logger import AuditLogger, verify_log
from agent_safe.inventory.loader import InventoryError, load_inventory
from agent_safe.models import DecisionResult
from agent_safe.pdp.engine import PDPError, load_policies
from agent_safe.registry.loader import RegistryError, load_registry
from agent_safe.sdk.client import AgentSafe
from agent_safe.testing.runner import PolicyTestError, load_test_files, run_tests

# --- Defaults ---

DEFAULT_REGISTRY = "./actions"
DEFAULT_POLICIES = "./policies"
DEFAULT_INVENTORY = "./inventory.yaml"
DEFAULT_AUDIT_LOG = "./audit.jsonl"


# --- Root group ---


@click.group()
@click.version_option(package_name="agent-safe")
def cli() -> None:
    """Agent-Safe: governance and policy enforcement for AI agents."""


# --- init command ---


_INIT_ACTION = """\
name: restart-deployment
version: "1.0.0"
description: Restart a Kubernetes deployment by triggering a rolling update.

parameters:
  - name: namespace
    type: string
    required: true
    description: Kubernetes namespace
  - name: deployment
    type: string
    required: true
    description: Deployment name

risk_class: medium
target_types:
  - k8s-deployment
reversible: true
tags:
  - kubernetes
  - deployment
"""

_INIT_POLICY = """\
# Agent-Safe policies — evaluated by priority (highest first), first match wins.
# Default: DENY if no rule matches.

rules:
  - name: require-approval-critical-risk
    description: Critical effective risk requires human approval
    priority: 1000
    match:
      risk_classes:
        - critical
    decision: require_approval
    reason: Critical-risk actions always require human approval

  - name: require-approval-prod
    description: All production actions require approval
    priority: 500
    match:
      targets:
        environments:
          - prod
    decision: require_approval
    reason: Production actions require explicit approval

  - name: allow-dev-all
    description: All actions are allowed on dev targets
    priority: 10
    match:
      targets:
        environments:
          - dev
    decision: allow
    reason: Development environment is unrestricted
"""

_INIT_INVENTORY = """\
targets:
  - id: prod/api-server
    type: k8s-deployment
    environment: prod
    sensitivity: critical
    owner: platform-team

  - id: staging/api-server
    type: k8s-deployment
    environment: staging
    sensitivity: internal
    owner: platform-team

  - id: dev/test-app
    type: k8s-deployment
    environment: dev
    sensitivity: public
"""


@cli.command()
@click.argument("directory", default=".")
def init(directory: str) -> None:
    """Scaffold a new Agent-Safe project with example config."""
    root = Path(directory)

    actions_dir = root / "actions"
    policies_dir = root / "policies"
    inventory_file = root / "inventory.yaml"

    created: list[str] = []

    if not actions_dir.exists():
        actions_dir.mkdir(parents=True)
        (actions_dir / "restart-deployment.yaml").write_text(
            _INIT_ACTION, encoding="utf-8"
        )
        created.append("actions/restart-deployment.yaml")
    else:
        click.echo("  skip  actions/ (already exists)")

    if not policies_dir.exists():
        policies_dir.mkdir(parents=True)
        (policies_dir / "default.yaml").write_text(
            _INIT_POLICY, encoding="utf-8"
        )
        created.append("policies/default.yaml")
    else:
        click.echo("  skip  policies/ (already exists)")

    if not inventory_file.exists():
        inventory_file.write_text(_INIT_INVENTORY, encoding="utf-8")
        created.append("inventory.yaml")
    else:
        click.echo("  skip  inventory.yaml (already exists)")

    if created:
        click.echo(click.style("Created:", fg="green"))
        for f in created:
            click.echo(f"  + {f}")
        click.echo(f"\nRun: agent-safe validate --registry {actions_dir} "
                    f"--policies {policies_dir} --inventory {inventory_file}")
    else:
        click.echo("Nothing to create — all files already exist.")


# --- test command ---


@cli.command("test")
@click.argument("test_path")
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--policies", default=DEFAULT_POLICIES,
    help="Path to policies directory",
)
@click.option(
    "--inventory", default=DEFAULT_INVENTORY,
    help="Path to inventory YAML file",
)
def test_policies(
    test_path: str,
    registry: str,
    policies: str,
    inventory: str,
) -> None:
    """Run policy test cases against the current configuration.

    TEST_PATH is a YAML file or directory of YAML files containing test cases.
    Each test declares an action/target/caller/params and the expected decision.
    """
    # Load test cases
    try:
        cases = load_test_files(Path(test_path))
    except PolicyTestError as e:
        click.echo(click.style("ERROR", fg="red") + f"  {e}", err=True)
        sys.exit(1)

    # Load policy engine
    inv_path: str | None = inventory if Path(inventory).exists() else None
    try:
        safe = AgentSafe(
            registry=registry,
            policies=policies,
            inventory=inv_path,
        )
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    # Run tests
    suite = run_tests(safe, cases)

    # Report results
    for result in suite.results:
        if result.passed:
            click.echo(
                click.style("  PASS", fg="green")
                + f"  {result.case.name}"
            )
        else:
            click.echo(
                click.style("  FAIL", fg="red")
                + f"  {result.case.name}"
                + f"  (expected {result.case.expect},"
                + f" got {result.actual})"
            )
            click.echo(f"        reason: {result.reason}")

    # Summary
    click.echo("")
    if suite.all_passed:
        click.echo(click.style(
            f"All {suite.total} test(s) passed.", fg="green", bold=True,
        ))
    else:
        click.echo(
            click.style(f"{suite.failed} failed", fg="red", bold=True)
            + f", {suite.passed} passed, {suite.total} total."
        )
        sys.exit(1)


# --- check command ---


@cli.command()
@click.argument("action")
@click.option("--target", "-t", default=None, help="Target identifier")
@click.option("--caller", "-c", default=None, help="Caller agent ID")
@click.option(
    "--params", "-p", default=None,
    help="Action parameters as JSON string",
)
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--policies", default=DEFAULT_POLICIES,
    help="Path to policies directory",
)
@click.option(
    "--inventory", default=DEFAULT_INVENTORY,
    help="Path to inventory YAML file",
)
@click.option(
    "--audit-log", default=DEFAULT_AUDIT_LOG,
    help="Path to audit log file",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--signing-key", default=None,
    help="HMAC signing key for execution tickets",
)
@click.option(
    "--approval-store", default=None,
    help="Path to approval store file",
)
def check(
    action: str,
    target: str | None,
    caller: str | None,
    params: str | None,
    registry: str,
    policies: str,
    inventory: str,
    audit_log: str,
    json_output: bool,
    signing_key: str | None,
    approval_store: str | None,
) -> None:
    """Evaluate a policy decision for an action."""
    parsed_params: dict[str, Any] | None = None
    if params is not None:
        try:
            parsed_params = json.loads(params)
        except json.JSONDecodeError as e:
            click.echo(f"Error: invalid JSON in --params: {e}", err=True)
            sys.exit(1)

    inv_path: str | None = inventory if Path(inventory).exists() else None

    try:
        safe = AgentSafe(
            registry=registry,
            policies=policies,
            inventory=inv_path,
            audit_log=audit_log,
            signing_key=signing_key,
            approval_store=approval_store,
        )
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    decision = safe.check(
        action=action,
        target=target,
        caller=caller,
        params=parsed_params,
    )

    if json_output:
        click.echo(json.dumps(decision.model_dump(mode="json"), indent=2))
    else:
        color = {
            DecisionResult.ALLOW: "green",
            DecisionResult.DENY: "red",
            DecisionResult.REQUIRE_APPROVAL: "yellow",
        }.get(decision.result, "white")

        click.echo(
            click.style(decision.result.value.upper(), fg=color, bold=True)
            + f" — {decision.reason}"
        )
        click.echo(f"  action: {decision.action}")
        click.echo(f"  target: {decision.target}")
        click.echo(f"  caller: {decision.caller}")
        click.echo(f"  risk:   {decision.effective_risk}")
        click.echo(f"  audit:  {decision.audit_id}")
        if decision.policy_matched:
            click.echo(f"  policy: {decision.policy_matched}")
        if decision.ticket:
            click.echo(f"  ticket: {decision.ticket.token[:40]}...")
            click.echo(f"  nonce:  {decision.ticket.nonce}")
            click.echo(f"  expires: {decision.ticket.expires_at.isoformat()}")
        if decision.request_id:
            click.echo(f"  request: {decision.request_id}")
            click.echo(
                f"\n  Resolve: agent-safe approval approve {decision.request_id}"
            )


# --- list-actions command ---


@cli.command("list-actions")
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option("--tag", default=None, help="Filter by tag")
@click.option("--risk", default=None, help="Filter by risk class")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def list_actions(
    registry: str,
    tag: str | None,
    risk: str | None,
    json_output: bool,
) -> None:
    """Show all registered actions."""
    try:
        reg = load_registry(registry)
    except RegistryError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    actions = reg.actions
    if tag:
        actions = [a for a in actions if tag in a.tags]
    if risk:
        actions = [a for a in actions if a.risk_class == risk]

    actions.sort(key=lambda a: a.name)

    if json_output:
        data = [a.model_dump(mode="json") for a in actions]
        click.echo(json.dumps(data, indent=2))
    else:
        if not actions:
            click.echo("No actions found.")
            return
        for a in actions:
            risk_color = {
                "low": "green", "medium": "yellow",
                "high": "red", "critical": "magenta",
            }.get(a.risk_class, "white")
            click.echo(
                f"  {a.name:<30} "
                + click.style(f"[{a.risk_class}]", fg=risk_color)
                + f"  v{a.version}"
            )
        click.echo(f"\n{len(actions)} action(s) registered.")


# --- validate command ---


@cli.command()
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--policies", default=DEFAULT_POLICIES,
    help="Path to policies directory",
)
@click.option(
    "--inventory", default=None,
    help="Path to inventory YAML file",
)
def validate(
    registry: str | None,
    policies: str | None,
    inventory: str | None,
) -> None:
    """Validate configuration files."""
    errors: list[str] = []
    ok_count = 0

    if registry and Path(registry).is_dir():
        try:
            reg = load_registry(registry)
            click.echo(
                click.style("OK", fg="green")
                + f"  registry: {len(reg)} action(s) loaded"
            )
            ok_count += 1
        except RegistryError as e:
            errors.append(f"registry: {e}")
            click.echo(click.style("FAIL", fg="red") + f"  registry: {e}")

    if policies and Path(policies).is_dir():
        try:
            rules = load_policies(policies)
            click.echo(
                click.style("OK", fg="green")
                + f"  policies: {len(rules)} rule(s) loaded"
            )
            ok_count += 1
        except PDPError as e:
            errors.append(f"policies: {e}")
            click.echo(click.style("FAIL", fg="red") + f"  policies: {e}")

    if inventory and Path(inventory).exists():
        try:
            inv = load_inventory(inventory)
            click.echo(
                click.style("OK", fg="green")
                + f"  inventory: {len(inv)} target(s) loaded"
            )
            ok_count += 1
        except InventoryError as e:
            errors.append(f"inventory: {e}")
            click.echo(click.style("FAIL", fg="red") + f"  inventory: {e}")

    if errors:
        click.echo(f"\n{len(errors)} error(s) found.")
        sys.exit(1)
    elif ok_count > 0:
        click.echo(f"\nAll {ok_count} config(s) valid.")
    else:
        click.echo("No config files found to validate.")


# --- audit group ---


@cli.group()
def audit() -> None:
    """Audit log commands."""


@audit.command("verify")
@click.argument("log_file", default=DEFAULT_AUDIT_LOG)
def audit_verify(log_file: str) -> None:
    """Verify audit log chain integrity."""
    path = Path(log_file)
    if not path.exists():
        click.echo(f"Audit log not found: {path}")
        sys.exit(1)

    is_valid, errors = verify_log(path)

    if is_valid:
        click.echo(click.style("VALID", fg="green", bold=True)
                    + f" — audit log chain is intact ({path})")
    else:
        click.echo(click.style("INVALID", fg="red", bold=True)
                    + f" — {len(errors)} error(s) found:")
        for error in errors:
            click.echo(f"  - {error}")
        sys.exit(1)


@audit.command("show")
@click.argument("log_file", default=DEFAULT_AUDIT_LOG)
@click.option("--last", "count", default=20, help="Number of entries to show")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def audit_show(log_file: str, count: int, json_output: bool) -> None:
    """Show recent audit log entries."""
    path = Path(log_file)
    if not path.exists():
        click.echo(f"Audit log not found: {path}")
        sys.exit(1)

    logger = AuditLogger(path)
    events = logger.read_events()

    # Take last N
    events = events[-count:]

    if json_output:
        data = [e.model_dump(mode="json") for e in events]
        click.echo(json.dumps(data, indent=2))
    else:
        if not events:
            click.echo("No audit entries found.")
            return
        for event in events:
            color = {
                DecisionResult.ALLOW: "green",
                DecisionResult.DENY: "red",
                DecisionResult.REQUIRE_APPROVAL: "yellow",
            }.get(event.decision, "white")
            click.echo(
                f"  {event.timestamp.isoformat()[:19]}  "
                + click.style(
                    f"{event.decision.value.upper():<17}", fg=color
                )
                + f" {event.action:<25} "
                + f"target={event.target}  caller={event.caller}"
            )
        click.echo(f"\n{len(events)} event(s) shown.")


@audit.command("ship")
@click.argument("log_file", default=DEFAULT_AUDIT_LOG)
@click.option(
    "--backend", required=True,
    type=click.Choice(["filesystem", "webhook", "s3"]),
    help="Shipping backend",
)
@click.option("--path", "dest_path", default=None, help="Destination path (filesystem backend)")
@click.option("--url", default=None, help="Webhook URL (webhook backend)")
@click.option("--bucket", default=None, help="S3 bucket name (s3 backend)")
@click.option("--prefix", default="audit-logs/", help="S3 key prefix (s3 backend)")
def audit_ship(
    log_file: str,
    backend: str,
    dest_path: str | None,
    url: str | None,
    bucket: str | None,
    prefix: str,
) -> None:
    """Ship audit log events to an external backend.

    Reads all events from LOG_FILE and ships each one to the specified
    backend. Useful for backfilling, catch-up, or one-off exports.
    """
    from agent_safe.audit.shipper import (
        FilesystemShipper,
        S3Shipper,
        WebhookShipper,
    )

    path = Path(log_file)
    if not path.exists():
        click.echo(f"Audit log not found: {path}", err=True)
        sys.exit(1)

    # Build shipper
    if backend == "filesystem":
        if dest_path is None:
            click.echo("Error: --path is required for filesystem backend", err=True)
            sys.exit(1)
        shipper = FilesystemShipper(dest_path)
    elif backend == "webhook":
        if url is None:
            click.echo("Error: --url is required for webhook backend", err=True)
            sys.exit(1)
        shipper = WebhookShipper(url)
    elif backend == "s3":
        if bucket is None:
            click.echo("Error: --bucket is required for s3 backend", err=True)
            sys.exit(1)
        shipper = S3Shipper(bucket=bucket, prefix=prefix)
    else:
        click.echo(f"Unknown backend: {backend}", err=True)
        sys.exit(1)

    # Read and ship
    logger = AuditLogger(path)
    events = logger.read_events()

    if not events:
        click.echo("No events to ship.")
        return

    shipped = 0
    errors = 0
    for event in events:
        try:
            shipper.ship(event)
            shipped += 1
        except Exception as e:
            errors += 1
            click.echo(f"  Error shipping {event.event_id}: {e}", err=True)

    click.echo(
        click.style(f"Shipped {shipped} event(s)", fg="green")
        + (f", {errors} error(s)" if errors else "")
        + f" via {backend}."
    )
    if errors:
        sys.exit(1)


# --- ticket group ---


@cli.group()
def ticket() -> None:
    """Execution ticket commands."""


@ticket.command("verify")
@click.argument("token")
@click.option(
    "--signing-key", required=True,
    help="HMAC signing key used to issue the ticket",
)
@click.option("--action", "expected_action", default=None, help="Expected action (optional)")
@click.option("--target", "expected_target", default=None, help="Expected target (optional)")
@click.option("--issuer", default="agent-safe", help="Expected issuer")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def ticket_verify(
    token: str,
    signing_key: str,
    expected_action: str | None,
    expected_target: str | None,
    issuer: str,
    json_output: bool,
) -> None:
    """Verify a signed execution ticket."""
    from agent_safe.tickets.validator import TicketValidator

    validator = TicketValidator(signing_key=signing_key, issuer=issuer)
    result = validator.validate(
        token=token,
        expected_action=expected_action,
        expected_target=expected_target,
    )

    if json_output:
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        if result.valid:
            click.echo(
                click.style("VALID", fg="green", bold=True)
                + f" — {result.reason}"
            )
            assert result.ticket is not None
            click.echo(f"  action:  {result.ticket.action}")
            click.echo(f"  target:  {result.ticket.target}")
            click.echo(f"  caller:  {result.ticket.caller}")
            click.echo(f"  audit:   {result.ticket.audit_id}")
            click.echo(f"  nonce:   {result.ticket.nonce}")
            click.echo(f"  expires: {result.ticket.expires_at.isoformat()}")
        else:
            click.echo(
                click.style("INVALID", fg="red", bold=True)
                + f" — {result.reason}"
            )
            sys.exit(1)


# --- approval group ---


DEFAULT_APPROVAL_STORE = "./approvals.jsonl"


@cli.group()
def approval() -> None:
    """Approval workflow commands."""


@approval.command("list")
@click.option(
    "--store", default=DEFAULT_APPROVAL_STORE,
    help="Path to approval store file",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
def approval_list(store: str, json_output: bool) -> None:
    """List pending approval requests."""
    from agent_safe.approval.store import FileApprovalStore

    path = Path(store)
    if not path.exists():
        click.echo("No approval store found (no pending requests).")
        return

    approval_store = FileApprovalStore(path)
    pending = approval_store.list_pending()

    if json_output:
        data = [r.model_dump(mode="json") for r in pending]
        click.echo(json.dumps(data, indent=2))
    else:
        if not pending:
            click.echo("No pending approval requests.")
            return
        for req in pending:
            risk_color = {
                "low": "green", "medium": "yellow",
                "high": "red", "critical": "magenta",
            }.get(req.effective_risk, "white")
            click.echo(
                f"  {req.request_id}  "
                + click.style(f"[{req.effective_risk}]", fg=risk_color)
                + f"  {req.action:<25} target={req.target}"
                + f"  caller={req.caller}",
            )
            click.echo(f"    reason: {req.reason}")
            click.echo(f"    expires: {req.expires_at.isoformat()[:19]}")
        click.echo(f"\n{len(pending)} pending request(s).")


@approval.command("show")
@click.argument("request_id")
@click.option(
    "--store", default=DEFAULT_APPROVAL_STORE,
    help="Path to approval store file",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
def approval_show(
    request_id: str, store: str, json_output: bool,
) -> None:
    """Show details of an approval request."""
    from agent_safe.approval.store import FileApprovalStore

    path = Path(store)
    if not path.exists():
        click.echo(f"Approval store not found: {path}", err=True)
        sys.exit(1)

    approval_store = FileApprovalStore(path)
    req = approval_store.get(request_id)

    if req is None:
        click.echo(f"Request not found: {request_id}", err=True)
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(req.model_dump(mode="json"), indent=2))
    else:
        status_color = {
            "pending": "yellow", "approved": "green",
            "denied": "red", "expired": "white",
        }.get(req.status, "white")

        click.echo(
            click.style(req.status.value.upper(), fg=status_color, bold=True)
            + f" — {req.request_id}",
        )
        click.echo(f"  action:   {req.action}")
        click.echo(f"  target:   {req.target}")
        click.echo(f"  caller:   {req.caller}")
        click.echo(f"  risk:     {req.effective_risk}")
        click.echo(f"  reason:   {req.reason}")
        click.echo(f"  created:  {req.created_at.isoformat()[:19]}")
        click.echo(f"  expires:  {req.expires_at.isoformat()[:19]}")
        click.echo(f"  audit_id: {req.audit_id}")
        if req.resolved_by:
            click.echo(f"  resolved_by: {req.resolved_by}")
        if req.resolved_at:
            click.echo(f"  resolved_at: {req.resolved_at.isoformat()[:19]}")
        if req.resolution_reason:
            click.echo(f"  resolution_reason: {req.resolution_reason}")


@approval.command("approve")
@click.argument("request_id")
@click.option("--by", "resolved_by", default="cli-user", help="Who is approving")
@click.option("--reason", default=None, help="Reason for approval")
@click.option(
    "--store", default=DEFAULT_APPROVAL_STORE,
    help="Path to approval store file",
)
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--policies", default=DEFAULT_POLICIES,
    help="Path to policies directory",
)
@click.option(
    "--audit-log", default=DEFAULT_AUDIT_LOG,
    help="Path to audit log file",
)
@click.option("--signing-key", default=None, help="HMAC signing key")
def approval_approve(
    request_id: str,
    resolved_by: str,
    reason: str | None,
    store: str,
    registry: str,
    policies: str,
    audit_log: str,
    signing_key: str | None,
) -> None:
    """Approve a pending approval request."""
    _resolve_approval_cli(
        request_id, "approve", resolved_by, reason,
        store, registry, policies, audit_log, signing_key,
    )


@approval.command("deny")
@click.argument("request_id")
@click.option("--by", "resolved_by", default="cli-user", help="Who is denying")
@click.option("--reason", default=None, help="Reason for denial")
@click.option(
    "--store", default=DEFAULT_APPROVAL_STORE,
    help="Path to approval store file",
)
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--policies", default=DEFAULT_POLICIES,
    help="Path to policies directory",
)
@click.option(
    "--audit-log", default=DEFAULT_AUDIT_LOG,
    help="Path to audit log file",
)
def approval_deny(
    request_id: str,
    resolved_by: str,
    reason: str | None,
    store: str,
    registry: str,
    policies: str,
    audit_log: str,
) -> None:
    """Deny a pending approval request."""
    _resolve_approval_cli(
        request_id, "deny", resolved_by, reason,
        store, registry, policies, audit_log, None,
    )


def _resolve_approval_cli(
    request_id: str,
    action: str,
    resolved_by: str,
    reason: str | None,
    store: str,
    registry: str,
    policies: str,
    audit_log: str,
    signing_key: str | None,
) -> None:
    """Shared logic for approve/deny CLI commands."""
    try:
        safe = AgentSafe(
            registry=registry,
            policies=policies,
            audit_log=audit_log,
            approval_store=store,
            signing_key=signing_key,
        )
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    try:
        decision = safe.resolve_approval(
            request_id=request_id,
            action=action,
            resolved_by=resolved_by,
            reason=reason,
        )
    except Exception as e:
        click.echo(
            click.style("ERROR", fg="red") + f"  {e}", err=True,
        )
        sys.exit(1)

    color = "green" if decision.result == DecisionResult.ALLOW else "red"
    click.echo(
        click.style(decision.result.value.upper(), fg=color, bold=True)
        + f" — {decision.reason}",
    )
    click.echo(f"  request: {request_id}")
    click.echo(f"  action:  {decision.action}")
    click.echo(f"  target:  {decision.target}")
    if decision.ticket:
        click.echo(f"  ticket:  {decision.ticket.token[:40]}...")


# --- credential group ---


@cli.group()
def credential() -> None:
    """Credential vault commands."""


@credential.command("resolve")
@click.argument("token")
@click.option(
    "--signing-key", required=True,
    help="HMAC signing key used to issue the ticket",
)
@click.option(
    "--registry", default=DEFAULT_REGISTRY,
    help="Path to actions directory",
)
@click.option(
    "--vault-cred", multiple=True,
    help="Static credential: TYPE=VALUE (e.g., kubernetes=my-token)",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
def credential_resolve(
    token: str,
    signing_key: str,
    registry: str,
    vault_cred: tuple[str, ...],
    json_output: bool,
) -> None:
    """Resolve credentials for a valid execution ticket.

    Takes a signed ticket token, validates it, looks up the action's
    credential scope, and fetches credentials from the vault.
    """
    from agent_safe.tickets.validator import TicketValidator

    validator = TicketValidator(signing_key=signing_key)
    validation = validator.validate(token)

    if not validation.valid:
        click.echo(
            click.style("INVALID TICKET", fg="red", bold=True)
            + f" — {validation.reason}",
        )
        sys.exit(1)

    static_creds = _parse_vault_creds(vault_cred)

    from agent_safe.credentials.resolver import CredentialResolver
    from agent_safe.credentials.vault import build_vault

    vault = build_vault({"type": "env", "credentials": static_creds or None})
    reg = load_registry(registry)
    resolver = CredentialResolver(registry=reg, vault=vault)

    result = resolver.resolve(validation.ticket)

    if json_output:
        click.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    elif result.success:
        click.echo(
            click.style("OK", fg="green", bold=True)
            + f" — credential resolved for {result.action}",
        )
        assert result.credential is not None
        click.echo(f"  credential_id: {result.credential.credential_id}")
        click.echo(f"  type:          {result.credential.type}")
        click.echo(f"  expires:       {result.credential.expires_at.isoformat()}")
        click.echo(f"  ticket_nonce:  {result.ticket_nonce}")
    else:
        click.echo(
            click.style("FAILED", fg="red", bold=True)
            + f" — {result.error}",
        )
        sys.exit(1)


@credential.command("test-vault")
@click.option(
    "--vault-cred", multiple=True,
    help="Static credential: TYPE=VALUE",
)
@click.option(
    "--cred-type", default="kubernetes",
    help="Credential type to test",
)
def credential_test_vault(
    vault_cred: tuple[str, ...],
    cred_type: str,
) -> None:
    """Test vault connectivity and credential retrieval.

    Attempts to fetch a test credential from the configured vault.
    """
    from datetime import UTC, datetime, timedelta

    from agent_safe.credentials.vault import build_vault
    from agent_safe.models import CredentialScope, ExecutionTicket

    static_creds = _parse_vault_creds(vault_cred)
    vault = build_vault({"type": "env", "credentials": static_creds or None})

    scope = CredentialScope(type=cred_type, fields={"test": True}, ttl=60)
    now = datetime.now(tz=UTC)
    dummy_ticket = ExecutionTicket(
        token="test-token",
        action="test-action",
        target="test-target",
        caller="test-caller",
        audit_id="evt-test",
        nonce="test-nonce",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    try:
        cred = vault.get_credential(scope, dummy_ticket, ttl=60)
        click.echo(
            click.style("OK", fg="green", bold=True)
            + f" — vault returned credential: {cred.credential_id}",
        )
        click.echo(f"  type:    {cred.type}")
        click.echo(f"  expires: {cred.expires_at.isoformat()}")
        vault.revoke(cred.credential_id)
        click.echo("  revoke:  OK")
    except Exception as exc:
        click.echo(
            click.style("FAILED", fg="red", bold=True)
            + f" — {exc}",
        )
        sys.exit(1)


def _parse_vault_creds(
    vault_cred: tuple[str, ...],
) -> dict[str, dict[str, str]]:
    """Parse --vault-cred TYPE=VALUE args into a credentials dict."""
    creds: dict[str, dict[str, str]] = {}
    for entry in vault_cred:
        if "=" not in entry:
            click.echo(
                f"Error: --vault-cred must be TYPE=VALUE, got: {entry}",
                err=True,
            )
            sys.exit(1)
        cred_type, cred_value = entry.split("=", 1)
        creds[cred_type] = {"token": cred_value}
    return creds
