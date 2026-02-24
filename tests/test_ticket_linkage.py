"""Tests for ticket/incident linkage (v0.5.0).

Covers:
- PolicyMatch.require_ticket model field
- Decision.ticket_id model field
- AuditEvent.ticket_id model field
- PDP ticket matching logic
- SDK check()/check_plan() with ticket_id
- CLI --ticket-id option
- Policy testing runner ticket_id support
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from agent_safe.audit.logger import AuditLogger
from agent_safe.cli.main import cli
from agent_safe.models import (
    AuditEvent,
    DecisionResult,
    PolicyMatch,
    PolicyRule,
    RiskClass,
    TargetDefinition,
)
from agent_safe.pdp.engine import PolicyDecisionPoint, _rule_matches
from agent_safe.registry.loader import load_registry
from agent_safe.sdk.client import AgentSafe
from agent_safe.testing.runner import TestCase, load_test_file, run_tests

# --- Test constants ---

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"

NOW = datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC)


def _make_rule(
    name: str,
    decision: DecisionResult,
    reason: str = "test",
    priority: int = 100,
    require_ticket: bool | None = None,
    actions: list[str] | None = None,
    environments: list[str] | None = None,
) -> PolicyRule:
    """Helper to create a PolicyRule."""
    match_kwargs: dict[str, Any] = {}
    if actions is not None:
        match_kwargs["actions"] = actions
    if require_ticket is not None:
        match_kwargs["require_ticket"] = require_ticket
    if environments is not None:
        from agent_safe.models import TargetSelector
        match_kwargs["targets"] = TargetSelector(environments=environments)
    return PolicyRule(
        name=name,
        priority=priority,
        match=PolicyMatch(**match_kwargs),
        decision=decision,
        reason=reason,
    )


# ============================================================
# PolicyMatch.require_ticket model tests
# ============================================================


class TestPolicyMatchRequireTicket:
    """Test the require_ticket field on PolicyMatch."""

    def test_default_is_none(self):
        match = PolicyMatch()
        assert match.require_ticket is None

    def test_set_to_true(self):
        match = PolicyMatch(require_ticket=True)
        assert match.require_ticket is True

    def test_set_to_false(self):
        match = PolicyMatch(require_ticket=False)
        assert match.require_ticket is False

    def test_backward_compatible(self):
        """Existing policies without require_ticket still work."""
        match = PolicyMatch(
            actions=["restart-deployment"],
            risk_classes=[RiskClass.HIGH],
        )
        assert match.require_ticket is None

    def test_from_yaml_dict(self):
        """PolicyRule can be constructed from a dict with require_ticket."""
        rule = PolicyRule(
            name="test",
            match=PolicyMatch(require_ticket=True),
            decision=DecisionResult.DENY,
            reason="needs ticket",
        )
        assert rule.match.require_ticket is True


# ============================================================
# Decision.ticket_id model tests
# ============================================================


class TestDecisionTicketId:
    """Test the ticket_id field on Decision."""

    def test_default_is_none(self):
        from agent_safe.models import Decision

        d = Decision(
            result=DecisionResult.ALLOW,
            reason="ok",
            action="test",
            target="t",
            caller="c",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )
        assert d.ticket_id is None

    def test_with_ticket_id(self):
        from agent_safe.models import Decision

        d = Decision(
            result=DecisionResult.ALLOW,
            reason="ok",
            action="test",
            target="t",
            caller="c",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
            ticket_id="JIRA-1234",
        )
        assert d.ticket_id == "JIRA-1234"

    def test_to_dict_includes_ticket_id(self):
        from agent_safe.models import Decision

        d = Decision(
            result=DecisionResult.ALLOW,
            reason="ok",
            action="test",
            target="t",
            caller="c",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
            ticket_id="INC-5678",
        )
        data = d.to_dict()
        assert data["ticket_id"] == "INC-5678"


# ============================================================
# AuditEvent.ticket_id model tests
# ============================================================


class TestAuditEventTicketId:
    """Test the ticket_id field on AuditEvent."""

    def test_default_is_none(self):
        event = AuditEvent(
            event_id="evt-1",
            timestamp=NOW,
            prev_hash="0" * 64,
            action="test",
            target="t",
            caller="c",
            decision=DecisionResult.ALLOW,
            reason="ok",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
        )
        assert event.ticket_id is None

    def test_with_ticket_id(self):
        event = AuditEvent(
            event_id="evt-1",
            timestamp=NOW,
            prev_hash="0" * 64,
            action="test",
            target="t",
            caller="c",
            decision=DecisionResult.ALLOW,
            reason="ok",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            ticket_id="JIRA-1234",
        )
        assert event.ticket_id == "JIRA-1234"


# ============================================================
# PDP ticket matching tests
# ============================================================


class TestPDPTicketMatching:
    """Test require_ticket matching in the PDP engine."""

    def _make_target(self) -> TargetDefinition:
        return TargetDefinition(
            id="dev/test-app",
            type="k8s-deployment",
            environment="dev",
            sensitivity="public",
        )

    def test_require_ticket_true_with_ticket_matches(self):
        """require_ticket: true matches when ticket_id is provided."""
        match = PolicyMatch(require_ticket=True)
        assert _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id="JIRA-1234",
        )

    def test_require_ticket_true_without_ticket_no_match(self):
        """require_ticket: true does not match when no ticket_id."""
        match = PolicyMatch(require_ticket=True)
        assert not _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id=None,
        )

    def test_require_ticket_true_empty_string_no_match(self):
        """require_ticket: true does not match when ticket_id is empty."""
        match = PolicyMatch(require_ticket=True)
        assert not _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id="",
        )

    def test_require_ticket_false_without_ticket_matches(self):
        """require_ticket: false matches when no ticket_id."""
        match = PolicyMatch(require_ticket=False)
        assert _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id=None,
        )

    def test_require_ticket_false_with_ticket_no_match(self):
        """require_ticket: false does not match when ticket_id is present."""
        match = PolicyMatch(require_ticket=False)
        assert not _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id="JIRA-1234",
        )

    def test_require_ticket_none_ignores_ticket(self):
        """require_ticket: null matches regardless of ticket_id."""
        match = PolicyMatch(require_ticket=None)
        assert _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id=None,
        )
        assert _rule_matches(
            match, "restart-deployment", self._make_target(),
            None, RiskClass.LOW, NOW, ticket_id="JIRA-1234",
        )

    def test_ticket_id_flows_to_decision(self):
        """ticket_id passed to evaluate() appears on the Decision."""
        registry = load_registry(ACTIONS_DIR)
        rule = _make_rule("allow-all", DecisionResult.ALLOW, reason="ok")
        pdp = PolicyDecisionPoint(rules=[rule], registry=registry)

        target = self._make_target()
        decision = pdp.evaluate(
            action="restart-deployment",
            target=target,
            caller=None,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=NOW,
            ticket_id="JIRA-1234",
        )
        assert decision.ticket_id == "JIRA-1234"

    def test_ticket_id_none_on_decision(self):
        """Decision.ticket_id is None when not provided."""
        registry = load_registry(ACTIONS_DIR)
        rule = _make_rule("allow-all", DecisionResult.ALLOW, reason="ok")
        pdp = PolicyDecisionPoint(rules=[rule], registry=registry)

        target = self._make_target()
        decision = pdp.evaluate(
            action="restart-deployment",
            target=target,
            caller=None,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=NOW,
        )
        assert decision.ticket_id is None

    def test_require_ticket_policy_denies_without_ticket(self):
        """A policy requiring a ticket causes default-deny when no ticket."""
        registry = load_registry(ACTIONS_DIR)
        # Only rule requires a ticket — without one, it won't match → default deny
        rule = _make_rule(
            "allow-with-ticket",
            DecisionResult.ALLOW,
            reason="ticket provided",
            require_ticket=True,
        )
        pdp = PolicyDecisionPoint(rules=[rule], registry=registry)

        target = self._make_target()
        decision = pdp.evaluate(
            action="restart-deployment",
            target=target,
            caller=None,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=NOW,
            ticket_id=None,
        )
        assert decision.result == DecisionResult.DENY
        assert "default deny" in decision.reason.lower()

    def test_require_ticket_policy_allows_with_ticket(self):
        """A policy requiring a ticket allows when ticket is provided."""
        registry = load_registry(ACTIONS_DIR)
        rule = _make_rule(
            "allow-with-ticket",
            DecisionResult.ALLOW,
            reason="ticket provided",
            require_ticket=True,
        )
        pdp = PolicyDecisionPoint(rules=[rule], registry=registry)

        target = self._make_target()
        decision = pdp.evaluate(
            action="restart-deployment",
            target=target,
            caller=None,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=NOW,
            ticket_id="JIRA-1234",
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket_id == "JIRA-1234"

    def test_ticket_id_in_audit_log(self):
        """ticket_id is recorded in the audit log."""
        registry = load_registry(ACTIONS_DIR)
        rule = _make_rule("allow-all", DecisionResult.ALLOW, reason="ok")

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = f.name

        audit = AuditLogger(log_path)
        pdp = PolicyDecisionPoint(
            rules=[rule], registry=registry, audit_logger=audit,
        )

        target = self._make_target()
        pdp.evaluate(
            action="restart-deployment",
            target=target,
            caller=None,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=NOW,
            ticket_id="INC-5678",
        )

        events = audit.read_events()
        assert len(events) == 1
        assert events[0].ticket_id == "INC-5678"

        Path(log_path).unlink(missing_ok=True)


# ============================================================
# SDK ticket linkage tests
# ============================================================


class TestSDKTicketLinkage:
    """Test ticket_id flow through the SDK."""

    def test_check_with_ticket_id(self):
        """safe.check() with ticket_id passes it to the decision."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
            ticket_id="JIRA-1234",
        )
        assert decision.ticket_id == "JIRA-1234"

    def test_check_without_ticket_id(self):
        """safe.check() without ticket_id leaves it as None."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.ticket_id is None

    def test_check_plan_with_ticket_id(self):
        """check_plan() passes ticket_id from each step."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        decisions = safe.check_plan([
            {
                "action": "restart-deployment",
                "target": "dev/test-app",
                "caller": "agent-01",
                "params": {"namespace": "dev", "deployment": "app"},
                "ticket_id": "JIRA-1234",
            },
            {
                "action": "restart-deployment",
                "target": "dev/test-app",
                "caller": "agent-01",
                "params": {"namespace": "dev", "deployment": "app"},
            },
        ])
        assert decisions[0].ticket_id == "JIRA-1234"
        assert decisions[1].ticket_id is None

    def test_ticket_id_in_decision_dict(self):
        """ticket_id appears in decision.to_dict()."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
            ticket_id="CHANGE-99",
        )
        data = decision.to_dict()
        assert data["ticket_id"] == "CHANGE-99"

    def test_ticket_id_with_correlation_id(self):
        """ticket_id and correlation_id can coexist."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
            correlation_id="trace-abc",
            ticket_id="JIRA-1234",
        )
        assert decision.ticket_id == "JIRA-1234"

    def test_ticket_id_in_audit_log_via_sdk(self):
        """ticket_id flows to audit log through the SDK."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            log_path = f.name

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=log_path,
        )
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
            ticket_id="INC-999",
        )

        events = safe.audit.read_events()
        assert len(events) == 1
        assert events[0].ticket_id == "INC-999"

        Path(log_path).unlink(missing_ok=True)


# ============================================================
# CLI ticket_id tests
# ============================================================


class TestCLITicketId:
    """Test --ticket-id CLI option."""

    def test_ticket_id_in_text_output(self):
        """--ticket-id appears in text output."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--caller", "agent-01",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--ticket-id", "JIRA-1234",
        ])
        assert result.exit_code == 0
        assert "JIRA-1234" in result.output

    def test_ticket_id_in_json_output(self):
        """--ticket-id appears in JSON output."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--caller", "agent-01",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--ticket-id", "INC-5678",
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["ticket_id"] == "INC-5678"

    def test_no_ticket_id_omits_line(self):
        """Without --ticket-id, no ticket_id line in output."""
        runner = CliRunner()
        result = runner.invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--caller", "agent-01",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 0
        assert "ticket_id:" not in result.output


# ============================================================
# Policy testing runner ticket_id tests
# ============================================================


class TestPolicyTestingTicketId:
    """Test ticket_id in the policy test runner."""

    def test_test_case_with_ticket_id(self):
        """TestCase accepts ticket_id."""
        case = TestCase(
            name="test",
            action="restart-deployment",
            ticket_id="JIRA-1234",
            expect="allow",
        )
        assert case.ticket_id == "JIRA-1234"

    def test_load_test_file_parses_ticket_id(self):
        """load_test_file() parses ticket_id from YAML."""
        yaml_content = """\
tests:
  - name: with-ticket
    action: restart-deployment
    target: dev/test-app
    params:
      namespace: dev
      deployment: app
    ticket_id: JIRA-1234
    expect: allow

  - name: without-ticket
    action: restart-deployment
    target: dev/test-app
    params:
      namespace: dev
      deployment: app
    expect: allow
"""
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False,
        ) as f:
            f.write(yaml_content)
            f.flush()
            cases = load_test_file(Path(f.name))

        assert len(cases) == 2
        assert cases[0].ticket_id == "JIRA-1234"
        assert cases[1].ticket_id is None

        Path(f.name).unlink(missing_ok=True)

    def test_run_tests_passes_ticket_id(self):
        """run_tests() passes ticket_id to safe.check()."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        cases = [
            TestCase(
                name="with-ticket",
                action="restart-deployment",
                target="dev/test-app",
                params={"namespace": "dev", "deployment": "app"},
                ticket_id="JIRA-1234",
                expect="allow",
            ),
        ]
        suite = run_tests(safe, cases)
        assert suite.all_passed
        assert suite.total == 1
