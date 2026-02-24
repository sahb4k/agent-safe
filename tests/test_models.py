"""Tests for Agent-Safe core data models.

TDD: these tests define the expected behavior of the schemas
before the business logic that uses them is built.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_safe.models import (
    ActionDefinition,
    ActionParameter,
    AgentIdentity,
    AuditEvent,
    CallerSelector,
    Decision,
    DecisionResult,
    Environment,
    ParamConstraints,
    ParamType,
    PolicyMatch,
    PolicyRule,
    Precheck,
    RiskClass,
    Sensitivity,
    TargetDefinition,
    TargetSelector,
    TimeWindow,
    compute_effective_risk,
)

# --- ActionDefinition Tests ---


class TestActionDefinition:
    def test_valid_minimal_action(self):
        action = ActionDefinition(
            name="restart-deployment",
            version="1.0.0",
            description="Restart a Kubernetes deployment",
            risk_class=RiskClass.MEDIUM,
            target_types=["k8s-deployment"],
        )
        assert action.name == "restart-deployment"
        assert action.version == "1.0.0"
        assert action.risk_class == RiskClass.MEDIUM
        assert action.parameters == []
        assert action.reversible is False
        assert action.rollback_action is None

    def test_valid_full_action(self):
        action = ActionDefinition(
            name="scale-deployment",
            version="1.0.0",
            description="Scale a Kubernetes deployment",
            parameters=[
                ActionParameter(
                    name="replicas",
                    type=ParamType.INTEGER,
                    required=True,
                    description="Target replica count",
                    constraints=ParamConstraints(min_value=0, max_value=100),
                ),
                ActionParameter(
                    name="namespace",
                    type=ParamType.STRING,
                    required=True,
                    description="Kubernetes namespace",
                ),
            ],
            risk_class=RiskClass.MEDIUM,
            target_types=["k8s-deployment"],
            prechecks=[
                Precheck(name="deployment-exists", description="Verify the deployment exists"),
            ],
            reversible=True,
            rollback_action="scale-deployment",
            required_privileges=["apps/deployments:patch"],
            tags=["kubernetes", "scaling"],
        )
        assert len(action.parameters) == 2
        assert action.parameters[0].name == "replicas"
        assert action.parameters[0].constraints.min_value == 0
        assert action.reversible is True
        assert len(action.prechecks) == 1

    def test_invalid_name_uppercase(self):
        with pytest.raises(ValidationError, match="name"):
            ActionDefinition(
                name="RestartDeployment",
                version="1.0.0",
                description="Bad name",
                risk_class=RiskClass.LOW,
                target_types=["k8s-deployment"],
            )

    def test_invalid_name_starts_with_number(self):
        with pytest.raises(ValidationError, match="name"):
            ActionDefinition(
                name="1-restart",
                version="1.0.0",
                description="Bad name",
                risk_class=RiskClass.LOW,
                target_types=["k8s-deployment"],
            )

    def test_invalid_version_format(self):
        with pytest.raises(ValidationError, match="version"):
            ActionDefinition(
                name="restart-deployment",
                version="1.0",
                description="Bad version",
                risk_class=RiskClass.LOW,
                target_types=["k8s-deployment"],
            )

    def test_empty_target_types_rejected(self):
        with pytest.raises(ValidationError, match="target_types"):
            ActionDefinition(
                name="restart-deployment",
                version="1.0.0",
                description="No targets",
                risk_class=RiskClass.LOW,
                target_types=[],
            )

    def test_invalid_risk_class(self):
        with pytest.raises(ValidationError):
            ActionDefinition(
                name="restart-deployment",
                version="1.0.0",
                description="Bad risk",
                risk_class="extreme",
                target_types=["k8s-deployment"],
            )


# --- ActionParameter Tests ---


class TestActionParameter:
    def test_required_param_no_default(self):
        param = ActionParameter(
            name="namespace",
            type=ParamType.STRING,
            required=True,
            description="K8s namespace",
        )
        assert param.required is True
        assert param.default is None

    def test_optional_param_with_default(self):
        param = ActionParameter(
            name="timeout",
            type=ParamType.INTEGER,
            required=False,
            default=30,
            description="Timeout in seconds",
        )
        assert param.required is False
        assert param.default == 30

    def test_param_with_constraints(self):
        param = ActionParameter(
            name="replicas",
            type=ParamType.INTEGER,
            required=True,
            description="Replica count",
            constraints=ParamConstraints(min_value=0, max_value=100),
        )
        assert param.constraints.min_value == 0
        assert param.constraints.max_value == 100

    def test_param_with_enum_constraint(self):
        param = ActionParameter(
            name="strategy",
            type=ParamType.STRING,
            required=False,
            default="RollingUpdate",
            description="Deployment strategy",
            constraints=ParamConstraints(enum=["RollingUpdate", "Recreate"]),
        )
        assert param.constraints.enum == ["RollingUpdate", "Recreate"]


# --- TargetDefinition Tests ---


class TestTargetDefinition:
    def test_valid_target(self):
        target = TargetDefinition(
            id="prod/api-server",
            type="k8s-deployment",
            environment=Environment.PROD,
            sensitivity=Sensitivity.CRITICAL,
            owner="platform-team",
            labels={"app": "api-server", "tier": "backend"},
        )
        assert target.id == "prod/api-server"
        assert target.environment == Environment.PROD
        assert target.sensitivity == Sensitivity.CRITICAL
        assert target.labels["app"] == "api-server"

    def test_minimal_target(self):
        target = TargetDefinition(
            id="dev/test-app",
            type="k8s-deployment",
            environment=Environment.DEV,
            sensitivity=Sensitivity.PUBLIC,
        )
        assert target.owner == ""
        assert target.labels == {}

    def test_invalid_environment(self):
        with pytest.raises(ValidationError):
            TargetDefinition(
                id="test",
                type="k8s-deployment",
                environment="laboratory",
                sensitivity=Sensitivity.PUBLIC,
            )

    def test_invalid_sensitivity(self):
        with pytest.raises(ValidationError):
            TargetDefinition(
                id="test",
                type="k8s-deployment",
                environment=Environment.DEV,
                sensitivity="top-secret",
            )


# --- PolicyRule Tests ---


class TestPolicyRule:
    def test_simple_deny_policy(self):
        rule = PolicyRule(
            name="deny-prod-without-approval",
            description="All prod actions need approval",
            priority=100,
            match=PolicyMatch(
                targets=TargetSelector(environments=[Environment.PROD]),
            ),
            decision=DecisionResult.DENY,
            reason="Production actions require explicit approval",
        )
        assert rule.priority == 100
        assert rule.decision == DecisionResult.DENY
        assert rule.match.targets.environments == [Environment.PROD]

    def test_allow_with_caller_restriction(self):
        rule = PolicyRule(
            name="allow-deploy-agent-staging",
            priority=50,
            match=PolicyMatch(
                actions=["restart-deployment", "scale-deployment"],
                targets=TargetSelector(environments=[Environment.STAGING]),
                callers=CallerSelector(roles=["deployer"]),
            ),
            decision=DecisionResult.ALLOW,
            reason="Deploy agents can manage staging deployments",
        )
        assert rule.match.actions == ["restart-deployment", "scale-deployment"]
        assert rule.match.callers.roles == ["deployer"]

    def test_time_windowed_policy(self):
        rule = PolicyRule(
            name="allow-maintenance-window",
            priority=200,
            match=PolicyMatch(
                actions=["drain-node"],
                targets=TargetSelector(environments=[Environment.PROD]),
                time_windows=[TimeWindow(days=[5, 6], start_hour=2, end_hour=6)],
            ),
            decision=DecisionResult.ALLOW,
            reason="Node drain allowed during weekend maintenance window",
        )
        assert rule.match.time_windows[0].days == [5, 6]
        assert rule.match.time_windows[0].start_hour == 2

    def test_wildcard_action_match(self):
        rule = PolicyRule(
            name="log-all-actions",
            match=PolicyMatch(actions=["*"]),
            decision=DecisionResult.ALLOW,
            reason="Catch-all allow for dev",
        )
        assert rule.match.actions == ["*"]
        assert rule.priority == 0  # default

    def test_risk_class_match(self):
        rule = PolicyRule(
            name="deny-critical-risk",
            priority=1000,
            match=PolicyMatch(
                risk_classes=[RiskClass.CRITICAL],
            ),
            decision=DecisionResult.REQUIRE_APPROVAL,
            reason="Critical risk actions always require human approval",
        )
        assert rule.match.risk_classes == [RiskClass.CRITICAL]

    def test_invalid_time_window_hour(self):
        with pytest.raises(ValidationError):
            TimeWindow(start_hour=25)


# --- AgentIdentity Tests ---


class TestAgentIdentity:
    def test_valid_identity(self):
        identity = AgentIdentity(
            agent_id="deploy-agent-01",
            agent_name="Deploy Agent",
            roles=["deployer", "reader"],
            groups=["platform-team"],
        )
        assert identity.agent_id == "deploy-agent-01"
        assert "deployer" in identity.roles

    def test_minimal_identity(self):
        identity = AgentIdentity(agent_id="test-agent")
        assert identity.agent_name == ""
        assert identity.roles == []
        assert identity.groups == []


# --- Decision Tests ---


class TestDecision:
    def test_allow_decision(self):
        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="Action allowed by policy staging-allow-all",
            action="restart-deployment",
            target="staging/api-server",
            caller="deploy-agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            policy_matched="staging-allow-all",
            audit_id="evt-abc123",
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.policy_matched == "staging-allow-all"

    def test_deny_decision(self):
        decision = Decision(
            result=DecisionResult.DENY,
            reason="No matching policy (default deny)",
            action="delete-namespace",
            target="prod/payments",
            caller="unknown-agent",
            risk_class=RiskClass.CRITICAL,
            effective_risk=RiskClass.CRITICAL,
            policy_matched=None,
            audit_id="evt-def456",
        )
        assert decision.result == DecisionResult.DENY
        assert decision.policy_matched is None

    def test_decision_to_dict(self):
        decision = Decision(
            result=DecisionResult.REQUIRE_APPROVAL,
            reason="Prod target requires approval",
            action="scale-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.HIGH,
            policy_matched="prod-require-approval",
            audit_id="evt-ghi789",
        )
        d = decision.to_dict()
        assert d["result"] == "require_approval"
        assert d["audit_id"] == "evt-ghi789"
        assert isinstance(d, dict)


# --- AuditEvent Tests ---


class TestAuditEvent:
    def test_valid_audit_event(self):
        event = AuditEvent(
            event_id="evt-abc123",
            timestamp=datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC),
            prev_hash="0" * 64,
            entry_hash="a" * 64,
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "production", "deployment": "api-server"},
            decision=DecisionResult.DENY,
            reason="Prod requires approval",
            policy_matched="deny-prod",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.HIGH,
            correlation_id="req-xyz789",
        )
        assert event.event_id == "evt-abc123"
        assert event.decision == DecisionResult.DENY
        assert event.correlation_id == "req-xyz789"

    def test_audit_event_minimal(self):
        event = AuditEvent(
            event_id="evt-001",
            timestamp=datetime.now(tz=UTC),
            prev_hash="0" * 64,
            action="get-pod-logs",
            target="dev/debug-pod",
            caller="debug-agent",
            decision=DecisionResult.ALLOW,
            reason="Dev allow-all",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
        )
        assert event.params == {}
        assert event.correlation_id is None
        assert event.context is None


# --- Risk Matrix Tests ---


class TestRiskMatrix:
    @pytest.mark.parametrize(
        "action_risk,target_sens,expected",
        [
            # Low-risk action across sensitivities
            (RiskClass.LOW, Sensitivity.PUBLIC, RiskClass.LOW),
            (RiskClass.LOW, Sensitivity.INTERNAL, RiskClass.LOW),
            (RiskClass.LOW, Sensitivity.RESTRICTED, RiskClass.MEDIUM),
            (RiskClass.LOW, Sensitivity.CRITICAL, RiskClass.HIGH),
            # Medium-risk action across sensitivities
            (RiskClass.MEDIUM, Sensitivity.PUBLIC, RiskClass.LOW),
            (RiskClass.MEDIUM, Sensitivity.INTERNAL, RiskClass.MEDIUM),
            (RiskClass.MEDIUM, Sensitivity.RESTRICTED, RiskClass.HIGH),
            (RiskClass.MEDIUM, Sensitivity.CRITICAL, RiskClass.CRITICAL),
            # High-risk action across sensitivities
            (RiskClass.HIGH, Sensitivity.PUBLIC, RiskClass.MEDIUM),
            (RiskClass.HIGH, Sensitivity.INTERNAL, RiskClass.HIGH),
            (RiskClass.HIGH, Sensitivity.RESTRICTED, RiskClass.CRITICAL),
            (RiskClass.HIGH, Sensitivity.CRITICAL, RiskClass.CRITICAL),
            # Critical-risk action across sensitivities
            (RiskClass.CRITICAL, Sensitivity.PUBLIC, RiskClass.HIGH),
            (RiskClass.CRITICAL, Sensitivity.INTERNAL, RiskClass.CRITICAL),
            (RiskClass.CRITICAL, Sensitivity.RESTRICTED, RiskClass.CRITICAL),
            (RiskClass.CRITICAL, Sensitivity.CRITICAL, RiskClass.CRITICAL),
        ],
    )
    def test_risk_matrix(self, action_risk, target_sens, expected):
        assert compute_effective_risk(action_risk, target_sens) == expected

    def test_highest_risk_combination(self):
        result = compute_effective_risk(RiskClass.CRITICAL, Sensitivity.CRITICAL)
        assert result == RiskClass.CRITICAL

    def test_lowest_risk_combination(self):
        result = compute_effective_risk(RiskClass.LOW, Sensitivity.PUBLIC)
        assert result == RiskClass.LOW
