"""Core data models for Agent-Safe.

Defines the schemas for:
- Action definitions (what agents can do)
- Policy rules (what's allowed/denied)
- Target inventory (what infrastructure exists)
- Agent identity (who is the caller)
- Audit events (what happened)
- Decisions (PDP output)
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# --- Enums ---


class RiskClass(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(enum.StrEnum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class Sensitivity(enum.StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    CRITICAL = "critical"


class DecisionResult(enum.StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ParamType(enum.StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"


# --- Action Schema ---


class ParamConstraints(BaseModel):
    """Validation constraints for an action parameter."""

    min_value: float | None = None
    max_value: float | None = None
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None
    enum: list[str] | None = None


class ActionParameter(BaseModel):
    """A single parameter in an action definition."""

    name: str
    type: ParamType
    required: bool = True
    description: str = ""
    default: Any = None
    constraints: ParamConstraints | None = None


class Precheck(BaseModel):
    """A precondition to verify before an action can be considered."""

    name: str
    description: str


class ActionDefinition(BaseModel):
    """A registered action that agents can request.

    Loaded from YAML files in the actions/ directory.
    """

    name: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$")
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    description: str
    parameters: list[ActionParameter] = Field(default_factory=list)
    risk_class: RiskClass
    target_types: list[str] = Field(min_length=1)
    prechecks: list[Precheck] = Field(default_factory=list)
    reversible: bool = False
    rollback_action: str | None = None
    required_privileges: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


# --- Target Inventory Schema ---


class TargetDefinition(BaseModel):
    """A managed infrastructure target.

    Loaded from the inventory YAML file.
    """

    id: str
    type: str
    environment: Environment
    sensitivity: Sensitivity
    owner: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


# --- Policy Schema ---


class TargetSelector(BaseModel):
    """Matches targets by their properties. All specified fields must match (AND logic).
    Within a field, any value can match (OR logic)."""

    environments: list[Environment] | None = None
    sensitivities: list[Sensitivity] | None = None
    types: list[str] | None = None
    labels: dict[str, str] | None = None


class CallerSelector(BaseModel):
    """Matches callers by their identity claims. Same AND/OR logic as TargetSelector."""

    agent_ids: list[str] | None = None
    roles: list[str] | None = None
    groups: list[str] | None = None


class TimeWindow(BaseModel):
    """A time window during which a policy applies.

    days: 0=Monday, 6=Sunday
    hours: 0-23
    """

    days: list[int] | None = None
    start_hour: int = Field(0, ge=0, le=23)
    end_hour: int = Field(23, ge=0, le=23)


class PolicyMatch(BaseModel):
    """Conditions that must all be true for a policy rule to apply."""

    actions: list[str] = Field(default_factory=lambda: ["*"])
    targets: TargetSelector | None = None
    callers: CallerSelector | None = None
    time_windows: list[TimeWindow] | None = None
    risk_classes: list[RiskClass] | None = None


class PolicyRule(BaseModel):
    """A single policy rule.

    Rules are evaluated in priority order (highest first).
    First matching rule wins. If no rule matches, default is DENY.
    """

    name: str
    description: str = ""
    priority: int = 0
    match: PolicyMatch
    decision: DecisionResult
    reason: str


# --- Agent Identity Schema ---


class AgentIdentity(BaseModel):
    """Identity claims for an agent, extracted from a JWT."""

    agent_id: str
    agent_name: str = ""
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    issued_at: datetime | None = None
    expires_at: datetime | None = None


# --- Decision (PDP Output) ---


class Decision(BaseModel):
    """The result of a policy evaluation."""

    result: DecisionResult
    reason: str
    action: str
    target: str
    caller: str
    risk_class: RiskClass
    effective_risk: RiskClass
    policy_matched: str | None = None
    audit_id: str

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# --- Audit Event Schema ---


class AuditEvent(BaseModel):
    """A single entry in the append-only audit log."""

    event_id: str
    timestamp: datetime
    prev_hash: str
    entry_hash: str = ""
    action: str
    target: str
    caller: str
    params: dict[str, Any] = Field(default_factory=dict)
    decision: DecisionResult
    reason: str
    policy_matched: str | None = None
    risk_class: RiskClass
    effective_risk: RiskClass
    correlation_id: str | None = None
    context: dict[str, Any] | None = None


# --- Risk Matrix ---

RISK_MATRIX: dict[RiskClass, dict[Sensitivity, RiskClass]] = {
    RiskClass.LOW: {
        Sensitivity.PUBLIC: RiskClass.LOW,
        Sensitivity.INTERNAL: RiskClass.LOW,
        Sensitivity.RESTRICTED: RiskClass.MEDIUM,
        Sensitivity.CRITICAL: RiskClass.HIGH,
    },
    RiskClass.MEDIUM: {
        Sensitivity.PUBLIC: RiskClass.LOW,
        Sensitivity.INTERNAL: RiskClass.MEDIUM,
        Sensitivity.RESTRICTED: RiskClass.HIGH,
        Sensitivity.CRITICAL: RiskClass.CRITICAL,
    },
    RiskClass.HIGH: {
        Sensitivity.PUBLIC: RiskClass.MEDIUM,
        Sensitivity.INTERNAL: RiskClass.HIGH,
        Sensitivity.RESTRICTED: RiskClass.CRITICAL,
        Sensitivity.CRITICAL: RiskClass.CRITICAL,
    },
    RiskClass.CRITICAL: {
        Sensitivity.PUBLIC: RiskClass.HIGH,
        Sensitivity.INTERNAL: RiskClass.CRITICAL,
        Sensitivity.RESTRICTED: RiskClass.CRITICAL,
        Sensitivity.CRITICAL: RiskClass.CRITICAL,
    },
}


def compute_effective_risk(action_risk: RiskClass, target_sensitivity: Sensitivity) -> RiskClass:
    """Compute effective risk from action risk class and target sensitivity."""
    return RISK_MATRIX[action_risk][target_sensitivity]
