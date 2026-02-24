"""Pydantic response schemas for the dashboard API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# --- Generic ---


class PaginatedResponse(BaseModel):
    """Wrapper for paginated list endpoints."""

    items: list[Any]
    total: int
    page: int
    page_size: int


# --- Audit ---


class AuditEventResponse(BaseModel):
    """A single audit event returned by the API."""

    event_id: str
    timestamp: datetime
    event_type: str
    action: str
    target: str
    caller: str
    decision: str
    reason: str
    risk_class: str
    effective_risk: str
    policy_matched: str | None = None
    correlation_id: str | None = None
    ticket_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] | None = None


class AuditStatsResponse(BaseModel):
    """Aggregate audit statistics."""

    total_events: int
    by_decision: dict[str, int]
    by_risk_class: dict[str, int]
    by_event_type: dict[str, int]


class TimelineBucket(BaseModel):
    """A single time bucket in the timeline."""

    timestamp: str
    count: int
    allow: int = 0
    deny: int = 0
    require_approval: int = 0


# --- Actions ---


class ActionSummary(BaseModel):
    """Compact view of an action definition."""

    name: str
    description: str
    risk_class: str
    tags: list[str]
    reversible: bool
    target_types: list[str]


class ParameterDetail(BaseModel):
    """A single parameter from an action definition."""

    name: str
    type: str
    required: bool
    description: str
    default: Any = None


class ActionDetailResponse(BaseModel):
    """Full action definition for the detail page."""

    name: str
    version: str
    description: str
    risk_class: str
    tags: list[str]
    target_types: list[str]
    reversible: bool
    rollback_action: str | None = None
    parameters: list[ParameterDetail]
    prechecks: list[dict[str, str]]
    credentials: dict[str, Any] | None = None
    state_fields: list[dict[str, Any]] = Field(default_factory=list)


# --- Policies ---


class PolicyRuleResponse(BaseModel):
    """A single policy rule."""

    name: str
    description: str
    priority: int
    decision: str
    reason: str
    match_actions: list[str]
    match_environments: list[str] | None = None
    match_sensitivities: list[str] | None = None
    match_risk_classes: list[str] | None = None


class PolicyMatchAnalysis(BaseModel):
    """Analysis of which targets a policy rule matches."""

    rule_name: str
    priority: int
    decision: str
    matching_target_count: int
    matching_targets: list[str]


# --- Activity ---


class ActivityFeedItem(BaseModel):
    """A recent activity item for the live feed."""

    event_id: str
    timestamp: datetime
    event_type: str
    action: str
    target: str
    caller: str
    decision: str
    risk_class: str


# --- Health ---


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    audit_events: int
    actions: int
    policies: int
