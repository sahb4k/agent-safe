"""Data models for managed policy rules, revisions, and sync status."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# --- Match condition sub-models (mirrors core PolicyMatch) ---


class MatchTargets(BaseModel):
    """Target selector for policy matching."""

    environments: list[str] | None = None
    sensitivities: list[str] | None = None
    types: list[str] | None = None
    labels: dict[str, str] | None = None


class MatchCallers(BaseModel):
    """Caller selector for policy matching."""

    agent_ids: list[str] | None = None
    roles: list[str] | None = None
    groups: list[str] | None = None


class MatchConditions(BaseModel):
    """Serializable representation of policy match conditions."""

    actions: list[str] = Field(default_factory=lambda: ["*"])
    targets: MatchTargets | None = None
    callers: MatchCallers | None = None
    risk_classes: list[str] | None = None
    require_ticket: bool | None = None


# --- Managed policy CRUD ---


class ManagedPolicyInfo(BaseModel):
    """Read response for a managed policy rule."""

    policy_id: str
    name: str
    description: str
    priority: int
    decision: str
    reason: str
    match: MatchConditions
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime


class ManagedPolicyCreateRequest(BaseModel):
    """Request body for creating a managed policy rule."""

    name: str
    description: str = ""
    priority: int = 0
    decision: str  # allow | deny | require_approval
    reason: str
    match: MatchConditions = Field(default_factory=MatchConditions)


class ManagedPolicyUpdateRequest(BaseModel):
    """Request body for updating a managed policy. All fields optional."""

    name: str | None = None
    description: str | None = None
    priority: int | None = None
    decision: str | None = None
    reason: str | None = None
    match: MatchConditions | None = None
    is_active: bool | None = None


# --- Revisions ---


class PolicyRevisionInfo(BaseModel):
    """Read response for a policy revision snapshot."""

    revision_id: int
    rule_count: int
    published_by: str
    published_at: datetime
    notes: str


class PublishRequest(BaseModel):
    """Request body for publishing a new revision."""

    notes: str = ""


class PublishResponse(BaseModel):
    """Response after publishing a new revision."""

    revision: PolicyRevisionInfo
    bundle_preview: list[dict[str, Any]]


# --- Bundle sync ---


class PolicyBundleResponse(BaseModel):
    """Response returned to clusters pulling a policy bundle."""

    revision_id: int
    published_at: datetime
    rules: list[dict[str, Any]]


class ClusterSyncStatus(BaseModel):
    """Per-cluster policy sync status."""

    cluster_id: str
    cluster_name: str
    revision_id: int | None
    synced_at: datetime | None
    is_current: bool
