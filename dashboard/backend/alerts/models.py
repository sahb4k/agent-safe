"""Data models for alert rules and alert history."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AlertConditions(BaseModel):
    """Conditions that an event must match to trigger the rule."""

    risk_classes: list[str] | None = None
    decisions: list[str] | None = None
    action_patterns: list[str] | None = None
    event_types: list[str] | None = None


class AlertChannels(BaseModel):
    """Notification channel configuration."""

    webhook_url: str | None = None
    webhook_headers: dict[str, str] | None = None
    slack_webhook_url: str | None = None
    slack_channel: str | None = None


class AlertRuleInfo(BaseModel):
    """Read response for an alert rule."""

    rule_id: str
    name: str
    description: str
    is_active: bool
    conditions: AlertConditions
    cluster_ids: list[str] | None = None
    threshold: int = 1
    window_seconds: int = 0
    channels: AlertChannels
    cooldown_seconds: int = 300
    created_by: str
    created_at: datetime
    updated_at: datetime


class AlertRuleCreateRequest(BaseModel):
    """Request body for creating an alert rule."""

    name: str
    description: str = ""
    conditions: AlertConditions = Field(default_factory=AlertConditions)
    cluster_ids: list[str] | None = None
    threshold: int = 1
    window_seconds: int = 0
    channels: AlertChannels
    cooldown_seconds: int = 300


class AlertRuleUpdateRequest(BaseModel):
    """Request body for updating an alert rule. All fields optional."""

    name: str | None = None
    description: str | None = None
    conditions: AlertConditions | None = None
    cluster_ids: list[str] | None = Field(default=None)
    threshold: int | None = None
    window_seconds: int | None = None
    channels: AlertChannels | None = None
    cooldown_seconds: int | None = None
    is_active: bool | None = None


class AlertHistoryItem(BaseModel):
    """A single fired alert record."""

    id: int
    rule_id: str
    rule_name: str
    cluster_id: str
    fired_at: datetime
    trigger_event_ids: list[str]
    conditions_snapshot: AlertConditions
    notification_status: str
    notification_error: str | None = None
