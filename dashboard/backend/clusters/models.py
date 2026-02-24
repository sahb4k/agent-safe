"""Data models for multi-cluster management."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ClusterInfo(BaseModel):
    """Public cluster information (no secrets)."""

    cluster_id: str
    name: str
    description: str
    api_key_prefix: str
    is_active: bool
    created_at: datetime
    last_seen: datetime | None = None
    event_count: int = 0


class ClusterCreateRequest(BaseModel):
    """Request to register a new cluster."""

    name: str
    description: str = ""


class ClusterCreateResponse(BaseModel):
    """Response after registering a cluster. The api_key is shown ONCE."""

    cluster: ClusterInfo
    api_key: str


class IngestRequest(BaseModel):
    """Batch of audit events shipped from a sidecar."""

    events: list[dict[str, Any]]


class IngestResponse(BaseModel):
    """Result of an ingestion batch."""

    accepted: int
    duplicates: int
    errors: int
