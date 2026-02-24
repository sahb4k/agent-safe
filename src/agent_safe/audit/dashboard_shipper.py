"""Ship audit events to a central Agent-Safe dashboard.

Used by sidecars to POST audit events to a dashboard's ingestion endpoint.
Authentication is via cluster API key (generated during cluster registration).

Uses stdlib ``urllib.request`` — no extra dependencies required.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import UTC, datetime

from agent_safe.models import AuditEvent


class DashboardShipper:
    """POST audit events to an Agent-Safe dashboard.

    Configure a sidecar to ship events::

        from agent_safe.audit.dashboard_shipper import DashboardShipper

        shipper = DashboardShipper(
            dashboard_url="https://dashboard.example.com",
            api_key="ask_abc123...",
        )

    Or via the shipper factory in ``agent-safe.yaml``::

        audit:
          shippers:
            dashboard_url: "https://dashboard.example.com"
            dashboard_api_key: "ask_abc123..."
    """

    def __init__(
        self,
        dashboard_url: str,
        api_key: str,
        timeout: float = 10.0,
    ) -> None:
        self._url = dashboard_url.rstrip("/") + "/api/clusters/ingest"
        self._api_key = api_key
        self._timeout = timeout

    def ship(self, event: AuditEvent) -> None:
        """Ship a single audit event to the dashboard."""
        envelope = {
            "events": [event.model_dump(mode="json")],
            "shipped_at": datetime.now(tz=UTC).isoformat(),
        }
        body = json.dumps(envelope, sort_keys=True).encode("utf-8")

        req = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=self._timeout)  # noqa: S310
