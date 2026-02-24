"""Pluggable audit log shippers for external storage.

Ships audit events to external backends after the local file write.
Shipping is fire-and-forget — failures are warned but never block logging.

Built-in backends:
- FilesystemShipper: append JSON lines to a second file
- WebhookShipper: POST JSON to a URL (stdlib only)
- S3Shipper: upload to S3 (requires optional boto3)

Custom shippers just need a ``ship(event: AuditEvent) -> None`` method.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_safe.models import AuditEvent


@runtime_checkable
class AuditShipper(Protocol):
    """Protocol for audit event shippers.

    Any object with a ``ship(event)`` method satisfies this protocol.
    """

    def ship(self, event: AuditEvent) -> None:
        """Ship a single audit event to an external backend."""
        ...


class FilesystemShipper:
    """Append audit events as JSON lines to a second file.

    Useful for NFS mounts, log rotation, or testing.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def ship(self, event: AuditEvent) -> None:
        line = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


class WebhookShipper:
    """POST audit events as JSON to a webhook URL.

    Uses stdlib ``urllib.request`` — no extra dependencies required.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout

    def ship(self, event: AuditEvent) -> None:
        envelope = {
            "event": event.model_dump(mode="json"),
            "shipped_at": datetime.now(tz=UTC).isoformat(),
        }
        body = json.dumps(envelope, sort_keys=True).encode("utf-8")

        req = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Content-Type": "application/json",
                **self._headers,
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=self._timeout)  # noqa: S310


class S3Shipper:
    """Upload audit events to an S3 bucket.

    Requires the optional ``boto3`` package (``pip install agent-safe[s3]``).

    Each event is stored as a separate JSON object with the key format:
    ``{prefix}{YYYY-MM-DD}/{event_id}.json``
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "audit-logs/",
        client: Any | None = None,
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix

        if client is not None:
            self._client = client
        else:
            try:
                import boto3  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "boto3 is required for S3Shipper. "
                    "Install it with: pip install agent-safe[s3]"
                ) from exc
            self._client = boto3.client("s3")

    def ship(self, event: AuditEvent) -> None:
        date_str = event.timestamp.strftime("%Y-%m-%d")
        key = f"{self._prefix}{date_str}/{event.event_id}.json"
        body = json.dumps(event.model_dump(mode="json"), sort_keys=True)

        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
        )


def build_shippers(config: dict[str, Any]) -> list[AuditShipper]:
    """Build shipper instances from a configuration dict.

    Supported keys:
    - ``filesystem_path``: path for FilesystemShipper
    - ``webhook_url``: URL for WebhookShipper
    - ``webhook_headers``: optional headers dict for WebhookShipper
    - ``webhook_timeout``: optional timeout for WebhookShipper (default 10.0)
    - ``s3_bucket``: bucket name for S3Shipper
    - ``s3_prefix``: optional key prefix for S3Shipper (default "audit-logs/")
    """
    shippers: list[AuditShipper] = []

    if config.get("filesystem_path") is not None:
        shippers.append(FilesystemShipper(config["filesystem_path"]))

    if config.get("webhook_url") is not None:
        shippers.append(
            WebhookShipper(
                url=config["webhook_url"],
                headers=config.get("webhook_headers"),
                timeout=config.get("webhook_timeout", 10.0),
            )
        )

    if config.get("s3_bucket") is not None:
        shippers.append(
            S3Shipper(
                bucket=config["s3_bucket"],
                prefix=config.get("s3_prefix", "audit-logs/"),
            )
        )

    return shippers
