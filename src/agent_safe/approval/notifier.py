"""Approval notification dispatch.

Sends notifications when an approval request is created.
Fire-and-forget -- failures are warned but never block the request flow.

Built-in backends:
- WebhookApprovalNotifier: POST JSON to a URL (stdlib only)
- SlackApprovalNotifier: POST to Slack incoming webhook

Custom notifiers just need a ``notify(request: ApprovalRequest) -> None`` method.
"""

from __future__ import annotations

import json
import urllib.request
import warnings
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from agent_safe.models import ApprovalRequest


class NotifierWarning(UserWarning):
    """Emitted when an approval notifier fails (non-fatal)."""


@runtime_checkable
class ApprovalNotifier(Protocol):
    """Protocol for approval request notifiers."""

    def notify(self, request: ApprovalRequest) -> None:
        """Send notification for a new approval request."""
        ...


class WebhookApprovalNotifier:
    """POST approval requests as JSON to a webhook URL.

    Uses stdlib urllib.request -- no extra dependencies required.
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

    def notify(self, request: ApprovalRequest) -> None:
        envelope = {
            "type": "approval_request",
            "request": request.model_dump(mode="json"),
            "notified_at": datetime.now(tz=UTC).isoformat(),
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


class SlackApprovalNotifier:
    """Send approval requests to Slack via incoming webhook.

    Formats the request as a Slack message with action details.
    Uses stdlib urllib.request -- no extra dependencies required.
    """

    def __init__(
        self,
        webhook_url: str,
        channel: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._webhook_url = webhook_url
        self._channel = channel
        self._timeout = timeout

    def notify(self, request: ApprovalRequest) -> None:
        text = (
            f"*Approval Required*\n"
            f"*Action:* `{request.action}`\n"
            f"*Target:* `{request.target}`\n"
            f"*Caller:* `{request.caller}`\n"
            f"*Risk:* `{request.effective_risk}`\n"
            f"*Reason:* {request.reason}\n"
            f"*Request ID:* `{request.request_id}`\n"
            f"*Expires:* {request.expires_at.isoformat()}\n\n"
            f"Resolve with: `agent-safe approval approve {request.request_id}` "
            f"or `agent-safe approval deny {request.request_id}`"
        )

        payload: dict[str, Any] = {"text": text}
        if self._channel:
            payload["channel"] = self._channel

        body = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self._webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=self._timeout)  # noqa: S310


def dispatch_notifications(
    notifiers: list[ApprovalNotifier],
    request: ApprovalRequest,
) -> None:
    """Fire-and-forget notification dispatch.

    Follows the same pattern as audit shipper dispatch in AuditLogger.
    """
    for notifier in notifiers:
        try:
            notifier.notify(request)
        except Exception as exc:
            warnings.warn(
                f"Approval notifier {type(notifier).__name__} failed: {exc}",
                NotifierWarning,
                stacklevel=2,
            )


def build_notifiers(config: dict[str, Any]) -> list[ApprovalNotifier]:
    """Build notifier instances from a configuration dict.

    Supported keys:
    - webhook_url: URL for WebhookApprovalNotifier
    - webhook_headers: optional headers dict
    - webhook_timeout: optional timeout (default 10.0)
    - slack_webhook_url: Slack incoming webhook URL
    - slack_channel: optional Slack channel override
    """
    notifiers: list[ApprovalNotifier] = []

    if config.get("webhook_url") is not None:
        notifiers.append(
            WebhookApprovalNotifier(
                url=config["webhook_url"],
                headers=config.get("webhook_headers"),
                timeout=config.get("webhook_timeout", 10.0),
            ),
        )

    if config.get("slack_webhook_url") is not None:
        notifiers.append(
            SlackApprovalNotifier(
                webhook_url=config["slack_webhook_url"],
                channel=config.get("slack_channel"),
            ),
        )

    return notifiers
