"""Tests for the approval notifier system."""

from __future__ import annotations

import json
import warnings
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

from agent_safe.approval.notifier import (
    ApprovalNotifier,
    NotifierWarning,
    SlackApprovalNotifier,
    WebhookApprovalNotifier,
    build_notifiers,
    dispatch_notifications,
)
from agent_safe.models import ApprovalRequest, ApprovalStatus, RiskClass


def _make_request(**overrides) -> ApprovalRequest:
    """Helper to create a test ApprovalRequest."""
    now = datetime.now(tz=UTC)
    defaults: dict[str, Any] = {
        "request_id": "apr-test000001",
        "audit_id": "evt-test000001",
        "action": "restart-deployment",
        "target": "prod/api-server",
        "caller": "deploy-agent-01",
        "params": {"namespace": "prod"},
        "risk_class": RiskClass.MEDIUM,
        "effective_risk": RiskClass.CRITICAL,
        "policy_matched": "require-approval-prod",
        "reason": "Production actions require approval",
        "status": ApprovalStatus.PENDING,
        "created_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return ApprovalRequest(**defaults)


# --- WebhookApprovalNotifier ---


class TestWebhookApprovalNotifier:
    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_posts_json(self, mock_urlopen: MagicMock):
        notifier = WebhookApprovalNotifier(url="https://hook.example.com/notify")
        request = _make_request()
        notifier.notify(request)

        mock_urlopen.assert_called_once()
        req_obj = mock_urlopen.call_args[0][0]
        assert req_obj.full_url == "https://hook.example.com/notify"
        assert req_obj.method == "POST"
        assert req_obj.get_header("Content-type") == "application/json"

        body = json.loads(req_obj.data.decode("utf-8"))
        assert body["type"] == "approval_request"
        assert body["request"]["request_id"] == "apr-test000001"
        assert "notified_at" in body

    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_includes_custom_headers(self, mock_urlopen: MagicMock):
        notifier = WebhookApprovalNotifier(
            url="https://hook.example.com/notify",
            headers={"Authorization": "Bearer tok123"},
        )
        notifier.notify(_make_request())

        req_obj = mock_urlopen.call_args[0][0]
        assert req_obj.get_header("Authorization") == "Bearer tok123"

    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_custom_timeout(self, mock_urlopen: MagicMock):
        notifier = WebhookApprovalNotifier(
            url="https://hook.example.com/notify", timeout=5.0,
        )
        notifier.notify(_make_request())

        _, kwargs = mock_urlopen.call_args
        assert kwargs["timeout"] == 5.0


# --- SlackApprovalNotifier ---


class TestSlackApprovalNotifier:
    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_posts_slack_message(self, mock_urlopen: MagicMock):
        notifier = SlackApprovalNotifier(
            webhook_url="https://hooks.slack.com/test",
        )
        notifier.notify(_make_request())

        mock_urlopen.assert_called_once()
        req_obj = mock_urlopen.call_args[0][0]
        body = json.loads(req_obj.data.decode("utf-8"))

        assert "text" in body
        assert "Approval Required" in body["text"]
        assert "restart-deployment" in body["text"]
        assert "apr-test000001" in body["text"]

    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_includes_channel(self, mock_urlopen: MagicMock):
        notifier = SlackApprovalNotifier(
            webhook_url="https://hooks.slack.com/test",
            channel="#approvals",
        )
        notifier.notify(_make_request())

        req_obj = mock_urlopen.call_args[0][0]
        body = json.loads(req_obj.data.decode("utf-8"))
        assert body["channel"] == "#approvals"

    @patch("agent_safe.approval.notifier.urllib.request.urlopen")
    def test_no_channel_by_default(self, mock_urlopen: MagicMock):
        notifier = SlackApprovalNotifier(
            webhook_url="https://hooks.slack.com/test",
        )
        notifier.notify(_make_request())

        req_obj = mock_urlopen.call_args[0][0]
        body = json.loads(req_obj.data.decode("utf-8"))
        assert "channel" not in body


# --- dispatch_notifications ---


class TestDispatchNotifications:
    def test_calls_all_notifiers(self):
        mock1 = MagicMock()
        mock2 = MagicMock()
        request = _make_request()
        dispatch_notifications([mock1, mock2], request)

        mock1.notify.assert_called_once_with(request)
        mock2.notify.assert_called_once_with(request)

    def test_failure_warns_but_does_not_raise(self):
        failing = MagicMock()
        failing.notify.side_effect = ConnectionError("network down")
        ok = MagicMock()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            dispatch_notifications([failing, ok], _make_request())

        # Failing notifier warned but didn't block the ok notifier
        ok.notify.assert_called_once()
        assert len(w) == 1
        assert issubclass(w[0].category, NotifierWarning)
        assert "network down" in str(w[0].message)

    def test_empty_notifiers_is_ok(self):
        dispatch_notifications([], _make_request())  # no error


# --- build_notifiers ---


class TestBuildNotifiers:
    def test_webhook_only(self):
        notifiers = build_notifiers({"webhook_url": "https://example.com/hook"})
        assert len(notifiers) == 1
        assert isinstance(notifiers[0], WebhookApprovalNotifier)

    def test_slack_only(self):
        notifiers = build_notifiers({
            "slack_webhook_url": "https://hooks.slack.com/x",
        })
        assert len(notifiers) == 1
        assert isinstance(notifiers[0], SlackApprovalNotifier)

    def test_both(self):
        notifiers = build_notifiers({
            "webhook_url": "https://example.com/hook",
            "slack_webhook_url": "https://hooks.slack.com/x",
            "slack_channel": "#ops",
        })
        assert len(notifiers) == 2

    def test_empty_config(self):
        assert build_notifiers({}) == []


# --- Protocol ---


class TestProtocol:
    def test_webhook_satisfies_protocol(self):
        n = WebhookApprovalNotifier(url="https://x.com")
        assert isinstance(n, ApprovalNotifier)

    def test_slack_satisfies_protocol(self):
        n = SlackApprovalNotifier(webhook_url="https://x.com")
        assert isinstance(n, ApprovalNotifier)
