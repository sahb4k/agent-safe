"""Tests for PolicySyncClient — pulling policy bundles and writing local YAML."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from agent_safe.sync.policy_sync import PolicySyncClient

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _bundle_response(revision_id: int, rules: list[dict]) -> bytes:
    """Build a JSON response matching PolicyBundleResponse."""
    return json.dumps({
        "revision_id": revision_id,
        "published_at": "2025-06-01T12:00:00+00:00",
        "rules": rules,
    }).encode("utf-8")


SAMPLE_RULES = [
    {
        "name": "deny-prod-delete",
        "description": "Block deletions in prod",
        "priority": 900,
        "decision": "deny",
        "reason": "Production is protected",
        "match": {"actions": ["delete-*"], "targets": {"environments": ["prod"]}},
    },
    {
        "name": "allow-dev-all",
        "description": "All dev allowed",
        "priority": 10,
        "decision": "allow",
        "reason": "Dev is open",
        "match": {"targets": {"environments": ["dev"]}},
    },
]


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


class TestPolicySyncClient:
    def test_init_sets_url(self) -> None:
        client = PolicySyncClient("https://dash.example.com", "ask_key")
        assert "policy-bundle" in client._url

    def test_init_strips_trailing_slash(self) -> None:
        client = PolicySyncClient("https://dash.example.com/", "ask_key")
        assert client._url == "https://dash.example.com/api/clusters/policy-bundle"

    def test_last_revision_starts_none(self) -> None:
        client = PolicySyncClient("http://localhost", "key")
        assert client.last_revision is None


class TestSyncWrite:
    def test_sync_writes_managed_yaml(self, tmp_path: Path) -> None:
        """Successful sync should create _managed.yaml with valid YAML."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = _bundle_response(1, SAMPLE_RULES)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = client.sync()

        assert result is True
        assert client.last_revision == 1

        managed_file = tmp_path / "_managed.yaml"
        assert managed_file.exists()

        content = managed_file.read_text(encoding="utf-8")
        assert "DO NOT EDIT" in content
        assert "Revision: 1" in content

        parsed = yaml.safe_load(content)
        assert len(parsed["rules"]) == 2
        assert parsed["rules"][0]["name"] == "deny-prod-delete"

    def test_sync_skips_if_already_current(self, tmp_path: Path) -> None:
        """Second sync with same revision should return False."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = _bundle_response(1, SAMPLE_RULES)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert client.sync() is True
            assert client.sync() is False

    def test_sync_updates_on_new_revision(self, tmp_path: Path) -> None:
        """New revision should trigger a write."""
        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)

        mock_resp_1 = MagicMock()
        mock_resp_1.read.return_value = _bundle_response(1, SAMPLE_RULES[:1])
        mock_resp_1.__enter__ = lambda s: s
        mock_resp_1.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp_1):
            assert client.sync() is True
            assert client.last_revision == 1

        mock_resp_2 = MagicMock()
        mock_resp_2.read.return_value = _bundle_response(2, SAMPLE_RULES)
        mock_resp_2.__enter__ = lambda s: s
        mock_resp_2.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp_2):
            assert client.sync() is True
            assert client.last_revision == 2

        # Verify file has 2 rules from second revision
        parsed = yaml.safe_load(
            (tmp_path / "_managed.yaml").read_text(encoding="utf-8")
        )
        assert len(parsed["rules"]) == 2

    def test_sync_creates_output_dir(self) -> None:
        """Output dir is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "subdir" / "policies"

            mock_resp = MagicMock()
            mock_resp.read.return_value = _bundle_response(1, SAMPLE_RULES)
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)

            client = PolicySyncClient("http://localhost", "key", output_dir=output)

            with patch("urllib.request.urlopen", return_value=mock_resp):
                assert client.sync() is True

            assert (output / "_managed.yaml").exists()


class TestSyncErrors:
    def test_sync_returns_false_on_network_error(self, tmp_path: Path) -> None:
        """Network errors should be swallowed and return False."""
        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)

        with patch("urllib.request.urlopen", side_effect=ConnectionError("timeout")):
            assert client.sync() is False

        assert client.last_revision is None
        assert not (tmp_path / "_managed.yaml").exists()

    def test_sync_returns_false_on_404(self, tmp_path: Path) -> None:
        """HTTP 404 (no published revision) should return False gracefully."""
        import urllib.error

        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)
        err = urllib.error.HTTPError("url", 404, "Not Found", {}, None)

        with patch("urllib.request.urlopen", side_effect=err):
            assert client.sync() is False


class TestLoadPoliciesIntegration:
    def test_synced_yaml_loadable_by_pdp(self, tmp_path: Path) -> None:
        """The _managed.yaml file should be loadable by the PDP's load_policies()."""
        from agent_safe.pdp.engine import load_policies

        mock_resp = MagicMock()
        mock_resp.read.return_value = _bundle_response(1, SAMPLE_RULES)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        client = PolicySyncClient("http://localhost", "key", output_dir=tmp_path)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            client.sync()

        rules = load_policies(tmp_path)
        assert len(rules) == 2
        # Sorted by priority descending
        assert rules[0].name == "deny-prod-delete"
        assert rules[0].priority == 900
        assert rules[0].decision.value == "deny"
        assert rules[1].name == "allow-dev-all"
        assert rules[1].priority == 10
