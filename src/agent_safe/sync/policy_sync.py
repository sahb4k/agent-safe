"""Pull managed policy bundles from a central Agent-Safe dashboard.

Used by sidecars to GET the latest policy bundle and write it as local YAML.
Authentication is via cluster API key (generated during cluster registration).

Uses stdlib ``urllib.request`` — no extra dependencies required.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class PolicySyncClient:
    """Pull policy bundles from an Agent-Safe dashboard and write to local YAML.

    Configure in a sidecar::

        from agent_safe.sync.policy_sync import PolicySyncClient

        client = PolicySyncClient(
            dashboard_url="https://dashboard.example.com",
            api_key="ask_abc123...",
            output_dir="./policies",
        )
        updated = client.sync()

    The sync writes a single ``_managed.yaml`` file in the output directory.
    The PDP's ``load_policies()`` will automatically pick it up alongside
    any other YAML files in the policies directory.
    """

    BUNDLE_FILENAME = "_managed.yaml"

    def __init__(
        self,
        dashboard_url: str,
        api_key: str,
        output_dir: str | Path = "./policies",
        timeout: float = 15.0,
    ) -> None:
        self._url = dashboard_url.rstrip("/") + "/api/clusters/policy-bundle"
        self._api_key = api_key
        self._output_dir = Path(output_dir)
        self._timeout = timeout
        self._last_revision: int | None = None

    @property
    def last_revision(self) -> int | None:
        """The last revision ID that was successfully synced, or None."""
        return self._last_revision

    def sync(self) -> bool:
        """Pull the latest bundle and write to disk.

        Returns ``True`` if a new revision was written, ``False`` if already
        current or if an error occurred (errors are logged, not raised).
        """
        try:
            bundle = self._fetch_bundle()
        except Exception:
            logger.exception("Failed to fetch policy bundle from dashboard")
            return False

        if bundle is None:
            logger.debug("No published revision available")
            return False

        revision_id = bundle["revision_id"]

        if self._last_revision is not None and revision_id <= self._last_revision:
            logger.debug(
                "Already at revision %d, skipping", self._last_revision
            )
            return False

        try:
            self._write_bundle(bundle["rules"], revision_id)
        except Exception:
            logger.exception("Failed to write policy bundle to disk")
            return False

        self._last_revision = revision_id
        logger.info(
            "Synced policy revision %d (%d rules)",
            revision_id,
            len(bundle["rules"]),
        )
        return True

    def _fetch_bundle(self) -> dict[str, Any] | None:
        """GET the latest bundle from the dashboard."""
        req = urllib.request.Request(
            self._url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def _write_bundle(
        self, rules: list[dict[str, Any]], revision_id: int,
    ) -> None:
        """Write rules as a YAML file in the output directory (atomic)."""
        self._output_dir.mkdir(parents=True, exist_ok=True)

        yaml_data = {"rules": rules}
        header = (
            f"# Managed policies - synced from dashboard\n"
            f"# Revision: {revision_id}\n"
            f"# Synced at: {datetime.now(tz=UTC).isoformat()}\n"
            f"# DO NOT EDIT - this file is overwritten by PolicySyncClient\n\n"
        )

        output_path = self._output_dir / self.BUNDLE_FILENAME
        tmp_path = output_path.with_suffix(".tmp")

        # Atomic write: write to tmp, then rename
        tmp_path.write_text(
            header + yaml.dump(yaml_data, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        tmp_path.replace(output_path)
