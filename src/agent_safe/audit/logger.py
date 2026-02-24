"""Hash-chained append-only audit log.

Each entry is a JSON line containing the event data plus:
- prev_hash: SHA-256 of the previous entry (or "0"*64 for the first)
- entry_hash: SHA-256 of this entry's content (computed before writing)

This creates a tamper-evident chain — modifying or deleting any entry
breaks the chain and is detectable via verify().
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_safe.models import AuditEvent, Decision, DecisionResult, RiskClass, StateCapture

if TYPE_CHECKING:
    from agent_safe.audit.shipper import AuditShipper

GENESIS_HASH = "0" * 64


class AuditError(Exception):
    """Raised when the audit log encounters an error."""


class ShipperWarning(UserWarning):
    """Emitted when an audit shipper fails (non-fatal)."""


class AuditLogger:
    """Append-only, hash-chained JSON-lines audit logger.

    Thread-safe via a lock on write operations.
    """

    def __init__(
        self,
        log_path: str | Path,
        shippers: list[AuditShipper] | None = None,
    ) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._prev_hash = self._read_last_hash()
        self._shippers: list[AuditShipper] = shippers or []

    def _read_last_hash(self) -> str:
        """Read the hash of the last entry, or return genesis hash."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH

        # Read last non-empty line
        last_line = ""
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped

        if not last_line:
            return GENESIS_HASH

        try:
            entry = json.loads(last_line)
            return entry.get("entry_hash", GENESIS_HASH)
        except json.JSONDecodeError as exc:
            raise AuditError(
                f"Corrupt audit log — last line is not valid JSON: {self._path}"
            ) from exc

    @property
    def path(self) -> Path:
        return self._path

    @property
    def prev_hash(self) -> str:
        return self._prev_hash

    def log_decision(
        self,
        decision: Decision,
        params: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        context: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        """Log a PDP decision as an audit event.

        Returns the created AuditEvent (with computed hashes).
        """
        timestamp = timestamp or datetime.now(tz=UTC)

        event = AuditEvent(
            event_id=decision.audit_id,
            timestamp=timestamp,
            prev_hash=self._prev_hash,
            action=decision.action,
            target=decision.target,
            caller=decision.caller,
            params=params or {},
            decision=decision.result,
            reason=decision.reason,
            policy_matched=decision.policy_matched,
            risk_class=decision.risk_class,
            effective_risk=decision.effective_risk,
            correlation_id=correlation_id,
            ticket_id=decision.ticket_id,
            context=context,
        )

        return self._write_event(event)

    def log_raw(
        self,
        event_id: str,
        action: str,
        target: str,
        caller: str,
        decision: DecisionResult,
        reason: str,
        risk_class: RiskClass,
        effective_risk: RiskClass,
        params: dict[str, Any] | None = None,
        policy_matched: str | None = None,
        correlation_id: str | None = None,
        context: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        """Log an arbitrary audit event (for manual/direct logging)."""
        timestamp = timestamp or datetime.now(tz=UTC)

        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            prev_hash=self._prev_hash,
            action=action,
            target=target,
            caller=caller,
            params=params or {},
            decision=decision,
            reason=reason,
            policy_matched=policy_matched,
            risk_class=risk_class,
            effective_risk=effective_risk,
            correlation_id=correlation_id,
            context=context,
        )

        return self._write_event(event)

    def _write_event(self, event: AuditEvent) -> AuditEvent:
        """Compute hash, write to file, update chain."""
        # Compute entry hash over all fields except entry_hash itself
        hash_payload = event.model_dump(mode="json", exclude={"entry_hash"})
        payload_bytes = json.dumps(hash_payload, sort_keys=True).encode("utf-8")
        entry_hash = hashlib.sha256(payload_bytes).hexdigest()

        event.entry_hash = entry_hash

        # Serialize and write
        line = event.model_dump(mode="json")
        json_line = json.dumps(line, sort_keys=True)

        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json_line + "\n")
            self._prev_hash = entry_hash

        # Ship to external backends (fire-and-forget)
        for shipper in self._shippers:
            try:
                shipper.ship(event)
            except Exception as exc:
                warnings.warn(
                    f"Audit shipper {type(shipper).__name__} failed: {exc}",
                    ShipperWarning,
                    stacklevel=2,
                )

        return event

    def log_state_capture(
        self,
        state_capture: StateCapture,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        """Log a state capture event linked to an original decision.

        Uses the existing hash chain and shipping infrastructure.
        The state data is stored in the ``context`` field.

        Args:
            state_capture: The StateCapture with before/after/diff data.
            timestamp: Override event timestamp (defaults to now).

        Returns:
            The created AuditEvent.
        """
        timestamp = timestamp or datetime.now(tz=UTC)

        event = AuditEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            timestamp=timestamp,
            prev_hash=self._prev_hash,
            event_type="state_capture",
            action=state_capture.action,
            target=state_capture.target,
            caller=state_capture.caller,
            decision=DecisionResult.ALLOW,
            reason=f"State capture for {state_capture.audit_id}",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            correlation_id=state_capture.audit_id,
            context={
                "type": "state_capture",
                "original_audit_id": state_capture.audit_id,
                "before_state": state_capture.before_state,
                "after_state": state_capture.after_state,
                "diff": state_capture.diff,
                "capture_duration_ms": state_capture.capture_duration_ms,
                "state_fields_declared": state_capture.state_fields_declared,
                "state_fields_captured": state_capture.state_fields_captured,
            },
        )

        return self._write_event(event)

    def get_state_captures(self, audit_id: str) -> list[AuditEvent]:
        """Return state capture events linked to a decision audit_id."""
        events = self.read_events()
        return [
            e for e in events
            if e.event_type == "state_capture"
            and e.context is not None
            and e.context.get("original_audit_id") == audit_id
        ]

    def get_decision_event(self, audit_id: str) -> AuditEvent | None:
        """Return the decision audit event with the given event_id."""
        events = self.read_events()
        for event in events:
            if event.event_id == audit_id and event.event_type == "decision":
                return event
        return None

    def read_events(self) -> list[AuditEvent]:
        """Read all events from the log file."""
        if not self._path.exists():
            return []

        events: list[AuditEvent] = []
        with self._path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    events.append(AuditEvent(**data))
                except (json.JSONDecodeError, Exception) as e:
                    raise AuditError(
                        f"Corrupt entry at line {i + 1} in {self._path}: {e}"
                    ) from e

        return events


def verify_log(log_path: str | Path) -> tuple[bool, list[str]]:
    """Verify the integrity of a hash-chained audit log.

    Returns (is_valid, list_of_errors).
    An empty error list means the log is intact.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return True, []  # No log = nothing to verify

    errors: list[str] = []
    prev_hash = GENESIS_HASH
    line_num = 0

    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            line_num += 1

            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: invalid JSON: {e}")
                continue

            # Check prev_hash chain
            stored_prev = data.get("prev_hash", "")
            if stored_prev != prev_hash:
                errors.append(
                    f"Line {line_num}: chain broken — "
                    f"expected prev_hash {prev_hash[:16]}..., "
                    f"got {stored_prev[:16]}..."
                )

            # Recompute entry hash
            stored_hash = data.get("entry_hash", "")
            verify_data = {k: v for k, v in data.items() if k != "entry_hash"}
            recomputed = hashlib.sha256(
                json.dumps(verify_data, sort_keys=True).encode("utf-8")
            ).hexdigest()

            if stored_hash != recomputed:
                errors.append(
                    f"Line {line_num}: hash mismatch — "
                    f"stored {stored_hash[:16]}..., "
                    f"computed {recomputed[:16]}..."
                )

            prev_hash = stored_hash

    return len(errors) == 0, errors
