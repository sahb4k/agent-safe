"""Approval request store.

File-backed (JSONL) store for pending approval requests.
Thread-safe via a lock on all write operations.

Unlike the audit log (append-only for tamper evidence), the approval store
uses rewrite-on-update because approval requests are low-volume and need
mutable state (pending -> approved/denied/expired).
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agent_safe.models import ApprovalRequest, ApprovalStatus, Decision

DEFAULT_APPROVAL_TTL = timedelta(hours=1)


class ApprovalStoreError(Exception):
    """Raised when the approval store encounters an error."""


@runtime_checkable
class ApprovalStore(Protocol):
    """Protocol for approval request storage backends."""

    def create(
        self,
        decision: Decision,
        params: dict[str, Any] | None = None,
        ttl: timedelta | None = None,
    ) -> ApprovalRequest: ...

    def get(self, request_id: str) -> ApprovalRequest | None: ...

    def resolve(
        self,
        request_id: str,
        status: ApprovalStatus,
        resolved_by: str = "unknown",
        reason: str | None = None,
    ) -> ApprovalRequest: ...

    def list_pending(self) -> list[ApprovalRequest]: ...


class FileApprovalStore:
    """JSONL-backed approval request store.

    Each request is a JSON line in the store file. On resolution or expiry,
    the file is rewritten. Thread-safe via a lock.
    """

    def __init__(
        self,
        store_path: str | Path,
        ttl: timedelta | None = None,
    ) -> None:
        self._path = Path(store_path)
        self._ttl = ttl if ttl is not None else DEFAULT_APPROVAL_TTL
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def create(
        self,
        decision: Decision,
        params: dict[str, Any] | None = None,
        ttl: timedelta | None = None,
    ) -> ApprovalRequest:
        """Create a new pending approval request from a REQUIRE_APPROVAL decision."""
        now = datetime.now(tz=UTC)
        effective_ttl = ttl if ttl is not None else self._ttl
        request_id = f"apr-{uuid.uuid4().hex[:12]}"

        request = ApprovalRequest(
            request_id=request_id,
            audit_id=decision.audit_id,
            action=decision.action,
            target=decision.target,
            caller=decision.caller,
            params=params or {},
            risk_class=decision.risk_class,
            effective_risk=decision.effective_risk,
            policy_matched=decision.policy_matched,
            reason=decision.reason,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + effective_ttl,
        )

        with self._lock:
            self._append_request(request)

        return request

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Get a request by ID. Auto-expires if past TTL."""
        with self._lock:
            requests = self._read_all()
            for i, req in enumerate(requests):
                if req.request_id == request_id:
                    if (
                        req.status == ApprovalStatus.PENDING
                        and datetime.now(tz=UTC) > req.expires_at
                    ):
                        req.status = ApprovalStatus.EXPIRED
                        requests[i] = req
                        self._write_all(requests)
                    return req
        return None

    def resolve(
        self,
        request_id: str,
        status: ApprovalStatus,
        resolved_by: str = "unknown",
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Resolve a pending request (approve or deny)."""
        if status not in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED):
            msg = f"Resolution status must be 'approved' or 'denied', got '{status}'"
            raise ApprovalStoreError(msg)

        with self._lock:
            requests = self._read_all()
            for i, req in enumerate(requests):
                if req.request_id == request_id:
                    # Check expiry
                    if (
                        req.status == ApprovalStatus.PENDING
                        and datetime.now(tz=UTC) > req.expires_at
                    ):
                        req.status = ApprovalStatus.EXPIRED
                        requests[i] = req
                        self._write_all(requests)

                    if req.status != ApprovalStatus.PENDING:
                        msg = f"Request {request_id} is already {req.status}"
                        raise ApprovalStoreError(msg)

                    req.status = status
                    req.resolved_at = datetime.now(tz=UTC)
                    req.resolved_by = resolved_by
                    req.resolution_reason = reason
                    requests[i] = req
                    self._write_all(requests)
                    return req

            msg = f"Request not found: {request_id}"
            raise ApprovalStoreError(msg)

    def list_pending(self) -> list[ApprovalRequest]:
        """List all pending (non-expired) requests."""
        now = datetime.now(tz=UTC)
        with self._lock:
            requests = self._read_all()
            pending: list[ApprovalRequest] = []
            needs_rewrite = False
            for i, req in enumerate(requests):
                if req.status == ApprovalStatus.PENDING:
                    if now > req.expires_at:
                        req.status = ApprovalStatus.EXPIRED
                        requests[i] = req
                        needs_rewrite = True
                    else:
                        pending.append(req)
            if needs_rewrite:
                self._write_all(requests)
        return pending

    def _read_all(self) -> list[ApprovalRequest]:
        """Read all requests from the store file."""
        if not self._path.exists():
            return []
        requests: list[ApprovalRequest] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                requests.append(ApprovalRequest(**data))
        return requests

    def _append_request(self, request: ApprovalRequest) -> None:
        """Append a single request to the store file."""
        line = json.dumps(request.model_dump(mode="json"), sort_keys=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _write_all(self, requests: list[ApprovalRequest]) -> None:
        """Rewrite the entire store file (used for updates)."""
        with self._path.open("w", encoding="utf-8") as f:
            for req in requests:
                line = json.dumps(req.model_dump(mode="json"), sort_keys=True)
                f.write(line + "\n")
