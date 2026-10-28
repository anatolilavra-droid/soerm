"""Approval repository (table ``pending_changes``).

An approval stores identifiers, hashes, the requester/approver and a short reason - never the
change itself. A decision is a guarded ``UPDATE ... WHERE status = 'pending'``: of two
concurrent or repeated decisions exactly one succeeds. Each write appends its audit entry in the
same transaction. ``approval.apply`` records that an approved change was made (single use).
"""

import sqlite3
from datetime import datetime
from typing import Final

from soerm.domain.approval import Approval
from soerm.domain.audit import AuditEntry
from soerm.domain.enums import ApprovalStatus
from soerm.storage.audit import append_audit
from soerm.storage.codec import coerce_enum, to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, NotFoundError, StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = ["DECISION_ACTIONS", "ApprovalRepository"]

DECISION_ACTIONS: Final = frozenset({"approval.approve", "approval.reject", "approval.expire"})
_INSERT = (
    "INSERT INTO pending_changes (change_id, object_type, object_id, requester, approver,"
    " status, reason, before_hash, proposed_after_hash, requested_at, expires_at, decided_at,"
    " require_distinct_approver) VALUES (:change_id, :object_type, :object_id, :requester,"
    " :approver, :status, :reason, :before_hash, :proposed_after_hash, :requested_at,"
    " :expires_at, :decided_at, :require_distinct_approver)"
)
_DECIDE = (
    "UPDATE pending_changes SET status = :status, approver = :approver, decided_at = :decided_at"
    " WHERE change_id = :change_id AND status = 'pending'"
)
_GET = "SELECT * FROM pending_changes WHERE change_id = :change_id"
_LIST = (
    "SELECT * FROM pending_changes WHERE (:status IS NULL OR status = :status)"
    " AND (:object_id IS NULL OR object_id = :object_id) ORDER BY change_id"
)
_PENDING_SAME = (
    "SELECT * FROM pending_changes WHERE status = 'pending' AND object_type = :object_type"
    " AND object_id = :object_id AND proposed_after_hash = :proposed LIMIT 1"
)
_APPLIED = (
    "SELECT 1 FROM audit_log WHERE action = 'approval.apply' AND object_id = :change_id LIMIT 1"
)


def _optional_ts(value: datetime | None) -> str | None:
    return None if value is None else to_db_timestamp(value)


def _from_row(row: sqlite3.Row) -> Approval:
    try:
        return Approval(
            change_id=row["change_id"],
            object_type=row["object_type"],
            object_id=row["object_id"],
            requester=row["requester"],
            approver=row["approver"],
            status=row["status"],
            reason=row["reason"],
            before_hash=row["before_hash"],
            proposed_after_hash=row["proposed_after_hash"],
            requested_at=row["requested_at"],
            expires_at=row["expires_at"],
            decided_at=row["decided_at"],
            require_distinct_approver=bool(row["require_distinct_approver"]),
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="approval") from None


class ApprovalRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, approval: Approval, *, actor: str, at: datetime) -> AuditEntry:
        """Insert a pending approval and its ``approval.request`` audit entry."""
        if not isinstance(approval, Approval):
            raise StorageError("invalid_model", object_type="approval")
        model = approval.with_changes()
        if model.status is not ApprovalStatus.PENDING:
            raise StorageError("approval_not_pending")
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT,
                {
                    "change_id": model.change_id,
                    "object_type": model.object_type,
                    "object_id": model.object_id,
                    "requester": model.requester,
                    "approver": model.approver,
                    "status": model.status.value,
                    "reason": model.reason,
                    "before_hash": model.before_hash,
                    "proposed_after_hash": model.proposed_after_hash,
                    "requested_at": to_db_timestamp(model.requested_at),
                    "expires_at": to_db_timestamp(model.expires_at),
                    "decided_at": _optional_ts(model.decided_at),
                    "require_distinct_approver": int(model.require_distinct_approver),
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="approval.request",
                object_type="approval",
                object_id=model.change_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def decide(self, decided: Approval, *, actor: str, at: datetime, action: str) -> AuditEntry:
        """Store a decision (approved / rejected / expired) of a *pending* approval.

        The guarded update makes a repeated or concurrent decision a :class:`ConflictError`.
        """
        if action not in DECISION_ACTIONS:
            raise StorageError("invalid_action")
        model = decided.with_changes()
        if model.status is ApprovalStatus.PENDING:
            raise StorageError("approval_still_pending")
        with transaction(self._connection, write=True) as conn:
            row = conn.execute(_GET, {"change_id": model.change_id}).fetchone()
            if row is None:
                raise NotFoundError("approval")
            existing = _from_row(row)
            immutable = (
                "object_type", "object_id", "requester", "reason", "before_hash",
                "proposed_after_hash", "requested_at", "expires_at", "require_distinct_approver",
            )  # fmt: skip
            if any(getattr(existing, name) != getattr(model, name) for name in immutable):
                raise StorageError("immutable_field", field="approval")
            cursor = conn.execute(
                _DECIDE,
                {
                    "change_id": model.change_id,
                    "status": model.status.value,
                    "approver": model.approver,
                    "decided_at": _optional_ts(model.decided_at),
                },
            )
            if cursor.rowcount != 1:
                raise ConflictError("approval")
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action=action,
                object_type="approval",
                object_id=model.change_id,
                before_hash=existing.digest(),
                after_hash=model.digest(),
            )

    def record_application(
        self, change_id: str, *, before_hash: str, after_hash: str, actor: str, at: datetime
    ) -> AuditEntry:
        """Audit entry ``approval.apply``: the approved change was made (hashes of the target)."""
        require_write_transaction(self._connection)
        with transaction(self._connection, write=True) as conn:
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="approval.apply",
                object_type="approval",
                object_id=change_id,
                before_hash=before_hash,
                after_hash=after_hash,
            )

    def was_applied(self, change_id: str) -> bool:
        with transaction(self._connection, write=False) as conn:
            return conn.execute(_APPLIED, {"change_id": change_id}).fetchone() is not None

    def get(self, change_id: str) -> Approval | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET, {"change_id": change_id}).fetchone()
        return None if row is None else _from_row(row)

    def list_all(
        self, *, status: ApprovalStatus | None = None, object_id: str | None = None
    ) -> list[Approval]:
        params = {
            "status": None
            if status is None
            else coerce_enum(ApprovalStatus, status, "status").value,
            "object_id": object_id,
        }
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST, params).fetchall()
        return [_from_row(row) for row in rows]

    def find_pending(self, object_type: str, object_id: str, proposed_hash: str) -> Approval | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(
                _PENDING_SAME,
                {"object_type": object_type, "object_id": object_id, "proposed": proposed_hash},
            ).fetchone()
        return None if row is None else _from_row(row)
