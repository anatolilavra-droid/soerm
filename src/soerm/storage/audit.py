"""Append-only audit log with a SHA-256 hash chain.

* ``append_audit`` runs inside the caller's write transaction, so an object change and its
  audit entry commit or roll back together.
* The database refuses ``UPDATE`` and ``DELETE`` on ``audit_log`` (triggers with
  ``RAISE(ABORT, ...)``) and refuses an insert that does not extend the chain.
* ``verify_audit_chain`` recomputes the whole chain from the first entry. It also detects
  tampering done by someone who bypassed the triggers (for example dropped them).
* Entries hold identifiers, an action name and hashes only: no payload, evidence,
  description or secrets.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime

from soerm.domain.audit import GENESIS_HASH, AuditEntry, create_audit_entry
from soerm.domain.errors import IntegrityDomainError, ValidationDomainError
from soerm.storage.codec import to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = [
    "AuditHead",
    "AuditRepository",
    "append_audit",
    "get_audit_entry",
    "get_audit_head",
    "list_audit_entries",
    "verify_audit_chain",
]

_MAX_PAGE = 1000
_HEAD = "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
_INSERT = (
    "INSERT INTO audit_log (seq, ts, actor, action, object_type, object_id,"
    " before_hash, after_hash, prev_hash, entry_hash)"
    " VALUES (:seq, :ts, :actor, :action, :object_type, :object_id,"
    " :before_hash, :after_hash, :prev_hash, :entry_hash)"
)
_GET = (
    "SELECT seq, ts, actor, action, object_type, object_id, before_hash, after_hash,"
    " prev_hash, entry_hash FROM audit_log WHERE seq = :seq"
)
_LIST = (
    "SELECT seq, ts, actor, action, object_type, object_id, before_hash, after_hash,"
    " prev_hash, entry_hash FROM audit_log WHERE seq > :after ORDER BY seq LIMIT :limit"
)
_ALL = (
    "SELECT seq, ts, actor, action, object_type, object_id, before_hash, after_hash,"
    " prev_hash, entry_hash FROM audit_log ORDER BY seq"
)


@dataclass(frozen=True, slots=True)
class AuditHead:
    """Position and hash of the newest entry. An empty log has ``seq=0`` and the genesis
    hash. Store this value outside the database to detect a wholesale replacement."""

    seq: int
    entry_hash: str


def _entry_from_row(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        seq=row["seq"],
        timestamp=row["ts"],
        actor=row["actor"],
        action=row["action"],
        object_type=row["object_type"],
        object_id=row["object_id"],
        before_hash=row["before_hash"],
        after_hash=row["after_hash"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
    )


def _head(connection: sqlite3.Connection) -> AuditHead:
    row = connection.execute(_HEAD).fetchone()
    if row is None:
        return AuditHead(0, GENESIS_HASH)
    return AuditHead(int(row["seq"]), str(row["entry_hash"]))


def get_audit_head(connection: SoermConnection) -> AuditHead:
    """``seq`` and ``entry_hash`` of the newest audit entry."""
    with transaction(connection, write=False) as conn:
        return _head(conn)


def append_audit(
    connection: SoermConnection,
    *,
    timestamp: datetime,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    before_hash: str | None = None,
    after_hash: str | None = None,
) -> AuditEntry:
    """Append one entry to the chain. Needs an active write transaction."""
    require_write_transaction(connection)
    head = _head(connection)
    entry = create_audit_entry(
        seq=head.seq + 1,
        timestamp=timestamp,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        before_hash=before_hash,
        after_hash=after_hash,
        prev_hash=head.entry_hash,
    )
    connection.execute(
        _INSERT,
        {
            "seq": entry.seq,
            "ts": to_db_timestamp(entry.timestamp),
            "actor": entry.actor,
            "action": entry.action,
            "object_type": entry.object_type,
            "object_id": entry.object_id,
            "before_hash": entry.before_hash,
            "after_hash": entry.after_hash,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
        },
    )
    return entry


def get_audit_entry(connection: SoermConnection, seq: int) -> AuditEntry | None:
    """One entry by sequence number, or ``None``."""
    with transaction(connection, write=False) as conn:
        row = conn.execute(_GET, {"seq": seq}).fetchone()
    return None if row is None else _entry_from_row(row)


def list_audit_entries(
    connection: SoermConnection, *, after_seq: int = 0, limit: int = 100
) -> list[AuditEntry]:
    """Entries with ``seq > after_seq`` in order, at most ``limit`` (1..1000)."""
    if not 1 <= limit <= _MAX_PAGE or after_seq < 0:
        raise StorageError("invalid_page")
    with transaction(connection, write=False) as conn:
        rows = conn.execute(_LIST, {"after": after_seq, "limit": limit}).fetchall()
    return [_entry_from_row(row) for row in rows]


def verify_audit_chain(connection: SoermConnection) -> AuditHead:
    """Recompute the whole chain from the first entry; return the head if it is intact.

    Checks sequence numbers (1, 2, 3, ...), the genesis rule for the first ``prev_hash``,
    ``prev_hash`` links, recomputed ``entry_hash`` values and their uniqueness. Raises
    :class:`IntegrityDomainError` naming the first broken entry.
    """
    previous = GENESIS_HASH
    seen: set[str] = set()
    count = 0
    with transaction(connection, write=False) as conn:
        for row in conn.execute(_ALL):
            count += 1
            seq = row["seq"]
            if type(seq) is not int or seq != count:
                raise IntegrityDomainError("sequence_gap", seq=count)
            if row["prev_hash"] != previous:
                reason = "genesis_rule" if count == 1 else "chain_broken"
                raise IntegrityDomainError(reason, seq=count)
            try:
                entry = _entry_from_row(row)
            except IntegrityDomainError as exc:
                raise IntegrityDomainError(
                    exc.details.get("reason", "integrity"), seq=count
                ) from None
            except ValidationDomainError:
                raise IntegrityDomainError("malformed_row", seq=count) from None
            if entry.entry_hash in seen:
                raise IntegrityDomainError("duplicate_entry_hash", seq=count)
            seen.add(entry.entry_hash)
            previous = entry.entry_hash
    return AuditHead(count, previous)


class AuditRepository:
    """Thin object wrapper over the module functions."""

    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def append(
        self,
        *,
        timestamp: datetime,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        before_hash: str | None = None,
        after_hash: str | None = None,
    ) -> AuditEntry:
        return append_audit(
            self._connection,
            timestamp=timestamp,
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            before_hash=before_hash,
            after_hash=after_hash,
        )

    def get(self, seq: int) -> AuditEntry | None:
        return get_audit_entry(self._connection, seq)

    def list(self, *, after_seq: int = 0, limit: int = 100) -> list[AuditEntry]:
        return list_audit_entries(self._connection, after_seq=after_seq, limit=limit)

    def head(self) -> AuditHead:
        return get_audit_head(self._connection)

    def verify(self) -> AuditHead:
        return verify_audit_chain(self._connection)
