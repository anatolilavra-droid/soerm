"""Incident repository: incidents, finding links, timeline events and notes.

Every audited write appends its audit entry in the same transaction. Audit entries hold
identifiers and hashes only; a note body is never copied into the audit log.
"""

import sqlite3
from datetime import datetime
from typing import Final

from soerm.domain.audit import AuditEntry
from soerm.domain.enums import IncidentStatus
from soerm.domain.hashing import hash_canonical
from soerm.domain.incident import Incident
from soerm.domain.incident_log import IncidentEvent, IncidentNote
from soerm.storage.audit import append_audit
from soerm.storage.codec import coerce_enum, to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, NotFoundError, StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = ["INCIDENT_UPDATE_ACTIONS", "IncidentRepository"]

# Audit actions an incident update may be recorded under (a fixed allowlist).
INCIDENT_UPDATE_ACTIONS: Final = frozenset(
    {"incident.update", "incident.transition", "incident.reopen", "incident.playbook_attach"}
)
_INSERT = (
    "INSERT INTO incidents (incident_id, title, severity, status, owner, summary, created_at,"
    " updated_at, closed_at, playbook_id, closure_reason) VALUES (:incident_id, :title,"
    " :severity, :status, :owner, :summary, :created_at, :updated_at, :closed_at,"
    " :playbook_id, :closure_reason)"
)
_UPDATE = (
    "UPDATE incidents SET title = :title, severity = :severity, status = :status,"
    " owner = :owner, summary = :summary, updated_at = :updated_at, closed_at = :closed_at,"
    " playbook_id = :playbook_id, closure_reason = :closure_reason"
    " WHERE incident_id = :incident_id"
)
_GET = "SELECT * FROM incidents WHERE incident_id = :incident_id"
_LIST = "SELECT * FROM incidents WHERE (:status IS NULL OR status = :status) ORDER BY incident_id"
_INSERT_LINK = (
    "INSERT INTO incident_links (incident_id, finding_id, linked_at)"
    " VALUES (:incident_id, :finding_id, :linked_at)"
)
_LINKS = (
    "SELECT finding_id, linked_at FROM incident_links WHERE incident_id = :id ORDER BY finding_id"
)
_LINKS_OF_FINDING = (
    "SELECT incident_id FROM incident_links WHERE finding_id = :id ORDER BY incident_id"
)
_INSERT_EVENT = (
    "INSERT INTO incident_events (incident_id, occurred_at, actor, event_type, from_status,"
    " to_status) VALUES (:incident_id, :occurred_at, :actor, :event_type, :from_status,"
    " :to_status)"
)
_EVENTS = "SELECT * FROM incident_events WHERE incident_id = :id ORDER BY event_id"
_INSERT_NOTE = (
    "INSERT INTO incident_notes (incident_id, created_at, author, redacted_body)"
    " VALUES (:incident_id, :created_at, :author, :redacted_body)"
)
_NOTES = "SELECT * FROM incident_notes WHERE incident_id = :id ORDER BY note_id"


def _params(incident: Incident) -> dict[str, object]:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "owner": incident.owner,
        "summary": incident.summary,
        "created_at": to_db_timestamp(incident.created_at),
        "updated_at": to_db_timestamp(incident.updated_at),
        "closed_at": None if incident.closed_at is None else to_db_timestamp(incident.closed_at),
        "playbook_id": incident.playbook_id,
        "closure_reason": incident.closure_reason,
    }


def _from_row(row: sqlite3.Row) -> Incident:
    try:
        return Incident(**{key: row[key] for key in row.keys()})  # noqa: SIM118 - sqlite3.Row
    except ValueError:
        raise StorageError("corrupt_row", object_type="incident") from None


def _checked(incident: object) -> Incident:
    if not isinstance(incident, Incident):
        raise StorageError("invalid_model", object_type="incident")
    return incident.with_changes()


def _event_from_row(row: sqlite3.Row) -> IncidentEvent:
    try:
        return IncidentEvent(
            incident_id=row["incident_id"],
            occurred_at=row["occurred_at"],
            actor=row["actor"],
            event_type=row["event_type"],
            from_status=row["from_status"],
            to_status=row["to_status"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="incident_event") from None


def _note_from_row(row: sqlite3.Row) -> IncidentNote:
    try:
        return IncidentNote(
            incident_id=row["incident_id"],
            created_at=row["created_at"],
            author=row["author"],
            redacted_body=row["redacted_body"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="incident_note") from None


class IncidentRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, incident: Incident, *, actor: str, at: datetime) -> AuditEntry:
        model = _checked(incident)
        with transaction(self._connection, write=True) as conn:
            conn.execute(_INSERT, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="incident.create",
                object_type="incident",
                object_id=model.incident_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def update(
        self,
        incident: Incident,
        *,
        actor: str,
        at: datetime,
        expected_before_hash: str | None = None,
        action: str = "incident.update",
    ) -> AuditEntry:
        """Replace the mutable fields and append the audit entry (``created_at`` is fixed)."""
        if action not in INCIDENT_UPDATE_ACTIONS:
            raise StorageError("invalid_action")
        model = _checked(incident)
        with transaction(self._connection, write=True) as conn:
            row = conn.execute(_GET, {"incident_id": model.incident_id}).fetchone()
            if row is None:
                raise NotFoundError("incident")
            existing = _from_row(row)
            if expected_before_hash is not None and existing.digest() != expected_before_hash:
                raise ConflictError("incident")
            if existing.created_at != model.created_at:
                raise StorageError("immutable_field", field="created_at")
            conn.execute(_UPDATE, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action=action,
                object_type="incident",
                object_id=model.incident_id,
                before_hash=existing.digest(),
                after_hash=model.digest(),
            )

    def get(self, incident_id: str) -> Incident | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET, {"incident_id": incident_id}).fetchone()
        return None if row is None else _from_row(row)

    def list_all(self, *, status: IncidentStatus | None = None) -> list[Incident]:
        params = {
            "status": None
            if status is None
            else coerce_enum(IncidentStatus, status, "status").value
        }
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST, params).fetchall()
        return [_from_row(row) for row in rows]

    # -- links -------------------------------------------------------------------------------

    def link_finding(
        self, incident_id: str, finding_id: str, *, actor: str, at: datetime
    ) -> AuditEntry:
        """Link a finding (once) and append ``incident.link``. A second link is a conflict."""
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_LINK,
                {
                    "incident_id": incident_id,
                    "finding_id": finding_id,
                    "linked_at": to_db_timestamp(at),
                },
            )
            digest = hash_canonical({"incident_id": incident_id, "finding_id": finding_id})
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="incident.link",
                object_type="incident",
                object_id=incident_id,
                before_hash=None,
                after_hash=digest,
            )

    def linked_findings(self, incident_id: str) -> list[tuple[str, str]]:
        """``(finding_id, linked_at)`` pairs."""
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LINKS, {"id": incident_id}).fetchall()
        return [(row["finding_id"], row["linked_at"]) for row in rows]

    def incidents_of_finding(self, finding_id: str) -> list[str]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LINKS_OF_FINDING, {"id": finding_id}).fetchall()
        return [row["incident_id"] for row in rows]

    # -- timeline ----------------------------------------------------------------------------

    def add_event(self, event: IncidentEvent) -> None:
        """Append a timeline event. Needs an active write transaction; not audited itself
        (the change that caused it is)."""
        require_write_transaction(self._connection)
        model = event.with_changes()
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_EVENT,
                {
                    "incident_id": model.incident_id,
                    "occurred_at": to_db_timestamp(model.occurred_at),
                    "actor": model.actor,
                    "event_type": model.event_type,
                    "from_status": None if model.from_status is None else model.from_status.value,
                    "to_status": None if model.to_status is None else model.to_status.value,
                },
            )

    def events(self, incident_id: str) -> list[IncidentEvent]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_EVENTS, {"id": incident_id}).fetchall()
        return [_event_from_row(row) for row in rows]

    def add_note(self, note: IncidentNote, *, at: datetime) -> AuditEntry:
        """Insert a note and append ``incident.note`` (the audit entry holds the note's hash)."""
        model = note.with_changes()
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_NOTE,
                {
                    "incident_id": model.incident_id,
                    "created_at": to_db_timestamp(model.created_at),
                    "author": model.author,
                    "redacted_body": model.redacted_body,
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=model.author,
                action="incident.note",
                object_type="incident",
                object_id=model.incident_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def notes(self, incident_id: str) -> list[IncidentNote]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_NOTES, {"id": incident_id}).fetchall()
        return [_note_from_row(row) for row in rows]
