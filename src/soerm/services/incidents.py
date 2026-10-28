"""Incident service (M8): create, update, transitions, notes, finding links and the timeline.

* Statuses follow the domain state machine: one step forward at a time; ``closed`` needs a
  ``closure_reason``; leaving ``closed`` needs ``reopen=True`` (and a reason, recorded as a note)
  and lands in ``investigating``. A closed incident accepts no other change.
* Title, summary, owner, reasons and notes are redacted (M4) before storage. Notes and the
  closure reason never reach the audit log - it holds identifiers and hashes only.
* Every change, its timeline event and its audit entry are one transaction.
* Nothing here acts on the outside world: no containment, no notification, no playbook.
"""

from dataclasses import dataclass
from typing import Final

from soerm.domain.enums import IncidentStatus, TechnicalSeverity
from soerm.domain.errors import DomainError
from soerm.domain.identifiers import check_identifier
from soerm.domain.incident import Incident, transition_incident
from soerm.domain.incident_log import IncidentEvent, IncidentNote
from soerm.services.common import (
    PLACEHOLDER_TIME,
    MutationResult,
    require_actor,
    require_expected_hash,
)
from soerm.services.errors import (
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_redactor
from soerm.services.workspace import Session, Workspace
from soerm.storage.counters import CounterRepository
from soerm.storage.findings import FindingRepository
from soerm.storage.incidents import IncidentRepository

__all__ = [
    "IncidentView",
    "TimelineEntry",
    "add_note",
    "create_incident",
    "get_incident",
    "incident_timeline",
    "link_finding",
    "list_incidents",
    "transition",
    "update_incident",
]

_PLACEHOLDER_ID: Final = "INC-000001"


@dataclass(frozen=True, slots=True)
class IncidentView:
    incident: Incident
    finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    at: str
    kind: str  # "event" | "note"
    actor: str
    label: str  # event type, or "note"
    from_status: str | None = None
    to_status: str | None = None
    body: str | None = None  # redacted note text (notes only)


def _incident_id(value: object) -> str:
    try:
        return check_identifier("INC", value, field="incident_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def _severity(value: object) -> TechnicalSeverity:
    try:
        severity = TechnicalSeverity(value)  # type: ignore[arg-type]
    except ValueError:
        raise InvalidInputError("severity: invalid_enum") from None
    if severity is TechnicalSeverity.NONE:
        raise InvalidInputError("severity: not_allowed")
    return severity


def _event(
    session: Session,
    incident_id: str,
    actor: str,
    event_type: str,
    old: IncidentStatus | None = None,
    new: IncidentStatus | None = None,
) -> IncidentEvent:
    return IncidentEvent(
        incident_id=incident_id,
        occurred_at=session.now,
        actor=actor,
        event_type=event_type,
        from_status=old,
        to_status=new,
    )


def _load_open(repo: IncidentRepository, incident_id: str, expected: str | None) -> Incident:
    incident = repo.get(incident_id)
    if incident is None:
        raise NotFoundServiceError("object_not_found", object_type="incident")
    if expected is not None and incident.digest() != expected:
        raise ConflictServiceError("hash_mismatch", object_type="incident")
    if incident.status is IncidentStatus.CLOSED:
        raise ConflictServiceError("incident_closed", object_type="incident")
    return incident


def create_incident(
    workspace: Workspace,
    *,
    actor: str,
    title: str,
    severity: TechnicalSeverity,
    owner: str,
    summary: str = "",
) -> MutationResult:
    actor = require_actor(actor)
    level = _severity(severity)
    redactor = FieldRedactor(load_redactor(workspace.path))
    fields: dict[str, object] = {
        "title": redactor.field("title", title, "title"),
        "severity": level,
        "owner": redactor.field("owner", owner, "name"),
        "summary": redactor.field("summary", summary, "text"),
    }
    try:
        Incident(
            incident_id=_PLACEHOLDER_ID,
            created_at=PLACEHOLDER_TIME,
            updated_at=PLACEHOLDER_TIME,
            **fields,  # type: ignore[arg-type]
        )
    except DomainError as exc:
        raise to_service_error(exc) from None
    with workspace.write() as session:
        incident_id = CounterRepository(session.connection).next_identifier("INC")
        incident = Incident(
            incident_id=incident_id,
            created_at=session.now,
            updated_at=session.now,
            **fields,  # type: ignore[arg-type]
        )
        repo = IncidentRepository(session.connection)
        entry = repo.add(incident, actor=actor, at=session.now)
        repo.add_event(
            _event(session, incident_id, actor, "incident_created", None, IncidentStatus.NEW)
        )
    return MutationResult(
        "incident", incident_id, None, incident.digest(), entry, redactor.report()
    )


def update_incident(
    workspace: Workspace,
    incident_id: str,
    *,
    actor: str,
    expected_hash: str,
    title: str | None = None,
    summary: str | None = None,
    owner: str | None = None,
    severity: TechnicalSeverity | None = None,
) -> MutationResult:
    """Change descriptive fields of an open incident (not its status)."""
    actor = require_actor(actor)
    incident_id = _incident_id(incident_id)
    expected = require_expected_hash(expected_hash)
    redactor = FieldRedactor(load_redactor(workspace.path))
    changes: dict[str, object] = {
        key: value
        for key, value in (
            ("title", redactor.optional("title", title, "title")),
            ("summary", redactor.optional("summary", summary, "text")),
            ("owner", redactor.optional("owner", owner, "name")),
            ("severity", None if severity is None else _severity(severity)),
        )
        if value is not None
    }
    if not changes:
        raise InvalidInputError("no_changes")
    with workspace.write() as session:
        repo = IncidentRepository(session.connection)
        current = _load_open(repo, incident_id, expected)
        candidate = current.with_changes(**changes)
        if candidate == current:
            raise InvalidInputError("no_changes")
        updated = candidate.with_changes(updated_at=session.now)
        entry = repo.update(updated, actor=actor, at=session.now, expected_before_hash=expected)
        repo.add_event(_event(session, incident_id, actor, "incident_updated"))
    return MutationResult(
        "incident", incident_id, current.digest(), updated.digest(), entry, redactor.report()
    )


def transition(
    workspace: Workspace,
    incident_id: str,
    target: IncidentStatus,
    *,
    actor: str,
    expected_hash: str,
    reason: str | None = None,
    reopen: bool = False,
) -> MutationResult:
    """Move an incident along its state machine.

    Closing needs ``reason`` (stored as ``closure_reason``). Leaving ``closed`` needs
    ``reopen=True`` and a ``reason`` (recorded as a note); it lands in ``investigating``.
    """
    actor = require_actor(actor)
    incident_id = _incident_id(incident_id)
    expected = require_expected_hash(expected_hash)
    try:
        target_status = IncidentStatus(target)
    except ValueError:
        raise InvalidInputError("status: invalid_enum") from None
    closing = target_status is IncidentStatus.CLOSED
    if (closing or reopen) and (reason is None or not reason.strip()):
        raise InvalidInputError("reason: required")
    if reason is not None and not (closing or reopen):
        raise InvalidInputError("reason: not_allowed")
    redactor = FieldRedactor(load_redactor(workspace.path))
    clean_reason = None if reason is None else redactor.field("reason", reason, "reason")
    with workspace.write() as session:
        repo = IncidentRepository(session.connection)
        current = repo.get(incident_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        before = current.digest()
        if before != expected:
            raise ConflictServiceError("hash_mismatch", object_type="incident")
        try:
            new_status = transition_incident(current.status, target_status, reopen=reopen)
        except DomainError as exc:
            raise to_service_error(exc) from None
        if closing:
            updated = current.with_changes(
                status=new_status,
                closed_at=session.now,
                closure_reason=clean_reason,
                updated_at=session.now,
            )
        else:
            updated = current.with_changes(
                status=new_status, closed_at=None, closure_reason=None, updated_at=session.now
            )
        action = "incident.reopen" if reopen else "incident.transition"
        entry = repo.update(
            updated, actor=actor, at=session.now, expected_before_hash=expected, action=action
        )
        event_type = "incident_reopened" if reopen else "status_changed"
        repo.add_event(_event(session, incident_id, actor, event_type, current.status, new_status))
        if reopen and clean_reason is not None:
            repo.add_note(
                IncidentNote(
                    incident_id=incident_id,
                    created_at=session.now,
                    author=actor,
                    redacted_body=f"Reopened: {clean_reason}",
                ),
                at=session.now,
            )
    return MutationResult(
        "incident", incident_id, before, updated.digest(), entry, redactor.report()
    )


def add_note(workspace: Workspace, incident_id: str, *, actor: str, text: str) -> MutationResult:
    """Add an analyst note (redacted) to an open incident."""
    actor = require_actor(actor)
    incident_id = _incident_id(incident_id)
    redactor = FieldRedactor(load_redactor(workspace.path))
    body = redactor.field("note", text, "text")
    if not body.strip():
        raise InvalidInputError("note: empty")
    with workspace.write() as session:
        repo = IncidentRepository(session.connection)
        incident = _load_open(repo, incident_id, None)
        note = IncidentNote(
            incident_id=incident_id, created_at=session.now, author=actor, redacted_body=body
        )
        entry = repo.add_note(note, at=session.now)
        repo.add_event(_event(session, incident_id, actor, "note_added"))
    return MutationResult(
        "incident", incident_id, incident.digest(), entry.after_hash or "", entry, redactor.report()
    )


def link_finding(
    workspace: Workspace, incident_id: str, finding_id: str, *, actor: str
) -> MutationResult:
    """Link an existing finding to an open incident (once)."""
    actor = require_actor(actor)
    incident_id = _incident_id(incident_id)
    try:
        finding_id = check_identifier("FND", finding_id, field="finding_id")
    except DomainError as exc:
        raise to_service_error(exc) from None
    with workspace.write() as session:
        repo = IncidentRepository(session.connection)
        _load_open(repo, incident_id, None)
        if FindingRepository(session.connection).get(finding_id) is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        if any(fid == finding_id for fid, _ in repo.linked_findings(incident_id)):
            raise ConflictServiceError("already_linked", object_type="incident")
        entry = repo.link_finding(incident_id, finding_id, actor=actor, at=session.now)
        repo.add_event(_event(session, incident_id, actor, "finding_linked"))
    return MutationResult("incident", incident_id, None, entry.after_hash or "", entry)


def get_incident(workspace: Workspace, incident_id: str) -> IncidentView:
    incident_id = _incident_id(incident_id)
    with workspace.read() as session:
        repo = IncidentRepository(session.connection)
        incident = repo.get(incident_id)
        if incident is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        links = tuple(fid for fid, _ in repo.linked_findings(incident_id))
    return IncidentView(incident, links)


def list_incidents(workspace: Workspace, *, status: IncidentStatus | None = None) -> list[Incident]:
    try:
        status_filter = None if status is None else IncidentStatus(status)
    except ValueError:
        raise InvalidInputError("filter: invalid_enum") from None
    with workspace.read() as session:
        return IncidentRepository(session.connection).list_all(status=status_filter)


def _stamp(value: object) -> str:
    return value.isoformat().replace("+00:00", "Z")  # type: ignore[attr-defined,no-any-return]


def incident_timeline(workspace: Workspace, incident_id: str) -> list[TimelineEntry]:
    """Status events and notes in time order (note events are shown as the notes themselves)."""
    incident_id = _incident_id(incident_id)
    with workspace.read() as session:
        repo = IncidentRepository(session.connection)
        if repo.get(incident_id) is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        events = repo.events(incident_id)
        notes = repo.notes(incident_id)
    entries = [
        TimelineEntry(
            _stamp(e.occurred_at),
            "event",
            e.actor,
            e.event_type,
            None if e.from_status is None else e.from_status.value,
            None if e.to_status is None else e.to_status.value,
        )
        for e in events
        if e.event_type != "note_added"
    ]
    entries += [
        TimelineEntry(_stamp(n.created_at), "note", n.author, "note", body=n.redacted_body)
        for n in notes
    ]
    return sorted(entries, key=lambda item: item.at)
