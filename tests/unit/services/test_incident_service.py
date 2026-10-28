"""Incidents (M8): state machine, closure reason, reopen, notes, links, timeline, audit."""

import sqlite3
from contextlib import closing

import pytest

from soerm.domain.enums import IncidentStatus, TechnicalSeverity
from soerm.services import incidents as svc
from soerm.services.errors import ConflictServiceError, InvalidInputError, NotFoundServiceError
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from tests.unit.services.helpers import SECRET, make_asset, make_finding

S = IncidentStatus


def new_incident(ws: Workspace, **kw: object) -> str:
    args: dict[str, object] = {
        "actor": "alice",
        "title": "Ransomware on host",
        "severity": TechnicalSeverity.HIGH,
        "owner": "ir-team",
    }
    args.update(kw)
    return svc.create_incident(ws, **args).object_id  # type: ignore[arg-type]


def digest(ws: Workspace, incident_id: str) -> str:
    return svc.get_incident(ws, incident_id).incident.digest()


def step(
    ws: Workspace,
    incident_id: str,
    target: IncidentStatus,
    *,
    reason: str | None = None,
    reopen: bool = False,
) -> None:
    svc.transition(
        ws,
        incident_id,
        target,
        actor="alice",
        expected_hash=digest(ws, incident_id),
        reason=reason,
        reopen=reopen,
    )


def to_closed(ws: Workspace, incident_id: str) -> None:
    for target in (S.TRIAGED, S.INVESTIGATING, S.CONTAINED, S.REMEDIATED):
        step(ws, incident_id, target)
    step(ws, incident_id, S.CLOSED, reason="all done")


def audit_rows(ws: Workspace) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        return conn.execute("SELECT action, object_id FROM audit_log ORDER BY seq").fetchall()


def test_create_defaults_and_event(ws: Workspace) -> None:
    result = svc.create_incident(
        ws, actor="alice", title="T", severity=TechnicalSeverity.LOW, owner="o"
    )
    assert result.object_id == "INC-000001"
    view = svc.get_incident(ws, "INC-000001")
    assert view.incident.status is S.NEW
    assert view.incident.closed_at is None
    kinds = [e.label for e in svc.incident_timeline(ws, "INC-000001")]
    assert kinds == ["incident_created"]
    assert result.audit.action == "incident.create"


def test_severity_none_refused(ws: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        new_incident(ws, severity=TechnicalSeverity.NONE)


def test_forward_only_one_step(ws: Workspace) -> None:
    iid = new_incident(ws)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.INVESTIGATING)  # skips triaged
    step(ws, iid, S.TRIAGED)
    assert svc.get_incident(ws, iid).incident.status is S.TRIAGED


def test_closing_requires_reason_and_sets_closed_at(ws: Workspace) -> None:
    iid = new_incident(ws)
    for target in (S.TRIAGED, S.INVESTIGATING, S.CONTAINED, S.REMEDIATED):
        step(ws, iid, target)
    with pytest.raises(InvalidInputError, match="reason"):
        step(ws, iid, S.CLOSED)
    with pytest.raises(InvalidInputError, match="reason"):
        step(ws, iid, S.CLOSED, reason="   ")
    step(ws, iid, S.CLOSED, reason="resolved by team")
    closed = svc.get_incident(ws, iid).incident
    assert closed.status is S.CLOSED
    assert closed.closed_at is not None
    assert closed.closure_reason == "resolved by team"


def test_reason_not_allowed_on_ordinary_step(ws: Workspace) -> None:
    iid = new_incident(ws)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.TRIAGED, reason="why")


def test_closed_to_investigating_only_with_reopen(ws: Workspace) -> None:
    iid = new_incident(ws)
    to_closed(ws, iid)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.INVESTIGATING)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.INVESTIGATING, reopen=True)  # reason missing
    step(ws, iid, S.INVESTIGATING, reopen=True, reason="new evidence")
    reopened = svc.get_incident(ws, iid).incident
    assert reopened.status is S.INVESTIGATING
    assert reopened.closed_at is None
    assert reopened.closure_reason is None
    timeline = svc.incident_timeline(ws, iid)
    assert any(e.label == "incident_reopened" for e in timeline)
    assert any(e.kind == "note" and "new evidence" in (e.body or "") for e in timeline)
    assert ("incident.reopen", iid) in audit_rows(ws)


def test_reopen_only_to_investigating(ws: Workspace) -> None:
    iid = new_incident(ws)
    to_closed(ws, iid)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.NEW, reopen=True, reason="x")


def test_closed_incident_is_frozen(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws)
    iid = new_incident(ws)
    to_closed(ws, iid)
    with pytest.raises(ConflictServiceError, match="closed"):
        svc.update_incident(ws, iid, actor="a", expected_hash=digest(ws, iid), title="x")
    with pytest.raises(ConflictServiceError):
        svc.add_note(ws, iid, actor="a", text="n")
    with pytest.raises(ConflictServiceError):
        svc.link_finding(ws, iid, "FND-000001", actor="a")


def test_update_hash_and_no_changes(ws: Workspace) -> None:
    iid = new_incident(ws)
    good = digest(ws, iid)
    with pytest.raises(ConflictServiceError):
        svc.update_incident(ws, iid, actor="a", expected_hash="0" * 64, title="x")
    with pytest.raises(InvalidInputError, match="no_changes"):
        svc.update_incident(ws, iid, actor="a", expected_hash=good)
    with pytest.raises(InvalidInputError, match="no_changes"):
        svc.update_incident(ws, iid, actor="a", expected_hash=good, owner="ir-team")
    svc.update_incident(ws, iid, actor="a", expected_hash=good, owner="soc")
    assert svc.get_incident(ws, iid).incident.owner == "soc"


def test_transition_stale_hash_conflict(ws: Workspace) -> None:
    iid = new_incident(ws)
    with pytest.raises(ConflictServiceError):
        svc.transition(ws, iid, S.TRIAGED, actor="a", expected_hash="0" * 64)


def test_missing_incident(ws: Workspace) -> None:
    with pytest.raises(NotFoundServiceError):
        svc.get_incident(ws, "INC-000009")
    with pytest.raises(InvalidInputError):
        svc.get_incident(ws, "bogus")


def test_link_finding_once_and_requires_existing(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws)
    iid = new_incident(ws)
    with pytest.raises(NotFoundServiceError):
        svc.link_finding(ws, iid, "FND-000099", actor="a")
    svc.link_finding(ws, iid, "FND-000001", actor="a")
    assert svc.get_incident(ws, iid).finding_ids == ("FND-000001",)
    with pytest.raises(ConflictServiceError, match="already_linked"):
        svc.link_finding(ws, iid, "FND-000001", actor="a")


def test_notes_are_redacted_and_never_in_audit(ws: Workspace) -> None:
    iid = new_incident(ws)
    svc.add_note(ws, iid, actor="alice", text=f"found password={SECRET} on host")
    notes = [e for e in svc.incident_timeline(ws, iid) if e.kind == "note"]
    assert len(notes) == 1
    assert SECRET not in (notes[0].body or "")
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        dump = "\n".join(conn.iterdump())
    assert SECRET not in dump
    audit_text = repr(audit_rows(ws))
    assert "found" not in audit_text


def test_empty_note_refused(ws: Workspace) -> None:
    iid = new_incident(ws)
    with pytest.raises(InvalidInputError):
        svc.add_note(ws, iid, actor="a", text="   ")


def test_timeline_order_and_no_duplicate_note_events(ws: Workspace) -> None:
    iid = new_incident(ws)
    svc.add_note(ws, iid, actor="a", text="first")
    step(ws, iid, S.TRIAGED)
    labels = [e.label for e in svc.incident_timeline(ws, iid)]
    assert labels.count("note") == 1
    assert "note_added" not in labels
    assert labels[0] == "incident_created"
    assert labels[-1] == "status_changed"


def test_title_secret_redacted(ws: Workspace) -> None:
    iid = new_incident(ws, title=f"leak token={SECRET}")
    assert SECRET not in svc.get_incident(ws, iid).incident.title


def test_errors_do_not_echo_values(ws: Workspace) -> None:
    iid = new_incident(ws)
    with pytest.raises(InvalidInputError) as info:
        svc.transition(ws, iid, "nonsense", actor="a", expected_hash="0" * 64)  # type: ignore[arg-type]
    assert "nonsense" not in str(info.value)


def test_failed_transition_leaves_no_audit(ws: Workspace) -> None:
    iid = new_incident(ws)
    before = audit_rows(ws)
    with pytest.raises(InvalidInputError):
        step(ws, iid, S.CLOSED, reason="skip everything")
    assert audit_rows(ws) == before
    assert svc.get_incident(ws, iid).incident.status is S.NEW


def test_actor_required(ws: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        new_incident(ws, actor="")
