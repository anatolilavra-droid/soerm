"""Playbooks (M9): safe loading, immutable versions, attachment, idempotent steps, approvals."""

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soerm.domain.enums import IncidentStatus, TechnicalSeverity
from soerm.services import incidents as inc
from soerm.services import playbooks as svc
from soerm.services.approvals import decide_approval
from soerm.services.errors import (
    ApprovalDeniedError,
    ApprovalRequiredError,
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
)
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from tests.unit.importers.helpers import put
from tests.unit.services.helpers import BASE_TIME, SECRET

PLAYBOOK = """\
version: 1
playbook_id: phishing-triage
name: Phishing triage
playbook_version: "1.0"
incident_types: [phishing]
roles: [analyst, lead]
steps:
  - id: step-001
    type: manual
    title: Confirm the report
    text: Read the reported message headers and confirm it is phishing.
    owner_role: analyst
  - id: step-002
    type: checklist
    title: Collect indicators
    items: ["Sender address recorded", "Links recorded"]
  - id: step-003
    type: notify_text
    title: Notify the team
    text: "Team, a phishing campaign was confirmed. Do not open the message."
  - id: step-004
    type: manual
    title: Block the sender domain
    text: Ask the mail admin to block the sender domain.
    requires_manual_approval: true
escalation_criteria: ["Credentials were entered"]
closure_criteria: ["Mailbox cleaned"]
"""


class Clock:
    def __init__(self) -> None:
        self.now = BASE_TIME

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now

    def jump(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def ws(tmp_path: Path, clock: Clock) -> Workspace:
    return Workspace(tmp_path, clock=clock)


def seed(ws: Workspace, text: str = PLAYBOOK, name: str = "pb.yaml") -> None:
    put(ws.path, name, text)
    svc.load_playbook(ws, name, actor="alice")


def incident(ws: Workspace) -> str:
    return inc.create_incident(
        ws, actor="alice", title="Phish", severity=TechnicalSeverity.HIGH, owner="ir"
    ).object_id


@pytest.fixture
def run(ws: Workspace) -> str:
    seed(ws)
    iid = incident(ws)
    svc.attach_playbook(ws, iid, "phishing-triage", actor="alice")
    return iid


def actions(ws: Workspace) -> list[str]:
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY seq")]


# -- loading ------------------------------------------------------------------------------


def test_load_stores_a_version(ws: Workspace) -> None:
    put(ws.path, "pb.yaml", PLAYBOOK)
    result = svc.load_playbook(ws, "pb.yaml", actor="alice")
    assert result.changed
    assert result.audit is not None
    assert result.audit.action == "playbook.load"
    playbook, versions = svc.get_playbook(ws, "phishing-triage")
    assert [s.step_id for s in playbook.steps][:2] == ["step-001", "step-002"]
    assert versions == [("1.0", playbook.config_hash)]
    assert [p.playbook_id for p in svc.list_playbooks(ws, incident_type="phishing")] == [
        "phishing-triage"
    ]
    assert svc.list_playbooks(ws, incident_type="malware") == []


def test_reload_same_content_is_a_noop(ws: Workspace) -> None:
    seed(ws)
    before = actions(ws)
    result = svc.load_playbook(ws, "pb.yaml", actor="alice")
    assert not result.changed
    assert result.audit is None
    assert actions(ws) == before


def test_same_version_different_content_is_refused(ws: Workspace) -> None:
    seed(ws)
    put(ws.path, "pb.yaml", PLAYBOOK.replace("Confirm the report", "Confirm the alert"))
    with pytest.raises(ConflictServiceError, match="playbook_version_immutable"):
        svc.load_playbook(ws, "pb.yaml", actor="alice")
    playbook, _ = svc.get_playbook(ws, "phishing-triage")
    assert playbook.steps[0].title == "Confirm the report"


def test_new_version_is_kept_beside_the_old_one(ws: Workspace) -> None:
    seed(ws)
    put(
        ws.path, "pb2.yaml",
        PLAYBOOK.replace('"1.0"', '"1.1"').replace("Confirm the report", "Confirm the alert"),
    )  # fmt: skip
    svc.load_playbook(ws, "pb2.yaml", actor="alice")
    latest, versions = svc.get_playbook(ws, "phishing-triage")
    assert latest.version == "1.1"
    assert [v for v, _ in versions] == ["1.0", "1.1"]
    old, _ = svc.get_playbook(ws, "phishing-triage", version="1.0")
    assert old.steps[0].title == "Confirm the report"


def test_destructive_step_must_require_approval(ws: Workspace) -> None:
    bad = PLAYBOOK.replace("    requires_manual_approval: true\n", "")
    put(ws.path, "pb.yaml", bad)
    with pytest.raises(InvalidInputError, match="required_for_destructive_step"):
        svc.load_playbook(ws, "pb.yaml", actor="alice")
    assert not (ws.path / DATABASE_FILE_NAME).exists()  # a refused file creates nothing


def test_texts_are_redacted_before_storage(ws: Workspace) -> None:
    text = PLAYBOOK.replace(
        "Do not open the message.", f"Do not open it. password={SECRET}"
    ).replace("Credentials were entered", f"token={SECRET} leaked")
    put(ws.path, "pb.yaml", text)
    svc.load_playbook(ws, "pb.yaml", actor="alice")
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        dump = "\n".join(conn.iterdump())
    assert SECRET not in dump
    assert "Do not open it." in dump


@pytest.mark.parametrize(
    ("old", "new", "fragment"),
    [
        ("version: 1\n", "version: 2\n", "unsupported_file_version"),
        ("roles: [analyst, lead]", "roles: [analyst, lead]\nshell: rm", "unknown_field"),
        ("    type: manual\n    title: Confirm", "    type: automatic\n    title: Confirm", "type"),
        ("requires_manual_approval: true", "requires_manual_approval: yes please", "boolean"),
        ("owner_role: analyst", "owner_role: stranger", "unknown_owner_role"),
        ("id: step-002", "id: step-001", "duplicate_step_id"),
    ],
)
def test_invalid_files_are_rejected(ws: Workspace, old: str, new: str, fragment: str) -> None:
    put(ws.path, "pb.yaml", PLAYBOOK.replace(old, new, 1))
    with pytest.raises(InvalidInputError, match=fragment):
        svc.load_playbook(ws, "pb.yaml", actor="alice")


def test_yaml_tricks_and_bad_files(ws: Workspace) -> None:
    for name, text, fragment in (
        ("a.yaml", "version: 1\nx: &a 1\ny: *a\n", "yaml_"),
        ("b.yaml", "version: !!python/object/apply:os.system [x]\n", "yaml_tag"),
        ("c.yaml", "- just\n- a list\n", "must_be_mapping"),
        ("d.yaml", "version: 1\nversion: 1\n", "yaml_duplicate_key"),
    ):
        put(ws.path, name, text)
        with pytest.raises(InvalidInputError, match=fragment):
            svc.load_playbook(ws, name, actor="alice")


def test_file_must_be_inside_the_workspace(ws: Workspace, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.yaml"
    outside.write_text(PLAYBOOK, encoding="utf-8")
    for bad in (str(outside), "../outside.yaml", "missing.yaml"):
        with pytest.raises(InvalidInputError, match="playbook_file"):
            svc.load_playbook(ws, bad, actor="alice")
    link = ws.path / "link.yaml"
    link.symlink_to(outside)
    with pytest.raises(InvalidInputError, match="playbook_file"):
        svc.load_playbook(ws, "link.yaml", actor="alice")


def test_oversized_and_binary_files(ws: Workspace) -> None:
    put(ws.path, "big.yaml", "version: 1\n" + "# " + "x" * 70000 + "\n")
    with pytest.raises(InvalidInputError, match="playbook_file"):
        svc.load_playbook(ws, "big.yaml", actor="alice")
    put(ws.path, "bin.yaml", b"\xff\xfe\x00")
    with pytest.raises(InvalidInputError, match="playbook_file"):
        svc.load_playbook(ws, "bin.yaml", actor="alice")


def test_unknown_playbook(ws: Workspace) -> None:
    seed(ws)
    with pytest.raises(NotFoundServiceError):
        svc.get_playbook(ws, "nope-nope")
    with pytest.raises(NotFoundServiceError):
        svc.get_playbook(ws, "phishing-triage", version="9.9")
    with pytest.raises(InvalidInputError):
        svc.get_playbook(ws, "bad id!")


def test_ids_are_case_insensitive_ascii(ws: Workspace) -> None:
    seed(ws)
    assert svc.get_playbook(ws, "PHISHING-TRIAGE")[0].playbook_id == "phishing-triage"
    with pytest.raises(InvalidInputError):
        svc.get_playbook(ws, "phi\u017fhing-triage")  # non-ASCII look-alike


# -- attach -------------------------------------------------------------------------------


def test_attach_pins_the_version(ws: Workspace) -> None:
    seed(ws)
    iid = incident(ws)
    attachment, changed, audit = svc.attach_playbook(ws, iid, "phishing-triage", actor="alice")
    assert changed
    assert audit is not None
    assert attachment.version == "1.0"
    assert inc.get_incident(ws, iid).incident.playbook_id == "phishing-triage"
    assert "playbook_attached" in [e.label for e in inc.incident_timeline(ws, iid)]
    put(ws.path, "v2.yaml", PLAYBOOK.replace('"1.0"', '"2.0"'))
    svc.load_playbook(ws, "v2.yaml", actor="alice")
    assert svc.playbook_status(ws, iid).playbook.version == "1.0"


def test_attach_is_idempotent_and_exclusive(ws: Workspace) -> None:
    seed(ws)
    iid = incident(ws)
    svc.attach_playbook(ws, iid, "phishing-triage", actor="alice")
    before = actions(ws)
    _, changed, audit = svc.attach_playbook(ws, iid, "phishing-triage", actor="bob")
    assert not changed
    assert audit is None
    assert actions(ws) == before
    put(ws.path, "v2.yaml", PLAYBOOK.replace('"1.0"', '"2.0"'))
    svc.load_playbook(ws, "v2.yaml", actor="alice")
    with pytest.raises(ConflictServiceError, match="playbook_already_attached"):
        svc.attach_playbook(ws, iid, "phishing-triage", actor="alice", version="2.0")


def test_attach_requires_existing_open_incident_and_playbook(ws: Workspace) -> None:
    seed(ws)
    with pytest.raises(NotFoundServiceError):
        svc.attach_playbook(ws, "INC-000009", "phishing-triage", actor="a")
    iid = incident(ws)
    with pytest.raises(NotFoundServiceError):
        svc.attach_playbook(ws, iid, "other-playbook", actor="a")
    with pytest.raises(InvalidInputError):
        svc.attach_playbook(ws, "bogus", "phishing-triage", actor="a")


def test_status_without_attachment(ws: Workspace) -> None:
    seed(ws)
    iid = incident(ws)
    with pytest.raises(ConflictServiceError, match="no_playbook_attached"):
        svc.playbook_status(ws, iid)
    with pytest.raises(ConflictServiceError, match="no_playbook_attached"):
        svc.complete_step(ws, iid, "step-001", actor="a")


# -- steps --------------------------------------------------------------------------------


def test_complete_step_records_actor_and_time(ws: Workspace, run: str) -> None:
    outcome = svc.complete_step(ws, run, "step-001", actor="Alice")
    assert outcome.changed
    assert outcome.completion.completed_by == "alice"
    assert outcome.audit is not None
    assert outcome.audit.action == "playbook.step_done"
    status = svc.playbook_status(ws, run)
    assert (status.progress.completed, status.progress.total) == (1, 4)
    assert status.progress.next_step_id == "step-002"
    assert "playbook_step_done" in [e.label for e in inc.incident_timeline(ws, run)]


def test_repeated_completion_is_idempotent(ws: Workspace, run: str) -> None:
    first = svc.complete_step(ws, run, "step-001", actor="alice")
    before = actions(ws)
    again = svc.complete_step(ws, run, "STEP-001", actor="bob")
    assert not again.changed
    assert again.audit is None
    assert again.completion == first.completion  # still alice, still the first time
    assert actions(ws) == before


def test_idempotent_even_after_the_incident_closed(ws: Workspace, run: str) -> None:
    svc.complete_step(ws, run, "step-001", actor="alice")
    close_incident(ws, run)
    assert not svc.complete_step(ws, run, "step-001", actor="alice").changed
    with pytest.raises(ConflictServiceError, match="incident_closed"):
        svc.complete_step(ws, run, "step-002", actor="alice")


def close_incident(ws: Workspace, iid: str) -> None:
    for target in ("triaged", "investigating", "contained", "remediated"):
        inc.transition(
            ws, iid, IncidentStatus(target), actor="a",
            expected_hash=inc.get_incident(ws, iid).incident.digest(),
        )  # fmt: skip
    inc.transition(
        ws, iid, IncidentStatus.CLOSED, actor="a", reason="done",
        expected_hash=inc.get_incident(ws, iid).incident.digest(),
    )  # fmt: skip


def test_unknown_step(ws: Workspace, run: str) -> None:
    with pytest.raises(NotFoundServiceError):
        svc.complete_step(ws, run, "step-099", actor="a")
    with pytest.raises(InvalidInputError):
        svc.complete_step(ws, run, "bad step", actor="a")


def test_steps_may_be_done_in_any_order(ws: Workspace, run: str) -> None:
    svc.complete_step(ws, run, "step-003", actor="a")
    assert svc.playbook_status(ws, run).progress.next_step_id == "step-001"


def test_finishing_every_step_never_closes_the_incident(ws: Workspace, run: str) -> None:
    before_finding_area = inc.get_incident(ws, run).incident.status
    for step in ("step-001", "step-002", "step-003"):
        svc.complete_step(ws, run, step, actor="alice")
    change = request_and_approve(ws, run)
    svc.complete_step(ws, run, "step-004", actor="alice", change_id=change)
    status = svc.playbook_status(ws, run)
    assert status.progress.all_done
    assert status.ready_for_closure_review
    after = inc.get_incident(ws, run).incident
    assert after.status is before_finding_area
    assert after.closed_at is None


def request_and_approve(ws: Workspace, iid: str, step: str = "step-004") -> str:
    change = svc.request_step_approval(ws, iid, step, actor="alice", reason="mail admin agreed")
    decide_approval(ws, change.object_id, actor="bob", approved=True)
    return change.object_id


def test_gated_step_needs_an_approval(ws: Workspace, run: str) -> None:
    with pytest.raises(ApprovalRequiredError):
        svc.complete_step(ws, run, "step-004", actor="alice")
    done = [s.step.step_id for s in svc.playbook_status(ws, run).progress.steps if s.done]
    assert "step-004" not in done


def test_gated_step_with_approval_is_single_use(ws: Workspace, run: str) -> None:
    change = request_and_approve(ws, run)
    outcome = svc.complete_step(ws, run, "step-004", actor="carol", change_id=change)
    assert outcome.completion.change_id == change
    assert actions(ws)[-2:] == ["playbook.step_done", "approval.apply"]
    # a second incident cannot reuse the same approval
    other = incident(ws)
    svc.attach_playbook(ws, other, "phishing-triage", actor="alice")
    with pytest.raises(ApprovalDeniedError, match="approval_already_applied"):
        svc.complete_step(ws, other, "step-004", actor="alice", change_id=change)


def test_approval_rules_for_steps(ws: Workspace, run: str) -> None:
    with pytest.raises(InvalidInputError, match="approval_not_applicable"):
        svc.request_step_approval(ws, run, "step-001", actor="alice", reason="r")
    change = svc.request_step_approval(ws, run, "step-004", actor="alice", reason="r")
    with pytest.raises(ConflictServiceError, match="duplicate_pending_request"):
        svc.request_step_approval(ws, run, "step-004", actor="alice", reason="r")
    with pytest.raises(ApprovalDeniedError, match="self_approval"):
        decide_approval(ws, change.object_id, actor="alice", approved=True)
    with pytest.raises(ApprovalDeniedError, match="approval_not_approved"):
        svc.complete_step(ws, run, "step-004", actor="alice", change_id=change.object_id)
    decide_approval(ws, change.object_id, actor="bob", approved=False)
    with pytest.raises(ApprovalDeniedError, match="approval_not_approved"):
        svc.complete_step(ws, run, "step-004", actor="alice", change_id=change.object_id)


def test_approval_for_another_step_does_not_transfer(ws: Workspace, tmp_path: Path) -> None:
    text = PLAYBOOK.replace(
        "escalation_criteria",
        "  - id: step-005\n    type: manual\n    title: Reset the user password\n"
        "    text: Ask the user to reset the password.\n    requires_manual_approval: true\n"
        "escalation_criteria",
    )
    seed(ws, text)
    iid = incident(ws)
    svc.attach_playbook(ws, iid, "phishing-triage", actor="alice")
    change = request_and_approve(ws, iid, "step-004")
    with pytest.raises(ApprovalDeniedError, match="approval_other_object"):
        svc.complete_step(ws, iid, "step-005", actor="alice", change_id=change)


def test_expired_approval_cannot_complete(ws: Workspace, run: str, clock: Clock) -> None:
    change = request_and_approve(ws, run)
    clock.jump(hours=24 * 30)
    with pytest.raises(ApprovalDeniedError, match="approval_expired"):
        svc.complete_step(ws, run, "step-004", actor="alice", change_id=change)


def test_change_id_on_ordinary_step_refused(ws: Workspace, run: str) -> None:
    change = request_and_approve(ws, run)
    with pytest.raises(InvalidInputError, match="not_required"):
        svc.complete_step(ws, run, "step-001", actor="alice", change_id=change)


def test_audit_holds_no_playbook_text(ws: Workspace, run: str) -> None:
    svc.complete_step(ws, run, "step-003", actor="alice")
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        audit = repr(conn.execute("SELECT * FROM audit_log").fetchall())
    for fragment in ("phishing campaign", "Confirm the report", "Mailbox cleaned", "headers"):
        assert fragment not in audit
    assert "playbook.load" in audit
    assert "playbook.step_done" in audit


def test_audit_chain_and_actions(ws: Workspace, run: str) -> None:
    svc.complete_step(ws, run, "step-001", actor="alice")
    assert actions(ws) == [
        "playbook.load", "incident.create", "playbook.attach", "incident.playbook_attach",
        "playbook.step_done",
    ]  # fmt: skip


def test_pre_m9_workspace_is_upgraded_by_the_first_write(tmp_path: Path, clock: Clock) -> None:
    from soerm.services.errors import IntegrityServiceError
    from soerm.storage.connection import open_database
    from soerm.storage.migrations import MIGRATIONS, apply_migrations

    connection = open_database(tmp_path / DATABASE_FILE_NAME, create=True)
    try:
        apply_migrations(connection, migrations=MIGRATIONS[:1])
    finally:
        connection.close()
    ws = Workspace(tmp_path, clock=clock)
    with pytest.raises(IntegrityServiceError, match="schema_not_current"):
        svc.list_playbooks(ws)
    seed(ws)  # the first write applies migration 2
    assert [p.playbook_id for p in svc.list_playbooks(ws)] == ["phishing-triage"]
