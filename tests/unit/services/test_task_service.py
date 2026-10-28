"""Remediation tasks (M8)."""

import pytest

from soerm.domain.enums import IncidentStatus, TaskStatus, TechnicalSeverity
from soerm.services import incidents as inc
from soerm.services import tasks as svc
from soerm.services.errors import ConflictServiceError, InvalidInputError, NotFoundServiceError
from soerm.services.workspace import Workspace
from tests.unit.services.helpers import make_asset, make_finding

T = TaskStatus


def mk(ws: Workspace, **kw: object) -> str:
    args: dict[str, object] = {
        "actor": "alice",
        "title": "Patch it",
        "owner": "ops",
        "finding_id": "FND-000001",
    }
    args.update(kw)
    return svc.create_task(ws, **args).object_id  # type: ignore[arg-type]


def h(ws: Workspace, task_id: str) -> str:
    return svc.get_task(ws, task_id).digest()


def go(ws: Workspace, task_id: str, target: TaskStatus, **kw: object) -> None:
    svc.transition(ws, task_id, target, actor="alice", expected_hash=h(ws, task_id), **kw)  # type: ignore[arg-type]


@pytest.fixture
def seeded(ws: Workspace) -> Workspace:
    make_asset(ws)
    make_finding(ws)
    return ws


def test_create_needs_a_parent(seeded: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        mk(seeded, finding_id=None)
    with pytest.raises(NotFoundServiceError):
        mk(seeded, finding_id="FND-000099")
    with pytest.raises(NotFoundServiceError):
        mk(seeded, finding_id=None, incident_id="INC-000001")


def test_done_sets_completed_at(seeded: Workspace) -> None:
    tid = mk(seeded)
    assert svc.get_task(seeded, tid).completed_at is None
    go(seeded, tid, T.IN_PROGRESS)
    go(seeded, tid, T.DONE)
    task = svc.get_task(seeded, tid)
    assert task.status is T.DONE
    assert task.completed_at is not None


def test_done_is_final_and_not_updatable(seeded: Workspace) -> None:
    tid = mk(seeded)
    go(seeded, tid, T.IN_PROGRESS)
    go(seeded, tid, T.DONE)
    with pytest.raises(InvalidInputError):
        go(seeded, tid, T.OPEN)
    with pytest.raises(ConflictServiceError, match="task_final"):
        svc.update_task(seeded, tid, actor="a", expected_hash=h(seeded, tid), title="x")


def test_cancelled_cannot_go_to_done_only_reinstate(seeded: Workspace) -> None:
    tid = mk(seeded)
    go(seeded, tid, T.CANCELLED)
    with pytest.raises(InvalidInputError, match="cancelled_cannot_be_done"):
        go(seeded, tid, T.DONE)
    with pytest.raises(InvalidInputError):
        go(seeded, tid, T.OPEN)
    go(seeded, tid, T.OPEN, reinstate=True)
    task = svc.get_task(seeded, tid)
    assert task.status is T.OPEN
    assert task.completed_at is None


def test_stale_hash_and_no_changes(seeded: Workspace) -> None:
    tid = mk(seeded)
    with pytest.raises(ConflictServiceError):
        svc.update_task(seeded, tid, actor="a", expected_hash="0" * 64, title="x")
    with pytest.raises(InvalidInputError, match="no_changes"):
        svc.update_task(seeded, tid, actor="a", expected_hash=h(seeded, tid))
    with pytest.raises(ConflictServiceError):
        svc.transition(seeded, tid, T.IN_PROGRESS, actor="a", expected_hash="0" * 64)


def test_update_and_due_date(seeded: Workspace) -> None:
    tid = mk(seeded, due_at="2030-01-01T00:00:00Z")
    assert svc.get_task(seeded, tid).due_at is not None
    svc.update_task(seeded, tid, actor="a", expected_hash=h(seeded, tid), clear_due=True)
    assert svc.get_task(seeded, tid).due_at is None
    with pytest.raises(InvalidInputError):
        svc.update_task(
            seeded,
            tid,
            actor="a",
            expected_hash=h(seeded, tid),
            due_at="2031-01-01T00:00:00Z",
            clear_due=True,
        )


def test_task_on_closed_incident_refused(seeded: Workspace) -> None:
    iid = inc.create_incident(
        seeded,
        actor="a",
        title="t",
        severity=TechnicalSeverity.HIGH,
        owner="o",
    ).object_id
    tid = mk(seeded, finding_id=None, incident_id=iid)
    assert svc.get_task(seeded, tid).incident_id == iid
    for target in ("triaged", "investigating", "contained", "remediated"):
        inc.transition(
            seeded,
            iid,
            IncidentStatus(target),
            actor="a",
            expected_hash=inc.get_incident(seeded, iid).incident.digest(),
        )
    inc.transition(
        seeded,
        iid,
        IncidentStatus.CLOSED,
        actor="a",
        reason="done",
        expected_hash=inc.get_incident(seeded, iid).incident.digest(),
    )
    with pytest.raises(ConflictServiceError, match="incident_closed"):
        mk(seeded, finding_id=None, incident_id=iid)


def test_completing_task_does_not_touch_finding(seeded: Workspace) -> None:
    from soerm.services.findings import get_finding

    before = get_finding(seeded, "FND-000001").digest()
    tid = mk(seeded)
    go(seeded, tid, T.IN_PROGRESS)
    go(seeded, tid, T.DONE)
    assert get_finding(seeded, "FND-000001").digest() == before


def test_list_filters(seeded: Workspace) -> None:
    a = mk(seeded)
    mk(seeded, title="Second")
    go(seeded, a, T.IN_PROGRESS)
    assert len(svc.list_tasks(seeded)) == 2
    assert [t.task_id for t in svc.list_tasks(seeded, status=T.IN_PROGRESS)] == [a]
    assert len(svc.list_tasks(seeded, finding_id="FND-000001")) == 2
    with pytest.raises(InvalidInputError):
        svc.list_tasks(seeded, status="bogus")  # type: ignore[arg-type]
