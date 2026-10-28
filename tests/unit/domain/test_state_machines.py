"""Incident and task models with their pure transition functions."""

from datetime import timedelta
from itertools import pairwise, product

import pytest

from soerm.domain import (
    Incident,
    IncidentStatus,
    InvalidTransitionError,
    Task,
    TaskStatus,
    ValidationDomainError,
    transition_incident,
    transition_task,
)
from soerm.domain.incident import FORWARD_CHAIN

from .factories import SECRET, T0, T1, incident_data, task_data

# ---- Incident transitions -----------------------------------------------------------------

CHAIN = list(FORWARD_CHAIN)


def test_main_chain_is_exactly_as_specified() -> None:
    assert [s.value for s in CHAIN] == [
        "new", "triaged", "investigating", "contained", "remediated", "closed",
    ]  # fmt: skip


@pytest.mark.parametrize(("current", "target"), list(pairwise(CHAIN)))
def test_valid_forward_transitions(current: IncidentStatus, target: IncidentStatus) -> None:
    assert transition_incident(current, target) is target


def _invalid_pairs() -> list[tuple[IncidentStatus, IncidentStatus]]:
    valid = set(pairwise(CHAIN))
    return [pair for pair in product(CHAIN, CHAIN) if pair not in valid]


@pytest.mark.parametrize(("current", "target"), _invalid_pairs())
def test_every_other_transition_is_refused(current: IncidentStatus, target: IncidentStatus) -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        transition_incident(current, target)
    assert excinfo.value.code == "invalid_transition"
    assert current.value in str(excinfo.value)


@pytest.mark.parametrize(
    ("current", "target", "reason"),
    [
        (IncidentStatus.NEW, IncidentStatus.CONTAINED, "step_skipped"),
        (IncidentStatus.CONTAINED, IncidentStatus.TRIAGED, "backward_not_allowed"),
        (IncidentStatus.NEW, IncidentStatus.NEW, "no_change"),
        (IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING, "closed_requires_explicit_reopen"),
        (IncidentStatus.CLOSED, IncidentStatus.NEW, "closed_requires_explicit_reopen"),
    ],
)
def test_refusal_reasons_are_specific(
    current: IncidentStatus, target: IncidentStatus, reason: str
) -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        transition_incident(current, target)
    assert excinfo.value.details["reason"] == reason


def test_explicit_reopen_from_closed() -> None:
    assert transition_incident(
        IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING, reopen=True
    ) is (IncidentStatus.INVESTIGATING)


@pytest.mark.parametrize(
    "target", [s for s in IncidentStatus if s is not IncidentStatus.INVESTIGATING]
)
def test_reopen_only_to_investigating(target: IncidentStatus) -> None:
    with pytest.raises(InvalidTransitionError):
        transition_incident(IncidentStatus.CLOSED, target, reopen=True)


@pytest.mark.parametrize("current", [s for s in IncidentStatus if s is not IncidentStatus.CLOSED])
def test_reopen_flag_is_refused_unless_closed(current: IncidentStatus) -> None:
    for target in IncidentStatus:
        with pytest.raises(InvalidTransitionError):
            transition_incident(current, target, reopen=True)


def test_reopen_flag_does_not_enable_other_transitions() -> None:
    with pytest.raises(InvalidTransitionError):
        transition_incident(IncidentStatus.NEW, IncidentStatus.TRIAGED, reopen=True)


def test_transition_accepts_only_known_statuses() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        transition_incident(SECRET, IncidentStatus.NEW)  # type: ignore[arg-type]
    assert SECRET not in str(excinfo.value)
    with pytest.raises(ValidationDomainError):
        transition_incident(IncidentStatus.NEW, None)  # type: ignore[arg-type]
    assert transition_incident("new", "triaged") is IncidentStatus.TRIAGED  # type: ignore[arg-type]


def test_transition_function_has_no_side_effects() -> None:
    incident = Incident(**incident_data())
    before = incident.digest()
    transition_incident(incident.status, IncidentStatus.TRIAGED)
    assert incident.digest() == before
    assert incident.status is IncidentStatus.NEW


# ---- Incident model -----------------------------------------------------------------------


def test_valid_incident() -> None:
    incident = Incident(**incident_data(playbook_id="phishing-triage"))
    assert incident.status is IncidentStatus.NEW
    assert incident.closed_at is None


def test_closed_incident_requires_closed_at() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Incident(**incident_data(status="closed"))
    assert excinfo.value.issues[0].code == "required_when_closed"
    closed = Incident(**incident_data(status="closed", closed_at=T1, closure_reason="Resolved"))
    assert closed.closed_at == T1


def test_closure_reason_is_required_exactly_for_closed() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Incident(**incident_data(status="closed", closed_at=T1))
    assert excinfo.value.issues[0].code == "required_when_closed"
    assert excinfo.value.issues[0].field == "closure_reason"
    with pytest.raises(ValidationDomainError):
        Incident(**incident_data(status="closed", closed_at=T1, closure_reason=" "))
    closed = Incident(**incident_data(status="closed", closed_at=T1, closure_reason="Done"))
    assert closed.closure_reason == "Done"


def test_incident_severity_none_is_refused() -> None:
    with pytest.raises(ValidationDomainError):
        Incident(**incident_data(severity="none"))


@pytest.mark.parametrize("status", [s for s in IncidentStatus if s is not IncidentStatus.CLOSED])
def test_open_incident_must_not_have_closed_at(status: IncidentStatus) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Incident(**incident_data(status=status, closed_at=T1))
    assert excinfo.value.issues[0].code == "forbidden_unless_closed"
    with pytest.raises(ValidationDomainError):
        Incident(**incident_data(status=status, closure_reason="x"))


def test_incident_time_ordering() -> None:
    with pytest.raises(ValidationDomainError):
        Incident(**incident_data(updated_at=T0 - timedelta(seconds=1)))
    with pytest.raises(ValidationDomainError):
        Incident(
            **incident_data(
                status="closed", closed_at=T0 - timedelta(seconds=1), closure_reason="Resolved"
            )
        )


def test_incident_validation_of_fields() -> None:
    for bad in [{"title": " "}, {"owner": ""}, {"severity": "severe"}, {"playbook_id": "Bad Id"}]:
        with pytest.raises(ValidationDomainError):
            Incident(**incident_data(**bad))


# ---- Task ---------------------------------------------------------------------------------


def test_valid_task() -> None:
    assert Task(**task_data()).status is TaskStatus.OPEN
    assert Task(**task_data(finding_id=None, incident_id="INC-000001")).incident_id == "INC-000001"
    both = Task(**task_data(incident_id="INC-000001"))
    assert both.finding_id is not None
    assert both.incident_id is not None


def test_task_needs_finding_or_incident() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Task(**task_data(finding_id=None))
    assert excinfo.value.issues[0].code == "finding_or_incident_required"


def test_done_task_requires_completed_at() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Task(**task_data(status="done"))
    assert excinfo.value.issues[0].code == "required_when_done"
    assert Task(**task_data(status="done", completed_at=T1)).completed_at == T1


@pytest.mark.parametrize("status", [TaskStatus.OPEN, TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED])
def test_unfinished_task_must_not_have_completed_at(status: TaskStatus) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Task(**task_data(status=status, completed_at=T1))
    assert excinfo.value.issues[0].code == "forbidden_unless_done"


def test_task_time_ordering_and_ids() -> None:
    with pytest.raises(ValidationDomainError):
        Task(**task_data(status="done", completed_at=T0 - timedelta(seconds=1)))
    with pytest.raises(ValidationDomainError):
        Task(**task_data(updated_at=T0 - timedelta(seconds=1)))
    with pytest.raises(ValidationDomainError):
        Task(**task_data(finding_id="FND-1"))


def test_task_transitions() -> None:
    assert transition_task(TaskStatus.OPEN, TaskStatus.IN_PROGRESS) is TaskStatus.IN_PROGRESS
    assert transition_task(TaskStatus.OPEN, TaskStatus.DONE) is TaskStatus.DONE
    assert transition_task(TaskStatus.IN_PROGRESS, TaskStatus.DONE) is TaskStatus.DONE
    assert transition_task(TaskStatus.IN_PROGRESS, TaskStatus.OPEN) is TaskStatus.OPEN
    assert transition_task(TaskStatus.OPEN, TaskStatus.CANCELLED) is TaskStatus.CANCELLED
    assert transition_task(TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED) is TaskStatus.CANCELLED


def test_cancelled_task_cannot_become_done() -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        transition_task(TaskStatus.CANCELLED, TaskStatus.DONE)
    assert excinfo.value.details["reason"] == "cancelled_cannot_be_done"
    with pytest.raises(InvalidTransitionError):
        transition_task(TaskStatus.CANCELLED, TaskStatus.DONE, reinstate=True)


def test_cancelled_task_needs_separate_reinstate_transition() -> None:
    for target in (TaskStatus.OPEN, TaskStatus.IN_PROGRESS):
        with pytest.raises(InvalidTransitionError):
            transition_task(TaskStatus.CANCELLED, target)
    assert transition_task(TaskStatus.CANCELLED, TaskStatus.OPEN, reinstate=True) is TaskStatus.OPEN
    with pytest.raises(InvalidTransitionError):
        transition_task(TaskStatus.CANCELLED, TaskStatus.IN_PROGRESS, reinstate=True)
    with pytest.raises(InvalidTransitionError):
        transition_task(TaskStatus.OPEN, TaskStatus.OPEN, reinstate=True)


@pytest.mark.parametrize("target", list(TaskStatus))
def test_done_task_is_final(target: TaskStatus) -> None:
    with pytest.raises(InvalidTransitionError):
        transition_task(TaskStatus.DONE, target)


def test_task_no_change_is_refused() -> None:
    with pytest.raises(InvalidTransitionError) as excinfo:
        transition_task(TaskStatus.OPEN, TaskStatus.OPEN)
    assert excinfo.value.details["reason"] == "no_change"
