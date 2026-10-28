"""Remediation task model and its pure state machine."""

from typing import Final, Self

from pydantic import model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import TaskStatus
from soerm.domain.errors import InvalidTransitionError, ValidationDomainError
from soerm.domain.identifiers import FindingId, IncidentId, TaskId
from soerm.domain.text import Name, Title
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["Task", "transition_task"]

_ALLOWED: Final[dict[TaskStatus, frozenset[TaskStatus]]] = {
    TaskStatus.OPEN: frozenset({TaskStatus.IN_PROGRESS, TaskStatus.DONE, TaskStatus.CANCELLED}),
    TaskStatus.IN_PROGRESS: frozenset({TaskStatus.OPEN, TaskStatus.DONE, TaskStatus.CANCELLED}),
    TaskStatus.DONE: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


def _coerce(value: object, field: str) -> TaskStatus:
    if isinstance(value, str):
        try:
            return TaskStatus(value)
        except ValueError:
            pass
    raise ValidationDomainError.single(field, "invalid_status")


def transition_task(
    current_status: TaskStatus,
    target_status: TaskStatus,
    *,
    reinstate: bool = False,
) -> TaskStatus:
    """Return ``target_status`` if the transition is allowed; otherwise raise.

    ``Done`` and ``Cancelled`` are final. The only way out of ``Cancelled`` is the separate
    transition ``reinstate=True`` (``Cancelled -> Open``); a cancelled task can never go
    straight to ``Done``.
    """
    current = _coerce(current_status, "current_status")
    target = _coerce(target_status, "target_status")

    def refuse(reason: str) -> InvalidTransitionError:
        return InvalidTransitionError("task", current, target, reason)

    if reinstate:
        if current is not TaskStatus.CANCELLED:
            raise refuse("reinstate_requires_cancelled")
        if target is not TaskStatus.OPEN:
            raise refuse("reinstate_target_not_allowed")
        return target
    if current is TaskStatus.CANCELLED:
        raise refuse(
            "cancelled_cannot_be_done"
            if target is TaskStatus.DONE
            else "cancelled_requires_reinstate"
        )
    if target not in _ALLOWED[current]:
        raise refuse("no_change" if current is target else "transition_not_allowed")
    return target


class Task(DomainModel):
    task_id: TaskId
    finding_id: FindingId | None = None
    incident_id: IncidentId | None = None
    title: Title
    owner: Name
    due_at: UtcTimestamp | None = None
    status: TaskStatus = TaskStatus.OPEN
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    completed_at: UtcTimestamp | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.finding_id is None and self.incident_id is None:
            raise ValidationDomainError.single("finding_id", "finding_or_incident_required")
        done = self.status is TaskStatus.DONE
        if done and self.completed_at is None:
            raise ValidationDomainError.single("completed_at", "required_when_done")
        if not done and self.completed_at is not None:
            raise ValidationDomainError.single("completed_at", "forbidden_unless_done")
        if self.updated_at < self.created_at:
            raise ValidationDomainError.single("updated_at", "before_created_at")
        if self.completed_at is not None and self.completed_at < self.created_at:
            raise ValidationDomainError.single("completed_at", "before_created_at")
        return self
