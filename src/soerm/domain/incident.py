"""Incident model and its pure state machine."""

from typing import Final, Self

from pydantic import model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import IncidentStatus, TechnicalSeverity
from soerm.domain.errors import InvalidTransitionError, ValidationDomainError
from soerm.domain.identifiers import IncidentId, PlaybookId
from soerm.domain.text import LongText, Name, Reason, Title
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["FORWARD_CHAIN", "REOPEN_TARGET", "Incident", "transition_incident"]

FORWARD_CHAIN: Final = (
    IncidentStatus.NEW,
    IncidentStatus.TRIAGED,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
    IncidentStatus.REMEDIATED,
    IncidentStatus.CLOSED,
)
# An explicit reopen always lands here, so the new evidence is looked at again.
REOPEN_TARGET: Final = IncidentStatus.INVESTIGATING


def _coerce(value: object, field: str) -> IncidentStatus:
    if isinstance(value, str):
        try:
            return IncidentStatus(value)
        except ValueError:
            pass
    raise ValidationDomainError.single(field, "invalid_status")


def transition_incident(
    current_status: IncidentStatus,
    target_status: IncidentStatus,
    *,
    reopen: bool = False,
) -> IncidentStatus:
    """Return ``target_status`` if the transition is allowed; otherwise raise.

    Allowed: one step forward along ``New -> Triaged -> Investigating -> Contained ->
    Remediated -> Closed``. Leaving ``Closed`` needs ``reopen=True`` and lands in
    ``Investigating``. Skipping, going back and staying in place are refused. The function
    changes nothing; it only judges the transition.
    """
    current = _coerce(current_status, "current_status")
    target = _coerce(target_status, "target_status")

    def refuse(reason: str) -> InvalidTransitionError:
        return InvalidTransitionError("incident", current, target, reason)

    if reopen:
        if current is not IncidentStatus.CLOSED:
            raise refuse("reopen_requires_closed")
        if target is not REOPEN_TARGET:
            raise refuse("reopen_target_not_allowed")
        return target
    if current is IncidentStatus.CLOSED:
        raise refuse("closed_requires_explicit_reopen")
    if current is target:
        raise refuse("no_change")
    current_index = FORWARD_CHAIN.index(current)
    target_index = FORWARD_CHAIN.index(target)
    if target_index < current_index:
        raise refuse("backward_not_allowed")
    if target_index > current_index + 1:
        raise refuse("step_skipped")
    return target


class Incident(DomainModel):
    incident_id: IncidentId
    title: Title
    severity: TechnicalSeverity
    status: IncidentStatus = IncidentStatus.NEW
    owner: Name
    summary: LongText = ""
    created_at: UtcTimestamp
    updated_at: UtcTimestamp
    closed_at: UtcTimestamp | None = None
    playbook_id: PlaybookId | None = None
    closure_reason: Reason | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        closed = self.status is IncidentStatus.CLOSED
        if closed and self.closed_at is None:
            raise ValidationDomainError.single("closed_at", "required_when_closed")
        if not closed and self.closed_at is not None:
            raise ValidationDomainError.single("closed_at", "forbidden_unless_closed")
        if closed and self.closure_reason is None:
            raise ValidationDomainError.single("closure_reason", "required_when_closed")
        if not closed and self.closure_reason is not None:
            raise ValidationDomainError.single("closure_reason", "forbidden_unless_closed")
        if self.severity is TechnicalSeverity.NONE:
            raise ValidationDomainError.single("severity", "none_requires_zero_score")
        if self.updated_at < self.created_at:
            raise ValidationDomainError.single("updated_at", "before_created_at")
        if self.closed_at is not None and self.closed_at < self.created_at:
            raise ValidationDomainError.single("closed_at", "before_created_at")
        return self
