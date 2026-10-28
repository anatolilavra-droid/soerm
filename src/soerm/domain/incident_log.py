"""Incident timeline records: status events and analyst notes (M8).

Events hold identifiers and status codes only. A note body is analyst text that has passed the
M4 redaction before it gets here; it is never copied into the audit log (only its hash is).
"""

from typing import Annotated, Final, Self

from pydantic import Field, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import IncidentStatus
from soerm.domain.errors import ValidationDomainError
from soerm.domain.identifiers import ActionName, IncidentId
from soerm.domain.text import Actor, LongText
from soerm.domain.timestamps import UtcTimestamp

__all__ = [
    "EVENT_TYPES",
    "IncidentEvent",
    "IncidentNote",
]

EVENT_TYPES: Final = frozenset(
    {
        "incident_created",
        "incident_updated",
        "status_changed",
        "incident_reopened",
        "finding_linked",
        "playbook_attached",
        "playbook_step_done",
        "note_added",
        "task_created",
    }
)


class IncidentEvent(DomainModel):
    incident_id: IncidentId
    occurred_at: UtcTimestamp
    actor: Actor
    event_type: ActionName
    from_status: IncidentStatus | None = None
    to_status: IncidentStatus | None = None

    @model_validator(mode="after")
    def _known_type(self) -> Self:
        if self.event_type not in EVENT_TYPES:
            raise ValidationDomainError.single("event_type", "unknown_event_type")
        return self


class IncidentNote(DomainModel):
    incident_id: IncidentId
    created_at: UtcTimestamp
    author: Actor
    redacted_body: Annotated[LongText, Field(min_length=1)]
