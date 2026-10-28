"""Playbook attachment and step progress (M9). Pure data and arithmetic; nothing is executed.

An incident is bound to one exact playbook *version* (pinned by its config hash). A step is
completed once, by a named actor at a recorded time; completing it again changes nothing.
Finishing every step never closes an incident: the closure criteria are a prompt for a person.
"""

from dataclasses import dataclass
from typing import Final

from soerm.domain.base import DomainModel
from soerm.domain.hashing import Sha256, hash_canonical
from soerm.domain.identifiers import IncidentId, PlaybookId, Slug, VersionLabel
from soerm.domain.playbook import Playbook, PlaybookStep
from soerm.domain.text import Actor
from soerm.domain.timestamps import UtcTimestamp

__all__ = [
    "STEP_OBJECT_TYPE",
    "PlaybookAttachment",
    "PlaybookProgress",
    "StepCompletion",
    "StepState",
    "progress",
    "step_object_id",
]

STEP_OBJECT_TYPE: Final = "incident_step"


def step_object_id(incident_id: str, step_id: str) -> str:
    """Audited/approved object id of one step of one incident (``INC-000001:step-001``)."""
    return f"{incident_id}:{step_id}"


class PlaybookAttachment(DomainModel):
    incident_id: IncidentId
    playbook_id: PlaybookId
    version: VersionLabel
    config_hash: Sha256
    attached_at: UtcTimestamp
    attached_by: Actor

    def record_hash(self) -> str:
        return hash_canonical(self.canonical_dict())


class StepCompletion(DomainModel):
    incident_id: IncidentId
    step_id: Slug
    completed_at: UtcTimestamp
    completed_by: Actor
    change_id: str | None = None  # the approval that covered a gated step

    def record_hash(self) -> str:
        return hash_canonical(self.canonical_dict())


@dataclass(frozen=True, slots=True)
class StepState:
    step: PlaybookStep
    completion: StepCompletion | None

    @property
    def done(self) -> bool:
        return self.completion is not None


@dataclass(frozen=True, slots=True)
class PlaybookProgress:
    steps: tuple[StepState, ...]
    completed: int
    total: int
    next_step_id: str | None
    all_done: bool


def progress(playbook: Playbook, completions: list[StepCompletion]) -> PlaybookProgress:
    by_step = {c.step_id: c for c in completions}
    states = tuple(StepState(step, by_step.get(step.step_id)) for step in playbook.steps)
    done = sum(1 for state in states if state.done)
    pending = next((s.step.step_id for s in states if not s.done), None)
    return PlaybookProgress(states, done, len(states), pending, done == len(states))
