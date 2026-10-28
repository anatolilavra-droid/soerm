"""Playbook model. A playbook is a description for humans: the domain never executes a step."""

# ruff: noqa: RUF001
# (the Cyrillic stems below are intentional)
import re
from typing import Final, Self

from pydantic import model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import StepType
from soerm.domain.errors import ValidationDomainError
from soerm.domain.hashing import Sha256
from soerm.domain.identifiers import PlaybookId, Slug, VersionLabel
from soerm.domain.text import Criterion, LongText, Name, Title

__all__ = ["Playbook", "PlaybookStep", "looks_destructive"]

# Conservative stems of potentially destructive or disruptive actions (English and Russian).
# A step whose text matches must require manual approval. False positives only add an approval.
_DESTRUCTIVE_STEMS: Final = (
    "delet", "remov", "wip", "eras", "format", "drop", "truncat", "shut", "power off",
    "poweroff", "reboot", "restart", "terminat", "kill", "disabl", "block", "isolat",
    "quarantin", "revok", "rotat", "reset", "reimag", "re-imag", "deactivat", "disconnect",
    "uninstall", "purg", "overwrit", "lock out", "lockout",
    "удал", "стер", "стёр", "очист", "форматир", "отключ", "выключ", "перезагруз",
    "перезапуст", "блокир", "изолир", "карантин", "отозв", "сброс", "ротаци",
    "деактивир", "отсоедин", "деинсталл", "заблок", "заблокир", "обнул",
)  # fmt: skip
_DESTRUCTIVE = re.compile(r"\b(?:" + "|".join(re.escape(s) for s in _DESTRUCTIVE_STEMS) + ")")
_MAX_STEPS = 100
_MAX_ITEMS = 50


def looks_destructive(*texts: str) -> bool:
    """True if any text mentions a potentially destructive action."""
    return any(_DESTRUCTIVE.search(text.casefold()) for text in texts)


class PlaybookStep(DomainModel):
    step_id: Slug
    step_type: StepType
    title: Title
    text: LongText = ""
    items: tuple[Criterion, ...] = ()
    owner_role: Slug | None = None
    potentially_destructive: bool = False
    requires_manual_approval: bool = False

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.step_type is StepType.CHECKLIST:
            if not self.items or len(self.items) > _MAX_ITEMS:
                raise ValidationDomainError.single("items", "checklist_items_required")
            if self.text:
                raise ValidationDomainError.single("text", "forbidden_for_checklist")
        else:
            if not self.text:
                raise ValidationDomainError.single("text", "required_for_step_type")
            if self.items:
                raise ValidationDomainError.single("items", "only_for_checklist")
        destructive = self.potentially_destructive or looks_destructive(
            self.title, self.text, *self.items
        )
        if destructive and not self.requires_manual_approval:
            raise ValidationDomainError.single(
                "requires_manual_approval", "required_for_destructive_step"
            )
        return self


class Playbook(DomainModel):
    playbook_id: PlaybookId
    name: Name
    version: VersionLabel
    incident_types: tuple[Slug, ...] = ()
    roles: tuple[Slug, ...]
    steps: tuple[PlaybookStep, ...]
    escalation_criteria: tuple[Criterion, ...] = ()
    closure_criteria: tuple[Criterion, ...] = ()
    config_hash: Sha256

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValidationDomainError.single("roles", "roles_required_and_unique")
        if not self.steps or len(self.steps) > _MAX_STEPS:
            raise ValidationDomainError.single("steps", "steps_required")
        step_ids = [step.step_id for step in self.steps]
        if len(set(step_ids)) != len(step_ids):
            raise ValidationDomainError.single("steps", "duplicate_step_id")
        if len(self.incident_types) > _MAX_ITEMS or len(set(self.incident_types)) != len(
            self.incident_types
        ):
            raise ValidationDomainError.single("incident_types", "incident_types_unique")
        known_roles = set(self.roles)
        if any(s.owner_role is not None and s.owner_role not in known_roles for s in self.steps):
            raise ValidationDomainError.single("steps", "unknown_owner_role")
        return self
