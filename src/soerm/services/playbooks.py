"""Playbook service (M9): load versions, attach to an incident, track manual steps.

A playbook is a set of instructions *for people*. Nothing here runs a command, opens a socket,
changes a file outside the workspace, contacts anyone or touches a finding:

* ``load_playbook`` reads one YAML file inside the workspace (safe reader, strict YAML, size
  limit), redacts every text (M4) and stores an **immutable version**. The same version with
  different content is refused; a changed playbook needs a new version label.
* ``attach_playbook`` pins an incident to one version. Later versions never change it.
* ``complete_step`` marks a step done by a named actor at a recorded time, once. Repeating it
  changes nothing (no write, no audit). A step with ``requires_manual_approval`` needs an
  approved request (``request_step_approval``) presented with ``change_id``; the approval is
  single use and follows the M8 policy (distinct approver, expiry).
* Completing every step does **not** close the incident. ``closure_criteria`` are shown as a
  prompt; ``ready_for_closure_review`` only says that all steps are done.

Audit entries hold identifiers, versions, status codes and hashes - never step text.
"""

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from soerm.config import ConfigError
from soerm.config.loader import MAX_CONFIG_BYTES, load_yaml_text
from soerm.domain.approval import change_hash, new_approval
from soerm.domain.audit import AuditEntry
from soerm.domain.enums import IncidentStatus
from soerm.domain.errors import DomainError
from soerm.domain.hashing import compute_config_hash
from soerm.domain.identifiers import check_identifier
from soerm.domain.imports import ImportRejectedError
from soerm.domain.incident_log import IncidentEvent
from soerm.domain.playbook import Playbook
from soerm.domain.playbook_run import (
    STEP_OBJECT_TYPE,
    PlaybookAttachment,
    PlaybookProgress,
    StepCompletion,
    progress,
    step_object_id,
)
from soerm.importers.safe_file import read_workspace_file
from soerm.services.approvals import verify_approval
from soerm.services.common import MutationResult, require_actor
from soerm.services.errors import (
    ApprovalRequiredError,
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_runtime
from soerm.services.workspace import Session, Workspace
from soerm.storage.approvals import ApprovalRepository
from soerm.storage.counters import CounterRepository
from soerm.storage.errors import ConflictError
from soerm.storage.incidents import IncidentRepository
from soerm.storage.playbooks import PlaybookRepository

__all__ = [
    "LoadResult",
    "PlaybookStatus",
    "StepOutcome",
    "attach_playbook",
    "complete_step",
    "get_playbook",
    "list_playbooks",
    "load_playbook",
    "playbook_status",
    "request_step_approval",
]

_SLUG: Final = re.compile(r"[a-z][a-z0-9_-]{1,63}")
_FILE_VERSION: Final = 1
_TOP_KEYS: Final = frozenset(
    {
        "version", "playbook_id", "name", "playbook_version", "incident_types", "roles",
        "steps", "escalation_criteria", "closure_criteria",
    }
)  # fmt: skip
_STEP_KEYS: Final = frozenset(
    {
        "id", "type", "title", "text", "items", "owner_role", "potentially_destructive",
        "requires_manual_approval",
    }
)  # fmt: skip
_MAX_LIST: Final = 100


@dataclass(frozen=True, slots=True)
class LoadResult:
    playbook: Playbook
    changed: bool  # False: the identical version was already stored
    audit: AuditEntry | None
    redaction_hits: int


@dataclass(frozen=True, slots=True)
class StepOutcome:
    incident_id: str
    step_id: str
    changed: bool  # False: the step was already complete (nothing was written)
    completion: StepCompletion
    audit: AuditEntry | None


@dataclass(frozen=True, slots=True)
class PlaybookStatus:
    incident_id: str
    incident_status: IncidentStatus
    attachment: PlaybookAttachment
    playbook: Playbook
    progress: PlaybookProgress

    @property
    def ready_for_closure_review(self) -> bool:
        """All steps are done. A hint for a person; no transition ever follows from it."""
        return self.progress.all_done


# -- input helpers --------------------------------------------------------------------------


def _slug_arg(value: object, field: str) -> str:
    """Identifiers are lowercase ASCII slugs; ``PBK-000001`` is accepted as ``pbk-000001``."""
    if not isinstance(value, str) or not value.isascii():
        raise InvalidInputError(f"{field}: invalid_identifier")
    lowered = value.lower()
    if not _SLUG.fullmatch(lowered):
        raise InvalidInputError(f"{field}: invalid_identifier")
    return lowered


def _incident_arg(value: object) -> str:
    try:
        return check_identifier("INC", value, field="incident_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def _expect_mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise InvalidInputError(f"{where}: must_be_mapping")
    return value


def _check_keys(data: dict[str, object], allowed: frozenset[str], where: str) -> None:
    if set(data) - allowed:
        raise InvalidInputError(f"{where}: unknown_field")  # the key itself is never echoed


def _str_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_LIST:
        raise InvalidInputError(f"{field}: must_be_list")
    if not all(isinstance(item, str) for item in value):
        raise InvalidInputError(f"{field}: must_be_text")
    return [str(item) for item in value]


def _flag(data: dict[str, object], key: str, field: str) -> bool:
    value = data.get(key, False)
    if not isinstance(value, bool):
        raise InvalidInputError(f"{field}: must_be_boolean")
    return value


def _text(data: dict[str, object], key: str, field: str, default: str = "") -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise InvalidInputError(f"{field}: must_be_text")
    return value


def _build_playbook(data: dict[str, object], redactor: FieldRedactor) -> Playbook:
    """A validated playbook from the file content; every text is redacted first."""
    _check_keys(data, _TOP_KEYS, "playbook")
    if data.get("version") != _FILE_VERSION:
        raise InvalidInputError("version: unsupported_file_version")
    playbook_id = _slug_arg(data.get("playbook_id"), "playbook_id")
    version = data.get("playbook_version")
    if not isinstance(version, str):
        raise InvalidInputError("playbook_version: must_be_text")
    steps: list[dict[str, object]] = []
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) > _MAX_LIST:
        raise InvalidInputError("steps: must_be_list")
    for raw in raw_steps:
        step = _expect_mapping(raw, "steps")
        _check_keys(step, _STEP_KEYS, "steps")
        steps.append(
            {
                "step_id": _slug_arg(step.get("id"), "steps.id"),
                "step_type": _text(step, "type", "steps.type"),
                "title": redactor.field(
                    "steps.title", _text(step, "title", "steps.title"), "title"
                ),
                "text": redactor.field("steps.text", _text(step, "text", "steps.text"), "text"),
                "items": [
                    redactor.field("steps.items", item, "reason")
                    for item in _str_list(step.get("items"), "steps.items")
                ],
                "owner_role": None
                if step.get("owner_role") is None
                else _slug_arg(step.get("owner_role"), "steps.owner_role"),
                "potentially_destructive": _flag(step, "potentially_destructive", "steps"),
                "requires_manual_approval": _flag(step, "requires_manual_approval", "steps"),
            }
        )
    fields: dict[str, object] = {
        "playbook_id": playbook_id,
        "name": redactor.field("name", _text(data, "name", "name"), "name"),
        "version": version,
        "incident_types": [
            _slug_arg(item, "incident_types")
            for item in _str_list(data.get("incident_types"), "incident_types")
        ],
        "roles": [_slug_arg(item, "roles") for item in _str_list(data.get("roles"), "roles")],
        "steps": steps,
        "escalation_criteria": [
            redactor.field("escalation_criteria", item, "reason")
            for item in _str_list(data.get("escalation_criteria"), "escalation_criteria")
        ],
        "closure_criteria": [
            redactor.field("closure_criteria", item, "reason")
            for item in _str_list(data.get("closure_criteria"), "closure_criteria")
        ],
    }
    try:
        draft = Playbook(config_hash="0" * 64, **fields)  # type: ignore[arg-type]
        payload = {k: v for k, v in draft.canonical_dict().items() if k != "config_hash"}
        digest = compute_config_hash(name=draft.playbook_id, version=draft.version, payload=payload)
        return draft.with_changes(config_hash=digest)
    except DomainError as exc:
        raise to_service_error(exc) from None


# -- loading and reading --------------------------------------------------------------------


def load_playbook(workspace: Workspace, path: str, *, actor: str) -> LoadResult:
    """Store a playbook version from a YAML file inside the workspace (idempotent)."""
    who = require_actor(actor)
    try:
        raw = read_workspace_file(workspace.path, path, max_bytes=MAX_CONFIG_BYTES).data
        text = raw.decode("utf-8").removeprefix("﻿")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
            raise InvalidInputError("playbook_file: control_character")
        data = load_yaml_text(text)
    except ImportRejectedError as exc:
        raise InvalidInputError(f"playbook_file: {exc.reason}") from None
    except UnicodeDecodeError:
        raise InvalidInputError("playbook_file: not_utf8") from None
    except ConfigError as exc:
        raise InvalidInputError(f"playbook_file: {exc.reason}") from None
    _, redaction_engine = load_runtime(workspace.path)
    redactor = FieldRedactor(redaction_engine)
    playbook = _build_playbook(_expect_mapping(data, "playbook"), redactor)
    hits = redactor.report().total_hits
    with workspace.write() as session:
        repo = PlaybookRepository(session.connection)
        existing = repo.get(playbook.playbook_id, playbook.version)
        if existing is not None:
            if existing.config_hash == playbook.config_hash:
                return LoadResult(existing, False, None, hits)
            raise ConflictServiceError("playbook_version_immutable", object_type="playbook")
        try:
            entry = repo.add_version(playbook, actor=who, at=session.now)
        except ConflictError:
            raise ConflictServiceError(
                "playbook_version_immutable", object_type="playbook"
            ) from None
    return LoadResult(playbook, True, entry, hits)


def list_playbooks(workspace: Workspace, *, incident_type: str | None = None) -> list[Playbook]:
    wanted = None if incident_type is None else _slug_arg(incident_type, "incident_type")
    with workspace.read() as session:
        playbooks = PlaybookRepository(session.connection).list_latest()
    return [p for p in playbooks if wanted is None or wanted in p.incident_types]


def get_playbook(
    workspace: Workspace, playbook_id: str, *, version: str | None = None
) -> tuple[Playbook, list[tuple[str, str]]]:
    """The playbook (latest or the given version) and its version history."""
    pid = _slug_arg(playbook_id, "playbook_id")
    with workspace.read() as session:
        repo = PlaybookRepository(session.connection)
        playbook = repo.get(pid, version)
        if playbook is None:
            raise NotFoundServiceError("object_not_found", object_type="playbook")
        return playbook, repo.versions(pid)


# -- attachment and progress ----------------------------------------------------------------


def _event(session: Session, incident_id: str, actor: str, event_type: str) -> IncidentEvent:
    return IncidentEvent(
        incident_id=incident_id, occurred_at=session.now, actor=actor, event_type=event_type
    )


def _open_incident(repo: IncidentRepository, incident_id: str):  # type: ignore[no-untyped-def]
    incident = repo.get(incident_id)
    if incident is None:
        raise NotFoundServiceError("object_not_found", object_type="incident")
    if incident.status is IncidentStatus.CLOSED:
        raise ConflictServiceError("incident_closed", object_type="incident")
    return incident


def attach_playbook(
    workspace: Workspace,
    incident_id: str,
    playbook_id: str,
    *,
    actor: str,
    version: str | None = None,
) -> tuple[PlaybookAttachment, bool, AuditEntry | None]:
    """Pin an incident to a playbook version (latest unless ``version``). Idempotent.

    Returns ``(attachment, changed, audit)``. Attaching the same version again changes nothing;
    attaching a different playbook or version is refused (``playbook_already_attached``).
    """
    who = require_actor(actor)
    iid = _incident_arg(incident_id)
    pid = _slug_arg(playbook_id, "playbook_id")
    with workspace.write() as session:
        incidents = IncidentRepository(session.connection)
        repo = PlaybookRepository(session.connection)
        incident = incidents.get(iid)
        if incident is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        playbook = repo.get(pid, version)
        if playbook is None:
            raise NotFoundServiceError("object_not_found", object_type="playbook")
        current = repo.get_attachment(iid)
        if current is not None:
            if (current.playbook_id, current.version) == (playbook.playbook_id, playbook.version):
                return current, False, None
            raise ConflictServiceError("playbook_already_attached", object_type="incident")
        if incident.status is IncidentStatus.CLOSED:
            raise ConflictServiceError("incident_closed", object_type="incident")
        attachment = PlaybookAttachment(
            incident_id=iid,
            playbook_id=playbook.playbook_id,
            version=playbook.version,
            config_hash=playbook.config_hash,
            attached_at=session.now,
            attached_by=who,
        )
        entry = repo.attach(attachment, actor=who, at=session.now)
        incidents.update(
            incident.with_changes(playbook_id=playbook.playbook_id, updated_at=session.now),
            actor=who,
            at=session.now,
            expected_before_hash=incident.digest(),
            action="incident.playbook_attach",
        )
        incidents.add_event(_event(session, iid, who, "playbook_attached"))
    return attachment, True, entry


def _load_run(repo: PlaybookRepository, incident_id: str) -> tuple[PlaybookAttachment, Playbook]:
    attachment = repo.get_attachment(incident_id)
    if attachment is None:
        raise ConflictServiceError("no_playbook_attached", object_type="incident")
    playbook = repo.get(attachment.playbook_id, attachment.version)
    if playbook is None or playbook.config_hash != attachment.config_hash:
        raise ConflictServiceError("playbook_version_missing", object_type="playbook")
    return attachment, playbook


def playbook_status(workspace: Workspace, incident_id: str) -> PlaybookStatus:
    iid = _incident_arg(incident_id)
    with workspace.read() as session:
        incident = IncidentRepository(session.connection).get(iid)
        if incident is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        repo = PlaybookRepository(session.connection)
        attachment, playbook = _load_run(repo, iid)
        done = repo.completions(iid)
    return PlaybookStatus(iid, incident.status, attachment, playbook, progress(playbook, done))


def _step_of(playbook: Playbook, step_id: str):  # type: ignore[no-untyped-def]
    for step in playbook.steps:
        if step.step_id == step_id:
            return step
    raise NotFoundServiceError("object_not_found", object_type="step")


def _step_change(step_id: str) -> dict[str, str]:
    return {"step": step_id, "completed": "true"}


# -- approvals for gated steps --------------------------------------------------------------


def request_step_approval(
    workspace: Workspace, incident_id: str, step_id: str, *, actor: str, reason: str
) -> MutationResult:
    """Ask for approval to complete a step that has ``requires_manual_approval``."""
    who = require_actor(actor)
    iid = _incident_arg(incident_id)
    sid = _slug_arg(step_id, "step_id")
    config, engine = load_runtime(workspace.path)
    redactor = FieldRedactor(engine)
    clean_reason = redactor.field("reason", reason, "reason")
    policy = config.approvals
    with workspace.write() as session:
        _open_incident(IncidentRepository(session.connection), iid)
        repo = PlaybookRepository(session.connection)
        attachment, playbook = _load_run(repo, iid)
        step = _step_of(playbook, sid)
        if not step.requires_manual_approval:
            raise InvalidInputError("step: approval_not_applicable")
        if any(c.step_id == sid for c in repo.completions(iid)):
            raise ConflictServiceError("step_already_completed", object_type="step")
        object_id = step_object_id(iid, sid)
        proposed = change_hash(STEP_OBJECT_TYPE, object_id, _step_change(sid))
        approvals = ApprovalRepository(session.connection)
        if approvals.find_pending(STEP_OBJECT_TYPE, object_id, proposed) is not None:
            raise ConflictServiceError("duplicate_pending_request", object_type="approval")
        try:
            approval = new_approval(
                change_id=CounterRepository(session.connection).next_identifier("CHG"),
                object_type=STEP_OBJECT_TYPE,
                object_id=object_id,
                requester=who,
                reason=clean_reason,
                before_hash=attachment.config_hash,
                proposed_after_hash=proposed,
                requested_at=session.now,
                ttl=timedelta(hours=policy.ttl_hours),
                require_distinct_approver=policy.require_distinct_approver,
            )
        except DomainError as exc:
            raise to_service_error(exc) from None
        entry = approvals.add(approval, actor=who, at=session.now)
    return MutationResult(
        "approval", approval.change_id, None, approval.digest(), entry, redactor.report()
    )


# -- steps ----------------------------------------------------------------------------------


def complete_step(
    workspace: Workspace,
    incident_id: str,
    step_id: str,
    *,
    actor: str,
    change_id: str | None = None,
) -> StepOutcome:
    """Mark a step done (by ``actor``, now). A repeat returns the first completion unchanged."""
    who = require_actor(actor)
    iid = _incident_arg(incident_id)
    sid = _slug_arg(step_id, "step_id")
    with workspace.write() as session:
        incidents = IncidentRepository(session.connection)
        repo = PlaybookRepository(session.connection)
        if incidents.get(iid) is None:
            raise NotFoundServiceError("object_not_found", object_type="incident")
        attachment, playbook = _load_run(repo, iid)
        step = _step_of(playbook, sid)
        for done in repo.completions(iid):
            if done.step_id == sid:  # idempotent: nothing is written, nothing is audited
                return StepOutcome(iid, sid, False, done, None)
        _open_incident(incidents, iid)
        approvals = ApprovalRepository(session.connection)
        if step.requires_manual_approval:
            if change_id is None:
                raise ApprovalRequiredError("step_requires_approval", step=sid)
            verify_approval(
                approvals,
                change_id,
                object_type=STEP_OBJECT_TYPE,
                object_id=step_object_id(iid, sid),
                proposed_hash=change_hash(
                    STEP_OBJECT_TYPE, step_object_id(iid, sid), _step_change(sid)
                ),
                before_hash=attachment.config_hash,
                now=session.now,
            )
        elif change_id is not None:
            raise InvalidInputError("change_id: not_required")
        completion = StepCompletion(
            incident_id=iid,
            step_id=sid,
            completed_at=session.now,
            completed_by=who,
            change_id=change_id,
        )
        entry = repo.complete_step(completion, actor=who, at=session.now)
        if change_id is not None:
            approvals.record_application(
                change_id,
                before_hash=attachment.config_hash,
                after_hash=completion.record_hash(),
                actor=who,
                at=session.now,
            )
        incidents.add_event(_event(session, iid, who, "playbook_step_done"))
    return StepOutcome(iid, sid, True, completion, entry)
