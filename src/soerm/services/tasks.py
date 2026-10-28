"""Remediation task service (M8).

A task belongs to a finding and/or an incident. States: ``open``, ``in_progress``, ``done``,
``cancelled``. ``done`` sets ``completed_at``; ``done`` and ``cancelled`` are final, a cancelled
task can only be reinstated (to ``open``) and never goes straight to ``done``. Completing tasks
changes nothing else: findings are never resolved or closed automatically.
"""

from datetime import datetime

from soerm.domain.enums import IncidentStatus, TaskStatus
from soerm.domain.errors import DomainError
from soerm.domain.identifiers import check_identifier
from soerm.domain.task import Task, transition_task
from soerm.domain.timestamps import parse_timestamp
from soerm.services.common import (
    PLACEHOLDER_TIME,
    MutationResult,
    require_actor,
    require_expected_hash,
)
from soerm.services.errors import (
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_redactor
from soerm.services.workspace import Workspace
from soerm.storage.counters import CounterRepository
from soerm.storage.findings import FindingRepository
from soerm.storage.incidents import IncidentRepository
from soerm.storage.tasks import TaskRepository

__all__ = ["create_task", "get_task", "list_tasks", "transition", "update_task"]

_PLACEHOLDER_ID = "TSK-000001"
_FINAL = frozenset({TaskStatus.DONE, TaskStatus.CANCELLED})


def _task_id(value: object) -> str:
    try:
        return check_identifier("TSK", value, field="task_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def _optional_id(prefix: str, field: str, value: object) -> str | None:
    if value is None:
        return None
    try:
        return check_identifier(prefix, value, field=field)
    except DomainError as exc:
        raise to_service_error(exc) from None


def _due(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return value if isinstance(value, datetime) else parse_timestamp(value, field="due_at")
    except DomainError as exc:
        raise to_service_error(exc) from None


def create_task(
    workspace: Workspace,
    *,
    actor: str,
    title: str,
    owner: str,
    finding_id: str | None = None,
    incident_id: str | None = None,
    due_at: datetime | str | None = None,
) -> MutationResult:
    actor = require_actor(actor)
    finding = _optional_id("FND", "finding_id", finding_id)
    incident = _optional_id("INC", "incident_id", incident_id)
    redactor = FieldRedactor(load_redactor(workspace.path))
    fields: dict[str, object] = {
        "finding_id": finding,
        "incident_id": incident,
        "title": redactor.field("title", title, "title"),
        "owner": redactor.field("owner", owner, "name"),
        "due_at": _due(due_at),
    }
    try:
        Task(
            task_id=_PLACEHOLDER_ID,
            created_at=PLACEHOLDER_TIME,
            updated_at=PLACEHOLDER_TIME,
            **fields,  # type: ignore[arg-type]
        )
    except DomainError as exc:
        raise to_service_error(exc) from None
    with workspace.write() as session:
        if finding is not None and FindingRepository(session.connection).get(finding) is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        if incident is not None:
            parent = IncidentRepository(session.connection).get(incident)
            if parent is None:
                raise NotFoundServiceError("object_not_found", object_type="incident")
            if parent.status is IncidentStatus.CLOSED:
                raise ConflictServiceError("incident_closed", object_type="incident")
        task_id = CounterRepository(session.connection).next_identifier("TSK")
        task = Task(
            task_id=task_id,
            created_at=session.now,
            updated_at=session.now,
            **fields,  # type: ignore[arg-type]
        )
        entry = TaskRepository(session.connection).add(task, actor=actor, at=session.now)
    return MutationResult("task", task_id, None, task.digest(), entry, redactor.report())


def update_task(
    workspace: Workspace,
    task_id: str,
    *,
    actor: str,
    expected_hash: str,
    title: str | None = None,
    owner: str | None = None,
    due_at: datetime | str | None = None,
    clear_due: bool = False,
) -> MutationResult:
    """Change title, owner or due date of a task that is not final."""
    actor = require_actor(actor)
    task_id = _task_id(task_id)
    expected = require_expected_hash(expected_hash)
    if clear_due and due_at is not None:
        raise InvalidInputError("due_at: conflicting_options")
    redactor = FieldRedactor(load_redactor(workspace.path))
    changes: dict[str, object] = {
        key: value
        for key, value in (
            ("title", redactor.optional("title", title, "title")),
            ("owner", redactor.optional("owner", owner, "name")),
            ("due_at", _due(due_at)),
        )
        if value is not None
    }
    if clear_due:
        changes["due_at"] = None
    if not changes:
        raise InvalidInputError("no_changes")
    with workspace.write() as session:
        repo = TaskRepository(session.connection)
        current = repo.get(task_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="task")
        if current.digest() != expected:
            raise ConflictServiceError("hash_mismatch", object_type="task")
        if current.status in _FINAL:
            raise ConflictServiceError("task_final", object_type="task")
        candidate = current.with_changes(**changes)
        if candidate == current:
            raise InvalidInputError("no_changes")
        updated = candidate.with_changes(updated_at=session.now)
        entry = repo.update(updated, actor=actor, at=session.now, expected_before_hash=expected)
    return MutationResult(
        "task", task_id, current.digest(), updated.digest(), entry, redactor.report()
    )


def transition(
    workspace: Workspace,
    task_id: str,
    target: TaskStatus,
    *,
    actor: str,
    expected_hash: str,
    reinstate: bool = False,
) -> MutationResult:
    actor = require_actor(actor)
    task_id = _task_id(task_id)
    expected = require_expected_hash(expected_hash)
    try:
        target_status = TaskStatus(target)
    except ValueError:
        raise InvalidInputError("status: invalid_enum") from None
    with workspace.write() as session:
        repo = TaskRepository(session.connection)
        current = repo.get(task_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="task")
        before = current.digest()
        if before != expected:
            raise ConflictServiceError("hash_mismatch", object_type="task")
        try:
            new_status = transition_task(current.status, target_status, reinstate=reinstate)
        except DomainError as exc:
            raise to_service_error(exc) from None
        updated = current.with_changes(
            status=new_status,
            completed_at=session.now if new_status is TaskStatus.DONE else None,
            updated_at=session.now,
        )
        entry = repo.update(
            updated,
            actor=actor,
            at=session.now,
            expected_before_hash=expected,
            action="task.transition",
        )
    return MutationResult("task", task_id, before, updated.digest(), entry)


def get_task(workspace: Workspace, task_id: str) -> Task:
    task_id = _task_id(task_id)
    with workspace.read() as session:
        task = TaskRepository(session.connection).get(task_id)
    if task is None:
        raise NotFoundServiceError("object_not_found", object_type="task")
    return task


def list_tasks(
    workspace: Workspace,
    *,
    status: TaskStatus | None = None,
    finding_id: str | None = None,
    incident_id: str | None = None,
) -> list[Task]:
    try:
        status_filter = None if status is None else TaskStatus(status)
    except ValueError:
        raise InvalidInputError("filter: invalid_enum") from None
    finding = _optional_id("FND", "finding_id", finding_id)
    incident = _optional_id("INC", "incident_id", incident_id)
    with workspace.read() as session:
        return TaskRepository(session.connection).list_all(
            status=status_filter, finding_id=finding, incident_id=incident
        )
