"""Remediation task repository. Every write appends its audit entry in the same transaction."""

import sqlite3
from datetime import datetime
from typing import Final

from soerm.domain.audit import AuditEntry
from soerm.domain.enums import TaskStatus
from soerm.domain.task import Task
from soerm.storage.audit import append_audit
from soerm.storage.codec import coerce_enum, to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, NotFoundError, StorageError
from soerm.storage.transactions import transaction

__all__ = ["TASK_UPDATE_ACTIONS", "TaskRepository"]

TASK_UPDATE_ACTIONS: Final = frozenset({"task.update", "task.transition"})
_INSERT = (
    "INSERT INTO tasks (task_id, finding_id, incident_id, title, owner, due_at, status,"
    " created_at, updated_at, completed_at) VALUES (:task_id, :finding_id, :incident_id,"
    " :title, :owner, :due_at, :status, :created_at, :updated_at, :completed_at)"
)
_UPDATE = (
    "UPDATE tasks SET title = :title, owner = :owner, due_at = :due_at, status = :status,"
    " updated_at = :updated_at, completed_at = :completed_at WHERE task_id = :task_id"
)
_GET = "SELECT * FROM tasks WHERE task_id = :task_id"
_LIST = (
    "SELECT * FROM tasks WHERE (:status IS NULL OR status = :status)"
    " AND (:finding_id IS NULL OR finding_id = :finding_id)"
    " AND (:incident_id IS NULL OR incident_id = :incident_id) ORDER BY task_id"
)


def _optional_ts(value: datetime | None) -> str | None:
    return None if value is None else to_db_timestamp(value)


def _params(task: Task) -> dict[str, object]:
    return {
        "task_id": task.task_id,
        "finding_id": task.finding_id,
        "incident_id": task.incident_id,
        "title": task.title,
        "owner": task.owner,
        "due_at": _optional_ts(task.due_at),
        "status": task.status.value,
        "created_at": to_db_timestamp(task.created_at),
        "updated_at": to_db_timestamp(task.updated_at),
        "completed_at": _optional_ts(task.completed_at),
    }


def _from_row(row: sqlite3.Row) -> Task:
    try:
        return Task(**{key: row[key] for key in row.keys()})  # noqa: SIM118 - sqlite3.Row
    except ValueError:
        raise StorageError("corrupt_row", object_type="task") from None


def _checked(task: object) -> Task:
    if not isinstance(task, Task):
        raise StorageError("invalid_model", object_type="task")
    return task.with_changes()


class TaskRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, task: Task, *, actor: str, at: datetime) -> AuditEntry:
        model = _checked(task)
        with transaction(self._connection, write=True) as conn:
            conn.execute(_INSERT, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="task.create",
                object_type="task",
                object_id=model.task_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def update(
        self,
        task: Task,
        *,
        actor: str,
        at: datetime,
        expected_before_hash: str | None = None,
        action: str = "task.update",
    ) -> AuditEntry:
        """Replace the mutable fields; the links to a finding/incident and ``created_at``
        cannot change."""
        if action not in TASK_UPDATE_ACTIONS:
            raise StorageError("invalid_action")
        model = _checked(task)
        with transaction(self._connection, write=True) as conn:
            row = conn.execute(_GET, {"task_id": model.task_id}).fetchone()
            if row is None:
                raise NotFoundError("task")
            existing = _from_row(row)
            if expected_before_hash is not None and existing.digest() != expected_before_hash:
                raise ConflictError("task")
            if (
                existing.created_at != model.created_at
                or existing.finding_id != model.finding_id
                or existing.incident_id != model.incident_id
            ):
                raise StorageError("immutable_field", field="task_links")
            conn.execute(_UPDATE, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action=action,
                object_type="task",
                object_id=model.task_id,
                before_hash=existing.digest(),
                after_hash=model.digest(),
            )

    def get(self, task_id: str) -> Task | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET, {"task_id": task_id}).fetchone()
        return None if row is None else _from_row(row)

    def list_all(
        self,
        *,
        status: TaskStatus | None = None,
        finding_id: str | None = None,
        incident_id: str | None = None,
    ) -> list[Task]:
        params = {
            "status": None if status is None else coerce_enum(TaskStatus, status, "status").value,
            "finding_id": finding_id,
            "incident_id": incident_id,
        }
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST, params).fetchall()
        return [_from_row(row) for row in rows]
