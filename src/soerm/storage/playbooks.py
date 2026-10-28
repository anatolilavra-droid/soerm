"""Playbook repository: immutable versions, the incident attachment and completed steps.

* ``playbook_versions`` keeps every loaded version (never updated or deleted - triggers);
  ``playbooks`` holds the latest one for the incident foreign key.
* ``incident_playbooks`` pins an incident to one exact version; ``incident_playbook_steps``
  holds one row per completed step. Both are insert-only.
* Every write appends its audit entry (identifiers, versions and hashes only) in the same
  transaction. Nothing here runs a step.
"""

import json
from datetime import datetime

from soerm.domain.audit import AuditEntry
from soerm.domain.playbook import Playbook
from soerm.domain.playbook_run import (
    STEP_OBJECT_TYPE,
    PlaybookAttachment,
    StepCompletion,
    step_object_id,
)
from soerm.storage.audit import append_audit
from soerm.storage.codec import to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = ["PlaybookRepository"]

_HEAD = "SELECT * FROM playbooks WHERE playbook_id = :id"
_UPSERT_HEAD = (
    "INSERT INTO playbooks (playbook_id, name, version, definition, config_hash, created_at,"
    " updated_at) VALUES (:id, :name, :version, :definition, :config_hash, :at, :at)"
    " ON CONFLICT (playbook_id) DO UPDATE SET name = excluded.name, version = excluded.version,"
    " definition = excluded.definition, config_hash = excluded.config_hash,"
    " updated_at = excluded.updated_at"
)
_INSERT_VERSION = (
    "INSERT INTO playbook_versions (playbook_id, version, definition, config_hash, created_at)"
    " VALUES (:id, :version, :definition, :config_hash, :at)"
)
_VERSION = "SELECT * FROM playbook_versions WHERE playbook_id = :id AND version = :version"
_VERSIONS = (
    "SELECT version, config_hash FROM playbook_versions WHERE playbook_id = :id"
    " ORDER BY created_at, rowid"
)
_LIST_HEADS = "SELECT playbook_id, version FROM playbooks ORDER BY playbook_id"
_INSERT_ATTACH = (
    "INSERT INTO incident_playbooks (incident_id, playbook_id, version, config_hash, attached_at,"
    " attached_by) VALUES (:incident_id, :playbook_id, :version, :config_hash, :attached_at,"
    " :attached_by)"
)
_GET_ATTACH = "SELECT * FROM incident_playbooks WHERE incident_id = :id"
_INSERT_STEP = (
    "INSERT INTO incident_playbook_steps (incident_id, step_id, completed_at, completed_by,"
    " change_id) VALUES (:incident_id, :step_id, :completed_at, :completed_by, :change_id)"
)
_STEPS = (
    "SELECT * FROM incident_playbook_steps WHERE incident_id = :id ORDER BY completed_at, step_id"
)


def _definition(playbook: Playbook) -> str:
    return json.dumps(playbook.canonical_dict(), sort_keys=True, separators=(",", ":"))


def _playbook_from(text: str) -> Playbook:
    try:
        return Playbook(**json.loads(text))
    except (ValueError, TypeError):
        raise StorageError("corrupt_row", object_type="playbook") from None


class PlaybookRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    # -- versions ----------------------------------------------------------------------------

    def add_version(self, playbook: Playbook, *, actor: str, at: datetime) -> AuditEntry:
        """Store a new version (audit ``playbook.load``). An existing version is a conflict."""
        require_write_transaction(self._connection)
        with transaction(self._connection, write=True) as conn:
            head = conn.execute(_HEAD, {"id": playbook.playbook_id}).fetchone()
            if conn.execute(
                _VERSION, {"id": playbook.playbook_id, "version": playbook.version}
            ).fetchone():
                raise ConflictError("playbook_version")
            before = None if head is None else head["config_hash"]
            conn.execute(_UPSERT_HEAD, _head_params(playbook, at))  # latest version
            conn.execute(
                _INSERT_VERSION,
                {
                    "id": playbook.playbook_id,
                    "version": playbook.version,
                    "definition": _definition(playbook),
                    "config_hash": playbook.config_hash,
                    "at": to_db_timestamp(at),
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="playbook.load",
                object_type="playbook",
                object_id=playbook.playbook_id,
                before_hash=before,
                after_hash=playbook.config_hash,
            )

    def get(self, playbook_id: str, version: str | None = None) -> Playbook | None:
        """The given version, or the latest one."""
        with transaction(self._connection, write=False) as conn:
            if version is None:
                head = conn.execute(_HEAD, {"id": playbook_id}).fetchone()
                if head is None:
                    return None
                version = head["version"]
            row = conn.execute(_VERSION, {"id": playbook_id, "version": version}).fetchone()
        return None if row is None else _playbook_from(row["definition"])

    def versions(self, playbook_id: str) -> list[tuple[str, str]]:
        """``(version, config_hash)`` in load order."""
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_VERSIONS, {"id": playbook_id}).fetchall()
        return [(row["version"], row["config_hash"]) for row in rows]

    def list_latest(self) -> list[Playbook]:
        with transaction(self._connection, write=False) as conn:
            heads = conn.execute(_LIST_HEADS).fetchall()
        result = []
        for head in heads:
            playbook = self.get(head["playbook_id"], head["version"])
            if playbook is not None:
                result.append(playbook)
        return result

    # -- attachment and steps ----------------------------------------------------------------

    def attach(self, attachment: PlaybookAttachment, *, actor: str, at: datetime) -> AuditEntry:
        require_write_transaction(self._connection)
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_ATTACH,
                {
                    "incident_id": attachment.incident_id,
                    "playbook_id": attachment.playbook_id,
                    "version": attachment.version,
                    "config_hash": attachment.config_hash,
                    "attached_at": to_db_timestamp(attachment.attached_at),
                    "attached_by": attachment.attached_by,
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="playbook.attach",
                object_type="incident",
                object_id=attachment.incident_id,
                before_hash=None,
                after_hash=attachment.record_hash(),
            )

    def get_attachment(self, incident_id: str) -> PlaybookAttachment | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET_ATTACH, {"id": incident_id}).fetchone()
        if row is None:
            return None
        try:
            return PlaybookAttachment(**{key: row[key] for key in row.keys()})  # noqa: SIM118
        except ValueError:
            raise StorageError("corrupt_row", object_type="incident_playbook") from None

    def complete_step(self, completion: StepCompletion, *, actor: str, at: datetime) -> AuditEntry:
        """Record a completed step (audit ``playbook.step_done``); a second one is a conflict."""
        require_write_transaction(self._connection)
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_STEP,
                {
                    "incident_id": completion.incident_id,
                    "step_id": completion.step_id,
                    "completed_at": to_db_timestamp(completion.completed_at),
                    "completed_by": completion.completed_by,
                    "change_id": completion.change_id,
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="playbook.step_done",
                object_type=STEP_OBJECT_TYPE,
                object_id=step_object_id(completion.incident_id, completion.step_id),
                before_hash=None,
                after_hash=completion.record_hash(),
            )

    def completions(self, incident_id: str) -> list[StepCompletion]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_STEPS, {"id": incident_id}).fetchall()
        try:
            return [StepCompletion(**{key: row[key] for key in row.keys()}) for row in rows]  # noqa: SIM118
        except ValueError:
            raise StorageError("corrupt_row", object_type="incident_playbook_step") from None


def _head_params(playbook: Playbook, at: datetime) -> dict[str, object]:
    return {
        "id": playbook.playbook_id,
        "name": playbook.name,
        "version": playbook.version,
        "definition": _definition(playbook),
        "config_hash": playbook.config_hash,
        "at": to_db_timestamp(at),
    }
