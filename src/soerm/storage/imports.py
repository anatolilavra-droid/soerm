"""Repositories for import runs and finding occurrences (the M1 tables, unchanged).

``ImportRunRepository.add`` appends an ``import.run`` audit entry in the same transaction.
Occurrences are provenance rows; they are covered by the run's audit entry and by the
``finding.create`` / ``finding.update`` entries of their finding, not by one entry each.
Nothing here stores evidence: a row holds identifiers, a file hash, a workspace-relative path
and a locator.
"""

import sqlite3
from datetime import datetime

from soerm.domain.audit import AuditEntry
from soerm.domain.enums import ImportSource
from soerm.domain.import_run import ImportRun
from soerm.domain.provenance import Occurrence
from soerm.storage.audit import append_audit
from soerm.storage.codec import to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import StorageError
from soerm.storage.transactions import require_write_transaction, transaction

__all__ = ["ImportRunRepository", "OccurrenceRepository"]

_INSERT_RUN = (
    "INSERT INTO import_runs (run_id, source, file_sha256, source_path, imported_at,"
    " record_count) VALUES (:run_id, :source, :file_sha256, :source_path, :imported_at,"
    " :record_count)"
)
_GET_RUN = "SELECT * FROM import_runs WHERE run_id = :run_id"
_LIST_RUNS = "SELECT * FROM import_runs ORDER BY run_id"
_INSERT_OCC = (
    "INSERT INTO finding_occurrences (finding_id, import_run_id, file_sha256, source_path,"
    " location, observed_at) VALUES (:finding_id, :import_run_id, :file_sha256, :source_path,"
    " :location, :observed_at)"
)
_EXISTS_OCC = (
    "SELECT 1 FROM finding_occurrences WHERE finding_id = :finding_id"
    " AND file_sha256 = :file_sha256 AND source_path = :source_path"
    " AND COALESCE(location, '') = :location LIMIT 1"
)
_LIST_OCC = (
    "SELECT * FROM finding_occurrences WHERE finding_id = :finding_id ORDER BY occurrence_id"
)


def _run_from_row(row: sqlite3.Row) -> ImportRun:
    try:
        return ImportRun(
            run_id=row["run_id"],
            source=row["source"],
            file_sha256=row["file_sha256"],
            source_path=row["source_path"],
            imported_at=row["imported_at"],
            record_count=row["record_count"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="import_run") from None


def _occurrence_from_row(row: sqlite3.Row) -> Occurrence:
    try:
        return Occurrence(
            import_run_id=row["import_run_id"],
            file_sha256=row["file_sha256"],
            source_path=row["source_path"],
            observed_at=row["observed_at"],
            location=row["location"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="occurrence") from None


class ImportRunRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, run: ImportRun, *, actor: str, at: datetime) -> AuditEntry:
        """Insert the run and its ``import.run`` audit entry atomically."""
        if not isinstance(run, ImportRun):
            raise StorageError("invalid_model", object_type="import_run")
        model = run.with_changes()
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_RUN,
                {
                    "run_id": model.run_id,
                    "source": ImportSource(model.source).value,
                    "file_sha256": model.file_sha256,
                    "source_path": model.source_path,
                    "imported_at": to_db_timestamp(model.imported_at),
                    "record_count": model.record_count,
                },
            )
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="import.run",
                object_type="import_run",
                object_id=model.run_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def get(self, run_id: str) -> ImportRun | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET_RUN, {"run_id": run_id}).fetchone()
        return None if row is None else _run_from_row(row)

    def list(self) -> list[ImportRun]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST_RUNS).fetchall()
        return [_run_from_row(row) for row in rows]


class OccurrenceRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, finding_id: str, occurrence: Occurrence) -> None:
        """Insert one occurrence. Needs an active write transaction."""
        require_write_transaction(self._connection)
        if not isinstance(occurrence, Occurrence):
            raise StorageError("invalid_model", object_type="occurrence")
        model = occurrence.with_changes()
        with transaction(self._connection, write=True) as conn:
            conn.execute(
                _INSERT_OCC,
                {
                    "finding_id": finding_id,
                    "import_run_id": model.import_run_id,
                    "file_sha256": model.file_sha256,
                    "source_path": model.source_path,
                    "location": model.location,
                    "observed_at": to_db_timestamp(model.observed_at),
                },
            )

    def exists(
        self, finding_id: str, *, file_sha256: str, source_path: str, location: str | None
    ) -> bool:
        """True if this finding was already recorded from this file (any run)."""
        params = {
            "finding_id": finding_id,
            "file_sha256": file_sha256,
            "source_path": source_path,
            "location": location or "",
        }
        with transaction(self._connection, write=False) as conn:
            return conn.execute(_EXISTS_OCC, params).fetchone() is not None

    def list_for_finding(self, finding_id: str) -> list[Occurrence]:
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST_OCC, {"finding_id": finding_id}).fetchall()
        return [_occurrence_from_row(row) for row in rows]
