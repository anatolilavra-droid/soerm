"""Workspace access for the service layer.

A mutating call runs the whole sequence under one exclusive workspace lock:
lock -> open SQLite -> migrate -> write transaction -> (object change + audit entry) ->
commit -> close -> unlock. The lock is the M2 :class:`~soerm.storage.lock.WorkspaceLock`;
this module adds no second locking scheme. Read calls do not take the lock (WAL readers do
not block the writer) and never create the database.

The workspace directory itself must already exist: it is created by a future workspace
service, not here. The database is ``<workspace>/soerm.db``.
"""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from soerm import __version__
from soerm.domain.errors import DomainError
from soerm.services.errors import (
    IntegrityServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.storage.connection import SoermConnection, open_database
from soerm.storage.lock import WorkspaceLock
from soerm.storage.migrations import MIGRATIONS, applied_versions, apply_migrations
from soerm.storage.transactions import transaction

__all__ = ["DATABASE_FILE_NAME", "Clock", "Session", "Workspace"]

DATABASE_FILE_NAME: Final = "soerm.db"
_MAX_PATH_LENGTH = 4096

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Session:
    """An open connection (inside a transaction) and the single timestamp of the operation."""

    connection: SoermConnection
    now: datetime


class Workspace:
    """A workspace directory. ``clock`` is injectable for tests."""

    def __init__(
        self, path: str | Path, *, clock: Clock | None = None, app_version: str = __version__
    ) -> None:
        text = str(path)
        if not text or len(text) > _MAX_PATH_LENGTH or any(not c.isprintable() for c in text):
            raise InvalidInputError("workspace: invalid_path")
        self._path = Path(text).absolute()
        self._clock = clock or _utc_now
        self._app_version = app_version

    @property
    def path(self) -> Path:
        return self._path

    @property
    def database_path(self) -> Path:
        return self._path / DATABASE_FILE_NAME

    @contextmanager
    def write(self) -> Iterator[Session]:
        """Lock, open, migrate and begin a write transaction; commit on success only."""
        try:
            with WorkspaceLock(self._path, app_version=self._app_version):
                connection = open_database(self.database_path)
                try:
                    now = self._clock()
                    apply_migrations(connection, now=now)
                    with transaction(connection, write=True):
                        yield Session(connection, now)
                finally:
                    connection.close()
        except DomainError as exc:
            raise to_service_error(exc) from None

    @contextmanager
    def read(self) -> Iterator[Session]:
        """Open the existing database read-only (no lock, nothing is created)."""
        try:
            connection = open_database(self.database_path, create=False)
            try:
                versions = applied_versions(connection)
                if not versions:
                    raise NotFoundServiceError("workspace_not_initialized", object_type="workspace")
                if versions != tuple(m.version for m in MIGRATIONS):
                    raise IntegrityServiceError("schema_not_current")
                with transaction(connection, write=False):
                    yield Session(connection, self._clock())
            finally:
                connection.close()
        except DomainError as exc:
            raise to_service_error(exc) from None
