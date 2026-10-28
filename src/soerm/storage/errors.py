"""Storage errors. Like domain errors they carry a stable code and never user values.

SQLite messages can name tables and columns, so they are not copied either: only the
symbolic SQLite error name (for example ``SQLITE_CONSTRAINT_UNIQUE``) is kept.
"""

import sqlite3
from typing import ClassVar, Final

from soerm.domain.errors import DomainError

__all__ = [
    "ConflictError",
    "ConstraintViolationError",
    "DatabaseBusyError",
    "MigrationError",
    "NotFoundError",
    "StorageError",
    "UnsupportedPlatformError",
    "WorkspaceLockError",
    "translate_sqlite_error",
]


class StorageError(DomainError):
    """Base class of storage errors."""

    code: ClassVar[str] = "storage_error"

    def __init__(self, reason: str, **details: object) -> None:
        super().__init__(f"storage operation failed ({reason})", reason=reason, **details)


class DatabaseBusyError(StorageError):
    """Another writer holds the database and the busy timeout elapsed."""

    code: ClassVar[str] = "database_busy"

    def __init__(self, **details: object) -> None:
        super().__init__("database_busy", **details)


class ConstraintViolationError(StorageError):
    """A uniqueness, foreign-key, check, not-null or trigger constraint was violated."""

    code: ClassVar[str] = "constraint_violation"

    def __init__(self, kind: str, **details: object) -> None:
        super().__init__("constraint_violation", kind=kind, **details)


class NotFoundError(StorageError):
    """The referenced record does not exist."""

    code: ClassVar[str] = "not_found"

    def __init__(self, object_type: str) -> None:
        super().__init__("not_found", object_type=object_type)


class ConflictError(StorageError):
    """The stored object no longer matches the hash the caller based its change on."""

    code: ClassVar[str] = "conflict"

    def __init__(self, object_type: str) -> None:
        super().__init__("conflict", object_type=object_type)


class MigrationError(StorageError):
    """Migrations cannot be applied or the stored migration history is not trusted."""

    code: ClassVar[str] = "migration_error"

    def __init__(self, reason: str, **details: object) -> None:
        super().__init__(reason, **details)


class WorkspaceLockError(StorageError):
    """The workspace lock cannot be taken."""

    code: ClassVar[str] = "workspace_lock_error"


class UnsupportedPlatformError(StorageError):
    """The operation needs a POSIX system."""

    code: ClassVar[str] = "unsupported_platform"


_CONSTRAINT_KINDS: Final = {
    "SQLITE_CONSTRAINT_UNIQUE": "unique",
    "SQLITE_CONSTRAINT_PRIMARYKEY": "unique",
    "SQLITE_CONSTRAINT_FOREIGNKEY": "foreign_key",
    "SQLITE_CONSTRAINT_CHECK": "check",
    "SQLITE_CONSTRAINT_NOTNULL": "not_null",
    "SQLITE_CONSTRAINT_TRIGGER": "trigger",
}


def translate_sqlite_error(exc: sqlite3.Error) -> StorageError:
    """Map a ``sqlite3`` error to a storage error without copying its message."""
    name = getattr(exc, "sqlite_errorname", None) or type(exc).__name__
    if name.startswith(("SQLITE_BUSY", "SQLITE_LOCKED")):
        return DatabaseBusyError(sqlite=name)
    if name.startswith("SQLITE_CONSTRAINT"):
        return ConstraintViolationError(_CONSTRAINT_KINDS.get(name, "other"), sqlite=name)
    if name == "SQLITE_NOTADB":
        return StorageError("not_a_database", sqlite=name)
    return StorageError("database_error", sqlite=name)
