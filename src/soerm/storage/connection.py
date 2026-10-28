"""SQLite connection and its PRAGMA / configuration policy.

Settings are sorted into three classes and each is handled differently:

* **required** security settings are applied and read back; if one cannot be applied the
  connection is closed and opening fails (fail closed);
* **desirable** settings are applied and read back; if one is unsupported or does not take
  effect it is listed in ``PolicyReport.unsupported`` (documented fallback, never silent);
* anything that raises an unexpected database error is not swallowed in either class.
"""

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from soerm.storage.errors import StorageError, translate_sqlite_error

__all__ = [
    "DEFAULT_BUSY_TIMEOUT_MS",
    "MIN_SQLITE_VERSION",
    "PolicyReport",
    "SoermConnection",
    "open_database",
]

DEFAULT_BUSY_TIMEOUT_MS: Final = 5000
MIN_SQLITE_VERSION: Final = (3, 45, 0)
_FILE_MODE: Final = 0o600
_MAX_BUSY_TIMEOUT_MS: Final = 600_000

# (statement, query, expected value). Literal strings: nothing here is built at run time.
_REQUIRED_PRAGMAS: Final = (
    ("PRAGMA foreign_keys = ON", "PRAGMA foreign_keys", 1),
    ("PRAGMA trusted_schema = OFF", "PRAGMA trusted_schema", 0),
    ("PRAGMA recursive_triggers = ON", "PRAGMA recursive_triggers", 1),
    ("PRAGMA synchronous = FULL", "PRAGMA synchronous", 2),
)
_DESIRABLE_PRAGMAS: Final = (
    ("PRAGMA cell_size_check = ON", "PRAGMA cell_size_check", 1),
    ("PRAGMA secure_delete = ON", "PRAGMA secure_delete", 1),
)
# (sqlite3 constant name, value, required)
_DBCONFIG: Final = (
    ("SQLITE_DBCONFIG_DEFENSIVE", True, True),
    ("SQLITE_DBCONFIG_TRUSTED_SCHEMA", False, True),
    ("SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION", False, True),
    ("SQLITE_DBCONFIG_ENABLE_TRIGGER", True, True),
    ("SQLITE_DBCONFIG_ENABLE_FKEY", True, True),
    ("SQLITE_DBCONFIG_DQS_DDL", False, False),
    ("SQLITE_DBCONFIG_DQS_DML", False, False),
)
_SWITCHABLE_JOURNAL_MODES: Final = frozenset({"delete", "truncate", "persist"})


@dataclass(frozen=True, slots=True)
class PolicyReport:
    """What the connection policy actually did."""

    sqlite_version: str
    journal_mode: str
    applied: tuple[str, ...]
    unsupported: tuple[str, ...]


class SoermConnection(sqlite3.Connection):
    """``sqlite3.Connection`` that also tracks the transaction nesting managed by
    :func:`soerm.storage.transactions.transaction`."""

    tx_depth: int
    tx_write: bool
    policy: PolicyReport

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.tx_depth = 0
        self.tx_write = False


def _scalar(connection: sqlite3.Connection, query: str) -> object:
    row = connection.execute(query).fetchone()
    return None if row is None else row[0]


def _set_dbconfig(
    connection: SoermConnection, name: str, value: bool, *, required: bool
) -> str | None:
    """Apply one ``SQLITE_DBCONFIG_*`` option. Returns ``name`` if it is unsupported."""
    option = getattr(sqlite3, name, None)
    if option is None or not hasattr(connection, "setconfig"):
        if required:
            raise StorageError("unsupported_required_setting", setting=name)
        return name
    connection.setconfig(option, value)
    if connection.getconfig(option) != value:
        if required:
            raise StorageError("required_setting_not_applied", setting=name)
        return name
    return None


def _apply_pragmas(
    connection: SoermConnection,
    pragmas: tuple[tuple[str, str, int], ...],
    *,
    required: bool,
) -> list[str]:
    unsupported: list[str] = []
    for statement, query, expected in pragmas:
        connection.execute(statement)
        if _scalar(connection, query) != expected:
            if required:
                raise StorageError("required_setting_not_applied", setting=query)
            unsupported.append(query)
    return unsupported


def _journal_mode(connection: SoermConnection) -> tuple[str, list[str]]:
    """Use WAL only when it is compatible with the current mode.

    An existing WAL database stays WAL; a rollback-journal database (``delete``,
    ``truncate``, ``persist``) is switched; ``memory`` and ``off`` are left alone. If the
    switch does not take effect the fallback is recorded.
    """
    mode = str(_scalar(connection, "PRAGMA journal_mode")).lower()
    if mode in _SWITCHABLE_JOURNAL_MODES:
        mode = str(_scalar(connection, "PRAGMA journal_mode = WAL")).lower()
        if mode != "wal":
            return mode, ["journal_mode_wal"]
    return mode, []


def _apply_policy(connection: SoermConnection, busy_timeout_ms: int) -> PolicyReport:
    applied: list[str] = []
    unsupported: list[str] = []
    for name, value, required in _DBCONFIG:
        missing = _set_dbconfig(connection, name, value, required=required)
        if missing is not None:
            unsupported.append(missing)
        else:
            applied.append(name)
    # Extension loading must be off. A Python without the API cannot load extensions at all.
    if hasattr(connection, "enable_load_extension"):
        connection.enable_load_extension(False)
    # PRAGMA cannot take bound parameters and SQL is never built at run time, so the policy
    # value is a literal; other values (tests only) were already set by ``sqlite3.connect``.
    if busy_timeout_ms == DEFAULT_BUSY_TIMEOUT_MS:
        connection.execute("PRAGMA busy_timeout = 5000")
    if _scalar(connection, "PRAGMA busy_timeout") != busy_timeout_ms:
        raise StorageError("required_setting_not_applied", setting="busy_timeout")
    _apply_pragmas(connection, _REQUIRED_PRAGMAS, required=True)
    unsupported += _apply_pragmas(connection, _DESIRABLE_PRAGMAS, required=False)
    mode, journal_unsupported = _journal_mode(connection)
    unsupported += journal_unsupported
    return PolicyReport(
        sqlite_version=sqlite3.sqlite_version,
        journal_mode=mode,
        applied=(*applied, "pragmas"),
        unsupported=tuple(unsupported),
    )


def _prepare_file(path: Path, *, create: bool) -> None:
    """Check the database path; create an empty private file when allowed.

    The path must be absolute, its parent must be an existing directory and the file itself
    must not be a symlink. A new file is created with mode 0600 and without following links.
    """
    candidate: object = path  # callers may pass anything at run time
    if (
        not isinstance(candidate, Path)
        or not candidate.is_absolute()
        or candidate.name in {"", ".", ".."}
    ):
        raise StorageError("invalid_database_path")
    if not path.parent.is_dir():
        raise StorageError("database_directory_missing")
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise StorageError("database_missing") from None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            os.close(os.open(path, flags, _FILE_MODE))
        except OSError:
            raise StorageError("database_create_failed") from None
        return
    if not stat.S_ISREG(info.st_mode):
        raise StorageError("database_not_a_regular_file")


def open_database(
    path: Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    create: bool = True,
) -> SoermConnection:
    """Open a database file with the full security policy applied.

    ``isolation_level=None`` keeps the ``sqlite3`` module out of transaction control: all
    transactions are explicit (see :func:`soerm.storage.transactions.transaction`).
    """
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise StorageError("sqlite_too_old", sqlite=sqlite3.sqlite_version)
    if not 0 <= busy_timeout_ms <= _MAX_BUSY_TIMEOUT_MS:
        raise StorageError("invalid_busy_timeout")
    _prepare_file(path, create=create)
    try:
        connection = sqlite3.connect(
            str(path),
            timeout=busy_timeout_ms / 1000,
            isolation_level=None,
            factory=SoermConnection,
        )
    except sqlite3.Error as exc:
        raise translate_sqlite_error(exc) from None
    try:
        connection.row_factory = sqlite3.Row
        connection.policy = _apply_policy(connection, busy_timeout_ms)
    except sqlite3.Error as exc:
        connection.close()
        raise translate_sqlite_error(exc) from None
    except BaseException:
        connection.close()
        raise
    return connection
