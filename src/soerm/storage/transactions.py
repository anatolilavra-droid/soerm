"""Explicit transactions.

* A write transaction is ``BEGIN IMMEDIATE``: the write lock is taken up front, so writers
  are serialized and read-modify-write sequences (counters, the audit chain) cannot race.
  If another writer is active the call fails with :class:`DatabaseBusyError` after the busy
  timeout.
* A read transaction is a plain ``BEGIN`` with ``query_only`` switched on, so a mistaken
  write fails instead of silently taking the write lock.
* Commit happens only on a clean exit; any exception rolls back.
* Nesting uses ``SAVEPOINT``: an inner failure undoes only the inner work, and an inner block
  never commits the outer transaction. A write inside a read transaction is refused.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

from soerm.storage.connection import SoermConnection
from soerm.storage.errors import StorageError, translate_sqlite_error

__all__ = ["require_write_transaction", "transaction"]

# Literal statements: savepoint names are never built at run time.
_SAVEPOINT: Final = (
    "SAVEPOINT soerm_sp_1", "SAVEPOINT soerm_sp_2",
    "SAVEPOINT soerm_sp_3", "SAVEPOINT soerm_sp_4",
    "SAVEPOINT soerm_sp_5", "SAVEPOINT soerm_sp_6",
    "SAVEPOINT soerm_sp_7", "SAVEPOINT soerm_sp_8",
)  # fmt: skip
_RELEASE: Final = (
    "RELEASE SAVEPOINT soerm_sp_1", "RELEASE SAVEPOINT soerm_sp_2",
    "RELEASE SAVEPOINT soerm_sp_3", "RELEASE SAVEPOINT soerm_sp_4",
    "RELEASE SAVEPOINT soerm_sp_5", "RELEASE SAVEPOINT soerm_sp_6",
    "RELEASE SAVEPOINT soerm_sp_7", "RELEASE SAVEPOINT soerm_sp_8",
)  # fmt: skip
_ROLLBACK_TO: Final = (
    "ROLLBACK TO SAVEPOINT soerm_sp_1", "ROLLBACK TO SAVEPOINT soerm_sp_2",
    "ROLLBACK TO SAVEPOINT soerm_sp_3", "ROLLBACK TO SAVEPOINT soerm_sp_4",
    "ROLLBACK TO SAVEPOINT soerm_sp_5", "ROLLBACK TO SAVEPOINT soerm_sp_6",
    "ROLLBACK TO SAVEPOINT soerm_sp_7", "ROLLBACK TO SAVEPOINT soerm_sp_8",
)  # fmt: skip


def _require_connection(connection: object) -> SoermConnection:
    if not isinstance(connection, SoermConnection):
        raise StorageError("unsupported_connection")
    return connection


def require_write_transaction(connection: SoermConnection) -> None:
    """Refuse to continue unless a write transaction is active on ``connection``."""
    if connection.tx_depth == 0 or not connection.tx_write:
        raise StorageError("write_transaction_required")


def _rollback(connection: SoermConnection) -> None:
    """Roll back the outer transaction. If that fails the connection is unusable, which is
    reported explicitly; the original exception is replaced because it can no longer be
    trusted to describe the state."""
    if connection.in_transaction:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            raise StorageError("rollback_failed") from None


@contextmanager
def _outer(connection: SoermConnection, *, write: bool) -> Iterator[SoermConnection]:
    if connection.in_transaction:
        raise StorageError("foreign_transaction_active")
    try:
        if not write:
            connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
    except sqlite3.Error as exc:
        _reset_query_only(connection, write=write)
        raise translate_sqlite_error(exc) from None
    connection.tx_depth = 1
    connection.tx_write = write
    try:
        try:
            yield connection
        except BaseException as exc:
            _rollback(connection)
            if isinstance(exc, sqlite3.Error):
                raise translate_sqlite_error(exc) from None
            raise
        try:
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            _rollback(connection)
            raise translate_sqlite_error(exc) from None
    finally:
        connection.tx_depth = 0
        connection.tx_write = False
        _reset_query_only(connection, write=write)


def _reset_query_only(connection: SoermConnection, *, write: bool) -> None:
    if not write:
        try:
            connection.execute("PRAGMA query_only = OFF")
        except sqlite3.Error:
            raise StorageError("query_only_reset_failed") from None


@contextmanager
def _nested(connection: SoermConnection, *, write: bool) -> Iterator[SoermConnection]:
    if write and not connection.tx_write:
        raise StorageError("write_in_read_transaction")
    index = connection.tx_depth - 1
    if index >= len(_SAVEPOINT):
        raise StorageError("nesting_too_deep")
    try:
        connection.execute(_SAVEPOINT[index])
    except sqlite3.Error as exc:
        raise translate_sqlite_error(exc) from None
    connection.tx_depth += 1
    try:
        try:
            yield connection
        except BaseException as exc:
            try:
                connection.execute(_ROLLBACK_TO[index])
                connection.execute(_RELEASE[index])
            except sqlite3.Error:
                raise StorageError("rollback_failed") from None
            if isinstance(exc, sqlite3.Error):
                raise translate_sqlite_error(exc) from None
            raise
        try:
            connection.execute(_RELEASE[index])
        except sqlite3.Error as exc:
            raise translate_sqlite_error(exc) from None
    finally:
        connection.tx_depth -= 1


@contextmanager
def transaction(connection: sqlite3.Connection, *, write: bool) -> Iterator[SoermConnection]:
    """Run a block in a transaction (``write=True``: ``BEGIN IMMEDIATE``)."""
    conn = _require_connection(connection)
    manager = _outer(conn, write=write) if conn.tx_depth == 0 else _nested(conn, write=write)
    with manager as active:
        yield active
