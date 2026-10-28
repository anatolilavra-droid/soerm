"""Fixtures: every database lives in pytest's temporary directory, never in the repository."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soerm.storage.connection import SoermConnection, open_database
from soerm.storage.migrations import apply_migrations

PROJECT_ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _tmp_is_outside_repository(tmp_path: Path) -> None:
    assert PROJECT_ROOT not in tmp_path.resolve().parents, "tests must not write into the repo"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "soerm.db"


@pytest.fixture
def conn(db_path: Path) -> Iterator[SoermConnection]:
    connection = open_database(db_path)
    try:
        apply_migrations(connection, now=NOW)
        yield connection
    finally:
        connection.close()


@pytest.fixture
def second(db_path: Path, conn: SoermConnection) -> Iterator[SoermConnection]:
    """A second connection to the same migrated database with a short busy timeout."""
    other = open_database(db_path, busy_timeout_ms=50)
    try:
        yield other
    finally:
        other.close()


@pytest.fixture
def raw(db_path: Path, conn: SoermConnection) -> Iterator[sqlite3.Connection]:
    """A plain connection used by tests to tamper with the file like an attacker would."""
    with closing(sqlite3.connect(str(db_path), isolation_level=None)) as plain:
        yield plain
