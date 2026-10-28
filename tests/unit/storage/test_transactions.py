"""Transactions, savepoints, write serialization and counters."""
# ruff: noqa: PT012  (the transaction context managers are the point of these blocks)

import sqlite3
from pathlib import Path

import pytest

from soerm.domain.errors import InvalidIdentifierError
from soerm.storage.connection import SoermConnection
from soerm.storage.counters import CounterRepository
from soerm.storage.errors import ConstraintViolationError, DatabaseBusyError, StorageError
from soerm.storage.transactions import require_write_transaction, transaction

ASSET = (
    "INSERT INTO assets (asset_id, name, owner, environment, business_criticality,"
    " data_classification, exposure, tags, created_at, updated_at)"
    " VALUES (?, 'n', 'o', 'production', 'low', 'public', 'internal', '[]',"
    " '2026-03-01T12:00:00.000000Z', '2026-03-01T12:00:00.000000Z')"
)


class BoomError(Exception):
    pass


class Interrupt(BaseException):
    pass


def asset_ids(connection: sqlite3.Connection) -> list[str]:
    return [r[0] for r in connection.execute("SELECT asset_id FROM assets ORDER BY asset_id")]


def test_commit_on_success(conn: SoermConnection, second: SoermConnection) -> None:
    with transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
    assert not conn.in_transaction
    assert asset_ids(second) == ["AST-000001"]


def test_rollback_on_exception(conn: SoermConnection) -> None:
    with pytest.raises(BoomError), transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
        raise BoomError
    assert not conn.in_transaction
    assert conn.tx_depth == 0
    assert asset_ids(conn) == []


def test_rollback_on_base_exception(conn: SoermConnection) -> None:
    with pytest.raises(Interrupt), transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
        raise Interrupt
    assert asset_ids(conn) == []
    assert conn.tx_depth == 0


def test_database_errors_become_storage_errors_without_details(conn: SoermConnection) -> None:
    with transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
    with pytest.raises(ConstraintViolationError) as excinfo, transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
    error = excinfo.value
    assert error.details["kind"] == "unique"
    assert "AST-000001" not in str(error) + repr(error.to_dict())
    assert error.__cause__ is None
    assert asset_ids(conn) == ["AST-000001"]


def test_read_transaction_is_read_only(conn: SoermConnection) -> None:
    with pytest.raises(StorageError), transaction(conn, write=False):
        conn.execute(ASSET, ("AST-000001",))
    assert asset_ids(conn) == []
    with transaction(conn, write=True):  # query_only was switched off again
        conn.execute(ASSET, ("AST-000001",))
    assert asset_ids(conn) == ["AST-000001"]


def test_read_transaction_does_not_block_a_writer(
    conn: SoermConnection, second: SoermConnection
) -> None:
    with transaction(conn, write=False), transaction(second, write=True):
        second.execute(ASSET, ("AST-000001",))
    assert asset_ids(conn) == ["AST-000001"]


def test_nested_transaction_uses_savepoints(conn: SoermConnection) -> None:
    with transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
        with pytest.raises(BoomError), transaction(conn, write=True):
            conn.execute(ASSET, ("AST-000002",))
            raise BoomError
        assert conn.tx_depth == 1
        with transaction(conn, write=True):
            conn.execute(ASSET, ("AST-000003",))
    assert asset_ids(conn) == ["AST-000001", "AST-000003"]


def test_inner_block_does_not_commit_the_outer_transaction(
    conn: SoermConnection, second: SoermConnection
) -> None:
    with pytest.raises(BoomError), transaction(conn, write=True):
        with transaction(conn, write=True):
            conn.execute(ASSET, ("AST-000001",))
        assert asset_ids(second) == []  # not visible: nothing committed yet
        assert conn.in_transaction
        raise BoomError
    assert asset_ids(conn) == []


def test_inner_database_error_rolls_back_only_the_inner_part(conn: SoermConnection) -> None:
    with transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
        with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
            conn.execute(ASSET, ("AST-000002",))
            conn.execute(ASSET, ("AST-000001",))  # duplicate
        assert asset_ids(conn) == ["AST-000001"]
    assert asset_ids(conn) == ["AST-000001"]


def test_write_inside_read_transaction_is_refused(conn: SoermConnection) -> None:
    with transaction(conn, write=False):
        with pytest.raises(StorageError) as excinfo, transaction(conn, write=True):
            pass
        assert excinfo.value.details["reason"] == "write_in_read_transaction"
        with transaction(conn, write=False):  # nested read is fine
            assert conn.tx_depth == 2
    assert conn.tx_depth == 0


def test_nesting_depth_is_bounded(conn: SoermConnection) -> None:
    def descend(level: int) -> None:
        with transaction(conn, write=True):
            descend(level + 1)

    with pytest.raises(StorageError) as excinfo:
        descend(1)
    assert excinfo.value.details["reason"] == "nesting_too_deep"
    assert conn.tx_depth == 0
    assert not conn.in_transaction


def test_foreign_transaction_is_not_adopted(conn: SoermConnection) -> None:
    conn.execute("BEGIN")
    with pytest.raises(StorageError) as excinfo, transaction(conn, write=True):
        pass
    assert excinfo.value.details["reason"] == "foreign_transaction_active"
    conn.execute("ROLLBACK")


def test_plain_sqlite_connection_is_refused(tmp_path: Path) -> None:
    plain = sqlite3.connect(str(tmp_path / "plain.db"), isolation_level=None)
    try:
        with pytest.raises(StorageError), transaction(plain, write=True):
            pass
    finally:
        plain.close()


def test_second_writer_gets_a_controlled_busy_error(
    conn: SoermConnection, second: SoermConnection
) -> None:
    with transaction(conn, write=True):
        conn.execute(ASSET, ("AST-000001",))
        with pytest.raises(DatabaseBusyError) as excinfo, transaction(second, write=True):
            pass
        assert excinfo.value.code == "database_busy"
        assert second.tx_depth == 0
        assert not second.in_transaction
    with transaction(second, write=True):  # the loser is still usable afterwards
        second.execute(ASSET, ("AST-000002",))
    assert asset_ids(conn) == ["AST-000001", "AST-000002"]


def test_readers_see_a_consistent_snapshot_while_a_writer_works(
    conn: SoermConnection, second: SoermConnection
) -> None:
    with transaction(second, write=False):
        assert asset_ids(second) == []  # the snapshot starts at the first read
        with transaction(conn, write=True):
            conn.execute(ASSET, ("AST-000001",))
        assert asset_ids(second) == []  # still the old snapshot
    assert asset_ids(second) == ["AST-000001"]


# ---- counters -----------------------------------------------------------------------------


def test_counter_issues_sequential_identifiers(conn: SoermConnection) -> None:
    counters = CounterRepository(conn)
    with transaction(conn, write=True):
        ids = [counters.next_identifier("AST") for _ in range(3)]
        other = counters.next_identifier("FND")
    assert ids == ["AST-000001", "AST-000002", "AST-000003"]
    assert other == "FND-000001"
    assert counters.current("AST") == 3


@pytest.mark.parametrize("prefix", ["AST", "FND", "INC", "TSK", "PBK", "CHG", "RUN"])
def test_every_documented_prefix_works(conn: SoermConnection, prefix: str) -> None:
    with transaction(conn, write=True):
        assert CounterRepository(conn).next_identifier(prefix) == f"{prefix}-000001"


def test_counter_rollback_does_not_consume_a_number(conn: SoermConnection) -> None:
    counters = CounterRepository(conn)
    with pytest.raises(BoomError), transaction(conn, write=True):
        assert counters.next_identifier("AST") == "AST-000001"
        raise BoomError
    assert counters.current("AST") == 0
    with transaction(conn, write=True):
        assert counters.next_identifier("AST") == "AST-000001"


def test_counter_inner_savepoint_rollback_returns_the_number(conn: SoermConnection) -> None:
    counters = CounterRepository(conn)
    with transaction(conn, write=True):
        with pytest.raises(BoomError), transaction(conn, write=True):
            counters.next_identifier("AST")
            raise BoomError
        assert counters.next_identifier("AST") == "AST-000001"


def test_counter_needs_a_write_transaction(conn: SoermConnection) -> None:
    counters = CounterRepository(conn)
    with pytest.raises(StorageError) as excinfo:
        counters.next_identifier("AST")
    assert excinfo.value.details["reason"] == "write_transaction_required"
    with pytest.raises(StorageError), transaction(conn, write=False):
        counters.next_identifier("AST")


@pytest.mark.parametrize("prefix", ["XXX", "ast", "", "AST'; DROP TABLE counters;--", None, 5])
def test_counter_rejects_unknown_prefixes(conn: SoermConnection, prefix: object) -> None:
    with pytest.raises(InvalidIdentifierError), transaction(conn, write=True):
        CounterRepository(conn).next_identifier(prefix)  # type: ignore[arg-type]
    assert conn.execute("SELECT count(*) FROM counters").fetchone()[0] == 7


def test_two_connections_never_get_the_same_number(
    conn: SoermConnection, second: SoermConnection
) -> None:
    a, b = CounterRepository(conn), CounterRepository(second)
    seen = []
    for _ in range(5):
        with transaction(conn, write=True):
            seen.append(a.next_identifier("INC"))
        with transaction(second, write=True):
            seen.append(b.next_identifier("INC"))
    assert seen == [f"INC-{n:06d}" for n in range(1, 11)]


def test_counter_exhaustion_is_reported(conn: SoermConnection) -> None:
    with transaction(conn, write=True):
        conn.execute("UPDATE counters SET value = 999999999998 WHERE prefix = 'AST'")
        counters = CounterRepository(conn)
        assert counters.next_identifier("AST") == "AST-999999999999"
        with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
            counters.next_identifier("AST")


def test_require_write_transaction_helper(conn: SoermConnection) -> None:
    with pytest.raises(StorageError):
        require_write_transaction(conn)
    with transaction(conn, write=True):
        require_write_transaction(conn)
