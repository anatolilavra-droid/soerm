"""Audit hash chain, append-only triggers and atomicity with object changes."""
# ruff: noqa: PT012  (the transaction context managers are the point of these blocks)

import sqlite3
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from soerm.domain import GENESIS_HASH, IntegrityDomainError, ValidationDomainError
from soerm.domain.asset import Asset
from soerm.storage.assets import AssetRepository
from soerm.storage.audit import (
    AuditRepository,
    append_audit,
    get_audit_entry,
    get_audit_head,
    list_audit_entries,
    verify_audit_chain,
)
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConstraintViolationError, StorageError
from soerm.storage.transactions import transaction
from tests.unit.domain.factories import SECRET, SHA_A, SHA_B, asset_data
from tests.unit.storage.conftest import NOW


def add_events(conn: SoermConnection, count: int) -> None:
    for number in range(count):
        with transaction(conn, write=True):
            append_audit(
                conn,
                timestamp=NOW + timedelta(seconds=number),
                actor="alice",
                action="asset.create",
                object_type="asset",
                object_id=f"AST-{number + 1:06d}",
                before_hash=None,
                after_hash=SHA_A,
            )


def test_empty_log_has_a_genesis_head(conn: SoermConnection) -> None:
    head = get_audit_head(conn)
    assert (head.seq, head.entry_hash) == (0, GENESIS_HASH)
    assert verify_audit_chain(conn) == head


def test_first_entry_uses_the_genesis_hash(conn: SoermConnection) -> None:
    with transaction(conn, write=True):
        entry = append_audit(
            conn, timestamp=NOW, actor="Alice", action="asset.create", object_type="asset",
            object_id="AST-000001", before_hash=None, after_hash=SHA_A,
        )  # fmt: skip
    assert (entry.seq, entry.prev_hash, entry.actor) == (1, GENESIS_HASH, "alice")
    head = get_audit_head(conn)
    assert (head.seq, head.entry_hash) == (1, entry.entry_hash)
    assert get_audit_entry(conn, 1) == entry
    assert get_audit_entry(conn, 2) is None


def test_chain_of_several_events_verifies(conn: SoermConnection) -> None:
    add_events(conn, 5)
    entries = list_audit_entries(conn)
    assert [e.seq for e in entries] == [1, 2, 3, 4, 5]
    assert entries[0].prev_hash == GENESIS_HASH
    for previous, current in pairwise(entries):
        assert current.prev_hash == previous.entry_hash
    head = verify_audit_chain(conn)
    assert (head.seq, head.entry_hash) == (5, entries[-1].entry_hash)
    assert len({e.entry_hash for e in entries}) == 5


def test_listing_is_paged_and_bounded(conn: SoermConnection) -> None:
    add_events(conn, 5)
    assert [e.seq for e in list_audit_entries(conn, after_seq=2, limit=2)] == [3, 4]
    assert AuditRepository(conn).list(after_seq=5) == []
    for bad in ({"limit": 0}, {"limit": 1001}, {"after_seq": -1}):
        with pytest.raises(StorageError):
            list_audit_entries(conn, **bad)


def test_repository_wrapper(conn: SoermConnection) -> None:
    repo = AuditRepository(conn)
    with transaction(conn, write=True):
        entry = repo.append(
            timestamp=NOW, actor="bob", action="asset.update", object_type="asset",
            object_id="AST-000001",
        )  # fmt: skip
    assert repo.get(1) == entry
    assert repo.head().seq == 1
    assert repo.verify().entry_hash == entry.entry_hash


def test_append_needs_a_write_transaction(conn: SoermConnection) -> None:
    kwargs = {"timestamp": NOW, "actor": "a", "action": "asset.create", "object_type": "asset",
              "object_id": "AST-000001"}  # fmt: skip
    with pytest.raises(StorageError):
        append_audit(conn, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(StorageError), transaction(conn, write=False):
        append_audit(conn, **kwargs)  # type: ignore[arg-type]


def test_invalid_entry_fields_are_rejected_and_roll_back(conn: SoermConnection) -> None:
    for bad in ({"actor": " "}, {"action": "Bad Action"}, {"object_id": ""},
                {"after_hash": "ABC"}, {"timestamp": datetime(2026, 1, 1)}):  # fmt: skip # noqa: DTZ001
        kwargs = {"timestamp": NOW, "actor": "a", "action": "asset.create",
                  "object_type": "asset", "object_id": "AST-000001", **bad}  # fmt: skip
        with pytest.raises(ValidationDomainError), transaction(conn, write=True):
            append_audit(conn, **kwargs)  # type: ignore[arg-type]
    assert get_audit_head(conn).seq == 0


# ---- append-only enforcement --------------------------------------------------------------


def test_update_is_rejected(conn: SoermConnection) -> None:
    add_events(conn, 2)
    with pytest.raises(ConstraintViolationError) as excinfo, transaction(conn, write=True):
        conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE seq = 1")
    assert excinfo.value.details["kind"] == "trigger"
    assert get_audit_entry(conn, 1) is not None
    assert verify_audit_chain(conn).seq == 2


def test_delete_is_rejected(conn: SoermConnection) -> None:
    add_events(conn, 2)
    for statement in ("DELETE FROM audit_log WHERE seq = 2", "DELETE FROM audit_log"):
        with pytest.raises(ConstraintViolationError) as excinfo, transaction(conn, write=True):
            conn.execute(statement)
        assert excinfo.value.details["kind"] == "trigger"
    assert verify_audit_chain(conn).seq == 2


def test_replace_cannot_rewrite_history(conn: SoermConnection) -> None:
    add_events(conn, 1)
    with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
        conn.execute(
            "INSERT OR REPLACE INTO audit_log (seq, ts, actor, action, object_type, object_id,"
            " prev_hash, entry_hash) VALUES (1, '2026-03-01T12:00:00.000000Z', 'x', 'a.b', 'asset',"
            " 'X', ?, ?)",
            (GENESIS_HASH, SHA_B),
        )
    assert verify_audit_chain(conn).seq == 1


@pytest.mark.parametrize(
    ("seq", "prev"),
    [(5, GENESIS_HASH), (1, SHA_A), (2, SHA_A), (0, GENESIS_HASH)],
)
def test_database_refuses_entries_that_do_not_extend_the_chain(
    conn: SoermConnection, seq: int, prev: str
) -> None:
    add_events(conn, 1)
    insert = (
        "INSERT INTO audit_log (seq, ts, actor, action, object_type, object_id, prev_hash,"
        " entry_hash) VALUES (?, '2026-03-01T12:00:00.000000Z', 'x', 'a.b', 'asset', 'X', ?, ?)"
    )
    with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
        conn.execute(insert, (seq, prev, "c" * 64))


def test_first_entry_prev_hash_must_be_genesis_in_sql(conn: SoermConnection) -> None:
    with pytest.raises(ConstraintViolationError), transaction(conn, write=True):
        conn.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, object_type, object_id, prev_hash,"
            " entry_hash) VALUES (1, '2026-03-01T12:00:00.000000Z', 'x', 'a.b',"
            " 'asset', 'X', ?, ?)",
            (SHA_A, SHA_B),
        )


def test_duplicate_entry_hash_is_rejected(conn: SoermConnection) -> None:
    add_events(conn, 1)
    first_hash = get_audit_head(conn).entry_hash
    with pytest.raises(ConstraintViolationError) as excinfo, transaction(conn, write=True):
        conn.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, object_type, object_id, prev_hash,"
            " entry_hash) VALUES (2, '2026-03-01T12:00:00.000000Z', 'x', 'a.b',"
            " 'asset', 'X', ?, ?)",
            (first_hash, first_hash),
        )
    assert excinfo.value.details["kind"] == "unique"


# ---- tamper detection (an attacker who bypasses the triggers) -----------------------------


def tamper(raw: sqlite3.Connection, statement: str, params: tuple[object, ...] = ()) -> None:
    raw.execute("DROP TRIGGER audit_log_no_update")
    raw.execute("DROP TRIGGER audit_log_no_delete")
    raw.execute("DROP TRIGGER audit_log_chain")
    raw.execute(statement, params)


@pytest.mark.parametrize(
    ("statement", "params", "reason", "seq"),
    [
        ("UPDATE audit_log SET entry_hash = ? WHERE seq = 2", ("d" * 64,),
         "entry_hash_mismatch", 2),
        ("UPDATE audit_log SET prev_hash = ? WHERE seq = 3", ("d" * 64,), "chain_broken", 3),
        ("UPDATE audit_log SET prev_hash = ? WHERE seq = 1", ("d" * 64,), "genesis_rule", 1),
        ("UPDATE audit_log SET seq = 9 WHERE seq = 3", (), "sequence_gap", 3),
        ("DELETE FROM audit_log WHERE seq = 2", (), "sequence_gap", 2),
        ("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2", (), "entry_hash_mismatch", 2),
        ("UPDATE audit_log SET after_hash = ? WHERE seq = 3", ("e" * 64,),
         "entry_hash_mismatch", 3),
        ("UPDATE audit_log SET ts = '2030-01-01T00:00:00.000000Z' WHERE seq = 1", (),
         "entry_hash_mismatch", 1),
    ],
)  # fmt: skip
def test_verify_detects_tampering(
    conn: SoermConnection,
    raw: sqlite3.Connection,
    statement: str,
    params: tuple[object, ...],
    reason: str,
    seq: int,
) -> None:
    add_events(conn, 3)
    verify_audit_chain(conn)
    tamper(raw, statement, params)
    with pytest.raises(IntegrityDomainError) as excinfo:
        verify_audit_chain(conn)
    assert excinfo.value.details["reason"] == reason
    assert excinfo.value.details["seq"] == str(seq)


def test_truncation_of_the_tail_is_visible_through_the_saved_head(
    conn: SoermConnection, raw: sqlite3.Connection
) -> None:
    add_events(conn, 3)
    saved = get_audit_head(conn)
    tamper(raw, "DELETE FROM audit_log WHERE seq = 3")
    assert verify_audit_chain(conn).seq == 2  # an internally consistent prefix still verifies
    assert verify_audit_chain(conn) != saved  # ...but not against the head stored elsewhere


# ---- atomicity with object changes --------------------------------------------------------


def make_asset(**overrides: object) -> Asset:
    return Asset(**asset_data(**overrides))


def test_object_change_and_audit_entry_commit_together(conn: SoermConnection) -> None:
    entry = AssetRepository(conn).add(make_asset(), actor="alice", at=NOW)
    assert entry.action == "asset.create"
    assert get_audit_head(conn).seq == 1
    assert conn.execute("SELECT count(*) FROM assets").fetchone()[0] == 1


def test_object_change_and_audit_entry_roll_back_together(conn: SoermConnection) -> None:
    repo = AssetRepository(conn)
    with pytest.raises(RuntimeError), transaction(conn, write=True):
        repo.add(make_asset(), actor="alice", at=NOW)
        repo.add(make_asset(asset_id="AST-000002"), actor="alice", at=NOW)
        assert get_audit_head(conn).seq == 2
        raise RuntimeError
    assert conn.execute("SELECT count(*) FROM assets").fetchone()[0] == 0
    assert get_audit_head(conn).seq == 0


def test_failed_audit_append_rolls_back_the_object(conn: SoermConnection) -> None:
    with pytest.raises(ValidationDomainError):
        AssetRepository(conn).add(make_asset(), actor="not a valid actor!", at=NOW)
    assert conn.execute("SELECT count(*) FROM assets").fetchone()[0] == 0
    assert get_audit_head(conn).seq == 0


def test_audit_never_contains_user_text(conn: SoermConnection, db_path: object) -> None:
    repo = AssetRepository(conn)
    repo.add(make_asset(name=SECRET, owner=SECRET, tags=[SECRET]), actor="alice", at=NOW)
    dump = repr(conn.execute("SELECT * FROM audit_log").fetchall())
    assert SECRET not in dump
    assert SECRET.lower() not in dump.lower()
    columns = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)")}
    assert columns == {"seq", "ts", "actor", "action", "object_type", "object_id", "before_hash",
                       "after_hash", "prev_hash", "entry_hash"}  # fmt: skip


def test_stored_timestamp_is_fixed_width_utc(conn: SoermConnection) -> None:
    add_events(conn, 1)
    stored = conn.execute("SELECT ts FROM audit_log").fetchone()[0]
    assert stored == "2026-03-01T12:00:00.000000Z"
    assert get_audit_entry(conn, 1).timestamp == NOW.astimezone(UTC)  # type: ignore[union-attr]
