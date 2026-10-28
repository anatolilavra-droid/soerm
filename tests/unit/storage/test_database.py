"""Connection policy, migrations and schema constraints."""

import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest

from soerm.storage import connection as connection_module
from soerm.storage.connection import DEFAULT_BUSY_TIMEOUT_MS, SoermConnection, open_database
from soerm.storage.errors import (
    ConstraintViolationError,
    MigrationError,
    StorageError,
)
from soerm.storage.migrations import (
    MIGRATIONS,
    Migration,
    applied_versions,
    apply_migrations,
)
from soerm.storage.transactions import transaction

from .conftest import NOW

V1_CHECKSUM = "d7c8ce7fa4af8f2b27925f95c0f10e5f87b6257d59c063096d48ec67346bea61"
V2_CHECKSUM = "76b5ee60b77c7dee73bc4105eb3f0a15917fce46510eebe1752d73860878ce62"
# Every released migration, pinned. A new migration is added here when it is released.
RELEASED_CHECKSUMS = {
    (1, "initial_schema"): V1_CHECKSUM,
    (2, "playbook_runs"): V2_CHECKSUM,
}
SHA = "a" * 64
TS = "2026-03-01T12:00:00.000000Z"
TS2 = "2026-03-01T13:00:00.000000Z"
GENESIS = "0" * 64


def scalar(connection: sqlite3.Connection, query: str) -> Any:
    return connection.execute(query).fetchone()[0]


# ---- PRAGMA policy ------------------------------------------------------------------------


def test_pragma_policy(conn: SoermConnection) -> None:
    assert conn.isolation_level is None
    assert scalar(conn, "PRAGMA foreign_keys") == 1
    assert scalar(conn, "PRAGMA synchronous") == 2  # FULL
    assert scalar(conn, "PRAGMA trusted_schema") == 0
    assert scalar(conn, "PRAGMA recursive_triggers") == 1
    assert scalar(conn, "PRAGMA busy_timeout") == DEFAULT_BUSY_TIMEOUT_MS == 5000
    assert scalar(conn, "PRAGMA journal_mode") == "wal"
    assert scalar(conn, "PRAGMA secure_delete") == 1
    assert scalar(conn, "PRAGMA cell_size_check") == 1


def test_dbconfig_policy(conn: SoermConnection) -> None:
    assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE) is True
    assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA) is False
    assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION) is False
    assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_TRIGGER) is True
    assert conn.getconfig(sqlite3.SQLITE_DBCONFIG_DQS_DML) is False
    assert conn.policy.unsupported == ()
    assert conn.policy.sqlite_version == sqlite3.sqlite_version
    assert conn.policy.journal_mode == "wal"


def test_sqlite_is_at_least_3_45() -> None:
    assert sqlite3.sqlite_version_info >= (3, 45, 0)


def test_extension_loading_is_disabled(conn: SoermConnection) -> None:
    with pytest.raises((sqlite3.OperationalError, sqlite3.NotSupportedError)):
        conn.load_extension("does-not-matter")


def test_defensive_mode_blocks_schema_tampering(conn: SoermConnection) -> None:
    conn.execute("PRAGMA writable_schema = ON")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE sqlite_master SET name = 'x' WHERE name = 'assets'")


def test_double_quoted_strings_are_not_literals(conn: SoermConnection) -> None:
    with pytest.raises(sqlite3.OperationalError):
        conn.execute('SELECT "no_such_column_or_string"')


def test_foreign_keys_are_enforced(conn: SoermConnection) -> None:
    with pytest.raises(ConstraintViolationError) as excinfo, transaction(conn, write=True):
        conn.execute(
            "INSERT INTO tasks (task_id, finding_id, title, owner, status, created_at, updated_at)"
            " VALUES ('TSK-000001', 'FND-000001', 't', 'o', 'open', ?, ?)",
            (TS, TS),
        )
    assert excinfo.value.details["kind"] == "foreign_key"


def test_journal_mode_switch_only_from_rollback_modes(db_path: Path) -> None:
    plain = sqlite3.connect(str(db_path), isolation_level=None)
    plain.execute("CREATE TABLE t (x)")
    assert scalar(plain, "PRAGMA journal_mode") == "delete"
    plain.close()
    first = open_database(db_path)
    assert first.policy.journal_mode == "wal"
    first.close()
    again = open_database(db_path)  # already WAL: left as it is
    assert again.policy.journal_mode == "wal"
    again.close()


def test_new_database_file_is_private(db_path: Path) -> None:
    open_database(db_path).close()
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("busy", [-1, 600_001])
def test_invalid_busy_timeout(db_path: Path, busy: int) -> None:
    with pytest.raises(StorageError):
        open_database(db_path, busy_timeout_ms=busy)


def test_path_rules(tmp_path: Path) -> None:
    with pytest.raises(StorageError):
        open_database(Path("relative.db"))
    with pytest.raises(StorageError):
        open_database(tmp_path / "missing-dir" / "x.db")
    with pytest.raises(StorageError):
        open_database(tmp_path / "absent.db", create=False)
    with pytest.raises(StorageError):
        open_database(tmp_path)  # a directory
    real = tmp_path / "real.db"
    real.touch()
    link = tmp_path / "link.db"
    link.symlink_to(real)
    with pytest.raises(StorageError):
        open_database(link)
    with pytest.raises(StorageError):
        open_database(str(real))  # type: ignore[arg-type]


def test_not_a_database_file_is_reported(tmp_path: Path) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is definitely not a sqlite database" * 20)
    with pytest.raises(StorageError):
        open_database(junk)


def test_required_setting_that_is_unsupported_fails_closed(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(connection_module, "_DBCONFIG", (("SQLITE_DBCONFIG_NO_SUCH", True, True),))
    with pytest.raises(StorageError) as excinfo:
        open_database(db_path)
    assert excinfo.value.details["reason"] == "unsupported_required_setting"


def test_optional_setting_that_is_unsupported_is_documented(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(connection_module, "_DBCONFIG", (("SQLITE_DBCONFIG_NO_SUCH", True, False),))
    connection = open_database(db_path)
    try:
        assert connection.policy.unsupported == ("SQLITE_DBCONFIG_NO_SUCH",)
    finally:
        connection.close()


def test_required_pragma_that_does_not_take_effect_fails_closed(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        connection_module,
        "_REQUIRED_PRAGMAS",
        (("PRAGMA foreign_keys = ON", "PRAGMA foreign_keys", 0),),
    )
    with pytest.raises(StorageError) as excinfo:
        open_database(db_path)
    assert excinfo.value.details["reason"] == "required_setting_not_applied"


# ---- migrations ---------------------------------------------------------------------------


def test_migrations_apply_exactly_once(db_path: Path) -> None:
    connection = open_database(db_path)
    try:
        assert applied_versions(connection) == ()
        assert apply_migrations(connection, now=NOW) == (1, 2)
        assert apply_migrations(connection, now=NOW) == ()
        assert applied_versions(connection) == (1, 2)
        rows = connection.execute("SELECT version, name, checksum, applied_at FROM schema_version")
        assert [tuple(r) for r in rows] == [
            (1, "initial_schema", MIGRATIONS[0].checksum, "2026-03-01T12:00:00.000000Z"),
            (2, "playbook_runs", MIGRATIONS[1].checksum, "2026-03-01T12:00:00.000000Z"),
        ]
    finally:
        connection.close()


def test_migration_two_is_pinned_and_v1_is_untouched() -> None:
    """Order, names and checksums of the released migrations. Editing an applied migration
    is refused at startup: see test_checksum_mismatch_stops_startup and
    test_edited_migration_is_detected (and test_m13_fixture for a real M13 database)."""
    assert [(m.version, m.name) for m in MIGRATIONS] == [
        (1, "initial_schema"),
        (2, "playbook_runs"),
    ]
    assert MIGRATIONS[0].checksum == V1_CHECKSUM
    assert MIGRATIONS[1].checksum == V2_CHECKSUM


def test_released_migration_is_pinned() -> None:
    """Editing migration 1 changes this checksum: add a new migration instead."""
    assert MIGRATIONS[0].checksum == V1_CHECKSUM


def test_every_released_migration_is_pinned() -> None:
    """Editing any released migration changes its checksum: add a new migration instead."""
    current = {(m.version, m.name): m.checksum for m in MIGRATIONS}
    assert {key: current.get(key) for key in RELEASED_CHECKSUMS} == RELEASED_CHECKSUMS


def test_first_migration_creates_the_required_tables(conn: SoermConnection) -> None:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert tables >= {
        "schema_version", "counters", "assets", "findings", "finding_occurrences",
        "import_runs", "incidents", "incident_links", "incident_events", "incident_notes",
        "evidence", "tasks", "playbooks", "pending_changes", "audit_log",
        "playbook_versions", "incident_playbooks", "incident_playbook_steps",
    }  # fmt: skip
    triggers = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    assert triggers == {
        "audit_log_chain", "audit_log_no_update", "audit_log_no_delete",
        "playbook_versions_no_update", "playbook_versions_no_delete",
        "incident_playbooks_no_update", "incident_playbooks_no_delete",
        "incident_playbook_steps_no_update", "incident_playbook_steps_no_delete",
    }  # fmt: skip


def test_every_table_is_strict_and_keyed(conn: SoermConnection) -> None:
    for name, sql in conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ):
        assert sql.rstrip().endswith("STRICT"), name
        assert "PRIMARY KEY" in sql, name


def test_no_table_has_raw_payload_columns(conn: SoermConnection) -> None:
    forbidden = {"raw", "raw_text", "raw_evidence", "payload", "raw_payload", "secret", "token"}
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        assert not columns & forbidden, table
    columns = {row[1] for row in conn.execute("PRAGMA table_info(pending_changes)")}
    assert "require_distinct_approver" in columns
    assert not columns & {"description", "evidence", "payload", "body"}


def test_checksum_mismatch_stops_startup(conn: SoermConnection, raw: sqlite3.Connection) -> None:
    raw.execute("UPDATE schema_version SET checksum = ?", ("b" * 64,))
    with pytest.raises(MigrationError) as excinfo:
        apply_migrations(conn)
    assert excinfo.value.details["reason"] == "migration_checksum_mismatch"


def test_edited_migration_is_detected(conn: SoermConnection) -> None:
    edited = Migration(1, "initial_schema", (*MIGRATIONS[0].statements, "CREATE TABLE extra (x)"))
    with pytest.raises(MigrationError) as excinfo:
        apply_migrations(conn, migrations=(edited, MIGRATIONS[1]))
    assert excinfo.value.details["reason"] == "migration_checksum_mismatch"
    renamed = Migration(1, "other_name", MIGRATIONS[0].statements)
    with pytest.raises(MigrationError) as excinfo:
        apply_migrations(conn, migrations=(renamed, MIGRATIONS[1]))
    assert excinfo.value.details["reason"] == "migration_name_mismatch"


SCHEMA_VERSION_DDL = MIGRATIONS[0].statements[0]


def test_failed_migration_rolls_back_completely(db_path: Path) -> None:
    good = Migration(1, "first", (SCHEMA_VERSION_DDL, "CREATE TABLE a (x INTEGER PRIMARY KEY)"))
    bad = Migration(
        2, "second", ("CREATE TABLE b (x INTEGER PRIMARY KEY)", "INSERT INTO nope VALUES (1)")
    )
    connection = open_database(db_path)
    try:
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection, migrations=(good, bad), now=NOW)
        assert excinfo.value.details["reason"] == "migration_failed"
        assert excinfo.value.details["version"] == "2"
        assert applied_versions(connection) == (1,)  # the good one stays
        names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master")}
        assert "a" in names
        assert "b" not in names  # partial work of the failed migration is gone
        assert not connection.in_transaction
    finally:
        connection.close()


def test_malformed_schema_version_is_refused(db_path: Path) -> None:
    plain = sqlite3.connect(str(db_path), isolation_level=None)
    plain.execute("CREATE TABLE schema_version (version INTEGER)")
    plain.close()
    connection = open_database(db_path)
    try:
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection)
        assert excinfo.value.details["reason"] == "malformed_schema_version"
    finally:
        connection.close()


@pytest.mark.parametrize(
    "row",
    [
        (2, "initial_schema", "a" * 64, TS),  # gap: history must start at 1
        (1, "initial_schema", "NOT-HEX", TS),
        (1, "initial_schema", "a" * 63, TS),
        ("1", "initial_schema", "a" * 64, TS),
    ],
)
def test_malformed_schema_version_rows_are_refused(db_path: Path, row: tuple[object, ...]) -> None:
    plain = sqlite3.connect(str(db_path), isolation_level=None)
    plain.execute(
        "CREATE TABLE schema_version (version, name, checksum, applied_at)"
    )  # no constraints: simulates a damaged file
    plain.execute("INSERT INTO schema_version VALUES (?, ?, ?, ?)", row)
    plain.close()
    connection = open_database(db_path)
    try:
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection)
        assert excinfo.value.details["reason"] == "malformed_schema_version"
    finally:
        connection.close()


def test_unmanaged_database_is_refused(db_path: Path) -> None:
    plain = sqlite3.connect(str(db_path), isolation_level=None)
    plain.execute("CREATE TABLE somebody_elses (x)")
    plain.close()
    connection = open_database(db_path)
    try:
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection)
        assert excinfo.value.details["reason"] == "unmanaged_database"
    finally:
        connection.close()


def test_database_newer_than_application(db_path: Path) -> None:
    one = Migration(1, "first", (SCHEMA_VERSION_DDL,))
    two = Migration(2, "second", ("CREATE TABLE b (x INTEGER PRIMARY KEY)",))
    connection = open_database(db_path)
    try:
        apply_migrations(connection, migrations=(one, two), now=NOW)
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection, migrations=(one,))
        assert excinfo.value.details["reason"] == "database_newer_than_application"
    finally:
        connection.close()


@pytest.mark.parametrize(
    "migrations",
    [
        (),
        (Migration(2, "x", ("SELECT 1",)),),
        (Migration(1, "x", ("SELECT 1",)), Migration(1, "y", ("SELECT 1",))),
        (Migration(1, "x", ("SELECT 1",)), Migration(2, "x", ("SELECT 1",))),
        (Migration(1, "x", ()),),
    ],
)
def test_invalid_migration_sets(db_path: Path, migrations: tuple[Migration, ...]) -> None:
    connection = open_database(db_path)
    try:
        with pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection, migrations=migrations)
        assert excinfo.value.details["reason"] == "invalid_migration_set"
    finally:
        connection.close()


def test_migrations_cannot_run_inside_a_transaction(db_path: Path) -> None:
    connection = open_database(db_path)
    try:
        with transaction(connection, write=True), pytest.raises(MigrationError) as excinfo:
            apply_migrations(connection)
        assert excinfo.value.details["reason"] == "migrations_require_top_level"
    finally:
        connection.close()


# ---- schema constraints -------------------------------------------------------------------

ASSET = (
    "INSERT INTO assets (asset_id, name, owner, environment, business_criticality,"
    " data_classification, exposure, tags, created_at, updated_at)"
    " VALUES (?, 'n', 'o', ?, 'low', 'public', 'internal', ?, ?, ?)"
)


def run(conn: SoermConnection, sql: str, params: tuple[object, ...] = ()) -> None:
    with transaction(conn, write=True):
        conn.execute(sql, params)


@pytest.mark.parametrize(
    "params",
    [
        ("AST-1", "production", "[]", TS, TS),  # id format
        ("ast-000001", "production", "[]", TS, TS),
        ("AST-00000a", "production", "[]", TS, TS),
        ("AST-000001", "prod", "[]", TS, TS),  # enum
        ("AST-000001", "production", "{}", TS, TS),  # tags must be a JSON array
        ("AST-000001", "production", "not json", TS, TS),
        ("AST-000001", "production", "[]", "2026-03-01T12:00:00Z", TS),  # fixed-width timestamps
        ("AST-000001", "production", "[]", "2026-03-01 12:00:00.000000Z", TS),
        ("AST-000001", "production", "[]", TS2, TS),  # updated before created
    ],
)
def test_asset_check_constraints(conn: SoermConnection, params: tuple[object, ...]) -> None:
    with pytest.raises(ConstraintViolationError) as excinfo:
        run(conn, ASSET, params)
    assert excinfo.value.details["kind"] == "check"


def test_primary_key_and_not_null(conn: SoermConnection) -> None:
    run(conn, ASSET, ("AST-000001", "production", "[]", TS, TS))
    with pytest.raises(ConstraintViolationError) as excinfo:
        run(conn, ASSET, ("AST-000001", "production", "[]", TS, TS))
    assert excinfo.value.details["kind"] == "unique"
    with pytest.raises(ConstraintViolationError) as excinfo:
        run(conn, "INSERT INTO assets (asset_id) VALUES ('AST-000002')")
    assert excinfo.value.details["kind"] == "not_null"


def test_strict_tables_reject_wrong_types(conn: SoermConnection) -> None:
    with pytest.raises(StorageError):
        run(conn, "UPDATE counters SET value = 'many' WHERE prefix = 'AST'")


def test_counters_are_seeded_and_bounded(conn: SoermConnection) -> None:
    rows = dict(conn.execute("SELECT prefix, value FROM counters").fetchall())
    assert rows == dict.fromkeys(["AST", "FND", "INC", "TSK", "PBK", "CHG", "RUN"], 0)
    with pytest.raises(ConstraintViolationError):
        run(conn, "INSERT INTO counters (prefix, value) VALUES ('XXX', 0)")
    with pytest.raises(ConstraintViolationError):
        run(conn, "UPDATE counters SET value = -1 WHERE prefix = 'AST'")


PENDING = (
    "INSERT INTO pending_changes (change_id, object_type, object_id, requester, approver,"
    " status, reason, before_hash, proposed_after_hash, requested_at, expires_at, decided_at,"
    " require_distinct_approver)"
    " VALUES ('CHG-000001', 'incident', 'INC-000001', ?, ?, ?, 'why', NULL, ?, ?, ?, ?, ?)"
)


def pending(**overrides: object) -> tuple[object, ...]:
    data: dict[str, object] = {
        "requester": "alice", "approver": None, "status": "pending", "after": SHA,
        "requested": TS, "expires": "2026-03-08T12:00:00.000000Z", "decided": None, "distinct": 1,
    }  # fmt: skip
    data.update(overrides)
    return tuple(data.values())


def test_pending_changes_valid_rows(conn: SoermConnection) -> None:
    run(conn, PENDING, pending())
    assert conn.execute("SELECT status, require_distinct_approver FROM pending_changes").fetchone()[
        :
    ] == ("pending", 1)


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires": TS},  # must expire after the request
        {"after": "A" * 64},
        {"status": "unknown"},
        {"status": "approved"},  # decided_at and approver required
        {"status": "approved", "approver": "bob"},
        {"status": "pending", "decided": TS2},
        {"status": "pending", "approver": "bob"},
        {"status": "approved", "approver": "alice", "decided": TS2},  # self approval
        {"distinct": 2},
        {"requester": "Alice"},  # actors are stored normalized
    ],
)
def test_pending_changes_constraints(conn: SoermConnection, overrides: dict[str, object]) -> None:
    with pytest.raises(ConstraintViolationError):
        run(conn, PENDING, pending(**overrides))


def test_self_approval_can_be_allowed_by_policy_flag(conn: SoermConnection) -> None:
    run(conn, PENDING, pending(status="approved", approver="alice", decided=TS2, distinct=0))


def test_other_tables_enforce_their_invariants(conn: SoermConnection) -> None:
    inc = (
        "INSERT INTO incidents (incident_id, title, severity, status, owner, summary, created_at,"
        " updated_at, closed_at, closure_reason)"
        " VALUES ('INC-000001', 't', ?, ?, 'o', '', ?, ?, ?, ?)"
    )
    run(conn, inc, ("high", "new", TS, TS, None, None))
    for params in (
        ("none", "new", TS, TS, None, None),  # incidents have no "none" severity
        ("high", "closed", TS, TS, None, "reason"),  # closed needs closed_at
        ("high", "closed", TS, TS, TS2, None),  # closed needs a reason
        ("high", "new", TS, TS, TS2, "reason"),  # open must not have them
    ):
        with pytest.raises(ConstraintViolationError):
            run(conn, inc.replace("INC-000001", "INC-000002"), params)
    task = (
        "INSERT INTO tasks (task_id, finding_id, incident_id, title, owner, status, created_at,"
        " updated_at, completed_at) VALUES ('TSK-000001', NULL, ?, 't', 'o', ?, ?, ?, ?)"
    )
    bad_tasks: list[tuple[object, ...]] = [
        (None, "open", TS, TS, None),  # needs a finding or an incident
        ("INC-000001", "done", TS, TS, None),
        ("INC-000001", "open", TS, TS, TS2),
        ("INC-000001", "cancelled", TS, TS, TS2),
    ]
    for task_params in bad_tasks:
        with pytest.raises(ConstraintViolationError):
            run(conn, task, task_params)
    run(conn, task, ("INC-000001", "done", TS, TS2, TS2))
    evidence = (
        "INSERT INTO evidence (finding_id, incident_id, evidence_type, redacted_text,"
        " content_sha256, created_at) VALUES (NULL, ?, 'note', ?, ?, ?)"
    )
    run(conn, evidence, ("INC-000001", "x" * 4096, SHA, TS))
    bad_evidence: list[tuple[object, ...]] = [
        ("INC-000001", "x" * 4097, SHA, TS),
        ("INC-000001", "é" * 2049, SHA, TS),
        (None, "x", SHA, TS),
    ]
    for evidence_params in bad_evidence:
        with pytest.raises(ConstraintViolationError):
            run(conn, evidence, evidence_params)
