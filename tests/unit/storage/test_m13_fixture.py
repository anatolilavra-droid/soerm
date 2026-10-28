"""A workspace database written by the released M13 code (schema v2) and the current code.

The fixture is a text dump (``tests/fixtures/m13_workspace.sql``) restored into ``tmp_path``.
It is the starting point of every future upgrade test: when a migration ships, the upgrade
tests below run it against this database.
"""

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.services.audit_check import verify_workspace_audit
from soerm.services.errors import IntegrityServiceError, NotFoundServiceError
from soerm.services.findings import list_findings
from soerm.services.reports import build_workspace_report
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.connection import open_database
from soerm.storage.errors import MigrationError, StorageError
from soerm.storage.migrations import MIGRATIONS, apply_migrations

from .conftest import NOW, PROJECT_ROOT
from .test_database import RELEASED_CHECKSUMS

FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
FIXTURE = FIXTURES / "m13_workspace.sql"
FIXTURE_SHA256 = "8b1e7bfa32415a42d47cfb9bfdd03b39988c191d9d2f4cab0d41ba65302a7f92"
M13_SCHEMA_VERSIONS = (1, 2)
M13_AUDIT_ENTRIES = 26
M13_AUDIT_HEAD = "6107ca21836a715eafc51dfc6c231912d49cafac1d60f060f0c99c6eb12eb169"
M13_ROW_COUNTS = {
    "assets": 1,
    "findings": 6,
    "finding_occurrences": 6,
    "import_runs": 3,
    "tasks": 1,
    "incidents": 1,
    "pending_changes": 1,
    "playbook_versions": 1,
    "incident_playbook_steps": 2,
    "audit_log": M13_AUDIT_ENTRIES,
}


def restore(script: str, workspace: Path) -> Path:
    workspace.mkdir()
    with closing(sqlite3.connect(workspace / DATABASE_FILE_NAME)) as raw:
        raw.executescript(script)
    return workspace


@pytest.fixture
def m13_workspace(tmp_path: Path) -> Path:
    return restore(FIXTURE.read_text(encoding="ascii"), tmp_path / "workspace")


def raw_connection(workspace: Path) -> sqlite3.Connection:
    return sqlite3.connect(workspace / DATABASE_FILE_NAME)


def snapshot(workspace: Path) -> dict[str, list[tuple[object, ...]]]:
    """Every row of every table, in a stable order."""
    with closing(raw_connection(workspace)) as raw:
        tables = [
            row[0]
            for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            table: sorted(raw.execute(f"SELECT * FROM {table}").fetchall(), key=repr)  # noqa: S608
            for table in tables
        }


def migrate(workspace: Path) -> tuple[int, ...]:
    with closing(open_database(workspace / DATABASE_FILE_NAME)) as connection:
        return apply_migrations(connection, now=NOW)


def schema_rows(workspace: Path) -> list[tuple[object, ...]]:
    with closing(raw_connection(workspace)) as raw:
        return raw.execute("SELECT * FROM schema_version ORDER BY version").fetchall()


def audit_of(workspace: Path) -> tuple[bool, int, str]:
    facts = verify_workspace_audit(Workspace(workspace, clock=lambda: NOW))
    return facts.intact, facts.entries, facts.head_hash


# ---- The fixture itself -------------------------------------------------------------------


def test_fixture_file_is_pinned() -> None:
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256


def test_fixture_directory_holds_no_databases_or_temporary_files() -> None:
    forbidden_suffixes = {".db", ".sqlite", ".sqlite3", ".tmp", ".bak", ".journal", ".lock"}
    for path in FIXTURES.rglob("*"):
        assert path.suffix not in forbidden_suffixes, path.name
        assert not path.name.endswith(("-wal", "-shm", "-journal")), path.name
    assert sorted(p.name for p in FIXTURES.iterdir()) == ["m13_workspace.sql"]


def test_fixture_is_plain_ascii_without_secrets() -> None:
    text = FIXTURE.read_text(encoding="ascii")
    for marker in ("hunter2", "AKIA", "PRIVATE KEY", "/home/", "/tmp/", "EMP-"):
        assert marker not in text


def test_fixture_documents_its_schema_version() -> None:
    header = FIXTURE.read_text(encoding="ascii").split("BEGIN TRANSACTION;")[0]
    assert "Schema version: 2" in header
    for (version, name), checksum in RELEASED_CHECKSUMS.items():
        assert f"--   {version} {name}" in header
        assert checksum in header


def test_fixture_records_the_released_migrations(m13_workspace: Path) -> None:
    stored = [
        (version, name, checksum) for version, name, checksum, _ in schema_rows(m13_workspace)
    ]
    expected = [(v, n, c) for (v, n), c in RELEASED_CHECKSUMS.items() if v in M13_SCHEMA_VERSIONS]
    assert stored == expected


def test_fixture_database_is_consistent(m13_workspace: Path) -> None:
    with closing(raw_connection(m13_workspace)) as raw:
        assert raw.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
    rows = snapshot(m13_workspace)
    assert {table: len(rows[table]) for table in M13_ROW_COUNTS} == M13_ROW_COUNTS


def test_current_code_reads_the_m13_workspace(m13_workspace: Path) -> None:
    workspace = Workspace(m13_workspace, clock=lambda: NOW)
    assert len(list_findings(workspace)) == M13_ROW_COUNTS["findings"]
    assert audit_of(m13_workspace) == (True, M13_AUDIT_ENTRIES, M13_AUDIT_HEAD)
    assert build_workspace_report(workspace, generated_at=NOW).audit_intact


# ---- Upgrade M13 -> current schema ----------------------------------------------------------


def test_upgrade_from_m13_keeps_data_keys_and_released_checksums(m13_workspace: Path) -> None:
    before = snapshot(m13_workspace)
    released_rows = schema_rows(m13_workspace)

    applied = migrate(m13_workspace)

    assert applied == tuple(m.version for m in MIGRATIONS if m.version not in M13_SCHEMA_VERSIONS)
    after = snapshot(m13_workspace)
    for table, rows in before.items():  # existing data survives unchanged
        if table != "schema_version":
            assert after[table] == rows, table
    assert schema_rows(m13_workspace)[: len(released_rows)] == released_rows  # v1, v2 untouched
    with closing(raw_connection(m13_workspace)) as raw:
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
        assert raw.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert audit_of(m13_workspace) == (True, M13_AUDIT_ENTRIES, M13_AUDIT_HEAD)


def test_upgrade_is_idempotent(m13_workspace: Path) -> None:
    migrate(m13_workspace)
    once = snapshot(m13_workspace)
    assert migrate(m13_workspace) == ()
    assert migrate(m13_workspace) == ()
    assert snapshot(m13_workspace) == once


def test_write_path_upgrades_and_then_reads_work(m13_workspace: Path) -> None:
    workspace = Workspace(m13_workspace, clock=lambda: NOW)
    with workspace.write():  # lock -> migrate -> empty write transaction
        pass
    with workspace.write():
        pass
    assert [row[0] for row in schema_rows(m13_workspace)] == [m.version for m in MIGRATIONS]
    assert len(list_findings(workspace)) == M13_ROW_COUNTS["findings"]
    assert audit_of(m13_workspace) == (True, M13_AUDIT_ENTRIES, M13_AUDIT_HEAD)


# ---- Refusals ------------------------------------------------------------------------------


def test_tampered_v2_checksum_is_refused(m13_workspace: Path) -> None:
    with closing(raw_connection(m13_workspace)) as raw, raw:
        raw.execute("UPDATE schema_version SET checksum = ? WHERE version = 2", ("b" * 64,))
    before = snapshot(m13_workspace)
    with pytest.raises(MigrationError) as caught:
        migrate(m13_workspace)
    assert caught.value.details["reason"] == "migration_checksum_mismatch"
    assert caught.value.details["version"] == "2"
    workspace = Workspace(m13_workspace, clock=lambda: NOW)
    with pytest.raises(IntegrityServiceError) as refused, workspace.write():
        pass
    assert refused.value.details["reason"] == "migration:migration_checksum_mismatch"
    assert snapshot(m13_workspace) == before  # nothing was written


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ((3, "from_the_future", "c" * 64, "2026-03-01T12:00:00.000000Z"), "database_newer"),
        ((4, "gap", "c" * 64, "2026-03-01T12:00:00.000000Z"), "malformed_schema_version"),
    ],
)
def test_unknown_schema_version_is_refused(
    m13_workspace: Path, row: tuple[object, ...], reason: str
) -> None:
    if MIGRATIONS[-1].version >= 3:  # pragma: no cover - revisit when migration 3 ships
        pytest.fail("update this test: version 3 is now a real migration")
    with closing(raw_connection(m13_workspace)) as raw, raw:
        raw.execute("INSERT INTO schema_version VALUES (?, ?, ?, ?)", row)
    with pytest.raises(MigrationError) as caught:
        migrate(m13_workspace)
    assert caught.value.details["reason"].startswith(reason)
    with pytest.raises(IntegrityServiceError):
        list_findings(Workspace(m13_workspace, clock=lambda: NOW))


def test_reapplying_a_released_migration_fails_and_rolls_back(m13_workspace: Path) -> None:
    """If the record of v2 is lost, v2 runs again over its own tables: it must fail as a whole."""
    with closing(raw_connection(m13_workspace)) as raw, raw:
        raw.execute("DELETE FROM schema_version WHERE version = 2")
    before = snapshot(m13_workspace)
    with pytest.raises(MigrationError) as caught:
        migrate(m13_workspace)
    assert caught.value.details["reason"] == "migration_failed"
    assert caught.value.details["version"] == "2"
    assert snapshot(m13_workspace) == before


def test_corrupted_fixture_content_breaks_the_audit_chain(tmp_path: Path) -> None:
    text = FIXTURE.read_text(encoding="ascii")
    assert text.count(M13_AUDIT_HEAD) == 2  # the header and the last audit row
    position = text.rindex(M13_AUDIT_HEAD)
    tampered = text[:position] + "f" * 64 + text[position + 64 :]
    workspace = restore(tampered, tmp_path / "workspace")
    intact, _, _ = audit_of(workspace)
    assert not intact


def test_truncated_fixture_leaves_no_usable_workspace(tmp_path: Path) -> None:
    text = FIXTURE.read_text(encoding="ascii")
    truncated = text[: text.index("CREATE TABLE schema_version")]  # never reaches COMMIT
    workspace = restore(truncated, tmp_path / "workspace")
    with pytest.raises(NotFoundServiceError) as caught:
        list_findings(Workspace(workspace, clock=lambda: NOW))
    assert caught.value.details["reason"] == "workspace_not_initialized"


def test_corrupted_database_file_is_refused(m13_workspace: Path) -> None:
    database = m13_workspace / DATABASE_FILE_NAME
    data = bytearray(database.read_bytes())
    data[:16] = b"not a database!!"
    database.write_bytes(bytes(data))
    with pytest.raises(StorageError) as caught:
        migrate(m13_workspace)
    assert caught.value.details["reason"] == "not_a_database"
    with pytest.raises(IntegrityServiceError):
        list_findings(Workspace(m13_workspace, clock=lambda: NOW))
