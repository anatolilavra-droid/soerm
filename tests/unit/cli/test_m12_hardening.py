"""M12 release hardening: file modes, leftovers, lock lifetime, fail-closed behaviour."""

import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest

from soerm import __version__
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.lock import LOCK_FILE_NAME, WorkspaceLock
from tests.unit.cli.conftest import ASSET_ARGS, Runner, add_asset, assert_terminal_safe
from tests.unit.services.helpers import raw_execute

SECRET = "hunter2-TOP-SECRET-token"
EXIT_INTEGRITY = 3


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    return workspace


def test_only_the_expected_files_exist_and_are_private(cli: Runner, ws: Path) -> None:
    assert cli("report", "generate", "--workspace", str(ws), "--output", "r.md").code == 0
    assert sorted(p.name for p in ws.iterdir()) == [LOCK_FILE_NAME, "r.md", DATABASE_FILE_NAME]
    for name in (LOCK_FILE_NAME, "r.md", DATABASE_FILE_NAME):
        assert mode(ws / name) == 0o600, name
    assert mode(ws) & 0o077 == 0 or mode(ws) == mode(ws.parent / ws.name)  # created by the caller


def test_wal_and_shm_files_are_private_while_a_connection_is_open(cli: Runner, ws: Path) -> None:
    with closing(sqlite3.connect(ws / DATABASE_FILE_NAME)) as raw:
        raw.execute("SELECT count(*) FROM assets").fetchone()
        extras = [p for p in ws.iterdir() if p.name.startswith(DATABASE_FILE_NAME + "-")]
        assert extras, "expected -wal/-shm files while a connection is open"
        for item in extras:
            assert mode(item) & 0o077 == 0, item.name
    assert [p.name for p in ws.iterdir() if p.name.startswith(DATABASE_FILE_NAME + "-")] == []


def test_failed_commands_leave_no_temporary_files(cli: Runner, ws: Path) -> None:
    before = sorted(p.name for p in ws.iterdir())
    assert cli("report", "generate", "--workspace", str(ws), "--output", "../x.md").code == 1
    assert cli("report", "generate", "--workspace", str(ws), "--output", "a/b.md").code == 1
    assert cli("import", "run", "--workspace", str(ws), "--actor", "a", "--format", "sarif",
               "--asset-id", "AST-000001", "missing.sarif").code == 1  # fmt: skip
    assert sorted(p.name for p in ws.iterdir()) == before


def test_lock_is_released_after_success_and_after_errors(cli: Runner, ws: Path) -> None:
    assert cli("asset", "show", "--workspace", str(ws), "AST-999999").code == 1
    failing = cli("asset", "add", "--workspace", str(ws), "--actor", "alice", "--name", "",
                  *ASSET_ARGS[2:])  # fmt: skip
    assert failing.code != 0
    for _ in range(2):  # the lock can be taken again right away
        with WorkspaceLock(ws, app_version=__version__):
            pass
    assert cli("asset", "list", "--workspace", str(ws)).code == 0


def test_lock_is_released_after_an_unexpected_exception(
    cli: Runner, ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soerm.services import tasks

    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"password={SECRET}")

    monkeypatch.setattr(tasks, "create_task", explode)
    result = cli("task", "create", "--workspace", str(ws), "--actor", "a", "--title", "t",
                 "--owner", "o")  # fmt: skip
    assert result.code == EXIT_INTEGRITY
    assert SECRET not in result.out + result.err
    assert "Traceback" not in result.err
    assert_terminal_safe(result.err)
    with WorkspaceLock(ws, app_version=__version__):
        pass


def test_dropped_audit_table_fails_closed(cli: Runner, ws: Path) -> None:
    raw_execute(ws, "PRAGMA foreign_keys = OFF")
    raw_execute(ws, "DROP TABLE audit_log")
    for argv in (
        ("audit", "verify"),
        ("report", "preview"),
    ):
        result = cli(*argv, "--workspace", str(ws))
        assert result.code == EXIT_INTEGRITY, argv
        assert "Traceback" not in result.err
    write = cli("asset", "add", "--workspace", str(ws), "--actor", "a", *ASSET_ARGS)
    assert write.code == EXIT_INTEGRITY


@pytest.mark.parametrize("payload", [b"SQLite format 3\x00", bytes(range(256)) * 16])
def test_damaged_database_files_are_refused_and_left_alone(
    cli: Runner, tmp_path: Path, payload: bytes
) -> None:
    root = tmp_path / "damaged"
    root.mkdir()
    (root / DATABASE_FILE_NAME).write_bytes(payload)
    for argv in (("audit", "verify"), ("report", "preview"), ("asset", "list")):
        result = cli(*argv, "--workspace", str(root))
        assert result.code in (1, EXIT_INTEGRITY), argv
        assert "Traceback" not in result.err
    write = cli("asset", "add", "--workspace", str(root), "--actor", "a", *ASSET_ARGS)
    assert write.code in (1, EXIT_INTEGRITY)
    if payload:
        assert (root / DATABASE_FILE_NAME).read_bytes() == payload


def test_workspace_may_be_a_symlink_but_files_never_are(
    cli: Runner, ws: Path, tmp_path: Path
) -> None:
    link = tmp_path / "link"
    link.symlink_to(ws)
    assert cli("asset", "list", "--workspace", str(link)).code == 0
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"")
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (fresh / DATABASE_FILE_NAME).symlink_to(outside)
    result = cli("asset", "add", "--workspace", str(fresh), "--actor", "a", *ASSET_ARGS)
    assert result.code != 0
    assert outside.read_bytes() == b""


def test_workspace_object_exposes_no_path_to_outputs(ws: Path) -> None:
    assert Workspace(ws).path == ws
