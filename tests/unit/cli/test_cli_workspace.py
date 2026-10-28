"""Workspace handling: lock, database location, process-level behaviour."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from soerm.storage.lock import WorkspaceLock
from tests.unit.cli.conftest import Runner, add_asset, add_finding
from tests.unit.services.helpers import SECRET


def names(path: Path) -> set[str]:
    return {entry.name for entry in path.iterdir()}


def test_mutation_creates_only_the_database_and_the_lock_file_in_the_workspace(
    cli: Runner, workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    before = names(tmp_path)
    assert add_asset(cli, workspace).code == 0
    assert names(workspace) == {".soerm.lock", "soerm.db"}  # no -wal/-shm left behind
    assert names(tmp_path) == before
    assert names(elsewhere) == set()


def test_reads_never_create_anything(cli: Runner, workspace: Path) -> None:
    for argv in (("asset", "list"), ("asset", "show", "AST-000001"), ("finding", "list")):
        result = cli(argv[0], argv[1], "--workspace", str(workspace), *argv[2:])
        assert result.code == 1
        assert result.err.startswith("error[not_found]")
    assert names(workspace) == set()


def test_a_missing_workspace_is_never_created(cli: Runner, tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    result = add_asset(cli, missing)
    assert result.code == 1
    assert result.err.startswith("error[not_found]")
    assert not missing.exists()
    assert cli("asset", "list", "--workspace", str(missing)).code == 1
    assert not missing.exists()


def test_relative_workspace_paths_work(
    cli: Runner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(workspace.parent)
    assert cli("asset", "list", "--workspace", "workspace").code == 1  # empty, but resolved
    assert add_asset(cli, Path("workspace")).code == 0
    assert (workspace / "soerm.db").is_file()


def test_symlinked_workspace_is_refused(cli: Runner, workspace: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(workspace)
    assert add_asset(cli, link).code == 1
    assert names(workspace) == set()


@pytest.mark.parametrize("bad", ["", "dir\x00name", "dir\x1b[31m", "\n"])
def test_unusable_workspace_strings_are_rejected(cli: Runner, bad: str) -> None:
    result = cli("asset", "list", "--workspace", bad)
    assert result.code in {1, 2}
    assert_no_leak(result.err)


def assert_no_leak(text: str) -> None:
    assert "\x1b" not in text
    assert "\x00" not in text
    assert "Traceback" not in text


def test_a_held_lock_blocks_mutations_but_not_reads(cli: Runner, workspace: Path) -> None:
    assert add_asset(cli, workspace).code == 0
    with WorkspaceLock(workspace, app_version="test"):
        blocked = add_asset(cli, workspace)
        assert blocked.code == 1
        assert blocked.err.startswith("error[busy]")
        assert cli("asset", "list", "--workspace", str(workspace)).code == 0
    assert add_asset(cli, workspace).code == 0
    assert cli("asset", "list", "--workspace", str(workspace)).out.count("AST-") == 2


def test_the_lock_is_released_after_success_and_after_failure(cli: Runner, workspace: Path) -> None:
    assert add_asset(cli, workspace).code == 0
    assert add_finding(cli, workspace, fingerprint="bad").code == 1
    assert add_finding(cli, workspace, fingerprint="c" * 64).code == 0
    with WorkspaceLock(workspace, app_version="test"):  # acquirable: nothing left locked
        pass
    assert (workspace / ".soerm.lock").read_text() == ""


def test_a_failed_mutation_leaves_no_partial_state(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    failed = add_finding(cli, workspace, "--evidence", "x" * 70000)
    assert failed.code == 1
    assert cli("finding", "list", "--workspace", str(workspace)).out.count("FND-") == 0
    assert add_finding(cli, workspace).code == 0
    assert "FND-000001" in cli("finding", "list", "--workspace", str(workspace)).out


def test_tampered_migration_history_is_an_integrity_error(cli: Runner, workspace: Path) -> None:
    import sqlite3
    from contextlib import closing

    add_asset(cli, workspace)
    with closing(sqlite3.connect(workspace / "soerm.db", isolation_level=None)) as raw:
        raw.execute("UPDATE schema_version SET checksum = ?", ("f" * 64,))
    result = add_asset(cli, workspace)
    assert result.code == 3
    assert result.err.startswith("error[integrity_error]")
    assert "SELECT" not in result.err


def test_real_process_exit_codes_and_ascii_output(workspace: Path, tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}

    def run(*argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "soerm", *argv],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            cwd=tmp_path,
            env=env,
        )

    ws = str(workspace)
    added = run("asset", "add", "--workspace", ws, "--actor", "alice", "--name", "Тест ✓",
                "--owner", "o", "--environment", "test", "--criticality", "low",
                "--classification", "public", "--exposure", "isolated")  # fmt: skip
    assert added.returncode == 0, added.stderr
    shown = run("asset", "show", "--workspace", ws, "AST-000001")
    assert shown.returncode == 0
    assert shown.stdout.isascii()
    assert "\\u0422" in shown.stdout
    assert run("asset", "show", "--workspace", ws, "AST-000009").returncode == 1
    assert run("asset", "show", "--workspace", ws, "AST-000001", "--bogus", SECRET).returncode == 2
    usage = run("asset", "show", "--workspace", ws, "--bogus", SECRET)
    assert SECRET not in usage.stderr + usage.stdout
    assert "Traceback" not in usage.stderr
    with WorkspaceLock(workspace, app_version="parent"):
        busy = run("asset", "add", "--workspace", ws, "--actor", "bob", "--name", "n",
                   "--owner", "o",
                   "--environment", "test", "--criticality", "low", "--classification", "public",
                   "--exposure", "isolated")  # fmt: skip
        assert busy.returncode == 1
        assert "error[busy]" in busy.stderr
