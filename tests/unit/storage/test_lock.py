"""Workspace lock (POSIX flock)."""

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from soerm.storage import lock as lock_module
from soerm.storage.errors import UnsupportedPlatformError, WorkspaceLockError
from soerm.storage.lock import LOCK_FILE_NAME, WorkspaceLock

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith(("linux", "darwin")), reason="POSIX only"
)


def reason(excinfo: pytest.ExceptionInfo[WorkspaceLockError]) -> object:
    return excinfo.value.details["reason"]


def test_acquire_and_release(tmp_path: Path) -> None:
    lock = WorkspaceLock(tmp_path, app_version="0.0.1")
    assert lock.path == tmp_path / LOCK_FILE_NAME
    lock.acquire()
    with pytest.raises(WorkspaceLockError):
        WorkspaceLock(tmp_path, app_version="x").acquire()  # proves the lock is held
    lock.release()
    with WorkspaceLock(tmp_path, app_version="y"):  # proves it was released
        pass


def test_release_is_idempotent_and_safe_without_acquire(tmp_path: Path) -> None:
    lock = WorkspaceLock(tmp_path, app_version="0.0.1")
    lock.release()
    lock.acquire()
    lock.release()
    lock.release()


def test_hint_is_written_after_locking_and_cleared_on_release(tmp_path: Path) -> None:
    with WorkspaceLock(tmp_path, app_version="1.2.3") as lock:
        hint = json.loads(lock.path.read_text(encoding="ascii"))
        assert set(hint) == {"pid", "locked_at", "version"}
        assert hint["pid"] == os.getpid()
        assert hint["version"] == "1.2.3"
        assert hint["locked_at"].endswith("Z")
    assert lock.path.exists()  # never deleted
    assert lock.path.read_text() == ""


def test_file_mode_is_private(tmp_path: Path) -> None:
    with WorkspaceLock(tmp_path, app_version="0") as lock:
        assert stat.S_IMODE(lock.path.stat().st_mode) == 0o600


def test_second_lock_is_refused_and_does_not_disturb_the_first(tmp_path: Path) -> None:
    with WorkspaceLock(tmp_path, app_version="a") as first:
        before = first.path.read_text()
        with pytest.raises(WorkspaceLockError) as excinfo:
            WorkspaceLock(tmp_path, app_version="b").acquire()
        assert reason(excinfo) == "workspace_locked"
        assert first.path.read_text() == before
        assert first.held
    with WorkspaceLock(tmp_path, app_version="c"):  # free again
        pass


def test_same_object_cannot_acquire_twice(tmp_path: Path) -> None:
    with WorkspaceLock(tmp_path, app_version="a") as lock:
        with pytest.raises(WorkspaceLockError) as excinfo:
            lock.acquire()
        assert reason(excinfo) == "already_held_by_this_object"
        assert lock.held


def test_released_in_finally_after_an_error(tmp_path: Path) -> None:
    lock = WorkspaceLock(tmp_path, app_version="a")
    with pytest.raises(RuntimeError), lock:
        raise RuntimeError
    assert not lock.held
    with WorkspaceLock(tmp_path, app_version="b"):
        pass


def test_stale_lock_file_is_neither_trusted_nor_removed(tmp_path: Path) -> None:
    path = tmp_path / LOCK_FILE_NAME
    path.write_text('{"pid": 1, "locked_at": "2020-01-01T00:00:00Z", "version": "old"}')
    inode = path.stat().st_ino
    with WorkspaceLock(tmp_path, app_version="new") as lock:
        assert lock.path.stat().st_ino == inode
        assert json.loads(lock.path.read_text())["version"] == "new"
    assert path.stat().st_ino == inode


@pytest.mark.parametrize("kind", ["missing", "relative", "symlink", "file"])
def test_workspace_must_exist_and_be_a_real_directory(tmp_path: Path, kind: str) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = {
        "missing": tmp_path / "absent",
        "relative": Path("relative-dir"),
        "symlink": tmp_path / "link",
        "file": tmp_path / "file",
    }[kind]
    if kind == "symlink":
        target.symlink_to(real)
    if kind == "file":
        target.write_text("x")
    with pytest.raises(WorkspaceLockError) as excinfo:
        WorkspaceLock(target, app_version="a").acquire()
    assert reason(excinfo) == "workspace_missing"
    assert not (tmp_path / "absent").exists()  # the module never creates the workspace


def test_symlinked_lock_file_is_refused(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / LOCK_FILE_NAME).symlink_to(victim)
    with pytest.raises(WorkspaceLockError) as excinfo:
        WorkspaceLock(tmp_path, app_version="a").acquire()
    assert reason(excinfo) == "lock_file_unavailable"
    assert victim.read_text() == "keep"


def test_directory_in_place_of_lock_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / LOCK_FILE_NAME).mkdir()
    with pytest.raises(WorkspaceLockError):
        WorkspaceLock(tmp_path, app_version="a").acquire()


def test_unsupported_platform_is_reported_clearly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lock_module, "fcntl", None, raising=True)
    with pytest.raises(UnsupportedPlatformError) as excinfo:
        WorkspaceLock(tmp_path, app_version="a").acquire()
    assert excinfo.value.details["reason"] == "posix_required"
    assert not (tmp_path / LOCK_FILE_NAME).exists()


def test_lock_is_exclusive_across_processes(tmp_path: Path) -> None:
    code = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from soerm.storage.errors import WorkspaceLockError
        from soerm.storage.lock import WorkspaceLock

        try:
            WorkspaceLock(Path(sys.argv[1]), app_version="child").acquire()
        except WorkspaceLockError as exc:
            print(exc.details["reason"])
            raise SystemExit(3)
        print("acquired")
        """
    )

    def run_child() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-I", "-c", code, str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    with WorkspaceLock(tmp_path, app_version="parent"):
        refused = run_child()
        assert refused.returncode == 3, refused.stderr
        assert refused.stdout.strip() == "workspace_locked"
    free = run_child()  # the child exits, the kernel drops its lock
    assert (free.returncode, free.stdout.strip()) == (0, "acquired"), free.stderr
    with WorkspaceLock(tmp_path, app_version="parent"):  # and nothing stays locked
        pass
