"""Workspace lock: one process at a time inside a workspace (POSIX ``flock``).

* The lock file is ``<workspace>/.soerm.lock``. The workspace directory must already exist
  (it is created only by the future workspace service, never by this module).
* The lock is an advisory ``flock(LOCK_EX | LOCK_NB)`` on an open file descriptor: a second
  holder, in another process or on another descriptor, is refused immediately.
* After the lock is held, ``{pid, locked_at, version}`` is written into the file as a
  diagnostic hint. Release clears the hint and unlocks; the file is never deleted, because
  deleting a lock file while others may be opening it breaks mutual exclusion.
* A file left by a crashed process is **not** removed or trusted: the kernel drops the lock
  when the process dies, so the next process simply acquires the same file and overwrites the
  hint. Nothing is deleted automatically.
* Platforms without ``fcntl`` (Windows) are refused with an explicit error.
"""

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Final, Self

from soerm.domain.timestamps import format_timestamp
from soerm.storage.errors import UnsupportedPlatformError, WorkspaceLockError

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by monkeypatching in tests
    fcntl = None  # type: ignore[assignment]

__all__ = ["LOCK_FILE_NAME", "WorkspaceLock"]

LOCK_FILE_NAME: Final = ".soerm.lock"
_LOCK_MODE: Final = 0o600


class WorkspaceLock:
    """Context manager holding the exclusive lock of one workspace."""

    def __init__(self, workspace: Path, *, app_version: str) -> None:
        self._workspace = workspace
        self._app_version = app_version
        self._fd: int | None = None

    @property
    def path(self) -> Path:
        return self._workspace / LOCK_FILE_NAME

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        if fcntl is None:
            raise UnsupportedPlatformError("posix_required")
        if self._fd is not None:
            raise WorkspaceLockError("already_held_by_this_object")
        workspace = self._workspace
        if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
            raise WorkspaceLockError("workspace_missing")
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(self.path, flags, _LOCK_MODE)
        except OSError:
            raise WorkspaceLockError("lock_file_unavailable") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise WorkspaceLockError("lock_file_not_regular")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WorkspaceLockError("workspace_locked") from None
            self._write_hint(fd)
        except BaseException:
            os.close(fd)  # closing the descriptor also drops a lock taken above
            raise
        self._fd = fd

    def _write_hint(self, fd: int) -> None:
        hint = {
            "pid": os.getpid(),
            "locked_at": format_timestamp(datetime.now(UTC)),
            "version": self._app_version,
        }
        data = json.dumps(hint, sort_keys=True, separators=(",", ":")).encode("ascii")
        try:
            os.ftruncate(fd, 0)
            os.pwrite(fd, data, 0)
            os.fsync(fd)
        except OSError:
            raise WorkspaceLockError("lock_hint_write_failed") from None

    def release(self) -> None:
        """Clear the hint, unlock and close. Safe to call more than once."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            try:
                os.ftruncate(fd, 0)
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
