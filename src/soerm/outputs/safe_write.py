"""Writing a generated report file - the only filesystem *write* code outside the database.

The rules, in order:

1. the path text is printable and short; an absolute path must lie inside the workspace or one
   of the directories the configuration allows (``reports.allowed_output_dirs``); a relative
   path is taken relative to the workspace; ``..`` is refused;
2. the directories are opened one by one from the base with ``O_NOFOLLOW | O_DIRECTORY`` and
   directory descriptors, so a symlink anywhere in the path is refused and a swap between check
   and use cannot redirect the write; nothing is created implicitly (no ``mkdir``);
3. database, lock and configuration file names are reserved;
4. an existing target must be a regular file and is only replaced with ``force`` - and only if it
   carries the report marker, so ``--force`` cannot destroy an unrelated file;
5. the content goes to a private temporary file in the same directory (``O_EXCL``, mode 0600),
   is flushed and ``fsync``-ed, then published atomically: ``link`` (fails if the name exists)
   without ``force``, ``rename`` with it; the directory is ``fsync``-ed;
6. the published file is opened again, read back and its SHA-256 compared with the content;
   a mismatch removes the file and raises.

Errors carry stable reason codes and never a path.
"""

import contextlib
import hashlib
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from soerm.domain.report import REPORT_SCHEMA, OutputRejectedError

__all__ = ["WrittenFile", "write_report_file"]

_MAX_PATH_TEXT: Final = 4096
_MAX_NAME: Final = 200
_RESERVED_PREFIXES: Final = ("soerm.db", ".soerm.lock", "soerm.yaml")
_MARKER: Final = REPORT_SCHEMA.encode()
_MARKER_WINDOW: Final = 4096
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True, slots=True)
class WrittenFile:
    path: str
    size: int
    sha256: str
    replaced: bool


def _base_and_parts(
    output: str, root: Path, root_as_given: Path, allowed: Sequence[str]
) -> tuple[Path, tuple[str, ...]]:
    if any(segment in {"..", "."} for segment in output.split("/")):
        raise OutputRejectedError("output_path_traversal")  # Path() would silently drop "."
    candidate = Path(output)
    if not candidate.is_absolute():
        bases = [root]
    else:
        bases = [root, root_as_given]
        for text in allowed:
            directory = Path(text)
            bases.append(directory)
            try:
                bases.append(directory.resolve(strict=True))
            except (OSError, RuntimeError):
                continue
    parts: tuple[str, ...] | None = None
    base = root
    if candidate.is_absolute():
        for option in bases:
            try:
                parts = candidate.relative_to(option).parts
            except ValueError:
                continue
            base = option
            break
        if parts is None:
            raise OutputRejectedError("output_outside_allowed_directories")
    else:
        parts = candidate.parts
    if not parts:
        raise OutputRejectedError("output_path_invalid")
    if ".." in parts or "." in parts:
        raise OutputRejectedError("output_path_traversal")
    try:
        resolved = base.resolve(strict=True)
    except (OSError, RuntimeError):
        raise OutputRejectedError("output_directory_missing") from None
    return resolved, parts


def _check_name(name: str) -> None:
    if not name or len(name) > _MAX_NAME or not name.isprintable() or "\\" in name:
        raise OutputRejectedError("output_name_invalid")
    lowered = name.lower()
    if lowered.startswith(_RESERVED_PREFIXES) or lowered.startswith(".soerm-report-"):
        raise OutputRejectedError("output_name_reserved")


def _open_directory(base: Path, parts: tuple[str, ...]) -> int:
    """Descriptor of the directory that holds the file; every step refuses symlinks."""
    try:
        current = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise OutputRejectedError("output_directory_missing") from None
    try:
        for part in parts:
            try:
                following = os.open(part, _DIR_FLAGS, dir_fd=current)
            except FileNotFoundError:
                raise OutputRejectedError("output_directory_missing") from None
            except OSError:  # ELOOP (symlink), ENOTDIR, EACCES ...
                raise OutputRejectedError("output_symlink_or_not_directory") from None
            os.close(current)
            current = following
    except BaseException:
        os.close(current)
        raise
    return current


def _is_report(directory: int, name: str) -> bool:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError:
        return False
    try:
        return _MARKER in os.read(descriptor, _MARKER_WINDOW)
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _read_back(directory: int, name: str, expected_size: int) -> str:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=directory)
    except OSError:
        raise OutputRejectedError("output_readback_failed") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
            raise OutputRejectedError("output_readback_mismatch")
        digest = hashlib.sha256()
        remaining = expected_size + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining != 1:  # more or fewer bytes than expected
            raise OutputRejectedError("output_readback_mismatch")
    except OSError:
        raise OutputRejectedError("output_readback_failed") from None
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def write_report_file(
    workspace: Path,
    output: str,
    data: bytes,
    *,
    force: bool,
    allowed_dirs: Sequence[str] = (),
) -> WrittenFile:
    """Write ``data`` atomically and verify it by reading it back. See the module docstring."""
    if not 0 < len(output) <= _MAX_PATH_TEXT or not output.isprintable():
        raise OutputRejectedError("output_path_invalid")
    absolute = Path(workspace).absolute()
    try:
        root = absolute.resolve(strict=True)
    except (OSError, RuntimeError):
        raise OutputRejectedError("workspace_missing") from None
    base, parts = _base_and_parts(output, root, absolute, allowed_dirs)
    name = parts[-1]
    _check_name(name)
    expected = hashlib.sha256(data).hexdigest()
    directory = _open_directory(base, parts[:-1])
    temporary = f".soerm-report-{os.urandom(8).hex()}.tmp"
    created = False
    try:
        existing: os.stat_result | None
        try:
            existing = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise OutputRejectedError("output_unreadable") from None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise OutputRejectedError("output_symlink_or_not_directory")
            if not stat.S_ISREG(existing.st_mode):
                raise OutputRejectedError("output_not_regular_file")
            if not force:
                raise OutputRejectedError("output_exists")
            if not _is_report(directory, name):
                raise OutputRejectedError("output_not_a_report")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
        except OSError:
            raise OutputRejectedError("output_unwritable") from None
        created = True
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        except OSError:
            raise OutputRejectedError("output_unwritable") from None
        finally:
            os.close(descriptor)
        try:
            if force:
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        except FileExistsError:
            raise OutputRejectedError("output_exists") from None
        except OSError:
            raise OutputRejectedError("output_unwritable") from None
        if force:
            created = False  # the temporary name no longer exists
        with contextlib.suppress(OSError):  # some filesystems refuse fsync on directories
            os.fsync(directory)
        actual = _read_back(directory, name, len(data))
        if actual != expected:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=directory)
            raise OutputRejectedError("output_readback_mismatch")
        return WrittenFile("/".join(parts), len(data), actual, existing is not None)
    finally:
        if created:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory)
        os.close(directory)
