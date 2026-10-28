"""Reading a file that must live inside the workspace - the only filesystem code of M5.

Checks, in order: the path text; the workspace root (``resolve(strict=True)``, a directory);
containment (a relative path is taken relative to the root, an absolute path must be inside
it, ``..`` is refused); every component from the root down with ``lstat`` - no symlink anywhere,
the last one a regular file; ``resolve(strict=True)`` again as a second opinion; then
``open(O_NOFOLLOW)``, ``fstat`` (regular file, same device and inode as the ``lstat``), the size
limit, and a read of at most ``limit + 1`` bytes. Errors carry stable reasons and never a path.
"""

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from soerm.domain.imports import ImportRejectedError

__all__ = ["SafeFile", "read_workspace_file"]

_MAX_PATH_TEXT: Final = 4096
_CHUNK: Final = 65536


@dataclass(frozen=True, slots=True)
class SafeFile:
    """File name (last component only), its bytes and their SHA-256."""

    name: str
    data: bytes
    sha256: str


def _root(workspace: Path) -> tuple[Path, Path]:
    absolute = Path(workspace).absolute()
    try:
        real = absolute.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ImportRejectedError("workspace_missing") from None
    if not real.is_dir():
        raise ImportRejectedError("workspace_missing")
    return real, absolute


def _relative_parts(user_path: str, root: Path, root_as_given: Path) -> tuple[str, ...]:
    candidate = Path(user_path)
    if candidate.is_absolute():
        for base in (root, root_as_given):
            try:
                candidate = candidate.relative_to(base)
                break
            except ValueError:
                continue
        else:
            raise ImportRejectedError("path_outside_workspace")
    parts = candidate.parts
    if not parts:
        raise ImportRejectedError("path_invalid")
    if ".." in parts:
        raise ImportRejectedError("path_traversal")
    return parts


def _walk(root: Path, parts: tuple[str, ...]) -> tuple[Path, os.stat_result]:
    current = root
    info = os.stat_result((0,) * 10)
    for position, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise ImportRejectedError("file_missing") from None
        except OSError:
            raise ImportRejectedError("file_unreadable") from None
        if stat.S_ISLNK(info.st_mode):
            raise ImportRejectedError("symlink_not_allowed")
        last = position == len(parts) - 1
        if last and not stat.S_ISREG(info.st_mode):
            raise ImportRejectedError("not_regular_file")
        if not last and not stat.S_ISDIR(info.st_mode):
            raise ImportRejectedError("file_missing")
    return current, info


def _read(path: Path, expected: os.stat_result, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ImportRejectedError("file_unreadable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ImportRejectedError("not_regular_file")
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise ImportRejectedError("file_changed")
        if info.st_size > max_bytes:
            raise ImportRejectedError("import_file_too_large")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        raise ImportRejectedError("file_unreadable") from None
    finally:
        os.close(descriptor)
    if total > max_bytes:
        raise ImportRejectedError("import_file_too_large")
    return b"".join(chunks)


def read_workspace_file(workspace: Path, user_path: str, *, max_bytes: int) -> SafeFile:
    """Read ``user_path`` (inside ``workspace``) after all checks; at most ``max_bytes``."""
    if not 0 < len(user_path) <= _MAX_PATH_TEXT or not user_path.isprintable():
        raise ImportRejectedError("path_invalid")
    root, root_as_given = _root(workspace)
    parts = _relative_parts(user_path, root, root_as_given)
    path, info = _walk(root, parts)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ImportRejectedError("file_missing") from None
    if resolved != path or not resolved.is_relative_to(root):
        raise ImportRejectedError("path_outside_workspace")
    data = _read(path, info, max_bytes)
    return SafeFile(parts[-1], data, hashlib.sha256(data).hexdigest())
