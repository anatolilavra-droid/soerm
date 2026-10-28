"""Safe file access: containment, symlinks, special files, limits, encoding."""

import hashlib
import os
from pathlib import Path

import pytest

from soerm.domain.enums import ImportSource
from soerm.domain.imports import ImportRejectedError
from soerm.importers.safe_file import read_workspace_file
from soerm.services.errors import ImportServiceError, NotFoundServiceError
from tests.unit.importers.helpers import SECRET, config, put, run, sarif


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    return root


def reason(root: Path, path: str, limit: int = 1000) -> str:
    with pytest.raises(ImportRejectedError) as excinfo:
        read_workspace_file(root, path, max_bytes=limit)
    text = str(excinfo.value) + repr(excinfo.value.to_dict())
    assert str(root) not in text
    assert SECRET not in text
    return excinfo.value.reason


def test_reads_a_file_and_hashes_the_bytes(ws: Path) -> None:
    put(ws, "dir/a.txt", b"hello")
    safe = read_workspace_file(ws, "dir/a.txt", max_bytes=100)
    assert (safe.name, safe.data) == ("a.txt", b"hello")
    assert safe.sha256 == hashlib.sha256(b"hello").hexdigest()


def test_absolute_path_inside_the_workspace_is_accepted(ws: Path) -> None:
    put(ws, "a.txt", b"x")
    assert read_workspace_file(ws, str(ws / "a.txt"), max_bytes=10).data == b"x"
    assert read_workspace_file(ws, str(ws.resolve() / "a.txt"), max_bytes=10).data == b"x"


@pytest.mark.parametrize("path", ["../outside.txt", "a/../../outside.txt", "sub/../a.txt", ".."])
def test_path_traversal_is_refused(ws: Path, path: str) -> None:
    put(ws.parent, "outside.txt", b"x")
    put(ws, "a.txt", b"x")
    assert reason(ws, path) == "path_traversal"


def test_absolute_path_outside_the_workspace_is_refused(ws: Path) -> None:
    outside = put(ws.parent, "outside.txt", b"x")
    assert reason(ws, str(outside)) == "path_outside_workspace"
    assert reason(ws, "/etc/passwd") == "path_outside_workspace"


def test_sibling_directory_with_the_same_prefix_is_outside(ws: Path) -> None:
    sibling = put(ws.parent, "ws-evil/a.txt", b"x")
    assert reason(ws, str(sibling)) == "path_outside_workspace"


def test_symlink_to_a_file_inside_is_refused(ws: Path) -> None:
    put(ws, "real.txt", b"x")
    (ws / "link.txt").symlink_to(ws / "real.txt")
    assert reason(ws, "link.txt") == "symlink_not_allowed"


def test_symlink_pointing_outside_is_refused_and_not_followed(ws: Path) -> None:
    outside = put(ws.parent, "outside.txt", b"x")
    (ws / "link.txt").symlink_to(outside)
    assert reason(ws, "link.txt") == "symlink_not_allowed"


def test_symlinked_directory_component_is_refused(ws: Path) -> None:
    put(ws.parent, "elsewhere/a.txt", b"x")
    (ws / "d").symlink_to(ws.parent / "elsewhere", target_is_directory=True)
    assert reason(ws, "d/a.txt") == "symlink_not_allowed"


def test_dangling_symlink_and_symlink_loop(ws: Path) -> None:
    (ws / "dangling").symlink_to(ws / "nowhere")
    (ws / "loop").symlink_to(ws / "loop")
    assert reason(ws, "dangling") == "symlink_not_allowed"
    assert reason(ws, "loop") == "symlink_not_allowed"


def test_the_workspace_root_itself_may_be_a_symlink(ws: Path, tmp_path: Path) -> None:
    put(ws, "a.txt", b"x")
    alias = tmp_path / "alias"
    alias.symlink_to(ws, target_is_directory=True)
    assert read_workspace_file(alias, "a.txt", max_bytes=10).data == b"x"
    assert read_workspace_file(alias, str(alias / "a.txt"), max_bytes=10).data == b"x"


def test_non_regular_files_are_refused(ws: Path) -> None:
    (ws / "d").mkdir()
    os.mkfifo(ws / "fifo")
    assert reason(ws, "d") == "not_regular_file"
    assert reason(ws, "fifo") == "not_regular_file"


def test_missing_file_and_missing_workspace(ws: Path, tmp_path: Path) -> None:
    assert reason(ws, "nope.txt") == "file_missing"
    assert reason(ws, "nodir/nope.txt") == "file_missing"
    assert reason(tmp_path / "missing", "a.txt") == "workspace_missing"
    file_as_root = put(tmp_path, "file", b"x")
    assert reason(file_as_root, "a.txt") == "workspace_missing"


@pytest.mark.parametrize("path", ["", "a\x00b", "a\nb", "x" * 5000])
def test_invalid_path_text(ws: Path, path: str) -> None:
    assert reason(ws, path) == "path_invalid"


def test_size_limit_is_exact(ws: Path) -> None:
    put(ws, "a.bin", b"x" * 1000)
    assert len(read_workspace_file(ws, "a.bin", max_bytes=1000).data) == 1000
    put(ws, "b.bin", b"x" * 1001)
    assert reason(ws, "b.bin", 1000) == "import_file_too_large"


def test_never_reads_more_than_limit_plus_one(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    put(ws, "a.bin", b"x" * 5000)
    requested: list[int] = []
    real_read = os.read

    def spy(descriptor: int, count: int) -> bytes:
        requested.append(count)
        return real_read(descriptor, count)

    monkeypatch.setattr("soerm.importers.safe_file.os.read", spy)
    # fstat says 5000 > limit, so the file is refused before any read
    assert reason(ws, "a.bin", 100) == "import_file_too_large"
    assert requested == []


def test_errors_never_contain_paths_or_content(ws: Path) -> None:
    put(ws, f"{SECRET}.txt", b"x" * 50)
    with pytest.raises(ImportRejectedError) as excinfo:
        read_workspace_file(ws, f"{SECRET}.txt", max_bytes=10)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())


def test_service_maps_path_errors_to_stable_codes(ws: Path) -> None:
    put(ws, "a.sarif", sarif())
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "../x", ImportSource.SARIF)
    assert excinfo.value.code == "import_error"
    assert "path_traversal" in str(excinfo.value)
    with pytest.raises(NotFoundServiceError):
        run(ws / "missing", "a.sarif", ImportSource.SARIF)


def test_file_too_large_through_the_service_uses_the_configured_limit(ws: Path) -> None:
    config(ws, "imports:\n  max_import_file_bytes: 1024\n")
    put(ws, "big.sarif", sarif() + " " * 2000)
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "big.sarif", ImportSource.SARIF)
    assert "import_file_too_large" in str(excinfo.value)
