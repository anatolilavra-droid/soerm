"""Writing the report file: containment, symlinks, overwrite rules, atomicity, read-back."""

import hashlib
import os
from pathlib import Path

import pytest

from soerm.domain.report import REPORT_SCHEMA, OutputRejectedError
from soerm.outputs import safe_write
from soerm.outputs.safe_write import write_report_file

DATA = f"<!-- {REPORT_SCHEMA} -->\nhello\n".encode()
SHA = hashlib.sha256(DATA).hexdigest()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "ws"
    path.mkdir()
    return path


def reason(exc: pytest.ExceptionInfo[OutputRejectedError]) -> str:
    return exc.value.reason


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".soerm-report-"))


def test_writes_and_verifies(root: Path) -> None:
    written = write_report_file(root, "report.md", DATA, force=False)
    assert written.sha256 == SHA
    assert written.size == len(DATA)
    assert not written.replaced
    assert (root / "report.md").read_bytes() == DATA
    assert leftovers(root) == []


def test_file_is_private(root: Path) -> None:
    write_report_file(root, "report.md", DATA, force=False)
    assert (root / "report.md").stat().st_mode & 0o777 == 0o600


def test_subdirectory_must_exist_and_is_not_created(root: Path) -> None:
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "out/report.md", DATA, force=False)
    assert reason(exc) == "output_directory_missing"
    assert not (root / "out").exists()
    (root / "out").mkdir()
    write_report_file(root, "out/report.md", DATA, force=False)
    assert (root / "out" / "report.md").exists()


@pytest.mark.parametrize("bad", ["../x.md", "a/../../x.md", "./x.md", "a/./x.md"])
def test_traversal_is_refused(root: Path, bad: str) -> None:
    (root / "a").mkdir()
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, bad, DATA, force=False)
    assert reason(exc) == "output_path_traversal"


def test_absolute_path_outside_is_refused(root: Path, tmp_path: Path) -> None:
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, str(tmp_path / "elsewhere.md"), DATA, force=False)
    assert reason(exc) == "output_outside_allowed_directories"
    assert not (tmp_path / "elsewhere.md").exists()


def test_absolute_path_inside_the_workspace_is_fine(root: Path) -> None:
    written = write_report_file(root, str(root / "abs.md"), DATA, force=False)
    assert written.path == "abs.md"


def test_allowed_external_directory(root: Path, tmp_path: Path) -> None:
    external = tmp_path / "exports"
    external.mkdir()
    write_report_file(root, str(external / "r.md"), DATA, force=False, allowed_dirs=[str(external)])
    assert (external / "r.md").read_bytes() == DATA
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(OutputRejectedError):
        write_report_file(
            root, str(other / "r.md"), DATA, force=False, allowed_dirs=[str(external)]
        )


def test_symlinked_directory_is_refused(root: Path, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (root / "link").symlink_to(target)
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "link/report.md", DATA, force=False)
    assert reason(exc) == "output_symlink_or_not_directory"
    assert list(target.iterdir()) == []


def test_symlinked_target_file_is_refused_even_with_force(root: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious", encoding="utf-8")
    (root / "report.md").symlink_to(victim)
    for force in (False, True):
        with pytest.raises(OutputRejectedError):
            write_report_file(root, "report.md", DATA, force=force)
    assert victim.read_text(encoding="utf-8") == "precious"


def test_dangling_symlink_is_refused(root: Path, tmp_path: Path) -> None:
    (root / "report.md").symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(OutputRejectedError):
        write_report_file(root, "report.md", DATA, force=False)
    assert not (tmp_path / "does-not-exist").exists()


def test_workspace_that_is_a_symlink_is_resolved_once(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    write_report_file(link, "report.md", DATA, force=False)  # the root itself may be a link
    assert (real / "report.md").exists()


def test_existing_file_is_not_overwritten(root: Path) -> None:
    (root / "report.md").write_text("mine", encoding="utf-8")
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "report.md", DATA, force=False)
    assert reason(exc) == "output_exists"
    assert (root / "report.md").read_text(encoding="utf-8") == "mine"
    assert leftovers(root) == []


def test_force_replaces_only_a_previous_report(root: Path) -> None:
    write_report_file(root, "report.md", DATA, force=False)
    newer = f"<!-- {REPORT_SCHEMA} -->\nnewer\n".encode()
    written = write_report_file(root, "report.md", newer, force=True)
    assert written.replaced
    assert (root / "report.md").read_bytes() == newer
    (root / "notes.txt").write_text("not a report", encoding="utf-8")
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "notes.txt", DATA, force=True)
    assert reason(exc) == "output_not_a_report"
    assert (root / "notes.txt").read_text(encoding="utf-8") == "not a report"


def test_directory_target_is_refused(root: Path) -> None:
    (root / "report.md").mkdir()
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "report.md", DATA, force=True)
    assert reason(exc) == "output_not_regular_file"


@pytest.mark.parametrize(
    "name", ["soerm.db", "soerm.db-wal", ".soerm.lock", "soerm.yaml", "SOERM.DB"]
)
def test_reserved_names(root: Path, name: str) -> None:
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, name, DATA, force=True)
    assert reason(exc) == "output_name_reserved"


@pytest.mark.parametrize("text", ["", "a\nb.md", "a\x00b.md", "x" * 5000])
def test_bad_path_text(root: Path, text: str) -> None:
    with pytest.raises(OutputRejectedError):
        write_report_file(root, text, DATA, force=False)


def test_failed_write_leaves_nothing(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_fsync(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken_fsync)
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "report.md", DATA, force=False)
    assert reason(exc) == "output_unwritable"
    assert not (root / "report.md").exists()
    assert leftovers(root) == []


def test_failed_force_keeps_the_old_report(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_report_file(root, "report.md", DATA, force=False)

    def broken_fsync(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken_fsync)
    with pytest.raises(OutputRejectedError):
        write_report_file(root, "report.md", b"<!-- soerm-report-v1 -->\nnew", force=True)
    assert (
        root / "report.md"
    ).read_bytes() == DATA  # replacement is atomic: old or new, never half
    assert leftovers(root) == []


def test_readback_mismatch_removes_the_file(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_write, "_read_back", lambda *_a, **_k: "0" * 64)
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "report.md", DATA, force=False)
    assert reason(exc) == "output_readback_mismatch"
    assert not (root / "report.md").exists()
    assert leftovers(root) == []


def test_readback_detects_a_truncated_file(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_link = os.link

    def truncating_link(src, dst, **kwargs):  # type: ignore[no-untyped-def]
        real_link(src, dst, **kwargs)
        os.truncate(root / dst, 3)

    monkeypatch.setattr(os, "link", truncating_link)
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "report.md", DATA, force=False)
    assert reason(exc) == "output_readback_mismatch"


def test_workspace_must_exist(tmp_path: Path) -> None:
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(tmp_path / "missing", "r.md", DATA, force=False)
    assert reason(exc) == "workspace_missing"


def test_error_messages_hold_no_path(root: Path) -> None:
    with pytest.raises(OutputRejectedError) as exc:
        write_report_file(root, "../secret-name.md", DATA, force=False)
    assert "secret-name" not in str(exc.value)
    assert str(root) not in str(exc.value)
