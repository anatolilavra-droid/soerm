"""``soerm tui``: plain fallback, exit codes, terminal probe, missing extra."""

import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest

from soerm.services.workspace import DATABASE_FILE_NAME
from soerm.tui import terminal
from tests.unit.cli.conftest import Runner, assert_terminal_safe
from tests.unit.tui.conftest import DESCRIPTION_MARKER, EVIDENCE_MARKER, SECRET


def w(path: Path) -> list[str]:
    return ["--workspace", str(path)]


def test_help_works_and_documents_the_keys(cli: Runner) -> None:
    result = cli("tui", "--help")
    assert result.code == 0
    for text in ("Read-only", "Ctrl+P", "--plain", "--workspace"):
        assert text in result.out


def test_workspace_is_required(cli: Runner) -> None:
    assert cli("tui").code == 2
    assert cli("tui", "--bogus", "--workspace", "x").code == 2


def test_plain_overview(cli: Runner, populated: Path) -> None:
    result = cli("tui", *w(populated), "--plain")
    assert result.code == 0, result.err
    assert "active findings" in result.out
    assert "Findings" in result.out
    assert result.err == ""
    assert_terminal_safe(result.out)
    for forbidden in (SECRET, DESCRIPTION_MARKER, EVIDENCE_MARKER):
        assert forbidden not in result.out


def test_without_a_terminal_the_plain_overview_is_the_fallback(
    cli: Runner, populated: Path
) -> None:
    result = cli("tui", *w(populated))  # pytest's capture is not a TTY
    assert result.code == 0
    assert "not_a_terminal" in result.err
    assert "SOERM overview" in result.out


def test_missing_workspace_uses_the_usual_error(cli: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = cli("tui", *w(empty), "--plain")
    assert result.code == 1
    assert "workspace_not_initialized" in result.err
    assert list(empty.iterdir()) == []


def test_broken_audit_chain_exit_code_in_plain_mode(cli: Runner, populated: Path) -> None:
    with closing(sqlite3.connect(populated / DATABASE_FILE_NAME, isolation_level=None)) as raw:
        for (name,) in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall():
            if "audit" in name:
                raw.execute(f"DROP TRIGGER {name}")
        raw.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = 2", ("e" * 64,))
    result = cli("tui", *w(populated), "--plain")
    assert result.code == 3
    assert "BROKEN" in result.out


def test_missing_textual_extra_is_reported(
    cli: Runner, populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(terminal, "unsupported_reason", lambda: None)
    monkeypatch.setitem(sys.modules, "soerm.tui.app", None)  # import raises ImportError
    result = cli("tui", *w(populated))
    assert result.code == 1
    assert "tui_unavailable" in result.err
    assert "soerm[tui]" in result.err


def test_the_app_is_started_when_the_terminal_is_capable(
    cli: Runner, populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soerm.tui.app as app_module

    started: list[object] = []
    monkeypatch.setattr(terminal, "unsupported_reason", lambda: None)
    monkeypatch.setattr(app_module.SoermApp, "run", lambda self: started.append(self))
    result = cli("tui", *w(populated))
    assert result.code == 0
    assert len(started) == 1


class FakeStream:
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def fileno(self) -> int:
        return 1

    def isatty(self) -> bool:
        return self._tty


def probe(
    monkeypatch: pytest.MonkeyPatch, *, tty: bool = True, term: str = "xterm-256color",
    size: tuple[int, int] = (120, 40),
) -> str | None:  # fmt: skip
    monkeypatch.setattr(sys, "stdin", FakeStream(tty))
    monkeypatch.setattr(sys, "stdout", FakeStream(tty))
    monkeypatch.setenv("TERM", term)
    monkeypatch.setattr(os, "get_terminal_size", lambda _fd=0: _Size(*size))
    return terminal.unsupported_reason()


class _Size:
    def __init__(self, columns: int, lines: int) -> None:
        self.columns = columns
        self.lines = lines


def test_terminal_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    assert probe(monkeypatch) is None
    assert probe(monkeypatch, tty=False) == "not_a_terminal"
    assert probe(monkeypatch, term="dumb") == "dumb_terminal"
    assert probe(monkeypatch, term="") == "dumb_terminal"
    assert probe(monkeypatch, size=(79, 40)) == "terminal_too_small"
    assert probe(monkeypatch, size=(120, 23)) == "terminal_too_small"
    assert probe(monkeypatch, size=(80, 24)) is None


def test_terminal_probe_without_a_size(monkeypatch: pytest.MonkeyPatch) -> None:
    probe(monkeypatch)

    def no_size(_fd: int = 0) -> None:
        raise OSError("no terminal")

    monkeypatch.setattr(os, "get_terminal_size", no_size)
    assert terminal.unsupported_reason() == "not_a_terminal"
