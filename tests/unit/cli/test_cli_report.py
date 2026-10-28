"""``report preview`` / ``report generate``: flows, exit codes, safe output."""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.services.workspace import DATABASE_FILE_NAME
from soerm.storage.lock import LOCK_FILE_NAME
from tests.unit.cli.conftest import Runner, add_asset, add_finding, assert_terminal_safe
from tests.unit.services.helpers import raw_execute

SECRET = "hunter2-TOP-SECRET-token"
AT = "2026-11-01T00:00:00Z"


def w(path: Path) -> list[str]:
    return ["--workspace", str(path)]


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    out = add_finding(
        cli, workspace, "--description", "DESCRIPTION-MARKER", "--evidence", f"EV-MARKER {SECRET}"
    )
    assert out.code == 0, out.err
    return workspace


def db_bytes(path: Path) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(path / DATABASE_FILE_NAME)) as raw:
        names = [r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return sorted((n, repr(raw.execute(f"SELECT * FROM {n}").fetchall())) for n in names)  # noqa: S608


def test_preview_prints_and_writes_nothing(cli: Runner, ws: Path) -> None:
    before = sorted(p.name for p in ws.iterdir())
    snap = db_bytes(ws)
    result = cli("report", "preview", *w(ws), "--generated-at", AT)
    assert result.code == 0, result.err
    assert "soerm-report-v1" in result.out
    assert "Billing API" in result.out
    for forbidden in ("DESCRIPTION-MARKER", "EV-MARKER", SECRET):
        assert forbidden not in result.out
    assert_terminal_safe(result.out)
    assert sorted(p.name for p in ws.iterdir()) == before
    assert db_bytes(ws) == snap


def test_preview_json(cli: Runner, ws: Path) -> None:
    result = cli("report", "preview", *w(ws), "--format", "json", "--generated-at", AT)
    assert result.code == 0
    assert json.loads(result.out)["executive_summary"]["active_findings"] == 1


def test_preview_without_database_creates_nothing(cli: Runner, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = cli("report", "preview", *w(empty))
    assert result.code == 1
    assert "workspace_not_initialized" in result.err
    assert list(empty.iterdir()) == []


def test_workspace_is_required(cli: Runner) -> None:
    assert cli("report", "preview").code == 2
    assert cli("report", "generate", "--output", "r.md").code == 2


def test_generate_markdown_and_json(cli: Runner, ws: Path) -> None:
    md = cli("report", "generate", *w(ws), "--output", "report.md", "--generated-at", AT)
    assert md.code == 0, md.err
    assert "report.md" in md.out
    text = (ws / "report.md").read_text(encoding="utf-8")
    assert text.startswith("<!-- soerm-report-v1 -->")
    assert hashlib.sha256(text.encode()).hexdigest() in md.out
    js = cli(
        "report", "generate", *w(ws), "--output", "report.json", "--format", "json",
        "--generated-at", AT, "--json",
    )  # fmt: skip
    assert js.code == 0, js.err
    summary = js.json()
    assert summary["sha256"] == hashlib.sha256((ws / "report.json").read_bytes()).hexdigest()
    assert summary["readback_verified"] is True
    assert json.loads((ws / "report.json").read_text(encoding="utf-8"))["report_schema"]
    for name in ("report.md", "report.json"):
        content = (ws / name).read_text(encoding="utf-8")
        for forbidden in ("DESCRIPTION-MARKER", "EV-MARKER", SECRET):
            assert forbidden not in content
    assert SECRET not in js.out


def test_generate_does_not_change_the_database(cli: Runner, ws: Path) -> None:
    snap = db_bytes(ws)
    assert cli("report", "generate", *w(ws), "--output", "report.md").code == 0
    assert db_bytes(ws) == snap


def test_generate_is_deterministic(cli: Runner, ws: Path) -> None:
    for name in ("one.md", "two.md"):
        assert cli("report", "generate", *w(ws), "--output", name, "--generated-at", AT).code == 0
    assert (ws / "one.md").read_bytes() == (ws / "two.md").read_bytes()


def test_overwrite_needs_force_and_actor(cli: Runner, ws: Path) -> None:
    args = ["report", "generate", *w(ws), "--output", "report.md", "--generated-at", AT]
    assert cli(*args).code == 0
    again = cli(*args)
    assert again.code == 1
    assert "output_exists" in again.err
    no_actor = cli(*args, "--force")
    assert no_actor.code == 2
    assert "--actor" in no_actor.err
    forced = cli(*args, "--force", "--actor", "bob", "--json")
    assert forced.code == 0
    assert forced.json()["result"] == "replaced"


def test_force_never_replaces_a_foreign_file(cli: Runner, ws: Path) -> None:
    (ws / "notes.md").write_text("mine", encoding="utf-8")
    result = cli("report", "generate", *w(ws), "--output", "notes.md", "--force", "--actor", "bob")
    assert result.code == 1
    assert "output_not_a_report" in result.err
    assert (ws / "notes.md").read_text(encoding="utf-8") == "mine"


@pytest.mark.parametrize("bad", ["../escape.md", "a/../../escape.md", "/etc/escape.md", "./x.md"])
def test_output_escapes_are_refused(cli: Runner, ws: Path, bad: str) -> None:
    (ws / "a").mkdir()
    result = cli("report", "generate", *w(ws), "--output", bad)
    assert result.code == 1
    assert bad not in result.err  # the value is never echoed
    assert not (ws.parent / "escape.md").exists()


def test_symlink_outputs_are_refused(cli: Runner, ws: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (ws / "link").symlink_to(outside)
    (ws / "file.md").symlink_to(outside / "target.md")
    assert cli("report", "generate", *w(ws), "--output", "link/report.md").code == 1
    assert cli("report", "generate", *w(ws), "--output", "file.md").code == 1
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", [DATABASE_FILE_NAME, LOCK_FILE_NAME, "soerm.yaml"])
def test_workspace_internals_are_not_targets(cli: Runner, ws: Path, name: str) -> None:
    before = (ws / name).read_bytes() if (ws / name).exists() else None
    result = cli("report", "generate", *w(ws), "--output", name, "--force", "--actor", "bob")
    assert result.code == 1
    assert ((ws / name).read_bytes() if (ws / name).exists() else None) == before


def test_invalid_format_is_a_usage_error(cli: Runner, ws: Path) -> None:
    assert cli("report", "generate", *w(ws), "--output", "r.x", "--format", "pdf").code == 2


def test_invalid_actor_is_not_echoed(cli: Runner, ws: Path) -> None:
    (ws / "report.md").write_text("<!-- soerm-report-v1 -->\n", encoding="utf-8")
    result = cli(
        "report", "generate", *w(ws), "--output", "report.md", "--force", "--actor", "bad actor!"
    )
    assert result.code != 0
    assert "bad actor" not in result.err


def test_broken_audit_gives_exit_3_but_still_reports(cli: Runner, ws: Path) -> None:
    with closing(sqlite3.connect(ws / DATABASE_FILE_NAME)) as raw:
        triggers = [
            r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        ]
    for name in triggers:
        if "audit" in name:
            raw_execute(ws, f"DROP TRIGGER IF EXISTS {name}")
    raw_execute(ws, "UPDATE audit_log SET entry_hash = ? WHERE seq = 1", ("f" * 64,))
    preview = cli("report", "preview", *w(ws), "--generated-at", AT)
    assert preview.code == 3
    assert "audit" in preview.err.lower()
    assert "soerm-report-v1" in preview.out
    generated = cli("report", "generate", *w(ws), "--output", "report.md", "--generated-at", AT)
    assert generated.code == 3
    assert (ws / "report.md").is_file()
