"""The snapshot behind the screens: complete, safe and read-only."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.tui.data import MAX_ROWS, Snapshot, load_snapshot, render_plain
from tests.unit.tui.conftest import (
    DESCRIPTION_MARKER,
    EVIDENCE_MARKER,
    SECRET,
    SUMMARY_MARKER,
)


def everything(snapshot: Snapshot) -> str:
    parts = [snapshot.generated_at, repr(snapshot.audit), repr(snapshot.summary)]
    parts += [repr(snapshot.attention), snapshot.report_markdown, render_plain(snapshot)]
    for table in snapshot.tables:
        parts += [table.title, repr(table.columns)]
        parts += [repr((row.key, row.cells, row.details)) for row in table.rows]
    return "\n".join(parts)


def test_tables_and_counts(snapshot: Snapshot) -> None:
    names = [t.name for t in snapshot.tables]
    assert names == ["assets", "findings", "incidents", "tasks", "approvals", "playbooks"]
    assert len(snapshot.table("assets").rows) == 1
    assert len(snapshot.table("findings").rows) == 2
    assert len(snapshot.table("incidents").rows) == 1
    assert len(snapshot.table("tasks").rows) == 1
    assert len(snapshot.table("approvals").rows) == 1
    assert len(snapshot.table("playbooks").rows) == 1
    for table in snapshot.tables:
        for row in table.rows:
            assert len(row.cells) == len(table.columns)


def test_no_secrets_descriptions_evidence_or_summaries(snapshot: Snapshot) -> None:
    text = everything(snapshot)
    for forbidden in (SECRET, DESCRIPTION_MARKER, EVIDENCE_MARKER, SUMMARY_MARKER):
        assert forbidden not in text
    assert "block the domain" not in text  # approval reasons are not shown


def test_playbook_shows_titles_and_progress_but_not_step_text(snapshot: Snapshot) -> None:
    row = snapshot.table("playbooks").rows[0]
    flat = repr(row)
    assert "Block the sender domain" in flat
    assert "approval required" in flat
    assert "INC-000001: 1/4" in flat
    assert "Read the reported message headers" not in flat


def test_values_hold_no_control_characters(snapshot: Snapshot) -> None:
    for char in everything(snapshot):
        if char in "\n":
            continue
        assert char.isprintable(), repr(char)


def test_hostile_text_is_flattened_and_redacted(populated: Path) -> None:
    with closing(sqlite3.connect(populated / DATABASE_FILE_NAME, isolation_level=None)) as raw:
        for (name,) in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall():
            if "finding" in name and "update" in name:
                raw.execute(f"DROP TRIGGER {name}")
        try:
            raw.execute(
                "UPDATE findings SET title = ? WHERE finding_id = 'FND-000002'",
                (f"x password={SECRET}\x1b[31m‮\nline",),
            )
        except sqlite3.Error:
            return
    snapshot = load_snapshot(Workspace(populated))
    text = everything(snapshot)
    assert SECRET not in text
    assert "\x1b" not in text
    assert "‮" not in text


def test_loading_changes_nothing(populated: Path) -> None:
    def dump() -> str:
        with closing(sqlite3.connect(populated / DATABASE_FILE_NAME)) as raw:
            names = [r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            return repr([raw.execute(f"SELECT * FROM {n}").fetchall() for n in sorted(names)])  # noqa: S608

    before = dump()
    files = sorted(p.name for p in populated.iterdir())
    load_snapshot(Workspace(populated))
    assert dump() == before
    assert sorted(p.name for p in populated.iterdir()) == files


def test_row_limit_is_applied(populated: Path) -> None:
    assert MAX_ROWS >= 100
    snapshot = load_snapshot(Workspace(populated))
    assert not any(t.truncated for t in snapshot.tables)


def test_plain_overview(snapshot: Snapshot) -> None:
    text = render_plain(snapshot)
    assert "audit: intact" in text
    assert "Findings" in text
    assert "active P1" in text


def test_plain_overview_is_compact_and_readable(snapshot: Snapshot) -> None:
    text = render_plain(snapshot)
    assert len(text.splitlines()) <= 16  # fits a 20-row terminal with the prompt
    assert "attention:" in text
    assert "Active P1 findings" in text
    assert "active_p1_findings" not in text
    assert "objects: Assets 1 | Findings 2" in text
    assert "T" not in text.split("generated: ")[1].splitlines()[0]
    assert "LISTS TRUNCATED" not in text


def test_plain_overview_flags_truncation_and_a_broken_chain(
    snapshot: Snapshot, monkeypatch: pytest.MonkeyPatch
) -> None:
    import dataclasses

    cut = dataclasses.replace(snapshot.tables[0], truncated=True)
    broken = dataclasses.replace(
        snapshot, audit_intact=False, tables=(cut, *snapshot.tables[1:]),
    )  # fmt: skip
    text = render_plain(broken)
    assert "LISTS TRUNCATED" in text
    assert "audit: BROKEN" in text
