"""The app driven headlessly with Textual's pilot (no real terminal needed)."""

import re
from pathlib import Path
from typing import Any

import pytest
from rich.text import Text
from textual.coordinate import Coordinate
from textual.widgets import DataTable, Static, TabbedContent

from soerm.services.workspace import DATABASE_FILE_NAME
from soerm.tui.app import SECTIONS, SoermApp, TablePane
from soerm.tui.theme import THEME_NAME
from tests.unit.cli.conftest import ASSET_ARGS, Runner
from tests.unit.tui.conftest import INJECTION, SECRET, drive, run_ok

TABLE_SECTIONS = ("assets", "findings", "incidents", "tasks", "approvals", "playbooks")


def active(app: SoermApp) -> str:
    return str(app.query_one("#tabs", TabbedContent).active)


def static_text(app: SoermApp, selector: str) -> str:
    widget = app.query_one(selector, Static)
    return str(widget.render())


def test_every_screen_is_reachable_by_its_key(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        assert app.theme == THEME_NAME
        assert active(app) == "dashboard"
        for number, (name, _) in enumerate(SECTIONS, start=1):
            await pilot.press(str(number))
            await pilot.pause()
            assert active(app) == name

    drive(populated, scenario)


def test_tables_are_filled_and_the_cursor_updates_the_detail(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        counts = {
            name: app.query_one(f"#pane-{name}", TablePane).row_count for name in TABLE_SECTIONS
        }
        expected = {"assets": 1, "findings": 2, "incidents": 1}
        expected |= {"tasks": 1, "approvals": 1, "playbooks": 1}
        assert counts == expected
        await pilot.press("3")
        await pilot.pause()
        first = static_text(app, "#detail-findings")
        assert "FND-000001" in first
        await pilot.press("down")
        await pilot.pause()
        assert "FND-000002" in static_text(app, "#detail-findings")

    drive(populated, scenario)


def test_markup_in_data_is_shown_literally(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("3")
        await pilot.pause()
        table = app.query_one("#table-findings", DataTable)
        cells = [table.get_cell_at(Coordinate(0, column)) for column in range(len(table.columns))]
        assert all(isinstance(cell, Text) for cell in cells)
        title = cells[-1].plain
        assert "[bold red]" in title  # the brackets are text, not styling
        detail = app.query_one("#detail-findings", Static).render()
        assert "[bold red]" in " ".join(str(detail).split())  # wrapped lines, same literal text

    drive(populated, scenario)
    assert "[bold red]" in INJECTION


def test_filter_narrows_rows_and_escape_restores_them(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        pane = app.query_one("#pane-findings", TablePane)
        await pilot.press("3")
        await pilot.press("slash")
        await pilot.press(*"tls")
        await pilot.pause()
        assert pane.row_count == 1
        await pilot.press("escape")
        await pilot.pause()
        assert pane.row_count == 2
        await pilot.press("slash")
        await pilot.press(*"nothing-matches")
        await pilot.pause()
        assert pane.row_count == 0
        empty = static_text(app, "#empty-findings")
        assert 'No rows match "nothing-matches"' in empty
        assert "Esc" in empty
        assert app.query_one("#empty-findings", Static).has_class("visible")
        assert not app.query_one("#table-findings", DataTable).display
        assert "0 of 2" in str(app.query_one("#filter").border_subtitle)

    drive(populated, scenario)


def test_dashboard_report_and_audit_screens(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        summary = static_text(app, "#kpi-summary")
        assert "active findings" in summary
        assert "2" in summary
        await pilot.press("8")
        await pilot.pause()
        assert "soerm-report-v1" in static_text(app, "#text-report")
        await pilot.press("9")
        await pilot.pause()
        audit = static_text(app, "#text-audit")
        assert "intact" in audit
        assert "head hash" in audit

    drive(populated, scenario)


def test_no_secret_is_rendered_anywhere(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        for number in range(1, len(SECTIONS) + 1):
            await pilot.press(str(number))
            await pilot.pause()
        svg = app.export_screenshot()
        assert SECRET not in svg
        for selector in ("#kpi-summary", "#kpi-attention", "#text-report", "#text-audit"):
            assert SECRET not in static_text(app, selector)

    drive(populated, scenario)


def test_refresh_picks_up_new_data_and_writes_nothing(cli: Runner, populated: Path) -> None:
    files = sorted(p.name for p in populated.iterdir())

    async def scenario(app: SoermApp, pilot: Any) -> None:
        pane = app.query_one("#pane-assets", TablePane)
        assert pane.row_count == 1
        run_ok(cli, "asset", "add", "--workspace", str(populated), "--actor", "alice", *ASSET_ARGS)
        await pilot.press("r")
        await pilot.pause()
        assert pane.row_count == 2

    drive(populated, scenario)
    assert sorted(p.name for p in populated.iterdir()) == files


def test_verify_key_opens_the_audit_screen(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("v")
        await pilot.pause()
        assert active(app) == "audit"

    drive(populated, scenario)


def test_broken_audit_chain_turns_the_banner_red(populated: Path) -> None:
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(populated / DATABASE_FILE_NAME, isolation_level=None)) as raw:
        for (name,) in raw.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall():
            if "audit" in name:
                raw.execute(f"DROP TRIGGER {name}")
        raw.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = 2", ("e" * 64,))

    async def scenario(app: SoermApp, pilot: Any) -> None:
        banner = app.query_one("#banner", Static)
        assert banner.has_class("broken")
        assert "BROKEN" in str(banner.render())
        await pilot.press("9")
        await pilot.pause()
        assert "broken" in static_text(app, "#text-audit")
        assert app.query_one("#audit-verdict", Static).has_class("crit")
        assert "✖ CHAIN BROKEN" in static_text(app, "#audit-verdict")
        assert "cannot be trusted" in static_text(app, "#audit-verdict")
        assert "✖ AUDIT CHAIN BROKEN" in str(banner.render())
        tabs = app.query_one("#tabs", TabbedContent)
        assert tabs.get_tab("audit").label.plain.endswith("✖")

    drive(populated, scenario)


def test_failed_refresh_keeps_the_screen_and_reports_only_a_code(
    populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soerm.tui.app as app_module

    def boom(_workspace: object) -> None:
        raise RuntimeError(f"password={SECRET}")

    async def scenario(app: SoermApp, pilot: Any) -> None:
        monkeypatch.setattr(app_module, "load_snapshot", boom)
        await pilot.press("r")
        await pilot.pause()
        assert app.query_one("#pane-assets", TablePane).row_count == 1
        messages = " ".join(str(n.message) for n in app._notifications)
        assert "refresh failed" in messages
        assert SECRET not in messages

    drive(populated, scenario)


def test_command_palette_lists_navigation_and_no_file_writing_command(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        titles = [c.title for c in app.get_system_commands(app.screen)]
        for _, title in SECTIONS:
            assert f"Go to {title}" in titles
        for expected in ("Refresh data", "Verify audit chain", "Show keys", "Quit"):
            assert expected in titles
        assert not any("screenshot" in t.casefold() for t in titles)
        command = next(c for c in app.get_system_commands(app.screen) if c.title == "Go to Tasks")
        command.callback()
        await pilot.pause()
        assert active(app) == "tasks"

    drive(populated, scenario)


def test_help_key_and_quit(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("question_mark")
        await pilot.pause()
        assert any("Ctrl+P" in str(n.message) for n in app._notifications)
        await pilot.press("q")

    drive(populated, scenario)


def test_small_and_large_screens_both_work(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("3")
        await pilot.pause()
        assert active(app) == "findings"

    drive(populated, scenario, size=(80, 24))
    drive(populated, scenario, size=(220, 60))


def test_empty_workspace_renders(cli: Runner, workspace: Path) -> None:
    run_ok(cli, "asset", "add", "--workspace", str(workspace), "--actor", "alice", *ASSET_ARGS)

    async def scenario(app: SoermApp, pilot: Any) -> None:
        for number in range(1, len(SECTIONS) + 1):
            await pilot.press(str(number))
            await pilot.pause()
        assert app.query_one("#pane-findings", TablePane).row_count == 0
        empty = static_text(app, "#empty-findings")
        assert "No findings yet" in empty
        assert "soerm import run" in empty
        assert "read-only" in empty

    drive(workspace, scenario)


def test_truncation_is_announced_in_the_banner(
    populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soerm.tui.data as data_module

    monkeypatch.setattr(data_module, "MAX_ROWS", 1)

    async def scenario(app: SoermApp, pilot: Any) -> None:
        assert "LISTS TRUNCATED" in static_text(app, "#banner")
        assert app.query_one("#pane-findings", TablePane).row_count == 1

    drive(populated, scenario)


def test_status_bar_shows_audit_badge_and_time_but_no_key_hints(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        banner = static_text(app, "#banner")
        assert "SOERM" in banner
        assert "✔ AUDIT CHAIN INTACT" in banner
        assert "generated 20" in banner
        assert "Ctrl+P" not in banner  # the footer carries the key hints
        assert not app.query_one("#banner", Static).has_class("broken")

    drive(populated, scenario)


def test_tabs_carry_counts_and_flag_attention(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        tabs = app.query_one("#tabs", TabbedContent)
        label = {name: tabs.get_tab(name).label.plain for name, _ in SECTIONS}
        assert label["findings"] == "3 Findings 2"
        assert label["approvals"] == "6 Approvals 1"
        assert label["dashboard"] == "1 Dashboard"
        assert label["audit"].endswith("✔")

    drive(populated, scenario)


def test_dashboard_cards_queue_and_open_work(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        findings = app.query_one("#card-findings", Static)
        assert "P1" in static_text(app, "#card-findings")
        assert findings.has_class("crit") == ("P1 0" not in static_text(app, "#card-findings"))
        approvals = app.query_one("#card-approvals", Static)
        assert approvals.has_class("warn")
        assert "waiting for a decision" in static_text(app, "#card-approvals")
        distribution = static_text(app, "#kpi-distribution")
        assert "by severity" in distribution
        assert "by priority" in distribution
        queue = static_text(app, "#kpi-queue").splitlines()
        assert queue[0].startswith("FND-000001")  # highest priority first
        open_work = static_text(app, "#kpi-open")
        assert "INC-000001" in open_work
        assert "CHG-000001" in open_work
        attention = static_text(app, "#kpi-attention")
        assert "press 3" in attention or "nothing needs attention" in attention.lower()
        assert "active_p1_findings" not in attention  # readable text, not the raw code

    drive(populated, scenario)


def test_status_cells_are_badges_not_plain_words(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("3")
        await pilot.pause()
        table = app.query_one("#table-findings", DataTable)
        columns = [str(column.label) for column in table.columns.values()]
        row = [table.get_cell_at(Coordinate(0, i)).plain for i in range(len(columns))]
        shown = dict(zip(columns, row, strict=True))
        assert shown["Status"] == "● open"
        assert shown["Severity"] in {"▲ HIGH", "◆ MEDIUM", "▽ LOW", "✖ CRITICAL"}
        assert shown["Prio"].split()[0] in {"✖", "▲", "◆", "·"}
        assert "T" not in shown["SLA due"]  # a short time, not the ISO form with microseconds

    drive(populated, scenario)


def test_the_layout_stacks_on_narrow_terminals(populated: Path) -> None:
    async def narrow(app: SoermApp, pilot: Any) -> None:
        assert app.screen.has_class("narrow")
        await pilot.press("3")
        await pilot.pause()
        assert (
            app.query_one("#detailbox-findings").region.y
            > app.query_one("#table-findings").region.y
        )

    async def wide(app: SoermApp, pilot: Any) -> None:
        assert not app.screen.has_class("narrow")

    drive(populated, narrow, size=(80, 24))
    drive(populated, wide, size=(140, 45))


def test_a_failed_refresh_shows_a_persistent_notice_and_recovers(
    populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soerm.tui.app as app_module
    from soerm.tui.data import load_snapshot as real

    def boom(_workspace: object) -> None:
        raise RuntimeError(f"password={SECRET}")

    async def scenario(app: SoermApp, pilot: Any) -> None:
        notice = app.query_one("#notice", Static)
        assert not notice.has_class("visible")
        monkeypatch.setattr(app_module, "load_snapshot", boom)
        await pilot.press("r")
        await pilot.pause()
        assert notice.has_class("visible")
        text = static_text(app, "#notice")
        assert "REFRESH FAILED" in text
        assert "Press r to retry" in text
        assert SECRET not in text
        monkeypatch.setattr(app_module, "load_snapshot", real)
        await pilot.press("r")
        await pilot.pause()
        assert not notice.has_class("visible")

    drive(populated, scenario)


def test_audit_screen_shows_a_verdict_and_the_hash_in_groups(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        await pilot.press("9")
        await pilot.pause()
        verdict = app.query_one("#audit-verdict", Static)
        assert not verdict.has_class("crit")
        assert "✔ CHAIN INTACT" in static_text(app, "#audit-verdict")
        groups = static_text(app, "#text-audit").splitlines()
        hashes = [line for line in groups if re.fullmatch(r"([0-9a-f]{8} ){3}[0-9a-f]{8}", line)]
        assert len(hashes) == 2

    drive(populated, scenario)


def test_truncated_lists_are_marked_in_the_table_too(
    populated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import soerm.tui.data as data_module

    monkeypatch.setattr(data_module, "MAX_ROWS", 1)

    async def scenario(app: SoermApp, pilot: Any) -> None:
        grid = app.query_one("#table-findings", DataTable)
        assert "truncated" in str(grid.border_subtitle)
        assert "▲ LISTS TRUNCATED" in static_text(app, "#banner")

    drive(populated, scenario)


def test_command_palette_descriptions_name_the_keys(populated: Path) -> None:
    async def scenario(app: SoermApp, pilot: Any) -> None:
        commands = {c.title: c.help for c in app.get_system_commands(app.screen)}
        assert "[key 3]" in commands["Go to Findings"]
        assert "[key r]" in commands["Refresh data"]
        assert "[key v]" in commands["Verify audit chain"]
        assert "[key /]" in commands["Filter rows"]
        assert "Clear filter" in commands

    drive(populated, scenario)


def test_colours_come_from_the_shared_palette_not_from_literals() -> None:
    source = Path(__file__).resolve().parents[3] / "src" / "soerm" / "tui"
    literal = re.compile(r"#[0-9a-fA-F]{6}\b")
    for name in ("app.py", "data.py", "terminal.py"):
        assert not literal.search((source / name).read_text(encoding="utf-8")), name
    # the stylesheet takes its colours from theme variables, never from hex values
    css = (source / "theme.py").read_text(encoding="utf-8").split('CSS: Final = """')[1]
    assert not literal.search(css)
