"""The terminal application. Read-only: it shows service data and never writes anything.

Keys: ``1``-``9`` switch screens, ``/`` filters the table, ``Esc`` clears the filter,
``r`` refreshes, ``v`` re-verifies the audit chain, ``?`` lists the keys, ``Ctrl+P`` opens the
command palette and ``q`` quits. All text is shown as plain ``Text`` (never as markup), so data
cannot style or script the screen. Colours and badges come from :mod:`soerm.tui.style`.
"""

from collections.abc import Iterable
from typing import Any, ClassVar, Final

from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Input, Static, TabbedContent, TabPane

from soerm.domain.errors import DomainError
from soerm.services.errors import to_service_error
from soerm.services.workspace import Workspace
from soerm.tui import style
from soerm.tui.data import ATTENTION_TEXT, Row, Snapshot, Table, load_snapshot
from soerm.tui.theme import CSS, THEME, THEME_NAME

__all__ = ["SECTIONS", "SoermApp", "TablePane"]

SECTIONS: Final = (
    ("dashboard", "Dashboard"),
    ("assets", "Assets"),
    ("findings", "Findings"),
    ("incidents", "Incidents"),
    ("tasks", "Tasks"),
    ("approvals", "Approvals"),
    ("playbooks", "Playbooks"),
    ("report", "Report"),
    ("audit", "Audit"),
)
_HELP: Final = (
    "1-9 screens  /  filter  Esc clear  r refresh  v verify audit  Ctrl+P commands  q quit"
)
_BLOCKED_SYSTEM_COMMANDS: Final = frozenset({"screenshot"})  # it would write a file
_NO_TABLE: Final = frozenset({"dashboard", "report", "audit"})
NARROW_COLUMNS: Final = 110
_ACTIVE_STATUSES: Final = frozenset({"open", "triaged", "in_progress"})
_BAR_WIDTH: Final = 16
_QUEUE_ROWS: Final = 8
_WIDTHS: Final = {
    "ID": 11, "Prio": 5, "Severity": 10, "SLA due": 17, "Status": 12, "Object": 0,
}  # fmt: skip
_HOT_SUMMARY: Final = frozenset({"overdue findings", "overdue tasks", "pending approvals"})

# what an empty list means and which CLI command fills it (the UI itself never writes)
_EMPTY: Final = {
    "assets": "No assets yet.\nAdd one with: soerm asset add",
    "findings": "No findings yet.\nImport a scan with: soerm import run",
    "incidents": "No incidents yet.\nOpen one with: soerm incident create",
    "tasks": "No tasks yet.\nCreate one with: soerm task create",
    "approvals": "No approval requests.\nGated playbook steps create them.",
    "playbooks": "No playbooks loaded.\nLoad one with: soerm playbook load",
}
_LEVEL: Final = {"crit": ("▲", style.CRIT), "warn": ("◆", style.WARN)}


def _number(value: str) -> int:
    return int(value) if value.isdigit() else 0


def _hash_groups(value: str) -> str:
    if len(value) != 64:
        return value
    groups = [value[i : i + 8] for i in range(0, 64, 8)]
    return "\n".join(" ".join(groups[i : i + 4]) for i in (0, 4))


class TablePane(Horizontal):
    """A table with a detail panel; the filter narrows the rows by substring."""

    DEFAULT_CLASSES = "pane"

    def __init__(self, section: str) -> None:
        super().__init__(id=f"pane-{section}")
        self.section = section
        self._table: Table | None = None
        self._visible: list[Row] = []
        self._index = 0

    def compose(self) -> ComposeResult:
        with Vertical(classes="tcol"):
            yield DataTable(id=f"table-{self.section}", cursor_type="row")
            yield Static(Text(""), id=f"empty-{self.section}", classes="empty", markup=False)
        with VerticalScroll(classes="detail", id=f"detailbox-{self.section}"):
            yield Static(Text(""), id=f"detail-{self.section}", markup=False)

    @property
    def grid(self) -> DataTable[Text]:
        return self.query_one(f"#table-{self.section}", DataTable)

    def load(self, table: Table, needle: str = "") -> None:
        self._table = table
        grid = self.grid
        grid.clear(columns=True)
        for column in table.columns:
            grid.add_column(column)
        self._visible = [
            row
            for row in table.rows
            if not needle or needle.casefold() in " ".join(row.cells).casefold()
        ]
        for row in self._visible:
            grid.add_row(
                *(
                    style.cell(column, value)
                    for column, value in zip(table.columns, row.cells, strict=True)
                ),
                key=row.key,
            )
        total, shown = len(table.rows), len(self._visible)
        count = f"{shown} of {total}" if needle else str(total)
        grid.border_title = f"{table.title.upper()}  {count}"
        grid.border_subtitle = "list truncated - not every row is shown" if table.truncated else ""
        self._show_empty(needle, total)
        self._show_detail(0)

    def _show_empty(self, needle: str, total: int) -> None:
        empty = self.query_one(f"#empty-{self.section}", Static)
        none = not self._visible
        grid = self.grid
        grid.display = not none
        empty.set_class(none, "visible")
        if not none:
            return
        if total and needle:
            message = Text(f'No rows match "{needle}".\nPress Esc to clear the filter.')
        else:
            message = Text(_EMPTY[self.section] + "\nThis screen is read-only.")
        if self._table and self._table.truncated:
            message.append("\nThe list was truncated.", style=style.WARN)
        empty.update(message)

    def _show_detail(self, index: int) -> None:
        self._index = index
        detail = self.query_one(f"#detail-{self.section}", Static)
        box = self.query_one(f"#detailbox-{self.section}", VerticalScroll)
        if 0 <= index < len(self._visible):
            row = self._visible[index]
            box.border_title = f"DETAIL  {row.key}"
            room = box.size.width - 4  # padding and scrollbar; 0 before the first layout
            detail.update(style.key_values(row.details, wrap_at=room if room > 0 else None))
        else:
            box.border_title = "DETAIL"
            detail.update(Text("nothing selected", style=style.MUTED))

    def on_resize(self, event: events.Resize) -> None:
        self._show_detail(self._index)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        event.stop()
        self._show_detail(event.cursor_row)

    @property
    def row_count(self) -> int:
        return len(self._visible)


class SoermApp(App[None]):
    """Dashboard and browsers for assets, findings, incidents, tasks, approvals, playbooks."""

    TITLE = "SOERM"
    SUB_TITLE = "security operations evidence & response"
    CSS = CSS
    ENABLE_COMMAND_PALETTE = True
    AUTO_FOCUS = ""
    BINDINGS: ClassVar[list[BindingType]] = [
        *(
            Binding(str(n), f"show('{name}')", title, show=False)
            for n, (name, title) in enumerate(SECTIONS, start=1)
        ),
        Binding("slash", "filter", "Filter"),
        Binding("escape", "clear_filter", "Clear", show=False),
        Binding("r", "refresh", "Refresh"),
        Binding("v", "verify", "Verify audit"),
        Binding("question_mark", "help", "Keys"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, workspace: Workspace, snapshot: Snapshot) -> None:
        super().__init__()
        self._workspace = workspace
        self._snapshot = snapshot
        self._needle = ""
        self.register_theme(THEME)  # before the stylesheet is parsed: the CSS uses its variables
        self.theme = THEME_NAME

    # -- layout ---------------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(Text(""), id="banner", markup=False)
        yield Static(Text(""), id="notice", markup=False)
        with TabbedContent(id="tabs"):
            for number, (name, title) in enumerate(SECTIONS, start=1):
                with TabPane(f"{number} {title}", id=name):
                    if name == "dashboard":
                        with Horizontal(classes="cards"):
                            for card in ("findings", "incidents", "tasks", "approvals"):
                                yield Static(Text(""), id=f"card-{card}", classes="card")
                        with Horizontal(classes="dash-mid"):
                            yield Static(Text(""), id="kpi-attention", classes="dash-panel")
                            yield Static(
                                Text(""), id="kpi-distribution", classes="dash-panel dash-dist"
                            )
                            yield Static(Text(""), id="kpi-summary", classes="dash-panel")
                        with Horizontal(classes="dash-bottom"):
                            yield Static(Text(""), id="kpi-queue", classes="dash-panel wide")
                            yield Static(Text(""), id="kpi-open", classes="dash-panel")
                    elif name == "report":
                        with VerticalScroll(classes="panel", id="panel-report"):
                            yield Static(Text(""), id="text-report", markup=False)
                    elif name == "audit":
                        with VerticalScroll(classes="panel", id="panel-audit"):
                            yield Static(Text(""), id="audit-verdict", classes="verdict")
                            yield Static(Text(""), id="text-audit", markup=False)
                    else:
                        yield TablePane(name)
        yield Footer()
        yield Input(placeholder="type to filter rows - Enter keeps, Esc clears", id="filter")

    def on_mount(self) -> None:
        self.query_one("#filter", Input).disabled = True
        self.query_one("#filter", Input).border_title = "FILTER"
        self.query_one("#panel-report", VerticalScroll).border_title = "REPORT"
        self.query_one("#panel-audit", VerticalScroll).border_title = "AUDIT CHAIN"
        for panel, title in (
            ("kpi-summary", "SUMMARY"),
            ("kpi-distribution", "ACTIVE FINDINGS"),
            ("kpi-attention", "ATTENTION"),
            ("kpi-queue", "PRIORITY QUEUE"),
            ("kpi-open", "OPEN WORK"),
        ):
            self.query_one(f"#{panel}", Static).border_title = title
        for card in ("findings", "incidents", "tasks", "approvals"):
            self.query_one(f"#card-{card}", Static).border_title = card.upper()
        self._render_snapshot()
        self._apply_size()

    def on_resize(self, event: events.Resize) -> None:
        self._apply_size()

    def _apply_size(self) -> None:
        self.screen.set_class(self.size.width < NARROW_COLUMNS, "narrow")

    # -- rendering ------------------------------------------------------------------------

    def _render_snapshot(self) -> None:
        snap = self._snapshot
        self._render_banner(snap)
        self._render_dashboard(snap)
        for name in (name for name, _ in SECTIONS):
            if name in _NO_TABLE:
                continue
            self.query_one(f"#pane-{name}", TablePane).load(snap.table(name), self._needle)
        self.query_one("#text-report", Static).update(self._report_text(snap.report_markdown))
        self._render_audit(snap)
        self._render_tabs(snap)
        self._update_filter_status()

    def _render_banner(self, snap: Snapshot) -> None:
        banner = self.query_one("#banner", Static)
        banner.set_class(not snap.audit_intact, "broken")
        text = Text()
        text.append(" SOERM ", style=f"bold {style.BG} on {style.ACTIVE}")
        if snap.audit_intact:
            text.append("  ✔ AUDIT CHAIN INTACT", style=f"bold {style.OK}")
        else:
            text.append("  ✖ AUDIT CHAIN BROKEN - see Audit", style="bold")
        if any(t.truncated for t in snap.tables):
            warn = "bold" if not snap.audit_intact else f"bold {style.WARN}"
            text.append("  ▲ LISTS TRUNCATED", style=warn)
        text.append(
            f"   generated {style.stamp(snap.generated_at)}",
            style="" if not snap.audit_intact else style.MUTED,
        )
        banner.update(text)

    def _render_dashboard(self, snap: Snapshot) -> None:
        values = dict(snap.summary)
        number = {label: _number(value) for label, value in values.items()}
        p1, p2 = number["active P1"], number["active P2"]
        overdue_f, overdue_t = number["overdue findings"], number["overdue tasks"]
        pending = number["pending approvals"]
        self._card(
            "findings", number["active findings"], style.ACTIVE,
            [("P1", p1, style.CRIT), ("P2", p2, style.WARN), ("overdue", overdue_f, style.WARN)],
            "crit" if p1 else "warn" if overdue_f else "",
        )  # fmt: skip
        self._card(
            "incidents", number["open incidents"], style.ACTIVE,
            [("playbooks attached", number["playbooks attached"], style.ACTIVE)], "",
        )  # fmt: skip
        self._card(
            "tasks", number["open tasks"], style.ACTIVE,
            [("overdue", overdue_t, style.WARN)], "warn" if overdue_t else "",
            tail=f"{values['task completion %']}% complete",
        )  # fmt: skip
        self._card(
            "approvals", pending, style.WARN if pending else style.ACTIVE,
            [], "warn" if pending else "",
            tail="waiting for a decision" if pending else "none waiting",
        )  # fmt: skip
        summary = Text()
        for label, value in snap.summary:
            hot = label in _HOT_SUMMARY and value not in {"0", "-"}
            summary.append(f"{label:<20}", style=style.MUTED)
            summary.append(f"{value}\n", style=f"bold {style.WARN}" if hot else "bold")
        self.query_one("#kpi-summary", Static).update(summary)
        self.query_one("#kpi-distribution", Static).update(self._distribution(snap))
        self.query_one("#kpi-queue", Static).update(self._queue(snap))
        self.query_one("#kpi-open", Static).update(self._open_work(snap))
        attention = Text()
        for code in snap.attention:
            label, screen, level = ATTENTION_TEXT.get(code, (code, 0, "warn"))
            glyph, colour = _LEVEL[level]
            if code == "audit_chain_broken":
                glyph = "✖"
            attention.append(f"{glyph} {label}", style=f"bold {colour}")
            attention.append(f"  press {screen}\n" if screen else "\n", style=style.MUTED)
        if not snap.attention:
            attention.append("✔ Nothing needs attention", style=f"bold {style.OK}")
        self.query_one("#kpi-attention", Static).update(attention)

    def _card(
        self,
        name: str,
        big: int,
        colour: str,
        lines: list[tuple[str, int, str]],
        level: str,
        tail: str = "",
    ) -> None:
        card = self.query_one(f"#card-{name}", Static)
        card.set_class(level == "warn", "warn")
        card.set_class(level == "crit", "crit")
        text = style.big_number(big, colour)
        parts = Text()
        for label, value, hot in lines:
            parts.append(f"{label} ", style=style.MUTED)
            parts.append(f"{value}  ", style=f"bold {hot}" if value else style.MUTED)
        text.append_text(parts)
        if tail:
            text.append(f"\n{tail}", style=style.MUTED)
        card.update(text)

    def _distribution(self, snap: Snapshot) -> Text:
        table = snap.table("findings")
        columns = {name: index for index, name in enumerate(table.columns)}
        active = [row for row in table.rows if row.cells[columns["Status"]] in _ACTIVE_STATUSES]
        out = Text()
        if not active:
            out.append("No active findings.", style=style.MUTED)
            return out
        for title, column, order in (
            ("by severity", "Severity", ("critical", "high", "medium", "low", "none")),
            ("by priority", "Prio", ("p1", "p2", "p3", "p4")),
        ):
            counts = dict.fromkeys(order, 0)
            for row in active:
                key = row.cells[columns[column]]
                counts[key] = counts.get(key, 0) + 1
            top = max(counts.values())
            out.append(f"{title}\n", style=style.MUTED)
            for key, count in counts.items():
                shown = style.badge(column, key) or Text(key)
                shown.pad_right(max(0, 11 - len(shown.plain)))
                out.append_text(shown)
                bar = "█" * max(1 if count else 0, round(_BAR_WIDTH * count / top))
                out.append(bar, style=shown.style if count else style.MUTED)
                out.append(f" {count}\n", style="bold" if count else style.MUTED)
            out.append("\n")
        return out

    @staticmethod
    def _line(table: Table, row: Row, columns: tuple[str, ...]) -> Text:
        index = {name: i for i, name in enumerate(table.columns)}
        line = Text(no_wrap=True, overflow="ellipsis")
        for column in columns:
            shown = style.cell(column, row.cells[index[column]])
            shown.pad_right(max(0, _WIDTHS.get(column, 0) - len(shown.plain)))
            line.append_text(shown)
            line.append(" ")
        return line

    def _queue(self, snap: Snapshot) -> Text:
        table = snap.table("findings")
        index = {name: i for i, name in enumerate(table.columns)}
        rank = {"p1": 0, "p2": 1, "p3": 2, "p4": 3}
        severity = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        active = [r for r in table.rows if r.cells[index["Status"]] in _ACTIVE_STATUSES]
        active.sort(
            key=lambda r: (
                rank.get(r.cells[index["Prio"]], 9),
                severity.get(r.cells[index["Severity"]], 9),
            )
        )
        out = Text(no_wrap=True, overflow="ellipsis")
        if not active:
            out.append("No active findings.", style=style.MUTED)
        for row in active[:_QUEUE_ROWS]:
            out.append_text(self._line(table, row, ("ID", "Prio", "Severity", "SLA due", "Title")))
            out.append("\n")
        if len(active) > _QUEUE_ROWS:
            out.append(f"+ {len(active) - _QUEUE_ROWS} more on screen 3", style=style.MUTED)
        return out

    def _open_work(self, snap: Snapshot) -> Text:
        out = Text(no_wrap=True, overflow="ellipsis")
        approvals = snap.table("approvals")
        status = approvals.columns.index("Status")
        pending = [r for r in approvals.rows if r.cells[status] == "pending"]
        incidents = snap.table("incidents")
        istatus = incidents.columns.index("Status")
        open_incidents = [r for r in incidents.rows if r.cells[istatus] != "closed"]
        out.append("incidents\n", style=style.MUTED)
        for row in open_incidents[:4]:
            out.append_text(self._line(incidents, row, ("ID", "Severity", "Title")))
            out.append("\n")
        if not open_incidents:
            out.append("none open\n", style=style.MUTED)
        out.append("\napprovals waiting\n", style=style.MUTED)
        for row in pending[:4]:
            out.append_text(self._line(approvals, row, ("ID", "Object")))
            out.append("\n")
        if not pending:
            out.append("none waiting\n", style=style.MUTED)
        return out

    def _render_audit(self, snap: Snapshot) -> None:
        values = dict(snap.audit)
        verdict = self.query_one("#audit-verdict", Static)
        verdict.set_class(not snap.audit_intact, "crit")
        if snap.audit_intact:
            verdict.update(Text(f"✔ CHAIN INTACT\n{values['entries']} entries verified"))
        else:
            where = values["broken at seq"]
            verdict.update(
                Text(f"✖ CHAIN BROKEN\nentry {where}: {values['reason']}\n")
                + Text("Records from this entry on cannot be trusted.", style="not bold")
            )
        text = Text()
        for label, value in snap.audit:
            text.append(f"{label:<16}", style=style.MUTED)
            if label == "head hash":
                text.append("\n" + _hash_groups(value) + "\n", style=style.ACTIVE)
            else:
                shown = style.badge(label, value) if label == "status" else None
                if shown is not None:
                    text.append_text(shown)
                    text.append("\n")
                else:
                    text.append(f"{value}\n")
        text.append(
            "\nA passing check shows that the chain is self-consistent. Keep a copy of the head\n"
            "hash outside the database: a whole replaced file cannot be detected from inside.\n"
            "\nPress v to verify again.\n",
            style=style.MUTED,
        )
        self.query_one("#text-audit", Static).update(text)

    @staticmethod
    def _report_text(markdown: str) -> Text:
        out = Text()
        for line in markdown.splitlines():
            heading = line.startswith("#")
            out.append(line + "\n", style=f"bold {style.ACTIVE}" if heading else "")
        return out

    def _render_tabs(self, snap: Snapshot) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        values = {label: _number(value) for label, value in snap.summary}
        hot = {
            "findings": (style.CRIT, values["active P1"] > 0),
            "tasks": (style.WARN, values["overdue tasks"] > 0),
            "approvals": (style.WARN, values["pending approvals"] > 0),
        }
        for number, (name, title) in enumerate(SECTIONS, start=1):
            suffix = ""
            if name == "audit":
                suffix = "✔" if snap.audit_intact else f"[bold {style.CRIT}]✖[/]"
            elif name not in _NO_TABLE:
                count = len(snap.table(name).rows)
                colour, flagged = hot.get(name, (style.MUTED, False))
                suffix = f"[bold {colour}]{count}[/]" if flagged else f"[{style.MUTED}]{count}[/]"
            tabs.get_tab(name).label = f"{number} {title} {suffix}".strip()

    def _set_notice(self, message: str | None) -> None:
        notice = self.query_one("#notice", Static)
        notice.set_class(message is not None, "visible")
        notice.update(Text(f" {message}") if message else Text(""))

    def _reload(self) -> bool:
        try:
            self._snapshot = load_snapshot(self._workspace)
        except DomainError as exc:
            code = to_service_error(exc).code
            self._refresh_failed(code)
            return False
        except Exception:  # never show the exception text (it could hold data)
            self._refresh_failed("internal error")
            return False
        self._set_notice(None)
        self._render_snapshot()
        return True

    def _refresh_failed(self, code: str) -> None:
        shown = style.stamp(self._snapshot.generated_at)
        self.notify(f"refresh failed: {code}", severity="error")
        self._set_notice(
            f"✖ REFRESH FAILED ({code}) - showing data from {shown}. Press r to retry."
        )

    def _update_filter_status(self) -> None:
        box = self.query_one("#filter", Input)
        active = self.query_one("#tabs", TabbedContent).active
        if active in _NO_TABLE:
            box.border_subtitle = "filters the table screens only"
            return
        pane = self.query_one(f"#pane-{active}", TablePane)
        total = len(self._snapshot.table(active).rows)
        box.border_subtitle = f"{pane.row_count} of {total} rows"

    # -- actions --------------------------------------------------------------------------

    def action_show(self, name: str) -> None:
        self.set_focus(None)  # a focused widget in the old pane would pull the tab back
        self.query_one("#tabs", TabbedContent).active = name
        if name not in _NO_TABLE:
            self.query_one(f"#table-{name}", DataTable).focus()
        self._update_filter_status()

    def action_refresh(self) -> None:
        if self._reload():
            self.notify("data refreshed")

    def action_verify(self) -> None:
        if self._reload():
            self.action_show("audit")
            if self._snapshot.audit_intact:
                self.notify("audit chain verified: intact")
            else:
                self.notify("audit chain is BROKEN", severity="error")

    def action_help(self) -> None:
        self.notify(_HELP, title="Keys", timeout=10)

    def action_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.disabled = False
        box.add_class("visible")
        box.focus()
        self._update_filter_status()

    def action_clear_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.value = ""
        box.remove_class("visible")
        box.disabled = True
        self._needle = ""
        self._render_snapshot()
        active = self.query_one("#tabs", TabbedContent).active
        if active not in _NO_TABLE:
            self.query_one(f"#table-{active}", DataTable).focus()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self._needle = event.value.strip()
        self._render_snapshot()

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        active = self.query_one("#tabs", TabbedContent).active
        if active not in _NO_TABLE:
            self.query_one(f"#table-{active}", DataTable).focus()

    # -- command palette ------------------------------------------------------------------

    def get_system_commands(self, screen: Screen[Any]) -> Iterable[SystemCommand]:
        for command in super().get_system_commands(screen):
            if command.title.casefold() not in _BLOCKED_SYSTEM_COMMANDS:
                yield command
        for number, (name, title) in enumerate(SECTIONS, start=1):
            yield SystemCommand(
                f"Go to {title}", f"Open the {title} screen  [key {number}]", self._goto(name)
            )
        yield SystemCommand(
            "Refresh data", "Re-read the workspace, read-only  [key r]", self.action_refresh
        )
        yield SystemCommand(
            "Verify audit chain", "Re-compute the hash chain  [key v]", self.action_verify
        )
        yield SystemCommand("Filter rows", "Narrow the current table  [key /]", self.action_filter)
        yield SystemCommand(
            "Clear filter", "Show every row again  [key Esc]", self.action_clear_filter
        )
        yield SystemCommand("Show keys", "List the keyboard shortcuts  [key ?]", self.action_help)

    def _goto(self, name: str):  # type: ignore[no-untyped-def]
        def go() -> None:
            self.action_show(name)

        return go
