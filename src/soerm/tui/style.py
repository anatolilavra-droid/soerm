"""One source for the look of the terminal UI: palette, status badges and time format.

Roles, not hues, are what the screens use: cyan marks what is active, magenta is a rare accent,
yellow is a warning, red is critical and green is healthy. A badge never relies on colour alone:
it carries a glyph and the word as well, so it still reads on a monochrome terminal.
"""

import textwrap
from collections.abc import Iterable
from typing import Final

from rich.text import Text

__all__ = [
    "ACCENT",
    "ACTIVE",
    "BG",
    "CRIT",
    "FG",
    "LINE",
    "MUTED",
    "OK",
    "PANEL",
    "SURFACE",
    "WARN",
    "badge",
    "big_number",
    "cell",
    "key_values",
    "stamp",
]

BG: Final = "#05070d"
SURFACE: Final = "#0a1020"
PANEL: Final = "#101a30"
LINE: Final = "#1c2b4a"
FG: Final = "#cfe8f5"
MUTED: Final = "#6f86a8"
ACTIVE: Final = "#00e5ff"  # cyan: focus, selection, healthy activity
ACCENT: Final = "#ff2bd6"  # magenta: used sparingly
WARN: Final = "#ffd400"  # yellow: needs attention
CRIT: Final = "#ff3b5c"  # red: critical or broken
OK: Final = "#39ff88"  # green: verified

# (glyph, style) per lower-cased value, grouped by the column they appear in.
_SEVERITY: Final = {
    "critical": ("✖", f"bold {CRIT}"),
    "high": ("▲", CRIT),
    "medium": ("◆", WARN),
    "low": ("▽", ACTIVE),
    "none": ("·", MUTED),
}
_PRIORITY: Final = {
    "p1": ("✖", f"bold {CRIT}"),
    "p2": ("▲", WARN),
    "p3": ("◆", ACTIVE),
    "p4": ("·", MUTED),
}
_STATUS: Final = {
    # findings
    "open": ("●", ACTIVE),
    "triaged": ("◐", ACTIVE),
    "in_progress": ("◐", ACTIVE),
    "resolved": ("✔", OK),
    "accepted_risk": ("◇", MUTED),
    "false_positive": ("◇", MUTED),
    # incidents
    "new": ("●", WARN),
    "investigating": ("◐", ACTIVE),
    "contained": ("◑", ACTIVE),
    "remediated": ("✔", OK),
    "closed": ("✔", OK),
    # tasks
    "done": ("✔", OK),
    "cancelled": ("◇", MUTED),
    # approvals
    "pending": ("◌", WARN),
    "approved": ("✔", OK),
    "rejected": ("✖", CRIT),
    # audit chain
    "intact": ("✔", OK),
    "broken": ("✖", f"bold {CRIT}"),
    "expired": ("✖", CRIT),
}
_EXPOSURE: Final = {
    "internet": ("▲", WARN),
    "partner": ("◆", ACTIVE),
    "internal": ("·", MUTED),
    "isolated": ("·", MUTED),
}
_YES_NO: Final = {"yes": ("✔", OK), "no": ("·", MUTED)}

_BY_COLUMN: Final = {
    "status": _STATUS,
    "severity": _SEVERITY,
    "prio": _PRIORITY,
    "priority": _PRIORITY,
    "criticality": _SEVERITY,
    "exposure": _EXPOSURE,
    "applied": _YES_NO,
}
_UPPER: Final = frozenset({"severity", "prio", "priority", "criticality"})


def stamp(value: str, *, seconds: bool = False) -> str:
    """``2026-10-31T16:15:04.628082Z`` -> ``2026-10-31 16:15Z`` (other text is returned as is)."""
    is_time = len(value) >= 17 and value[10] == "T" and value[4] == "-" and value[-1] == "Z"
    if not is_time:
        return value
    clock = value[11:19] if seconds else value[11:16]
    return f"{value[:10]} {clock}Z"


def badge(column: str, value: str) -> Text | None:
    """A glyph + word badge for known status-like values, else ``None``."""
    table = _BY_COLUMN.get(column.casefold())
    entry = table.get(value.casefold()) if table else None
    if entry is None:
        return None
    glyph, style = entry
    word = value.upper() if column.casefold() in _UPPER else " ".join(value.split("_"))
    return Text(f"{glyph} {word}", style=style, no_wrap=True, overflow="ellipsis")


def cell(column: str, value: str) -> Text:
    """A table cell: a badge, a short time, or muted placeholder/plain text."""
    shown = badge(column, value)
    if shown is not None:
        return shown
    if value == "-":
        return Text("-", style=MUTED, no_wrap=True)
    return Text(stamp(value), no_wrap=True, overflow="ellipsis")


def key_values(
    pairs: Iterable[tuple[str, str]], *, width: int = 18, wrap_at: int | None = None
) -> Text:
    """Label/value lines for the detail panels: muted labels, badges for status-like values.

    With ``wrap_at`` (the panel width) long values wrap under the value column, not under the label.
    """
    out = Text()
    for label, value in pairs:
        out.append(f"{label:<{width}}", style=MUTED)
        shown = badge(label, value)
        if shown is not None:
            out.append_text(shown)
        else:
            text = stamp(value, seconds=True) if value != "-" else value
            room = (wrap_at - width) if wrap_at else 0
            parts = textwrap.wrap(text, room) if room >= 12 and len(text) > room else [text]
            out.append(
                ("\n" + " " * width).join(parts or [""]), style=MUTED if value == "-" else ""
            )
        out.append("\n")
    return out


_DIGITS: Final = {
    "0": ("┌─┐", "│ │", "└─┘"),
    "1": (" ┐ ", " │ ", "─┴─"),
    "2": ("╶─┐", "┌─┘", "└─╴"),
    "3": ("╶─┐", " ─┤", "╶─┘"),
    "4": ("╷ ╷", "└─┤", "  ╵"),
    "5": ("┌─╴", "└─┐", "╶─┘"),
    "6": ("┌─╴", "├─┐", "└─┘"),
    "7": ("╶─┐", "  │", "  ╵"),
    "8": ("┌─┐", "├─┤", "└─┘"),
    "9": ("┌─┐", "└─┤", "╶─┘"),
}


def big_number(value: int, colour: str) -> Text:
    """A three-line box-drawing number for the dashboard cards (a plain figure, no animation)."""
    glyphs = [_DIGITS[digit] for digit in str(max(0, value))]
    lines = ("  ".join(glyph[row] for glyph in glyphs) for row in range(3))
    return Text("\n".join(lines) + "\n", style=f"bold {colour}", no_wrap=True)
