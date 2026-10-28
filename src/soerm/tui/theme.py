"""Terminal theme ``soerm-cyber``: a security-operations console, not a light show.

Dark ground, cyan for what is active, yellow for warnings, red for critical states, green for a
verified chain; magenta appears only as a small accent (active tab bar, card titles). Colours come
from :mod:`soerm.tui.style`, the single source of the palette.
"""

from typing import Final

from textual.theme import Theme

from soerm.tui import style

__all__ = ["CSS", "THEME", "THEME_NAME"]

THEME_NAME: Final = "soerm-cyber"

THEME: Final = Theme(
    name=THEME_NAME,
    primary=style.ACTIVE,
    secondary=style.ACCENT,
    accent=style.ACCENT,
    warning=style.WARN,
    error=style.CRIT,
    success=style.OK,
    foreground=style.FG,
    background=style.BG,
    surface=style.SURFACE,
    panel=style.PANEL,
    dark=True,
    variables={
        "line": style.LINE,
        "muted": style.MUTED,
        "footer-background": style.SURFACE,
        "footer-item-background": style.SURFACE,
        "footer-key-foreground": style.ACTIVE,
        "footer-description-foreground": style.MUTED,
        "input-cursor-background": style.ACTIVE,
        "block-cursor-background": style.ACTIVE,
        "block-cursor-foreground": style.BG,
        "scrollbar": style.LINE,
        "scrollbar-background": style.BG,
        "scrollbar-hover": style.MUTED,
        "scrollbar-active": style.ACTIVE,
    },
)

CSS: Final = """
Screen { background: $background; color: $foreground; }

/* status bar and notices */
#banner { height: 1; padding: 0 1; background: $surface; color: $foreground; }
#banner.broken { background: $error; color: $background; text-style: bold; }
#notice {
    display: none; height: 1; padding: 0 1; background: $error; color: $background;
    text-style: bold;
}
#notice.visible { display: block; }

/* navigation */
Tabs { background: $surface; }
Tab { color: $muted; padding: 0 1; }
Tab:hover { color: $foreground; }
Tab.-active { color: $primary; text-style: bold; background: $surface; }
Underline > .underline--bar { color: $secondary; background: $panel; }
TabbedContent { height: 1fr; }
TabPane { padding: 0; }
.pane { height: 1fr; }

/* tables and detail panels */
.tcol { width: 1fr; height: 1fr; }
DataTable {
    width: 1fr; height: 1fr; background: $background; border: round $line;
    border-title-color: $muted; border-title-style: bold; border-subtitle-color: $warning;
}
DataTable:focus { border: round $primary; border-title-color: $primary; }
DataTable > .datatable--header { background: $panel; color: $primary; text-style: bold; }
DataTable > .datatable--cursor { background: $primary 22%; color: $foreground; text-style: bold; }
DataTable > .datatable--hover { background: $primary 10%; }
.detail {
    width: 34%; min-width: 34; height: 1fr; padding: 0 1; background: $surface;
    border: round $line; border-title-color: $secondary; border-title-style: bold;
}
.empty {
    display: none; width: 1fr; height: 1fr; align: center middle; padding: 1 4;
    background: $surface; border: round $line; color: $muted;
}
.empty.visible { display: block; }

/* dashboard */
.cards { height: 7; }
.card, .dash-panel {
    width: 1fr; height: 100%; margin: 0 1 0 0; padding: 0 1; background: $surface;
    border: round $line; border-title-color: $muted; border-title-style: bold;
}
.card.warn { border: round $warning; }
.card.crit { border: round $error; }
.dash-mid { height: 14; }
.dash-bottom { height: 1fr; }
.dash-panel { height: 100%; text-wrap: nowrap; text-overflow: ellipsis; }
.dash-panel.wide { width: 2fr; }

/* report and audit */
.panel {
    height: 1fr; padding: 0 2; background: $surface; border: round $line;
    border-title-color: $muted; border-title-style: bold;
}
.verdict {
    height: auto; margin: 1 0; padding: 0 2; background: $background; color: $success;
    border: round $success; text-style: bold;
}
.verdict.crit { color: $error; border: round $error; }

/* narrow terminals: stack the detail under the table and drop the extras */
Screen.narrow TablePane { layout: vertical; }
Screen.narrow .detail { width: 1fr; min-width: 0; height: 9; }
Screen.narrow .dash-dist, Screen.narrow .dash-bottom { display: none; }
Screen.narrow .dash-mid { height: 1fr; }

/* filter */
#filter {
    dock: bottom; display: none; height: 3; background: $surface; border: round $primary;
    border-title-color: $primary; border-subtitle-color: $muted;
}
#filter.visible { display: block; }

/* footer */
Footer { background: $surface; }
Footer .footer-key--key { color: $primary; background: $surface; text-style: bold; }
Footer .footer-key--description { color: $muted; background: $surface; }
FooterKey { background: $surface; }

/* command palette */
CommandPalette > Vertical { background: $background; }
CommandPalette #--input { border: round $primary; background: $surface; }
CommandPalette #--input.--list-visible { border-bottom: none; }
CommandPalette #--results { background: $surface; border: round $primary; border-top: none; }
CommandList { background: $surface; }
CommandList > .option-list--option-highlighted { background: $primary 22%; color: $foreground; }
CommandPalette > .command-palette--highlight { color: $secondary; text-style: bold underline; }
CommandPalette > .command-palette--help-text { color: $muted; text-style: none; }
"""
