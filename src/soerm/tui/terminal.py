"""Can this terminal show the full-screen UI? (No: print a plain overview instead.)"""

import os
import sys
from typing import Final

__all__ = ["MIN_COLUMNS", "MIN_LINES", "unsupported_reason"]

MIN_COLUMNS: Final = 80
MIN_LINES: Final = 24
_DUMB: Final = frozenset({"", "dumb", "unknown"})


def unsupported_reason() -> str | None:
    """A short reason code if the full-screen UI should not be started, else ``None``."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "not_a_terminal"
    if os.environ.get("TERM", "").lower() in _DUMB:
        return "dumb_terminal"
    try:
        size = os.get_terminal_size(sys.stdout.fileno())
    except (OSError, ValueError):
        return "not_a_terminal"
    if size.columns < MIN_COLUMNS or size.lines < MIN_LINES:
        return "terminal_too_small"
    return None
