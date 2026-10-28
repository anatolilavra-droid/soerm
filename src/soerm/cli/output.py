"""Safe terminal output: no ANSI sequences, no control characters, stable field order.

Every user-derived string goes through :func:`safe_text` before it reaches a terminal:
control, format (including bidirectional), surrogate, private-use, unassigned and exotic
space characters are replaced by visible ``\\n`` / ``\\uXXXX`` escapes. JSON output is
produced with ``ensure_ascii=True``, so it contains no raw control or non-ASCII characters.
"""

import json
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from typing import TextIO

__all__ = [
    "dumps_json",
    "render_key_values",
    "render_table",
    "safe_text",
    "write_line",
]

_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_ELLIPSIS = "..."


def safe_text(value: object, *, limit: int | None = None) -> str:
    """Printable, single-line rendering of ``value`` (optionally shortened to ``limit``)."""
    text = str(value)
    parts: list[str] = []
    for char in text:
        escaped = _ESCAPES.get(char)
        if escaped is not None:
            parts.append(escaped)
        elif char == " ":
            parts.append(char)
        elif unicodedata.category(char) in _UNSAFE_CATEGORIES or unicodedata.category(char) == "Zs":
            code = ord(char)
            parts.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            parts.append(char)
    result = "".join(parts)
    if limit is not None and len(result) > limit:
        return result[: max(limit - len(_ELLIPSIS), 0)] + _ELLIPSIS
    return result


def render_key_values(rows: Sequence[tuple[str, object]]) -> str:
    """``key: value`` lines with aligned values, in the given (stable) order."""
    width = max((len(key) for key, _ in rows), default=0)
    return "\n".join(f"{key + ':':<{width + 1}} {safe_text(value)}" for key, value in rows)


def render_table(
    headers: Sequence[str], rows: Sequence[Sequence[object]], *, limit: int = 48
) -> str:
    """Fixed-width table; long cells are shortened, nothing is wrapped."""
    cells = [[safe_text(cell, limit=limit) for cell in row] for row in rows]
    widths = [
        max([len(header), *(len(row[index]) for row in cells)])
        for index, header in enumerate(headers)
    ]

    def line(values: Sequence[str]) -> str:
        return "  ".join(
            value.ljust(width) for value, width in zip(values, widths, strict=True)
        ).rstrip()

    return "\n".join([line(headers), *(line(row) for row in cells)])


def dumps_json(value: Mapping[str, object] | Sequence[object]) -> str:
    """Deterministic ASCII-only JSON (keys keep the order they were built in)."""
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=False, allow_nan=False)


def write_line(text: str, stream: TextIO | None = None) -> None:
    """Write ``text`` and a newline; characters the stream cannot encode are escaped."""
    target = stream if stream is not None else sys.stdout
    encoding = getattr(target, "encoding", None) or "utf-8"
    data = text.encode(encoding, errors="backslashreplace").decode(encoding, errors="replace")
    target.write(data + "\n")
    target.flush()
