"""Helpers shared by the parsers: decoding, JSON loading with limits, safe field values."""

import json
import math
import re
from typing import Any, Final

from soerm.domain.imports import ImportLimits, ImportRejectedError

__all__ = [
    "FieldTypeError",
    "decode_utf8",
    "field_text",
    "load_json",
    "locator",
    "pointer",
]

_BOM: Final = "﻿"
_TOKENS: Final = re.compile(r'["\[\]{}]')
_STRING_TAIL: Final = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)


class FieldTypeError(ValueError):
    """A mapped value is an object/array where text or a number was expected."""


def decode_utf8(data: bytes) -> str:
    """Strict UTF-8 (a leading BOM is dropped); NUL bytes are refused."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ImportRejectedError("invalid_utf8") from None
    if "\x00" in text:
        raise ImportRejectedError("invalid_format", "nul_byte")
    return text.removeprefix(_BOM)


def _check_depth(text: str, limit: int) -> None:
    """Bracket depth outside strings, in linear time, before any real parsing."""
    depth = 0
    position = 0
    while True:
        match = _TOKENS.search(text, position)
        if match is None:
            return
        found = match.group()
        position = match.end()
        if found == '"':
            end = _STRING_TAIL.match(text, position)
            if end is None:
                raise ImportRejectedError("invalid_format", "unterminated_string")
            position = end.end()
        elif found in "[{":
            depth += 1
            if depth > limit:
                raise ImportRejectedError("json_too_deep")
        else:
            depth -= 1


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ImportRejectedError("invalid_format", "duplicate_json_key")
        result[key] = value
    return result


def _no_constant(_: str) -> Any:
    raise ImportRejectedError("invalid_format", "non_finite_number")


def load_json(text: str, limits: ImportLimits) -> Any:
    """Parse JSON: depth checked first, duplicate keys and NaN/Infinity refused."""
    _check_depth(text, limits.max_json_depth)
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except ImportRejectedError:
        raise
    except (ValueError, RecursionError):
        raise ImportRejectedError("invalid_format", "malformed_json") from None


def field_text(value: object) -> str | None:
    """Text of a scalar: strings as they are, numbers and booleans in JSON spelling."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return repr(value)
    raise FieldTypeError


def pointer(parts: tuple[str, ...]) -> str:
    """RFC 6901 JSON pointer."""
    return "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in parts)


def locator(parts: tuple[str, ...]) -> str:
    """Readable form of the same location: ``runs[0].results[3]``."""
    text = ""
    for part in parts:
        text += f"[{part}]" if part.isdigit() else (("." if text else "") + part)
    return text
