"""CSV with a declarative column mapping.

The standard ``csv`` reader is fed explicit line chunks (so quoted fields may contain
newlines); values stay plain strings - nothing is interpreted as a spreadsheet formula and
nothing is written back out.
"""

import csv
import re
import unicodedata
from collections.abc import Iterator
from typing import Final

from soerm.domain.imports import (
    CsvMapping,
    ImportLimits,
    ImportRejectedError,
    ParseResult,
    RawRecord,
    RejectedRecord,
)
from soerm.importers.common import decode_utf8

__all__ = ["parse_csv"]

_LINE: Final = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")


def _chunks(text: str) -> Iterator[str]:
    for match in _LINE.finditer(text):
        yield match.group()


def _bad(detail: str) -> ImportRejectedError:
    return ImportRejectedError("invalid_format", detail)


def _key(name: str) -> str:
    return unicodedata.normalize("NFKC", name).strip()


def _header_index(header: list[str], mapping: CsvMapping) -> dict[str, int]:
    names = [_key(cell) for cell in header]
    if any(not name for name in names):
        raise _bad("empty_header_name")
    if len(set(names)) != len(names):
        raise _bad("duplicate_header")
    positions = {name: position for position, name in enumerate(names)}
    mapped: dict[str, int] = {}
    for field, column in mapping.columns.items():
        position = positions.get(_key(str(column)))
        if position is None:
            raise _bad("mapped_column_missing")
        mapped[field] = position
    if not mapping.ignore_unknown_columns and set(mapped.values()) != set(range(len(names))):
        raise _bad("unknown_column")
    return mapped


def parse_csv(data: bytes, mapping: CsvMapping, limits: ImportLimits) -> ParseResult:
    """Rows -> raw records. Header and column-count problems abort; bad rows are rejected."""
    text = decode_utf8(data)
    previous_limit = csv.field_size_limit(limits.max_csv_row_bytes)
    try:
        return _read(text, mapping, limits)
    except csv.Error:
        raise _bad("malformed_csv") from None
    finally:
        csv.field_size_limit(previous_limit)


def _read(text: str, mapping: CsvMapping, limits: ImportLimits) -> ParseResult:
    reader = csv.reader(_chunks(text), delimiter=mapping.delimiter, strict=True)
    items: list[RawRecord | RejectedRecord] = []
    columns: dict[str, int] | None = None
    if not mapping.has_header:
        columns = {field: int(column) for field, column in mapping.columns.items()}
    last_line = 0
    seen_header = not mapping.has_header
    width: int | None = None
    for row in reader:
        start = last_line + 1
        last_line = reader.line_num
        if not seen_header:
            if len(row) > limits.max_csv_columns:
                raise _bad("too_many_columns")
            columns = _header_index(row, mapping)
            width = len(row)
            seen_header = True
            continue
        if not row:  # a blank line
            continue
        if len(items) >= limits.max_records:
            raise ImportRejectedError("too_many_records")
        index = len(items)
        where = f"row {start}"
        if len(row) > limits.max_csv_columns:
            items.append(RejectedRecord(index, where, "row", "too_many_columns"))
            continue
        if sum(len(cell.encode("utf-8")) for cell in row) > limits.max_csv_row_bytes:
            items.append(RejectedRecord(index, where, "row", "row_too_large"))
            continue
        too_short = max((columns or {}).values(), default=-1) >= len(row)
        if too_short or (width is not None and len(row) != width):
            items.append(RejectedRecord(index, where, "row", "column_count"))
            continue
        fields = {name: (row[position] or None) for name, position in (columns or {}).items()}
        items.append(RawRecord(index, fields, where, csv_row=start))
    if mapping.has_header and not seen_header:
        raise _bad("missing_header")
    return ParseResult(tuple(items))
