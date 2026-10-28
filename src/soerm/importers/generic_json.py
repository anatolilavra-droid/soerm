"""Generic JSON with a declarative mapping (see the path grammar in ``domain.imports``).

Paths are parsed into steps by a fixed grammar and walked over plain ``dict``/``list`` data.
Nothing is evaluated, imported or called; a path can only descend into the document.
"""

from typing import Any

from soerm.domain.imports import (
    ImportLimits,
    ImportRejectedError,
    JsonMapping,
    ParseResult,
    PathStep,
    RawRecord,
    RejectedRecord,
    parse_path,
)
from soerm.importers.common import FieldTypeError, field_text, load_json, locator, pointer

__all__ = ["parse_generic_json"]

_Node = tuple[tuple[str, ...], Any]


def _expand(document: Any, steps: tuple[PathStep, ...], limit: int) -> list[_Node]:
    frontier: list[_Node] = [((), document)]
    for step in steps:
        following: list[_Node] = []
        for parts, node in frontier:
            if step.kind == "key":
                if isinstance(node, dict) and step.key in node:
                    following.append(((*parts, step.key), node[step.key]))
            elif isinstance(node, list):
                if step.kind == "index":
                    if step.index < len(node):
                        following.append(((*parts, str(step.index)), node[step.index]))
                else:
                    for position, item in enumerate(node):
                        following.append(((*parts, str(position)), item))
                        if len(following) > limit:
                            raise ImportRejectedError("too_many_records")
        frontier = following
    return frontier


def _walk(node: Any, steps: tuple[PathStep, ...]) -> Any:
    for step in steps:
        if step.kind == "key":
            if not isinstance(node, dict) or step.key not in node:
                return None
            node = node[step.key]
        elif step.kind == "index":
            if not isinstance(node, list) or step.index >= len(node):
                return None
            node = node[step.index]
    return node


def parse_generic_json(text: str, mapping: JsonMapping, limits: ImportLimits) -> ParseResult:
    """Records found by ``records_path`` with each mapped field extracted as text."""
    document = load_json(text, limits)
    nodes = _expand(document, parse_path(mapping.records_path), limits.max_records)
    field_paths = {
        name: parse_path(path, allow_wildcard=False) for name, path in mapping.fields.items()
    }
    items: list[RawRecord | RejectedRecord] = []
    for index, (parts, node) in enumerate(nodes):
        where = locator(parts)
        if not isinstance(node, dict):
            items.append(RejectedRecord(index, where, "record", "record_not_object"))
            continue
        fields: dict[str, str | None] = {}
        try:
            for name, steps in field_paths.items():
                fields[name] = field_text(_walk(node, steps))
        except FieldTypeError:
            items.append(RejectedRecord(index, where, name, "invalid_field_type"))
            continue
        items.append(RawRecord(index, fields, where, json_pointer=pointer(parts)))
    warnings = () if nodes else ("records_path_matched_nothing",)
    return ParseResult(tuple(items), warnings)
