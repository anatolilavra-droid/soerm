"""SARIF 2.1.0 results -> raw records.

Only the fields below are read; everything else is ignored. Nothing in the document is
executed, fetched or opened: ``artifactLocation.uri`` is text, never a path to read.
``partialFingerprints`` / ``fingerprints`` are kept as provenance hints and are not identity.
"""

import re
from typing import Any, Final

from soerm.domain.imports import (
    MAX_HINTS,
    ImportLimits,
    ImportRejectedError,
    ParseResult,
    RawRecord,
    RejectedRecord,
)
from soerm.importers.common import load_json, locator, pointer

__all__ = ["LEVEL_TO_SEVERITY", "parse_sarif", "safe_uri"]

SUPPORTED_VERSION: Final = "2.1.0"
# SARIF result level -> technical severity text. A documented, declared mapping; "none"
# carries no severity. A result without a level gets none (no default is invented).
LEVEL_TO_SEVERITY: Final = {"error": "high", "warning": "medium", "note": "low", "none": None}
_BASELINE_STATES: Final = frozenset({"new", "unchanged", "updated", "absent"})
_HINT_KEY: Final = re.compile(r"[A-Za-z0-9_./-]{1,64}")
_MAX_URI: Final = 1000
_MAX_HINT_VALUE: Final = 128
_MAX_FINGERPRINT_HINTS: Final = 4
_MAX_COORDINATE: Final = 1_000_000_000
_TITLE_FROM_MESSAGE: Final = 200


def _bad(detail: str) -> ImportRejectedError:
    return ImportRejectedError("invalid_format", detail)


def safe_uri(uri: str) -> str:
    """Text form of an artifact URI: no query, no fragment, no user info; never opened."""
    uri = uri.strip()[:_MAX_URI]
    uri = re.split(r"[?#]", uri, maxsplit=1)[0]
    scheme, separator, rest = uri.partition("://")
    if separator:
        authority, slash, tail = rest.partition("/")
        authority = authority.rsplit("@", 1)[-1]
        return f"{scheme}://{authority}{slash}{tail}"
    return uri


def _text(node: Any, key: str) -> str | None:
    value = node.get(key) if isinstance(node, dict) else None
    return value if isinstance(value, str) and value.strip() else None


def _sub(node: Any, *keys: str) -> Any:
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _coordinate(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= _MAX_COORDINATE else None


def _first_physical_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations")
    if isinstance(locations, list):
        for item in locations:
            physical = _sub(item, "physicalLocation")
            if isinstance(physical, dict):
                return physical
    return {}


def _location_and_snippet(
    result: dict[str, Any], warnings: list[str]
) -> tuple[str | None, str | None]:
    physical = _first_physical_location(result)
    uri = _text(physical.get("artifactLocation"), "uri")
    if uri is None:
        return None, None
    location = safe_uri(uri)
    region = physical.get("region")
    line = _coordinate(_sub(region, "startLine"))
    column = _coordinate(_sub(region, "startColumn"))
    if region is not None and _sub(region, "startLine") is not None and line is None:
        warnings.append("invalid_start_line")
    if line is not None:
        location += f":{line}"
        if column is not None:
            location += f":{column}"
    snippet = _text(_sub(region, "snippet"), "text") or _text(
        _sub(physical, "contextRegion", "snippet"), "text"
    )
    return location, snippet


def _rule(rules: list[Any], result: dict[str, Any], rule_id: str | None) -> dict[str, Any]:
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        candidate = rules[index]
        if isinstance(candidate, dict) and (rule_id is None or candidate.get("id") == rule_id):
            return candidate
    if rule_id is not None:
        for candidate in rules:
            if isinstance(candidate, dict) and candidate.get("id") == rule_id:
                return candidate
    return {}


def _hints(result: dict[str, Any], warnings: list[str]) -> tuple[str, ...]:
    hints: list[str] = []
    state = result.get("baselineState")
    if isinstance(state, str) and state in _BASELINE_STATES:
        hints.append(f"baselineState={state}")
    elif state is not None:
        warnings.append("invalid_baseline_state")
    taken = 0
    for source in ("partialFingerprints", "fingerprints"):
        values = result.get(source)
        if not isinstance(values, dict):
            continue
        for key in sorted(values, key=str):
            value = values[key]
            if (
                taken < _MAX_FINGERPRINT_HINTS
                and isinstance(key, str)
                and _HINT_KEY.fullmatch(key)
                and isinstance(value, str)
                and 0 < len(value) <= _MAX_HINT_VALUE
            ):
                hints.append(f"{source}:{key}={value}")
                taken += 1
            else:
                warnings.append("fingerprint_hint_skipped")
    return tuple(hints[:MAX_HINTS])


def _record(
    index: int,
    parts: tuple[str, ...],
    result: Any,
    rules: list[Any],
) -> RawRecord | RejectedRecord:
    where = locator(parts)
    if not isinstance(result, dict):
        return RejectedRecord(index, where, "result", "result_not_object")
    message = _text(result.get("message"), "text")
    if message is None:
        return RejectedRecord(index, where, "message", "missing_message")
    warnings: list[str] = []
    rule_id = _text(result, "ruleId") or _text(result.get("rule"), "id")
    rule = _rule(rules, result, rule_id)
    short = _text(rule.get("shortDescription"), "text")
    full = _text(rule.get("fullDescription"), "text")
    title = short or _text(rule, "name") or rule_id or message.splitlines()[0][:_TITLE_FROM_MESSAGE]
    description = message if full is None or full == message else f"{message}\n\nRule: {full}"
    level = result.get("level")
    severity: str | None = None
    if isinstance(level, str) and level in LEVEL_TO_SEVERITY:
        severity = LEVEL_TO_SEVERITY[level]
    elif level is not None:
        warnings.append("invalid_level")
    location, snippet = _location_and_snippet(result, warnings)
    fields: dict[str, str | None] = {
        "title": title,
        "description": description,
        "asset_reference": None,
        "owner": None,
        "evidence": snippet,
        "severity": severity,
        "cvss_score": None,
        "cvss_vector": None,
        "location": location,
        "external_rule_id": rule_id,
        "observed_at": None,
    }
    return RawRecord(
        index,
        fields,
        where,
        json_pointer=pointer(parts),
        hints=_hints(result, warnings),
        warnings=tuple(warnings),
    )


def parse_sarif(text: str, limits: ImportLimits) -> ParseResult:
    """Validate the SARIF skeleton and turn every result into a raw record."""
    document = load_json(text, limits)
    if not isinstance(document, dict):
        raise _bad("sarif_not_an_object")
    if document.get("version") != SUPPORTED_VERSION:
        raise _bad("unsupported_sarif_version")
    if "$schema" in document and not isinstance(document["$schema"], str):
        raise _bad("sarif_schema_type")  # the schema URI is never fetched
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise _bad("sarif_runs_missing")
    items: list[RawRecord | RejectedRecord] = []
    file_warnings: list[str] = []
    for run_index, run in enumerate(runs):
        driver = _sub(run, "tool", "driver")
        if not isinstance(driver, dict) or _text(driver, "name") is None:
            raise _bad("sarif_tool_driver_name_missing")
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            raise _bad("sarif_rules_invalid")
        results = run.get("results")
        if results is None:
            file_warnings.append("sarif_run_without_results")
            continue
        if not isinstance(results, list):
            raise _bad("sarif_results_invalid")
        for result_index, result in enumerate(results):
            if len(items) >= limits.max_records:
                raise ImportRejectedError("too_many_records")
            parts = ("runs", str(run_index), "results", str(result_index))
            items.append(_record(len(items), parts, result, rules))
    return ParseResult(tuple(items), tuple(file_warnings))
