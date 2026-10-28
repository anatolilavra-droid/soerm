"""Import preview: read, check, redact and normalize a local file. Writes nothing.

Flow: safe file open -> size/encoding/depth limits -> parse -> validate structure -> raw
records -> **redaction through the M4 service** -> :class:`ImportedFinding` -> report.
There is no database access, no lock and no fingerprinting or deduplication (M6): the caller
receives the normalized records and a report that holds counts and codes only.
"""

from collections import Counter
from dataclasses import dataclass
from typing import Final

from soerm.config import ConfigError, load_yaml_text
from soerm.domain.enums import ImportSource
from soerm.domain.errors import ValidationDomainError
from soerm.domain.imports import (
    MAX_MAPPING_BYTES,
    REPORT_REJECTION_LIMIT,
    CsvMapping,
    ImportedFinding,
    ImportLimits,
    ImportRejectedError,
    ImportReport,
    JsonMapping,
    ParseResult,
    RawRecord,
    RejectedRecord,
    parse_mapping,
)
from soerm.importers import (
    SafeFile,
    parse_csv,
    parse_generic_json,
    parse_sarif,
    read_workspace_file,
)
from soerm.importers.common import decode_utf8
from soerm.services.errors import (
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_runtime
from soerm.services.workspace import Workspace

__all__ = ["SUPPORTED_FORMATS", "ImportPreview", "preview_import"]

SUPPORTED_FORMATS: Final = (ImportSource.SARIF, ImportSource.GENERIC_JSON, ImportSource.CSV)
# (raw field, model field, redaction kind)
_TEXT_FIELDS: Final = (
    ("title", "title", "title"),
    ("description", "description", "text"),
    ("asset_reference", "asset_reference", "name"),
    ("owner", "owner", "name"),
    ("evidence", "evidence", "evidence"),
    ("location", "location", "location"),
    ("external_rule_id", "external_rule_id", "name"),
)
_OPTIONAL_MODEL_FIELDS: Final = frozenset(
    {
        "asset_reference",
        "owner",
        "location",
        "technical_severity",
        "cvss_score",
        "cvss_vector",
        "external_rule_id",
        "observed_at",
    }
)
_RAW_NAME: Final = {"technical_severity": "severity"}


@dataclass(frozen=True, slots=True)
class ImportPreview:
    """Normalized, redacted records and the safe report. ``records`` is for the caller (M6)."""

    report: ImportReport
    records: tuple[ImportedFinding, ...]


def _load_mapping(workspace: Workspace, path: str, fmt: ImportSource) -> JsonMapping | CsvMapping:
    safe = read_workspace_file(workspace.path, path, max_bytes=MAX_MAPPING_BYTES)
    try:
        data = load_yaml_text(decode_utf8(safe.data))
        return parse_mapping(data, fmt)
    except ConfigError as exc:
        raise ImportRejectedError("invalid_mapping", exc.reason) from None
    except ValidationDomainError as exc:
        issues = "; ".join(f"{i.field}: {i.code}" for i in exc.issues[:5])
        raise ImportRejectedError("invalid_mapping", issues or "invalid") from None


def _parse(safe: SafeFile, fmt: ImportSource, mapping: object, limits: ImportLimits) -> ParseResult:
    if fmt is ImportSource.CSV:
        assert isinstance(mapping, CsvMapping)  # noqa: S101 - narrowed by the caller
        return parse_csv(safe.data, mapping, limits)
    text = decode_utf8(safe.data)
    if fmt is ImportSource.SARIF:
        return parse_sarif(text, limits)
    assert isinstance(mapping, JsonMapping)  # noqa: S101
    return parse_generic_json(text, mapping, limits)


def _blank_to_none(value: str | None) -> str | None:
    return value if value is not None and value.strip() else None


def _oversized(raw: RawRecord, limit: int) -> str | None:
    for name, value in raw.fields.items():
        if value is not None and len(value.encode("utf-8", errors="replace")) > limit:
            return name
    return None


class _Builder:
    def __init__(
        self, fmt: ImportSource, safe: SafeFile, limits: ImportLimits, fields: FieldRedactor
    ) -> None:
        self.fmt = fmt
        self.limits = limits
        self.fields = fields
        self.warnings: Counter[str] = Counter()
        self.sha = safe.sha256
        self.file_name = fields.field("source_file_name", safe.name, "name")

    def build(self, raw: RawRecord) -> ImportedFinding | RejectedRecord:
        too_big = _oversized(raw, self.limits.max_field_bytes)
        if too_big is not None:
            return RejectedRecord(raw.index, raw.locator, too_big, "field_too_large")
        if _blank_to_none(raw.fields.get("title")) is None:
            return RejectedRecord(raw.index, raw.locator, "title", "missing_required_field")
        data: dict[str, object] = {"source": self.fmt}
        for raw_name, model_name, kind in _TEXT_FIELDS:
            value = _blank_to_none(raw.fields.get(raw_name))
            if value is None:
                data[model_name] = "" if model_name in {"description", "evidence"} else None
                continue
            try:
                data[model_name] = self.fields.field(raw_name, value, kind)
            except InvalidInputError:
                return RejectedRecord(raw.index, raw.locator, raw_name, "redaction_refused")
        data["technical_severity"] = (
            _blank_to_none(raw.fields.get("severity")) or ""
        ).strip().casefold() or None
        data["cvss_vector"] = _blank_to_none(raw.fields.get("cvss_vector"))
        data["observed_at"] = _blank_to_none(raw.fields.get("observed_at"))
        data["cvss_score"] = self._score(_blank_to_none(raw.fields.get("cvss_score")))
        try:
            hints = tuple(self.fields.field("hint", hint, "hint") for hint in raw.hints)
        except InvalidInputError:
            return RejectedRecord(raw.index, raw.locator, "provenance", "redaction_refused")
        data["provenance"] = self._provenance(raw, hints)
        self.warnings.update(raw.warnings)
        return self._validate(raw, data)

    def _score(self, text: str | None) -> float | None:
        if text is None:
            return None
        try:
            return float(text.strip())
        except ValueError:
            self.warnings["invalid_cvss_score"] += 1
            return None

    def _provenance(self, raw: RawRecord, hints: tuple[str, ...]) -> object:
        return {
            "source_file_name": self.file_name,
            "source_file_sha256": self.sha,
            "location": raw.locator,
            "record_index": raw.index,
            "json_pointer": raw.json_pointer,
            "csv_row": raw.csv_row,
            "hints": hints,
        }

    def _validate(
        self, raw: RawRecord, data: dict[str, object]
    ) -> ImportedFinding | RejectedRecord:
        for attempt in range(2):
            try:
                return ImportedFinding(**data)  # type: ignore[arg-type]
            except ValidationDomainError as exc:
                bad = {issue.field.split(".")[0].split("[")[0] for issue in exc.issues}
                if attempt == 0 and bad and bad <= _OPTIONAL_MODEL_FIELDS:
                    for name in sorted(bad):
                        data[name] = None
                        self.warnings[f"invalid_{_RAW_NAME.get(name, name)}"] += 1
                    continue
                field = next(iter(sorted(bad)), "record")
                return RejectedRecord(
                    raw.index, raw.locator, _RAW_NAME.get(field, field), "invalid_field"
                )
        raise AssertionError  # pragma: no cover - the loop always returns


def preview_import(
    workspace: Workspace,
    path: str,
    *,
    fmt: ImportSource,
    mapping_path: str | None = None,
) -> ImportPreview:
    """Read ``path`` (inside the workspace), redact and normalize it. Nothing is stored."""
    try:
        fmt = ImportSource(fmt)
    except ValueError:
        raise InvalidInputError("format: invalid_enum") from None
    if fmt not in SUPPORTED_FORMATS:
        raise InvalidInputError("format: unsupported")
    needs_mapping = fmt is not ImportSource.SARIF
    if needs_mapping and mapping_path is None:
        raise InvalidInputError("mapping: required")
    if not needs_mapping and mapping_path is not None:
        raise InvalidInputError("mapping: not_allowed")
    if not workspace.path.is_dir():
        raise NotFoundServiceError("workspace_missing", object_type="workspace")
    config, redactor = load_runtime(workspace.path)
    limits = config.imports
    try:
        mapping = _load_mapping(workspace, mapping_path, fmt) if mapping_path else None
        safe = read_workspace_file(workspace.path, path, max_bytes=limits.max_import_file_bytes)
        parsed = _parse(safe, fmt, mapping, limits)
    except ImportRejectedError as exc:
        raise to_service_error(exc) from None
    fields = FieldRedactor(redactor)
    builder = _Builder(fmt, safe, limits, fields)
    accepted: list[ImportedFinding] = []
    rejected: list[RejectedRecord] = []
    for item in parsed.items:
        outcome = builder.build(item) if isinstance(item, RawRecord) else item
        if isinstance(outcome, RejectedRecord):
            rejected.append(outcome)
        else:
            accepted.append(outcome)
    redaction = fields.report()
    builder.warnings.update(parsed.warnings)
    builder.warnings["field_truncated"] += len(redaction.truncated_fields)
    codes = tuple(sorted((code, n) for code, n in builder.warnings.items() if n))
    report = ImportReport(
        source_name=builder.file_name,
        source_sha256=safe.sha256,
        format=fmt.value,
        total_records=len(parsed.items),
        accepted_records=len(accepted),
        rejected_records=len(rejected),
        warnings_count=sum(n for _, n in codes),
        redaction_rule_hits=redaction.rule_hits,
        records_with_provenance=sum(
            1 for r in accepted if r.provenance.source_file_sha256 == safe.sha256
        ),
        warning_codes=codes,
        rejections=tuple(rejected[:REPORT_REJECTION_LIMIT]),
        rejections_omitted=max(0, len(rejected) - REPORT_REJECTION_LIMIT),
        config_hash=redaction.config_hash,
    )
    return ImportPreview(report, tuple(accepted))
