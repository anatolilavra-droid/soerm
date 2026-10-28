"""Import model: limits, declarative mappings, the path grammar and the normalized records.

M5 reads, checks, cleans and normalizes; it does not write to the database, fingerprint or
deduplicate (M6). Nothing here performs I/O. Error objects and reports never hold raw values.

Path grammar (JSON mappings)::

    path    := segment ("." segment)*
    segment := identifier [selector]  |  selector          (a bare selector only as first segment)
    selector:= "[]" | "[*]" | "[" digits "]"                (all elements / all elements / index)
    identifier := [A-Za-z_][A-Za-z0-9_-]{0,63}, not starting with "__"

No expressions, functions, filters, slices or negative indexes. ``records_path`` must contain
a wildcard selector; field paths may use plain keys and numeric indexes only.
"""

import re
from dataclasses import dataclass
from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import BeforeValidator, Field, StrictInt, StrictStr, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.domain.errors import DomainError, ValidationDomainError
from soerm.domain.finding import CvssScore, CvssVector
from soerm.domain.hashing import Sha256
from soerm.domain.text import Evidence, LongText, Name, Reason, Title
from soerm.domain.timestamps import UtcTimestamp

__all__ = [
    "CSV_DELIMITERS",
    "FIELD_NAMES",
    "MAX_HINTS",
    "MAX_MAPPING_BYTES",
    "REPORT_REJECTION_LIMIT",
    "CsvMapping",
    "ImportLimits",
    "ImportRejectedError",
    "ImportReport",
    "ImportedFinding",
    "JsonMapping",
    "ParseResult",
    "PathStep",
    "Provenance",
    "RawRecord",
    "RejectedRecord",
    "parse_mapping",
    "parse_path",
]

MAX_MAPPING_BYTES: Final = 65536
MAX_HINTS: Final = 8
REPORT_REJECTION_LIMIT: Final = 100
CSV_DELIMITERS: Final = frozenset({",", ";", "\t", "|"})
FIELD_NAMES: Final = (
    "title",
    "description",
    "asset_reference",
    "evidence",
    "owner",
    "severity",
    "cvss_score",
    "cvss_vector",
    "location",
    "external_rule_id",
    "observed_at",
)
_REQUIRED_FIELDS: Final = frozenset({"title"})
_MAX_PATH_LENGTH: Final = 256
_MAX_SEGMENTS: Final = 16
_MAX_WILDCARDS: Final = 2
_MAX_INDEX: Final = 9999
_FORBIDDEN_NAMES: Final = frozenset(
    {"__class__", "__dict__", "__globals__", "__subclasses__", "__import__", "__builtins__"}
)
_SEGMENT: Final = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_-]{0,63})?(?P<selector>\[(?P<arg>\*|[0-9]{1,4})?\])?"
)


class ImportRejectedError(DomainError):
    """The whole import is refused. ``reason`` is a stable code; no value is ever included."""

    code: ClassVar[str] = "import_error"

    def __init__(self, reason: str, detail: str | None = None) -> None:
        shown = reason if detail is None else f"{reason}: {detail}"
        super().__init__(f"import rejected ({shown})", reason=reason)
        self.reason = reason
        self.detail = detail


class ImportLimits(DomainModel):
    """Limits of ``soerm.yaml`` -> ``imports``. All are checked before heavy parsing."""

    max_import_file_bytes: Annotated[int, Field(strict=True, ge=1024, le=67_108_864)] = 10_485_760
    max_records: Annotated[int, Field(strict=True, ge=1, le=1_000_000)] = 50_000
    max_json_depth: Annotated[int, Field(strict=True, ge=2, le=256)] = 64
    max_field_bytes: Annotated[int, Field(strict=True, ge=64, le=1_048_576)] = 65_536
    max_csv_row_bytes: Annotated[int, Field(strict=True, ge=256, le=4_194_304)] = 262_144
    max_csv_columns: Annotated[int, Field(strict=True, ge=1, le=1024)] = 64


# ---- path grammar --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PathStep:
    """``key`` (object member), ``all`` (every array element) or ``index`` (one element)."""

    kind: Literal["key", "all", "index"]
    key: str = ""
    index: int = 0


def parse_path(text: object, *, allow_wildcard: bool = True) -> tuple[PathStep, ...]:
    """Parse a path; raises :class:`ValidationDomainError` with a rule code only."""
    if not isinstance(text, str):
        raise ValidationDomainError.single("path", "path_type")
    if not text or len(text) > _MAX_PATH_LENGTH:
        raise ValidationDomainError.single("path", "path_length")
    segments = text.split(".")
    if len(segments) > _MAX_SEGMENTS:
        raise ValidationDomainError.single("path", "path_too_deep")
    steps: list[PathStep] = []
    wildcards = 0
    for position, segment in enumerate(segments):
        match = _SEGMENT.fullmatch(segment)
        if not segment or match is None:
            raise ValidationDomainError.single("path", "path_syntax")
        name, selector, arg = match.group("name"), match.group("selector"), match.group("arg")
        if name is None and (selector is None or position != 0):
            raise ValidationDomainError.single("path", "path_syntax")
        if name is not None:
            if name.startswith("__") or name in _FORBIDDEN_NAMES:
                raise ValidationDomainError.single("path", "path_forbidden_segment")
            steps.append(PathStep("key", key=name))
        if selector is None:
            continue
        if arg is None or arg == "*":
            wildcards += 1
            if not allow_wildcard or wildcards > _MAX_WILDCARDS:
                raise ValidationDomainError.single("path", "path_wildcard")
            steps.append(PathStep("all"))
        elif int(arg) > _MAX_INDEX:
            raise ValidationDomainError.single("path", "path_index")
        else:
            steps.append(PathStep("index", index=int(arg)))
    return tuple(steps)


# ---- mappings ------------------------------------------------------------------------------


def _records_path(value: object) -> str:
    steps = parse_path(value)
    if not any(step.kind == "all" for step in steps):
        raise ValidationDomainError.single("records_path", "records_path_needs_wildcard")
    return str(value)


def _check_field_names(fields: dict[str, object]) -> None:
    if any(name not in FIELD_NAMES for name in fields):
        raise ValidationDomainError.single("fields", "unknown_field_name")
    if not set(fields) >= _REQUIRED_FIELDS:
        raise ValidationDomainError.single("fields", "missing_required_field")


RecordsPath = Annotated[str, BeforeValidator(_records_path)]


class JsonMapping(DomainModel):
    """``format: generic_json`` - which record list to read and where each field lives."""

    format: Literal["generic_json"]
    records_path: RecordsPath
    fields: dict[str, str]

    @model_validator(mode="after")
    def _check(self) -> Self:
        _check_field_names(dict(self.fields))
        for path in self.fields.values():
            parse_path(path, allow_wildcard=False)
        return self


class CsvMapping(DomainModel):
    """``format: csv`` - delimiter, header handling and the column of each field."""

    format: Literal["csv"]
    delimiter: str = ","
    has_header: Annotated[bool, Field(strict=True)] = True
    columns: dict[str, StrictStr | StrictInt]
    ignore_unknown_columns: Annotated[bool, Field(strict=True)] = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.delimiter not in CSV_DELIMITERS:
            raise ValidationDomainError.single("delimiter", "invalid_delimiter")
        _check_field_names(dict(self.columns))
        for column in self.columns.values():
            if self.has_header:
                valid = (
                    isinstance(column, str)
                    and 0 < len(column) <= 128
                    and column.isprintable()
                    and column.strip() == column
                )
            else:
                valid = isinstance(column, int) and not isinstance(column, bool)
                valid = valid and 0 <= int(column) < 1024
            if not valid:
                raise ValidationDomainError.single("columns", "invalid_column")
        return self


def parse_mapping(data: object, expected: ImportSource) -> JsonMapping | CsvMapping:
    """Validate a parsed mapping document for the format the caller asked for."""
    if not isinstance(data, dict):
        raise ValidationDomainError.single("mapping", "mapping_not_a_mapping")
    if data.get("format") != expected.value:
        raise ValidationDomainError.single("format", "format_mismatch")
    if expected is ImportSource.GENERIC_JSON:
        return JsonMapping.model_validate(data)
    if expected is ImportSource.CSV:
        return CsvMapping.model_validate(data)
    raise ValidationDomainError.single("format", "format_has_no_mapping")


# ---- records -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RawRecord:
    """A record as read from a file: canonical field names, text values, not yet redacted."""

    index: int
    fields: dict[str, str | None]
    locator: str
    json_pointer: str | None = None
    csv_row: int | None = None
    hints: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RejectedRecord:
    """A record that could not be read. Holds a field name and a code, never a value."""

    index: int
    locator: str
    field: str
    code: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    """What a parser returns: records (accepted-shape or rejected) and file-level warnings."""

    items: tuple[RawRecord | RejectedRecord, ...]
    warnings: tuple[str, ...] = ()


class Provenance(DomainModel):
    """Where a record came from. Hints are redacted text (e.g. ``baselineState=new``)."""

    source_file_name: Name
    source_file_sha256: Sha256
    location: Reason | None = None
    record_index: Annotated[int, Field(strict=True, ge=0)]
    json_pointer: Annotated[str, Field(max_length=512)] | None = None
    csv_row: Annotated[int, Field(strict=True, ge=1)] | None = None
    hints: Annotated[tuple[Name, ...], Field(max_length=MAX_HINTS)] = ()

    @model_validator(mode="after")
    def _one_locator(self) -> Self:
        if (self.json_pointer is None) == (self.csv_row is None):
            raise ValidationDomainError.single("provenance", "exactly_one_locator")
        return self


class ImportedFinding(DomainModel):
    """A normalized import record. Every text field has passed redaction before this exists.

    ``technical_severity`` is the severity the source states (or its documented level
    mapping); ``cvss_score`` is a stored source value. Neither is computed here.
    """

    title: Title
    description: LongText = ""
    asset_reference: Name | None = None
    owner: Name | None = None
    source: ImportSource
    evidence: Evidence = ""
    location: Reason | None = None
    technical_severity: TechnicalSeverity | None = None
    cvss_score: CvssScore | None = None
    cvss_vector: CvssVector | None = None
    external_rule_id: Name | None = None
    observed_at: UtcTimestamp | None = None
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class ImportReport:
    """The only thing the CLI prints. No titles, descriptions, evidence, paths or raw values."""

    source_name: str
    source_sha256: str
    format: str
    total_records: int
    accepted_records: int
    rejected_records: int
    warnings_count: int
    redaction_rule_hits: tuple[tuple[str, int], ...]
    records_with_provenance: int
    warning_codes: tuple[tuple[str, int], ...] = ()
    rejections: tuple[RejectedRecord, ...] = ()
    rejections_omitted: int = 0
    config_hash: str = ""
