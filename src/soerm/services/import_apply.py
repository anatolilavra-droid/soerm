"""Apply an import: records -> fingerprint -> lookup -> finding + occurrence -> run -> audit.

M6 scope, deliberately narrow:

* the file is read, redacted and normalized by :func:`~soerm.services.imports.preview_import`
  (M5) *before* the workspace is locked; nothing unredacted ever reaches storage;
* every record goes to **one existing asset** chosen by the caller (``asset_id``); the free-text
  asset reference of a record is not used to guess an asset;
* the identity of a finding is the SOERM fingerprint (:func:`compute_fingerprint`); source
  fingerprints are provenance hints only;
* a new fingerprint creates a finding (status ``open``); a known one only extends ``first_seen``
  / ``last_seen`` (never beyond "now"). Title, description, owner, severity, status and every
  analyst decision of an existing finding are left alone;
* each record adds an occurrence (file hash, workspace-relative path, locator, observation time);
* **idempotence**: a record whose finding already has an occurrence from the same file content
  (hash), path and locator is *unchanged*. If every record is unchanged nothing is written - no
  run, no audit entry. Otherwise one run, its audit entry and the finding entries commit
  together in one transaction;
* records without a technical severity are skipped (``missing_severity``) unless the caller
  names a default; severity is never computed (M7).

Audit entries hold identifiers and hashes only (``import.run``, ``finding.create``,
``finding.update``) - never titles, descriptions, evidence, paths or hints.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.domain.errors import DomainError
from soerm.domain.finding import Finding
from soerm.domain.identifiers import check_identifier
from soerm.domain.import_run import ImportRun, compute_fingerprint
from soerm.domain.imports import ImportedFinding, ImportReport
from soerm.domain.provenance import Occurrence
from soerm.services.common import PLACEHOLDER_TIME, require_actor
from soerm.services.errors import InvalidInputError, NotFoundServiceError, to_service_error
from soerm.services.imports import preview_import
from soerm.services.redaction import FieldRedactor, load_redactor
from soerm.services.workspace import Workspace
from soerm.storage.assets import AssetRepository
from soerm.storage.counters import CounterRepository
from soerm.storage.findings import FindingRepository
from soerm.storage.imports import ImportRunRepository, OccurrenceRepository

__all__ = ["ImportApplyResult", "apply_import"]

_CVSS_VERSION: Final = "4.0"
_PLACEHOLDER_FINDING_ID: Final = "FND-000001"
_PLACEHOLDER_RUN_ID: Final = "RUN-000001"
_PLACEHOLDER_ASSET: Final = "AST-000001"


@dataclass(frozen=True, slots=True)
class ImportApplyResult:
    """Counts and identifiers only."""

    status: str  # "imported" | "unchanged"
    run_id: str | None
    run_hash: str | None
    report: ImportReport
    created: int = 0
    updated: int = 0
    seen_again: int = 0  # known finding, nothing to change on it
    occurrences_added: int = 0
    unchanged: int = 0  # records already imported from this same file content
    duplicates_in_file: int = 0
    skipped: tuple[tuple[str, int], ...] = ()
    audit_entries: int = 0
    last_audit_seq: int | None = None
    last_audit_hash: str | None = None
    finding_ids: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class _Prepared:
    fingerprint: str
    fields: dict[str, object]
    locator: str | None
    observed_at: datetime | None


def _finding_fields(
    record: ImportedFinding, asset_id: str, severity: TechnicalSeverity
) -> dict[str, object]:
    return {
        "title": record.title,
        "description": record.description,
        "asset_id": asset_id,
        "source": record.source,
        "evidence": record.evidence,
        "technical_severity": severity,
        "owner": record.owner,
        "cvss_version": _CVSS_VERSION if record.cvss_vector is not None else None,
        "cvss_vector": record.cvss_vector,
        "cvss_score": record.cvss_score,
        "cvss_score_source": "imported" if record.cvss_score is not None else None,
    }


def _prepare(
    records: tuple[ImportedFinding, ...],
    asset_id: str,
    default_severity: TechnicalSeverity | None,
) -> tuple[list[_Prepared], Counter[str]]:
    """Validate every record as a finding before the workspace is touched."""
    prepared: list[_Prepared] = []
    skipped: Counter[str] = Counter()
    for record in records:
        severity = record.technical_severity or default_severity
        if severity is None:
            skipped["missing_severity"] += 1
            continue
        fingerprint = compute_fingerprint(
            source=record.source,
            asset_id=asset_id,
            title=record.title,
            external_rule_id=record.external_rule_id,
            location=record.location,
        )
        fields = _finding_fields(record, asset_id, severity)
        try:
            Finding(
                finding_id=_PLACEHOLDER_FINDING_ID,
                fingerprint=fingerprint,
                first_seen=PLACEHOLDER_TIME,
                last_seen=PLACEHOLDER_TIME,
                created_at=PLACEHOLDER_TIME,
                updated_at=PLACEHOLDER_TIME,
                **fields,  # type: ignore[arg-type]
            )
            Occurrence(
                import_run_id=_PLACEHOLDER_RUN_ID,
                file_sha256=record.provenance.source_file_sha256,
                source_path="x",
                observed_at=PLACEHOLDER_TIME,
                location=record.provenance.location,
            )
        except DomainError:
            skipped["invalid_record"] += 1
            continue
        prepared.append(
            _Prepared(fingerprint, fields, record.provenance.location, record.observed_at)
        )
    return prepared, skipped


def _relative_source_path(workspace: Workspace, path: str, fallback: str) -> str:
    """Workspace-relative POSIX form of ``path`` (pure string handling; the file was already
    checked by the safe reader)."""
    text = path.replace("\\", "/")
    if text.startswith("/"):
        prefix = str(workspace.path).replace("\\", "/").rstrip("/") + "/"
        if not text.startswith(prefix):
            return fallback
        text = text[len(prefix) :]
    return "/".join(part for part in text.split("/") if part not in {"", "."}) or fallback


def _observed(prepared: _Prepared, now: datetime) -> datetime:
    """The observation time, never later than the moment of the import."""
    return now if prepared.observed_at is None else min(prepared.observed_at, now)


def apply_import(
    workspace: Workspace,
    path: str,
    *,
    actor: str,
    fmt: ImportSource,
    asset_id: str,
    mapping_path: str | None = None,
    default_severity: TechnicalSeverity | None = None,
) -> ImportApplyResult:
    """Import ``path`` into the asset ``asset_id``. See the module docstring."""
    actor = require_actor(actor)
    try:
        asset_id = check_identifier("AST", asset_id, field="asset_id")
    except DomainError as exc:
        raise to_service_error(exc) from None
    if default_severity is not None:
        try:
            default_severity = TechnicalSeverity(default_severity)
        except ValueError:
            raise InvalidInputError("default_severity: invalid_enum") from None
        if default_severity is TechnicalSeverity.NONE:
            raise InvalidInputError("default_severity: not_allowed")
    preview = preview_import(workspace, path, fmt=fmt, mapping_path=mapping_path)
    report = preview.report
    fmt = ImportSource(fmt)
    source_path = FieldRedactor(load_redactor(workspace.path)).field(
        "source_path", _relative_source_path(workspace, path, report.source_name), "location"
    )
    prepared, skipped = _prepare(preview.records, asset_id, default_severity)
    try:  # the path must be a valid workspace-relative path
        ImportRun(
            run_id=_PLACEHOLDER_RUN_ID,
            source=fmt,
            file_sha256=report.source_sha256,
            source_path=source_path,
            imported_at=PLACEHOLDER_TIME,
            record_count=len(prepared),
        )
    except DomainError as exc:
        raise to_service_error(exc) from None
    sha = report.source_sha256
    with workspace.write() as session:
        connection = session.connection
        if AssetRepository(connection).get(asset_id) is None:
            raise NotFoundServiceError("object_not_found", object_type="asset")
        findings = FindingRepository(connection)
        occurrences = OccurrenceRepository(connection)

        def known(item: _Prepared) -> bool:
            existing = findings.get_by_fingerprint(item.fingerprint)
            return existing is not None and occurrences.exists(
                existing.finding_id, file_sha256=sha, source_path=source_path, location=item.locator
            )

        pending = [item for item in prepared if not known(item)]
        skipped_codes = tuple(sorted(skipped.items()))
        if not pending:
            return ImportApplyResult(
                status="unchanged",
                run_id=None,
                run_hash=None,
                report=report,
                unchanged=len(prepared),
                skipped=skipped_codes,
            )
        run = ImportRun(
            run_id=CounterRepository(connection).next_identifier("RUN"),
            source=fmt,
            file_sha256=sha,
            source_path=source_path,
            imported_at=session.now,
            record_count=len(prepared),
        )
        run_entry = ImportRunRepository(connection).add(run, actor=actor, at=session.now)
        entries = [run_entry]
        created = updated = seen_again = duplicates = 0
        seen: set[str] = set()
        ids: list[str] = []
        for item in pending:
            observed = _observed(item, session.now)
            existing = findings.get_by_fingerprint(item.fingerprint)
            if existing is None:
                finding = Finding(
                    finding_id=CounterRepository(connection).next_identifier("FND"),
                    fingerprint=item.fingerprint,
                    first_seen=observed,
                    last_seen=observed,
                    created_at=session.now,
                    updated_at=session.now,
                    **item.fields,  # type: ignore[arg-type]
                )
                entries.append(findings.add(finding, actor=actor, at=session.now))
                created += 1
            else:
                finding = existing
                first, last = min(existing.first_seen, observed), max(existing.last_seen, observed)
                if (first, last) != (existing.first_seen, existing.last_seen):
                    finding = existing.with_changes(
                        first_seen=first, last_seen=last, updated_at=session.now
                    )
                    entries.append(
                        findings.update(
                            finding,
                            actor=actor,
                            at=session.now,
                            expected_before_hash=existing.digest(),
                        )
                    )
                    updated += 1
                elif item.fingerprint not in seen:
                    seen_again += 1
            if item.fingerprint in seen:
                duplicates += 1
            seen.add(item.fingerprint)
            occurrences.add(
                finding.finding_id,
                Occurrence(
                    import_run_id=run.run_id,
                    file_sha256=sha,
                    source_path=source_path,
                    observed_at=observed,
                    location=item.locator,
                ),
            )
            ids.append(finding.finding_id)
    return ImportApplyResult(
        status="imported",
        run_id=run.run_id,
        run_hash=run.digest(),
        created=created,
        updated=updated,
        seen_again=seen_again,
        occurrences_added=len(pending),
        unchanged=len(prepared) - len(pending),
        duplicates_in_file=duplicates,
        audit_entries=len(entries),
        last_audit_seq=entries[-1].seq,
        last_audit_hash=entries[-1].entry_hash,
        finding_ids=tuple(dict.fromkeys(ids)),
        report=report,
        skipped=skipped_codes,
    )
