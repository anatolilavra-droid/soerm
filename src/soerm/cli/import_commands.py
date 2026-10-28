"""``soerm import preview``: read, check, redact and summarize a local file. Writes nothing."""

import argparse

from soerm.cli.common import mutation_parent, open_workspace, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import CliUsageError, SafeArgumentParser
from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.domain.imports import ImportReport
from soerm.services.import_apply import ImportApplyResult, apply_import
from soerm.services.imports import preview_import

__all__ = ["register", "report_to_dict"]

_FORMATS = {
    "sarif": ImportSource.SARIF,
    "json": ImportSource.GENERIC_JSON,
    "csv": ImportSource.CSV,
}


def report_to_dict(report: ImportReport) -> dict[str, object]:
    """Counts, codes and locators only - no titles, descriptions, evidence or raw values."""
    return {
        "source_name": report.source_name,
        "source_sha256": report.source_sha256,
        "format": report.format,
        "total_records": report.total_records,
        "accepted_records": report.accepted_records,
        "rejected_records": report.rejected_records,
        "warnings_count": report.warnings_count,
        "warning_codes": dict(report.warning_codes),
        "redaction_rule_hits": dict(report.redaction_rule_hits),
        "records_with_provenance": report.records_with_provenance,
        "rejections": [
            {"record_index": r.index, "locator": r.locator, "field": r.field, "code": r.code}
            for r in report.rejections
        ],
        "rejections_omitted": report.rejections_omitted,
        "config_hash": report.config_hash,
    }


def _preview(args: argparse.Namespace) -> int:
    if args.format == "sarif" and args.mapping is not None:
        raise CliUsageError("--mapping is not used with --format sarif")
    if args.format != "sarif" and args.mapping is None:
        raise CliUsageError("--mapping is required for --format json and --format csv")
    preview = preview_import(
        open_workspace(args), args.path, fmt=_FORMATS[args.format], mapping_path=args.mapping
    )
    report = preview.report
    if args.json:
        write_line(dumps_json(report_to_dict(report)))
        return 0
    hits = ", ".join(f"{name}={count}" for name, count in report.redaction_rule_hits)
    codes = ", ".join(f"{name}={count}" for name, count in report.warning_codes)
    rows: list[tuple[str, object]] = [
        ("source_name", report.source_name),
        ("source_sha256", report.source_sha256),
        ("format", report.format),
        ("total_records", report.total_records),
        ("accepted_records", report.accepted_records),
        ("rejected_records", report.rejected_records),
        ("warnings_count", report.warnings_count),
        ("warning_codes", codes or "-"),
        ("redaction_hits", hits or "-"),
        ("with_provenance", report.records_with_provenance),
        ("config_hash", report.config_hash),
    ]
    write_line(render_key_values(rows))
    if report.rejections:
        write_line("")
        table = [(r.index, r.locator, r.field, r.code) for r in report.rejections]
        write_line(render_table(("RECORD", "LOCATOR", "FIELD", "CODE"), table))
        if report.rejections_omitted:
            write_line(f"... and {report.rejections_omitted} more rejected records")
    write_line("preview only: nothing was written")
    return 0


def _result_to_dict(result: ImportApplyResult) -> dict[str, object]:
    """Identifiers and counts only - never titles, descriptions, evidence or paths."""
    return {
        "result": result.status,
        "run_id": result.run_id,
        "run_hash": result.run_hash,
        "source_sha256": result.report.source_sha256,
        "format": result.report.format,
        "total_records": result.report.total_records,
        "rejected_records": result.report.rejected_records,
        "findings_created": result.created,
        "findings_updated": result.updated,
        "findings_seen_again": result.seen_again,
        "occurrences_added": result.occurrences_added,
        "records_unchanged": result.unchanged,
        "duplicates_in_file": result.duplicates_in_file,
        "skipped": dict(result.skipped),
        "warning_codes": dict(result.report.warning_codes),
        "redaction_rule_hits": dict(result.report.redaction_rule_hits),
        "config_hash": result.report.config_hash,
        "audit_entries": result.audit_entries,
        "last_audit_seq": result.last_audit_seq,
        "last_audit_hash": result.last_audit_hash,
        "finding_ids": list(result.finding_ids),
    }


def _run(args: argparse.Namespace) -> int:
    if args.format == "sarif" and args.mapping is not None:
        raise CliUsageError("--mapping is not used with --format sarif")
    if args.format != "sarif" and args.mapping is None:
        raise CliUsageError("--mapping is required for --format json and --format csv")
    result = apply_import(
        open_workspace(args),
        args.path,
        actor=args.actor,
        fmt=_FORMATS[args.format],
        asset_id=args.asset_id,
        mapping_path=args.mapping,
        default_severity=args.default_severity,
    )
    data = _result_to_dict(result)
    if args.json:
        write_line(dumps_json(data))
        return 0
    rows: list[tuple[str, object]] = []
    for key, value in data.items():
        if key == "finding_ids":
            continue
        if isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        rows.append((key, "-" if value is None or value == "" else value))
    write_line(render_key_values(rows))
    if result.status == "unchanged":
        write_line("nothing to import: every record is already recorded from this file")
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    parser = subparsers.add_parser(
        "import", help="preview and apply local files", description="Preview or apply imports."
    )
    commands = parser.add_subparsers(
        dest="import_command", required=True, parser_class=SafeArgumentParser
    )
    preview = commands.add_parser(
        "preview",
        parents=[read_parent()],
        help="read, redact and summarize a file",
        description="Read a file inside the workspace (SARIF 2.1.0, generic JSON or CSV), "
        "check its limits and structure, redact its text and print a report. Relative paths "
        "are taken relative to the workspace. Creates no database, takes no lock, copies no "
        "input and never prints titles, descriptions, evidence or rejected values.",
    )
    preview.add_argument("path", metavar="PATH", help="file inside the workspace")
    preview.add_argument(
        "--format", required=True, choices=sorted(_FORMATS), help="input format (no guessing)"
    )
    preview.add_argument(
        "--mapping", metavar="FILE", help="YAML mapping inside the workspace (json and csv)"
    )
    preview.set_defaults(handler=_preview)

    run = commands.add_parser(
        "run",
        parents=[mutation_parent()],
        help="import a file into the workspace database",
        description="Import a file inside the workspace into one existing asset. Text is "
        "redacted before it is stored. Each record gets a SOERM fingerprint: a new fingerprint "
        "creates a finding, a known one only updates first_seen/last_seen; every record adds an "
        "occurrence (file hash, path, locator). Repeating the same import changes nothing. "
        "Records without a severity are skipped unless --default-severity is given. The audit "
        "log gets identifiers and hashes only.",
    )
    run.add_argument("path", metavar="PATH", help="file inside the workspace")
    run.add_argument(
        "--format", required=True, choices=sorted(_FORMATS), help="input format (no guessing)"
    )
    run.add_argument("--asset-id", required=True, metavar="AST-NNNNNN", help="target asset")
    run.add_argument(
        "--mapping", metavar="FILE", help="YAML mapping inside the workspace (json and csv)"
    )
    run.add_argument(
        "--default-severity",
        type=TechnicalSeverity,
        choices=[s for s in TechnicalSeverity if s is not TechnicalSeverity.NONE],
        help="severity for records that state none (otherwise they are skipped)",
    )
    run.set_defaults(handler=_run)
