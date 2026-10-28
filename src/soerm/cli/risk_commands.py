"""``soerm risk preview`` (read-only) and ``soerm risk recalculate`` (the only writer).

Neither prints titles, descriptions or evidence: identifiers, enum values, numbers and
timestamps only. ``preview`` never writes; a recalculation happens only when asked for.
"""

import argparse

from soerm.cli.common import mutation_parent, open_workspace, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.services.risk import RiskItem, RiskRun, preview_risk, recalculate_risk

__all__ = ["register"]


def _stamp(value: object) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")  # type: ignore[attr-defined]


def _item_dict(item: RiskItem) -> dict[str, object]:
    cvss = item.cvss
    assessment = item.assessment
    return {
        "finding_id": item.finding_id,
        "outcome": item.outcome,
        "reason": item.reason,
        "technical_severity": item.severity.value,
        "cvss": {
            "vector": cvss.vector,
            "nomenclature": cvss.nomenclature,
            "computed_score": cvss.computed_score,
            "derived_severity": None
            if cvss.derived_severity is None
            else cvss.derived_severity.value,
            "imported_score": cvss.imported_score,
            "score_matches": cvss.score_matches,
            "severity_differs": cvss.severity_differs,
        },
        "severity_sync": item.severity_sync,
        "risk_score": None if assessment is None else assessment.score,
        "business_priority": None if assessment is None else assessment.priority.value,
        "priority_before": None if item.priority_before is None else item.priority_before.value,
        "sla_due_at": _stamp(item.sla_due_at),
        "sla_before": _stamp(item.sla_before),
        "warnings": list(item.warnings),
        "before_hash": item.before_hash,
        "after_hash": item.after_hash,
        "explanation": [
            {"factor": line.name, "value": line.value, "effect": line.effect}
            for line in item.explanation
        ],
    }


def _run_dict(run: RiskRun, *, written: bool) -> dict[str, object]:
    data: dict[str, object] = {
        "result": "recalculated" if written else "preview",
        "formula_version": run.formula_version,
        "risk_config_hash": run.config_hash,
        "changed": run.changed,
        "unchanged": run.unchanged,
        "skipped": run.skipped,
        "findings": [_item_dict(item) for item in run.items],
    }
    if written:
        data["audit_entries"] = run.audit_entries
        data["last_audit_seq"] = run.last_audit_seq
        data["last_audit_hash"] = run.last_audit_hash
    return data


def _print(run: RiskRun, args: argparse.Namespace, *, written: bool) -> int:
    if args.json:
        write_line(dumps_json(_run_dict(run, written=written)))
        return 0
    rows = [
        (
            item.finding_id,
            item.outcome if item.reason is None else f"{item.outcome} ({item.reason})",
            item.severity.value,
            "-" if item.assessment is None else f"{item.assessment.score:g}",
            "-" if item.assessment is None else item.assessment.priority.value.upper(),
            _stamp(item.sla_due_at) or "-",
            ",".join(item.warnings) or "-",
        )
        for item in run.items
    ]
    write_line(
        render_table(
            ("ID", "OUTCOME", "SEVERITY", "SCORE", "PRIORITY", "SLA_DUE", "WARNINGS"), rows
        )
    )
    summary: list[tuple[str, object]] = [
        ("formula_version", run.formula_version),
        ("risk_config_hash", run.config_hash),
        ("changed", run.changed),
        ("unchanged", run.unchanged),
        ("skipped", run.skipped),
    ]
    if written:
        summary.append(("audit_entries", run.audit_entries))
    write_line(render_key_values(summary))
    if len(run.items) == 1 and run.items[0].explanation:
        write_line("")
        write_line(
            render_table(
                ("FACTOR", "VALUE", "EFFECT"),
                [(line.name, line.value, line.effect) for line in run.items[0].explanation],
            )
        )
        cvss = run.items[0].cvss
        write_line(
            render_key_values(
                [
                    ("cvss_vector", cvss.vector),
                    ("cvss_nomenclature", cvss.nomenclature or "-"),
                    (
                        "cvss_computed_score",
                        "-" if cvss.computed_score is None else cvss.computed_score,
                    ),
                    (
                        "cvss_imported_score",
                        "-" if cvss.imported_score is None else cvss.imported_score,
                    ),
                    (
                        "cvss_score_matches",
                        "-" if cvss.score_matches is None else cvss.score_matches,
                    ),
                ]
            )
        )
    write_line("recalculated and stored" if written else "preview only: nothing was written")
    return 0


def _target(args: argparse.Namespace) -> dict[str, object]:
    return {
        "finding_id": args.finding_id,
        "all_findings": args.all,
        "sync_severity": args.sync_severity,
    }


def _preview(args: argparse.Namespace) -> int:
    run = preview_risk(open_workspace(args), **_target(args))  # type: ignore[arg-type]
    return _print(run, args, written=False)


def _recalculate(args: argparse.Namespace) -> int:
    run = recalculate_risk(open_workspace(args), actor=args.actor, **_target(args))  # type: ignore[arg-type]
    return _print(run, args, written=True)


def _add_target(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("finding_id", nargs="?", metavar="FINDING_ID", help="one finding")
    parser.add_argument("--all", action="store_true", help="every finding in the workspace")
    parser.add_argument(
        "--sync-severity",
        action="store_true",
        help="also adopt the severity derived from a valid CVSS v4.0 vector "
        "(otherwise it is only reported)",
    )


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    risk = subparsers.add_parser(
        "risk",
        help="CVSS check, business priority and SLA",
        description="Business risk (P1-P4) and SLA due dates from the risk model in soerm.yaml. "
        "Risk is not CVSS: the technical severity is combined with asset criticality, exposure, "
        "data classification and environment.",
    )
    commands = risk.add_subparsers(
        dest="risk_command", required=True, parser_class=SafeArgumentParser
    )
    preview = commands.add_parser(
        "preview",
        parents=[read_parent()],
        help="show what a recalculation would store (writes nothing)",
        description="Validate the CVSS v4.0 vector, compute score, priority and SLA, and explain "
        "the factors. Read-only: no lock, nothing is written.",
    )
    _add_target(preview)
    preview.set_defaults(handler=_preview)
    recalculate = commands.add_parser(
        "recalculate",
        parents=[mutation_parent()],
        help="recalculate and store priority, risk factors and SLA",
        description="Store business_priority, risk_factors, risk_config_hash and sla_due_at. "
        "Never changes status, owner or text, never closes or reopens a finding; resolved, "
        "accepted_risk and false_positive findings and priorities set outside the risk model "
        "are skipped. One audit entry (ids and hashes) per changed finding; repeating the "
        "command changes nothing.",
    )
    _add_target(recalculate)
    recalculate.set_defaults(handler=_recalculate)
