"""``soerm finding add | show | list | update``."""

import argparse
from datetime import datetime

from soerm.cli.common import (
    mutation_parent,
    open_workspace,
    print_mutation,
    read_parent,
)
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import CliUsageError, SafeArgumentParser
from soerm.domain.enums import BusinessPriority, FindingStatus, TechnicalSeverity
from soerm.domain.finding import Finding
from soerm.services import findings as finding_service

__all__ = ["finding_to_dict", "register"]

_SHELL_HISTORY_NOTE = (
    "Command-line arguments may be stored in shell history. "
    "For sensitive evidence, use a future file-based input mechanism after M4."
)
_EVIDENCE_HELP = " ".join(
    ("evidence text, redacted before storage and shortened to 4096 bytes.", _SHELL_HISTORY_NOTE)
)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Stable field order. The evidence text is never included, only its presence and size."""
    return {
        "finding_id": finding.finding_id,
        "hash": finding.digest(),
        "asset_id": finding.asset_id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "description": finding.description,
        "status": finding.status.value,
        "technical_severity": finding.technical_severity.value,
        "business_priority": None
        if finding.business_priority is None
        else finding.business_priority.value,
        "risk_factors": dict(finding.risk_factors),
        "risk_formula_version": finding.risk_formula_version,
        "risk_config_hash": finding.risk_config_hash,
        "cvss_version": finding.cvss_version,
        "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score,
        "cvss_score_source": finding.cvss_score_source,
        "owner": finding.owner,
        "source": finding.source.value,
        "sla_due_at": _iso(finding.sla_due_at),
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
        "created_at": _iso(finding.created_at),
        "updated_at": _iso(finding.updated_at),
        "evidence": {"present": bool(finding.evidence), "bytes": len(finding.evidence.encode())},
    }


def _add(args: argparse.Namespace) -> int:
    result = finding_service.create_finding(
        open_workspace(args),
        actor=args.actor,
        asset_id=args.asset_id,
        fingerprint=args.fingerprint,
        title=args.title,
        technical_severity=args.severity,
        description=args.description,
        evidence=args.evidence,
        owner=args.owner,
        cvss_vector=args.cvss_vector,
        cvss_score=args.cvss_score,
    )
    return print_mutation(result, verb="created", as_json=args.json)


def _show(args: argparse.Namespace) -> int:
    if args.show_evidence and args.json:
        raise CliUsageError("--show-evidence cannot be combined with --json")
    finding = finding_service.get_finding(open_workspace(args), args.finding_id)
    data = finding_to_dict(finding)
    if args.json:
        write_line(dumps_json(data))
        return 0
    rows: list[tuple[str, object]] = []
    for key, value in data.items():
        if key == "evidence":
            if not finding.evidence:
                rows.append((key, "-"))
            elif args.show_evidence:
                rows.append((key, finding.evidence))
            else:
                rows.append(
                    (key, f"hidden ({len(finding.evidence.encode())} bytes); use --show-evidence")
                )
        else:
            rows.append((key, "-" if value is None or value == "" else value))
    write_line(render_key_values(rows))
    return 0


def _list(args: argparse.Namespace) -> int:
    findings = finding_service.list_findings(
        open_workspace(args),
        status=args.status,
        asset_id=args.asset_id,
        severity=args.severity,
        sort=args.sort,
    )
    if args.json:
        write_line(dumps_json({"findings": [finding_to_dict(f) for f in findings]}))
        return 0
    rows = [
        (
            f.finding_id,
            f.status,
            f.technical_severity,
            "-" if f.business_priority is None else f.business_priority,
            f.asset_id,
            f.title,
        )
        for f in findings
    ]
    write_line(render_table(("ID", "STATUS", "SEVERITY", "PRIORITY", "ASSET", "TITLE"), rows))
    return 0


def _update(args: argparse.Namespace) -> int:
    result = finding_service.update_finding(
        open_workspace(args),
        args.finding_id,
        actor=args.actor,
        expected_hash=args.expect_hash,
        title=args.title,
        description=args.description,
        evidence=args.evidence,
        owner=args.owner,
        clear_owner=args.clear_owner,
        technical_severity=args.severity,
        status=args.status,
        business_priority=args.business_priority,
        change_id=args.change_id,
    )
    return print_mutation(result, verb="updated", as_json=args.json)


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    finding = subparsers.add_parser(
        "finding", help="manage findings", description="Manage findings."
    )
    commands = finding.add_subparsers(
        dest="finding_command", required=True, parser_class=SafeArgumentParser
    )
    add = commands.add_parser(
        "add",
        parents=[mutation_parent()],
        help="create a finding",
        description=" ".join(
            (
                "Create a finding. Title, description, owner and evidence are redacted",
                "(built-in rules plus soerm.yaml) before they are stored.",
                _SHELL_HISTORY_NOTE,
            )
        ),
    )
    add.add_argument("--asset-id", required=True, metavar="AST-NNNNNN")
    add.add_argument("--fingerprint", required=True, metavar="SHA256", help="lowercase hex SHA-256")
    add.add_argument("--title", required=True, metavar="TEXT")
    add.add_argument(
        "--severity", required=True, type=TechnicalSeverity, choices=list(TechnicalSeverity)
    )
    add.add_argument("--description", default="", metavar="TEXT")
    add.add_argument("--evidence", default="", metavar="TEXT", help=_EVIDENCE_HELP)
    add.add_argument("--owner", metavar="TEXT")
    add.add_argument(
        "--cvss-vector",
        metavar="VECTOR",
        help="CVSS:4.0/... (strict CVSS v4.0 syntax; the score is never derived on add)",
    )
    add.add_argument("--cvss-score", type=_score, metavar="0-10", help="stored, never calculated")
    add.set_defaults(handler=_add)

    show = commands.add_parser(
        "show", parents=[read_parent()], help="show a finding", description="Show a finding."
    )
    show.add_argument("finding_id", metavar="FINDING_ID")
    show.add_argument(
        "--show-evidence", action="store_true", help="print the stored evidence text (table only)"
    )
    show.set_defaults(handler=_show)

    list_parser = commands.add_parser(
        "list", parents=[read_parent()], help="list findings", description="List findings."
    )
    list_parser.add_argument("--status", type=FindingStatus, choices=list(FindingStatus))
    list_parser.add_argument("--asset-id", metavar="AST-NNNNNN")
    list_parser.add_argument("--severity", type=TechnicalSeverity, choices=list(TechnicalSeverity))
    list_parser.add_argument(
        "--sort",
        type=finding_service.FindingSort,
        choices=list(finding_service.FindingSort),
        default=finding_service.FindingSort.ID,
    )
    list_parser.set_defaults(handler=_list)

    update = commands.add_parser(
        "update",
        parents=[mutation_parent()],
        help="change a finding",
        description="Change a finding. The hash shown by 'finding show' is required. Changing "
        "the business priority, or moving a finding to or from accepted_risk / "
        "false_positive, needs an approved request "
        "('approval request' / 'approval approve') and is refused (exit 4) unless it is "
        "presented with --change-id. Changed text "
        "is redacted before it is stored. Command-line arguments may be stored in shell history; "
        "for sensitive evidence, use a future file-based input mechanism after M4.",
    )
    update.add_argument("finding_id", metavar="FINDING_ID")
    update.add_argument(
        "--expect-hash", required=True, metavar="SHA256", help="'hash' printed by 'finding show'"
    )
    update.add_argument("--title", metavar="TEXT")
    update.add_argument("--description", metavar="TEXT")
    update.add_argument("--evidence", metavar="TEXT", help=_EVIDENCE_HELP)
    owner = update.add_mutually_exclusive_group()
    owner.add_argument("--owner", metavar="TEXT")
    owner.add_argument("--clear-owner", action="store_true")
    update.add_argument("--severity", type=TechnicalSeverity, choices=list(TechnicalSeverity))
    update.add_argument("--status", type=FindingStatus, choices=list(FindingStatus))
    update.add_argument(
        "--business-priority", type=BusinessPriority, choices=list(BusinessPriority)
    )
    update.add_argument(
        "--change-id",
        metavar="CHG-NNNNNN",
        help="apply an approved change (only --status / --business-priority may be given)",
    )
    update.set_defaults(handler=_update)


def _score(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number") from None
