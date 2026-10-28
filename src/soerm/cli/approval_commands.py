"""``soerm approval request | show | list | approve | reject | expire``."""

import argparse
from datetime import datetime

from soerm.cli.common import mutation_parent, open_workspace, print_mutation, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.domain.enums import ApprovalStatus, BusinessPriority, FindingStatus
from soerm.services import approvals as approval_service
from soerm.services.approvals import ApprovalView

__all__ = ["register", "view_to_dict"]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def view_to_dict(view: ApprovalView) -> dict[str, object]:
    a = view.approval
    return {
        "change_id": a.change_id,
        "object_type": a.object_type,
        "object_id": a.object_id,
        "status": a.status.value,
        "effective_status": view.effective_status,
        "applied": view.applied,
        "requester": a.requester,
        "approver": a.approver,
        "reason": a.reason,
        "before_hash": a.before_hash,
        "proposed_after_hash": a.proposed_after_hash,
        "require_distinct_approver": a.require_distinct_approver,
        "requested_at": _iso(a.requested_at),
        "expires_at": _iso(a.expires_at),
        "decided_at": _iso(a.decided_at),
    }


def _request(args: argparse.Namespace) -> int:
    result = approval_service.request_change(
        open_workspace(args),
        args.finding_id,
        actor=args.actor,
        reason=args.reason,
        status=args.status,
        business_priority=args.business_priority,
    )
    return print_mutation(result, verb="requested", as_json=args.json)


def _show(args: argparse.Namespace) -> int:
    data = view_to_dict(approval_service.get_approval(open_workspace(args), args.change_id))
    if args.json:
        write_line(dumps_json(data))
    else:
        write_line(render_key_values([(k, "-" if v is None else v) for k, v in data.items()]))
    return 0


def _list(args: argparse.Namespace) -> int:
    views = approval_service.list_approvals(
        open_workspace(args), status=args.status, finding_id=args.finding_id
    )
    if args.json:
        write_line(dumps_json({"approvals": [view_to_dict(v) for v in views]}))
        return 0
    rows = [
        (
            v.approval.change_id,
            v.effective_status,
            v.approval.object_id,
            v.approval.requester,
            v.approval.approver or "-",
            _iso(v.approval.expires_at) or "-",
            "yes" if v.applied else "no",
        )
        for v in views
    ]
    write_line(
        render_table(
            ("ID", "STATUS", "OBJECT", "REQUESTER", "APPROVER", "EXPIRES", "APPLIED"), rows
        )
    )
    return 0


def _approve(args: argparse.Namespace) -> int:
    result = approval_service.decide_approval(
        open_workspace(args), args.change_id, actor=args.actor, approved=True
    )
    return print_mutation(result, verb="approved", as_json=args.json)


def _reject(args: argparse.Namespace) -> int:
    result = approval_service.decide_approval(
        open_workspace(args), args.change_id, actor=args.actor, approved=False
    )
    return print_mutation(result, verb="rejected", as_json=args.json)


def _expire(args: argparse.Namespace) -> int:
    outcome = approval_service.expire_pending(open_workspace(args), actor=args.actor)
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "expired",
                    "expired": list(outcome.expired),
                    "audit_entries": outcome.audit_entries,
                }
            )
        )
    else:
        write_line(
            render_key_values(
                [
                    ("expired", ", ".join(outcome.expired) or "-"),
                    ("audit_entries", outcome.audit_entries),
                ]
            )
        )
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    approval = subparsers.add_parser(
        "approval",
        help="approvals of critical finding changes",
        description="Gated changes: moving a finding to or from accepted_risk / false_positive "
        "and setting business priority by hand. Request, approve (by someone else, unless "
        "soerm.yaml allows otherwise), then apply with 'finding update --change-id'. An "
        "approval is single-use and expires.",
    )
    commands = approval.add_subparsers(
        dest="approval_command", required=True, parser_class=SafeArgumentParser
    )

    request = commands.add_parser(
        "request",
        parents=[mutation_parent()],
        help="ask for approval of a gated change",
        description="Describe the change with --status and/or --business-priority. Nothing is "
        "changed until it is approved and applied. The reason is redacted.",
    )
    request.add_argument("finding_id", metavar="FINDING_ID")
    request.add_argument("--reason", required=True, metavar="TEXT")
    request.add_argument("--status", type=FindingStatus, choices=list(FindingStatus))
    request.add_argument(
        "--business-priority", type=BusinessPriority, choices=list(BusinessPriority)
    )
    request.set_defaults(handler=_request)

    show = commands.add_parser("show", parents=[read_parent()], help="show an approval")
    show.add_argument("change_id", metavar="CHANGE_ID")
    show.set_defaults(handler=_show)

    list_parser = commands.add_parser("list", parents=[read_parent()], help="list approvals")
    list_parser.add_argument("--status", type=ApprovalStatus, choices=list(ApprovalStatus))
    list_parser.add_argument("--finding-id", metavar="FND-NNNNNN")
    list_parser.set_defaults(handler=_list)

    for name, handler, text in (
        ("approve", _approve, "approve a pending request (one decision only)"),
        ("reject", _reject, "reject a pending request (one decision only)"),
    ):
        parser = commands.add_parser(name, parents=[mutation_parent()], help=text)
        parser.add_argument("change_id", metavar="CHANGE_ID")
        parser.set_defaults(handler=handler)

    expire = commands.add_parser(
        "expire",
        parents=[mutation_parent()],
        help="record the expiry of overdue pending requests",
    )
    expire.set_defaults(handler=_expire)
