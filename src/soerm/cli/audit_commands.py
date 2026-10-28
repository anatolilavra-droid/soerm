"""``soerm audit verify``: re-compute the audit hash chain (read-only).

Exit 0 if the chain is intact, 3 if it is broken. Prints the number of entries, the last hash
and, if broken, the first bad position with a reason code - never the content of any entry.
"""

import argparse

from soerm.cli.common import open_workspace
from soerm.cli.output import dumps_json, render_key_values, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.services.audit_check import verify_workspace_audit

__all__ = ["register"]

EXIT_AUDIT_BROKEN = 3


def _verify(args: argparse.Namespace) -> int:
    audit = verify_workspace_audit(open_workspace(args))
    status = "intact" if audit.intact else "broken"
    if args.json:
        write_line(
            dumps_json(
                {
                    "status": status,
                    "entries": audit.entries,
                    "head_hash": audit.head_hash,
                    "broken_at_seq": audit.broken_at_seq,
                    "reason": audit.reason,
                }
            )
        )
    else:
        write_line(
            render_key_values(
                [
                    ("status", status),
                    ("entries", audit.entries),
                    ("head_hash", audit.head_hash or "-"),
                    ("broken_at_seq", "-" if audit.broken_at_seq is None else audit.broken_at_seq),
                    ("reason", audit.reason or "-"),
                ]
            )
        )
    return 0 if audit.intact else EXIT_AUDIT_BROKEN


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    audit = subparsers.add_parser(
        "audit",
        help="check the audit hash chain",
        description="Audit log checks. Read-only: no lock, no database creation.",
    )
    commands = audit.add_subparsers(
        dest="audit_command", required=True, parser_class=SafeArgumentParser
    )
    verify = commands.add_parser(
        "verify",
        help="re-compute the hash chain",
        description="Re-compute every audit entry hash and check the links. Exit 0 if intact, "
        "3 if broken.",
    )
    verify.add_argument("--workspace", required=True, metavar="DIR", help="workspace directory")
    verify.add_argument("--json", action="store_true", help="print JSON instead of a table")
    verify.set_defaults(handler=_verify)
