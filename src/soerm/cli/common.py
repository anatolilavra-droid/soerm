"""Shared CLI plumbing: common options, result rendering, error reporting."""

import argparse
import sys
from collections.abc import Callable, Mapping

from soerm.cli.output import dumps_json, render_key_values, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.services.common import MutationResult
from soerm.services.workspace import Workspace

__all__ = [
    "Handler",
    "mutation_parent",
    "open_workspace",
    "print_mutation",
    "read_parent",
]

Handler = Callable[[argparse.Namespace], int]


def read_parent() -> SafeArgumentParser:
    """Options of every command: the workspace and the output format."""
    parent = SafeArgumentParser(add_help=False)
    parent.add_argument("--workspace", required=True, metavar="DIR", help="workspace directory")
    parent.add_argument("--json", action="store_true", help="print JSON instead of a table")
    return parent


def mutation_parent() -> SafeArgumentParser:
    """Options of every mutating command: the workspace, the format and the actor."""
    parent = SafeArgumentParser(add_help=False, parents=[read_parent()])
    parent.add_argument(
        "--actor",
        required=True,
        metavar="NAME",
        help="who makes the change (letters, digits and . _ @ + -); recorded in the audit log",
    )
    return parent


def open_workspace(args: argparse.Namespace) -> Workspace:
    return Workspace(args.workspace)


def audit_fields(result: MutationResult) -> dict[str, object]:
    entry = result.audit
    return {
        "seq": entry.seq,
        "timestamp": entry.timestamp.isoformat().replace("+00:00", "Z"),
        "actor": entry.actor,
        "action": entry.action,
        "entry_hash": entry.entry_hash,
        "prev_hash": entry.prev_hash,
    }


def redaction_fields(result: MutationResult) -> dict[str, object] | None:
    """Rule names and counts only; never a matched value."""
    report = result.redaction
    if report is None:
        return None
    return {
        "config_hash": report.config_hash,
        "rule_hits": dict(report.rule_hits),
        "truncated_fields": list(report.truncated_fields),
    }


def print_mutation(result: MutationResult, *, verb: str, as_json: bool) -> int:
    """Report a created/updated object and its audit entry."""
    audit = audit_fields(result)
    if as_json:
        payload: Mapping[str, object] = {
            "result": verb,
            "object_type": result.object_type,
            "object_id": result.object_id,
            "before_hash": result.before_hash,
            "after_hash": result.after_hash,
            "audit": audit,
            "redaction": redaction_fields(result),
        }
        write_line(dumps_json(payload))
        return 0
    rows: list[tuple[str, object]] = [
        (verb, f"{result.object_type} {result.object_id}"),
        ("before_hash", result.before_hash or "-"),
        ("after_hash", result.after_hash),
        ("audit_seq", audit["seq"]),
        ("audit_action", audit["action"]),
        ("audit_actor", audit["actor"]),
        ("audit_entry_hash", audit["entry_hash"]),
    ]
    report = result.redaction
    if report is not None:
        hits = ", ".join(f"{name}={count}" for name, count in report.rule_hits)
        rows.append(("redaction_hits", hits or "-"))
        rows.append(("redaction_cut", ", ".join(report.truncated_fields) or "-"))
        rows.append(("redaction_hash", report.config_hash))
    write_line(render_key_values(rows))
    return 0


def report_error(code: str, message: str, details: Mapping[str, object], *, as_json: bool) -> None:
    """Print a stable, value-free error to stderr."""
    if as_json:
        write_line(
            dumps_json({"error": code, "message": message, "details": dict(details)}), sys.stderr
        )
    else:
        write_line(f"error[{code}]: {message}", sys.stderr)
