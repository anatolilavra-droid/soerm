"""Command-line entry point.

Commands: ``asset add|show|list|update``, ``finding add|show|list|update`` and
``config validate`` and ``import preview``. The CLI talks
to the service layer only (never to storage or SQLite) and performs no filesystem, network or
process operations itself.

Exit codes: 0 success, 1 domain/service error, 2 usage error, 3 integrity error, 4 approval
required. Errors print a stable code and a message built from constants only (no input
values, no SQL, no traceback).
"""

import argparse
import sys
from collections.abc import Sequence
from typing import Final

from soerm import __version__
from soerm.cli import (
    approval_commands,
    asset_commands,
    audit_commands,
    config_commands,
    finding_commands,
    import_commands,
    incident_commands,
    playbook_commands,
    report_commands,
    risk_commands,
    task_commands,
    tui_commands,
)
from soerm.cli.common import report_error
from soerm.cli.output import write_line
from soerm.cli.parser import CliUsageError, SafeArgumentParser
from soerm.domain.errors import DomainError
from soerm.services.errors import to_service_error

__all__ = [
    "EXIT_APPROVAL_REQUIRED",
    "EXIT_ERROR",
    "EXIT_INTEGRITY",
    "EXIT_OK",
    "EXIT_USAGE",
    "build_parser",
    "main",
]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTEGRITY = 3
EXIT_APPROVAL_REQUIRED = 4

_EXIT_BY_CODE: Final = {
    "not_found": EXIT_ERROR,
    "conflict": EXIT_ERROR,
    "invalid_input": EXIT_ERROR,
    "constraint_violation": EXIT_ERROR,
    "config_error": EXIT_ERROR,
    "import_error": EXIT_ERROR,
    "busy": EXIT_ERROR,
    "integrity_error": EXIT_INTEGRITY,
    "approval_required": EXIT_APPROVAL_REQUIRED,
    "approval_denied": EXIT_ERROR,
    "usage_error": EXIT_USAGE,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = SafeArgumentParser(
        prog="soerm",
        description=(
            "Security Operations Evidence & Response Manager. "
            "Local CLI; works only with local files and never uses the network."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", parser_class=SafeArgumentParser)
    asset_commands.register(subparsers)
    finding_commands.register(subparsers)
    config_commands.register(subparsers)
    import_commands.register(subparsers)
    risk_commands.register(subparsers)
    incident_commands.register(subparsers)
    task_commands.register(subparsers)
    approval_commands.register(subparsers)
    audit_commands.register(subparsers)
    playbook_commands.register(subparsers)
    report_commands.register(subparsers)
    tui_commands.register(subparsers)
    return parser


def _usage_failure(exc: CliUsageError) -> int:
    report_error("usage_error", exc.message, {}, as_json=False)
    if exc.usage:
        write_line(exc.usage, sys.stderr)
    return EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except CliUsageError as exc:
        return _usage_failure(exc)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    as_json = bool(getattr(args, "json", False))
    try:
        return int(handler(args))
    except CliUsageError as exc:
        return _usage_failure(exc)
    except DomainError as exc:
        error = to_service_error(exc)
        report_error(error.code, error.message, error.details, as_json=as_json)
        return _EXIT_BY_CODE.get(error.code, EXIT_ERROR)
    except Exception:
        report_error("integrity_error", "unexpected internal error", {}, as_json=as_json)
        return EXIT_INTEGRITY
