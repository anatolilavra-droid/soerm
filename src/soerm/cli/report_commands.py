"""``soerm report preview`` (prints, writes nothing) and ``soerm report generate``.

A report holds counts, identifiers, enum values, timestamps, hashes and redacted short titles -
never evidence, descriptions, notes or playbook texts. It is only ever written to a local file;
nothing is sent anywhere.
"""

import argparse
import sys
from typing import TextIO

from soerm.cli.common import open_workspace
from soerm.cli.output import dumps_json, render_key_values, write_line
from soerm.cli.parser import CliUsageError, SafeArgumentParser
from soerm.domain.report import ReportFormat
from soerm.services import reports as service

__all__ = ["register"]

EXIT_AUDIT_BROKEN = 3  # same as the integrity exit code of the CLI


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", required=True, metavar="DIR", help="workspace directory")
    parser.add_argument(
        "--format",
        default=ReportFormat.MARKDOWN,
        choices=[ReportFormat.MARKDOWN, ReportFormat.JSON],
        help="md (default) or json",
    )
    parser.add_argument(
        "--generated-at",
        metavar="TIMESTAMP",
        help="fix the report time (UTC, e.g. 2026-01-01T00:00:00Z) for a reproducible result",
    )


def _preview(args: argparse.Namespace) -> int:
    built = service.build_workspace_report(open_workspace(args), generated_at=args.generated_at)
    write_line(built.render(args.format).rstrip("\n"))
    if not built.audit_intact:
        write_line("warning: the audit chain is broken (see the Audit section)", _stderr())
        return EXIT_AUDIT_BROKEN
    return 0


def _stderr() -> TextIO:

    return sys.stderr


def _generate(args: argparse.Namespace) -> int:
    if args.force and not args.actor:
        raise CliUsageError("--force requires --actor")
    result = service.generate_report(
        open_workspace(args),
        args.output,
        fmt=args.format,
        force=args.force,
        actor=args.actor,
        generated_at=args.generated_at,
    )
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "replaced" if result.replaced else "written",
                    "path": result.path,
                    "format": result.format,
                    "bytes": result.size,
                    "sha256": result.sha256,
                    "readback_verified": result.readback_verified,
                    "audit_status": "intact" if result.audit_intact else "broken",
                }
            )
        )
    else:
        write_line(
            render_key_values(
                [
                    ("replaced" if result.replaced else "written", result.path),
                    ("format", result.format),
                    ("bytes", result.size),
                    ("sha256", result.sha256),
                    ("readback_verified", "yes"),
                    ("audit_status", "intact" if result.audit_intact else "broken"),
                ]
            )
        )
    if not result.audit_intact:
        write_line("warning: the audit chain is broken; the report says so", _stderr())
        return EXIT_AUDIT_BROKEN
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    report = subparsers.add_parser(
        "report",
        help="reports for people (Markdown or JSON)",
        description="Summaries of findings, assets, SLA, incidents, tasks, playbook progress "
        "and audit status. No evidence, descriptions, notes or secrets; nothing is sent over a "
        "network. Exit 3 if the audit chain is broken (the report is still produced and says so).",
    )
    commands = report.add_subparsers(
        dest="report_command", required=True, parser_class=SafeArgumentParser
    )
    preview = commands.add_parser(
        "preview",
        help="print the report (writes nothing)",
        description="Print the report to the terminal. Read-only: no lock, no file, no change.",
    )
    _common(preview)
    preview.set_defaults(handler=_preview)

    generate = commands.add_parser(
        "generate",
        help="write the report to a file",
        description="Write the report atomically and verify it by reading it back. The output "
        "path must be inside the workspace or in a directory allowed by soerm.yaml "
        "(reports.allowed_output_dirs); no '..', no symlinks, nothing is created implicitly. "
        "An existing file is not replaced without --force, which needs --actor and only "
        "replaces a previous SOERM report. The file is private (mode 0600).",
    )
    _common(generate)
    generate.add_argument("--output", required=True, metavar="PATH")
    generate.add_argument("--force", action="store_true", help="replace an existing report")
    generate.add_argument("--actor", metavar="NAME", help="required with --force")
    generate.add_argument("--json", action="store_true", help="print the result as JSON")
    generate.set_defaults(handler=_generate)
