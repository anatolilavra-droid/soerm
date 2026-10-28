"""``soerm config validate``: check ``<workspace>/soerm.yaml`` without touching the database."""

import argparse

from soerm.cli.common import open_workspace, read_parent
from soerm.cli.output import dumps_json, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.services.redaction import validate_workspace_config

__all__ = ["register"]


def _validate(args: argparse.Namespace) -> int:
    summary = validate_workspace_config(open_workspace(args))
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "valid",
                    "config_file": "found" if summary.file_found else "absent (built-in defaults)",
                    "config_hash": summary.config_hash,
                    "risk_config_hash": summary.risk_config_hash,
                    "max_input_bytes": summary.max_input_bytes,
                    "rules": [
                        {"name": name, "enabled": enabled, "builtin": builtin}
                        for name, enabled, builtin in summary.rules
                    ],
                }
            )
        )
        return 0
    source = "soerm.yaml" if summary.file_found else "no soerm.yaml (built-in defaults)"
    write_line(f"configuration valid: {source}")
    write_line(f"config_hash: {summary.config_hash}")
    write_line(f"risk_config_hash: {summary.risk_config_hash}")
    write_line(f"max_input_bytes: {summary.max_input_bytes}")
    rows = [
        (name, "yes" if enabled else "no", "built-in" if builtin else "custom")
        for name, enabled, builtin in summary.rules
    ]
    write_line(render_table(("RULE", "ENABLED", "KIND"), rows))
    enabled_count = sum(1 for _, enabled, _ in summary.rules if enabled)
    write_line(f"rules: {len(summary.rules)} ({enabled_count} enabled)")
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    config = subparsers.add_parser(
        "config", help="check the configuration", description="Configuration checks."
    )
    commands = config.add_subparsers(
        dest="config_command", required=True, parser_class=SafeArgumentParser
    )
    validate = commands.add_parser(
        "validate",
        parents=[read_parent()],
        help="validate soerm.yaml in the workspace",
        description="Validate <workspace>/soerm.yaml (redaction rules, imports, risk model). "
        "Reads only that file; prints rule names and flags, never patterns or values; "
        "creates no database or lock. "
        "Exit 0 if valid (or absent), 1 on a configuration error.",
    )
    validate.set_defaults(handler=_validate)
