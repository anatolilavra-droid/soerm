"""``soerm tui``: full-screen, read-only terminal UI (needs the optional ``tui`` extra).

The snapshot is read before the screen starts, so a missing workspace or a broken database ends
with the usual error and exit code. On a terminal that cannot show the UI (not a TTY, ``TERM``
unset or ``dumb``, too small) - or with ``--plain`` - a text overview is printed instead.
"""

import argparse
import sys

from soerm.cli.common import open_workspace
from soerm.cli.output import write_line
from soerm.cli.parser import SafeArgumentParser

__all__ = ["register"]

EXIT_ERROR = 1
EXIT_AUDIT_BROKEN = 3


def _tui(args: argparse.Namespace) -> int:
    from soerm.tui.data import load_snapshot, render_plain
    from soerm.tui.terminal import unsupported_reason

    workspace = open_workspace(args)
    snapshot = load_snapshot(workspace)
    reason = "requested" if args.plain else unsupported_reason()
    if reason is not None:
        if reason != "requested":
            write_line(f"note: full-screen UI not started ({reason}); plain overview", sys.stderr)
        write_line(render_plain(snapshot))
        return 0 if snapshot.audit_intact else EXIT_AUDIT_BROKEN
    try:
        from soerm.tui.app import SoermApp
    except ImportError:
        write_line(
            "error[tui_unavailable]: the terminal UI needs the optional extra: "
            "pip install 'soerm[tui]' (use --plain for a text overview)",
            sys.stderr,
        )
        return EXIT_ERROR
    SoermApp(workspace, snapshot).run()
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    tui = subparsers.add_parser(
        "tui",
        help="full-screen terminal UI (read-only)",
        description="Dashboard and browsers for assets, findings, incidents, tasks, approvals, "
        "playbooks, the report and the audit chain. Read-only: it changes nothing and shows no "
        "evidence, descriptions or secrets. Keys: 1-9 screens, / filter, r refresh, v verify "
        "audit, Ctrl+P command palette, q quit. Needs the optional 'tui' extra.",
    )
    tui.add_argument("--workspace", required=True, metavar="DIR", help="workspace directory")
    tui.add_argument(
        "--plain", action="store_true", help="print a text overview instead of the full-screen UI"
    )
    tui.set_defaults(handler=_tui)
