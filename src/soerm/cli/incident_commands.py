"""``soerm incident create | show | list | update | transition | note | link | timeline``."""

import argparse
from datetime import datetime

from soerm.cli.common import mutation_parent, open_workspace, print_mutation, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.cli.playbook_commands import register_incident_playbook
from soerm.domain.enums import IncidentStatus, TechnicalSeverity
from soerm.domain.incident import Incident
from soerm.services import incidents as incident_service

__all__ = ["incident_to_dict", "register"]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def incident_to_dict(incident: Incident, finding_ids: tuple[str, ...] = ()) -> dict[str, object]:
    return {
        "incident_id": incident.incident_id,
        "hash": incident.digest(),
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "owner": incident.owner,
        "summary": incident.summary,
        "playbook_id": incident.playbook_id,
        "closure_reason": incident.closure_reason,
        "created_at": _iso(incident.created_at),
        "updated_at": _iso(incident.updated_at),
        "closed_at": _iso(incident.closed_at),
        "findings": list(finding_ids),
    }


def _create(args: argparse.Namespace) -> int:
    result = incident_service.create_incident(
        open_workspace(args),
        actor=args.actor,
        title=args.title,
        severity=args.severity,
        owner=args.owner,
        summary=args.summary,
    )
    return print_mutation(result, verb="created", as_json=args.json)


def _show(args: argparse.Namespace) -> int:
    view = incident_service.get_incident(open_workspace(args), args.incident_id)
    data = incident_to_dict(view.incident, view.finding_ids)
    if args.json:
        write_line(dumps_json(data))
        return 0
    rows: list[tuple[str, object]] = []
    for key, value in data.items():
        if key == "findings":
            rows.append((key, ", ".join(view.finding_ids) or "-"))
        else:
            rows.append((key, "-" if value is None or value == "" else value))
    write_line(render_key_values(rows))
    return 0


def _list(args: argparse.Namespace) -> int:
    incidents = incident_service.list_incidents(open_workspace(args), status=args.status)
    if args.json:
        write_line(dumps_json({"incidents": [incident_to_dict(i) for i in incidents]}))
        return 0
    rows = [(i.incident_id, i.status, i.severity, i.owner, i.title) for i in incidents]
    write_line(render_table(("ID", "STATUS", "SEVERITY", "OWNER", "TITLE"), rows))
    return 0


def _update(args: argparse.Namespace) -> int:
    result = incident_service.update_incident(
        open_workspace(args),
        args.incident_id,
        actor=args.actor,
        expected_hash=args.expect_hash,
        title=args.title,
        summary=args.summary,
        owner=args.owner,
        severity=args.severity,
    )
    return print_mutation(result, verb="updated", as_json=args.json)


def _transition(args: argparse.Namespace) -> int:
    result = incident_service.transition(
        open_workspace(args),
        args.incident_id,
        args.status,
        actor=args.actor,
        expected_hash=args.expect_hash,
        reason=args.reason,
        reopen=args.reopen,
    )
    return print_mutation(result, verb="transitioned", as_json=args.json)


def _note(args: argparse.Namespace) -> int:
    result = incident_service.add_note(
        open_workspace(args), args.incident_id, actor=args.actor, text=args.text
    )
    return print_mutation(result, verb="noted", as_json=args.json)


def _link(args: argparse.Namespace) -> int:
    result = incident_service.link_finding(
        open_workspace(args), args.incident_id, args.finding_id, actor=args.actor
    )
    return print_mutation(result, verb="linked", as_json=args.json)


def _timeline(args: argparse.Namespace) -> int:
    entries = incident_service.incident_timeline(open_workspace(args), args.incident_id)
    if args.json:
        write_line(
            dumps_json(
                {
                    "incident_id": args.incident_id,
                    "timeline": [
                        {
                            "at": e.at,
                            "kind": e.kind,
                            "actor": e.actor,
                            "label": e.label,
                            "from_status": e.from_status,
                            "to_status": e.to_status,
                            "body": e.body,
                        }
                        for e in entries
                    ],
                }
            )
        )
        return 0
    rows = [
        (
            e.at,
            e.actor,
            e.label,
            "-" if e.to_status is None else f"{e.from_status or '-'} -> {e.to_status}",
            e.body or "-",
        )
        for e in entries
    ]
    write_line(render_table(("AT", "ACTOR", "EVENT", "STATUS", "NOTE"), rows, limit=80))
    return 0


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    incident = subparsers.add_parser(
        "incident",
        help="manage incidents",
        description="Incidents: records of what happened and what was decided. Nothing here "
        "acts on systems - no containment, no notification, no playbook execution.",
    )
    commands = incident.add_subparsers(
        dest="incident_command", required=True, parser_class=SafeArgumentParser
    )

    create = commands.add_parser(
        "create",
        parents=[mutation_parent()],
        help="open an incident (status new)",
        description="Open an incident. Title, summary and owner are redacted before storage.",
    )
    create.add_argument("--title", required=True, metavar="TEXT")
    create.add_argument(
        "--severity", required=True, type=TechnicalSeverity, choices=list(TechnicalSeverity)
    )
    create.add_argument("--owner", required=True, metavar="TEXT")
    create.add_argument("--summary", default="", metavar="TEXT")
    create.set_defaults(handler=_create)

    show = commands.add_parser("show", parents=[read_parent()], help="show an incident")
    show.add_argument("incident_id", metavar="INCIDENT_ID")
    show.set_defaults(handler=_show)

    list_parser = commands.add_parser("list", parents=[read_parent()], help="list incidents")
    list_parser.add_argument("--status", type=IncidentStatus, choices=list(IncidentStatus))
    list_parser.set_defaults(handler=_list)

    update = commands.add_parser(
        "update",
        parents=[mutation_parent()],
        help="change descriptive fields of an open incident",
        description="Change title, summary, owner or severity of a non-closed incident. The "
        "hash shown by 'incident show' is required. Status changes use 'incident transition'.",
    )
    update.add_argument("incident_id", metavar="INCIDENT_ID")
    update.add_argument("--expect-hash", required=True, metavar="SHA256")
    update.add_argument("--title", metavar="TEXT")
    update.add_argument("--summary", metavar="TEXT")
    update.add_argument("--owner", metavar="TEXT")
    update.add_argument("--severity", type=TechnicalSeverity, choices=list(TechnicalSeverity))
    update.set_defaults(handler=_update)

    transition = commands.add_parser(
        "transition",
        parents=[mutation_parent()],
        help="move an incident to its next status",
        description="Statuses go forward one step at a time (new, triaged, investigating, "
        "contained, remediated, closed). Closing needs --reason. Leaving closed "
        "needs --reopen and --reason, and lands in investigating.",
    )
    transition.add_argument("incident_id", metavar="INCIDENT_ID")
    transition.add_argument("--expect-hash", required=True, metavar="SHA256")
    transition.add_argument(
        "--status", required=True, type=IncidentStatus, choices=list(IncidentStatus)
    )
    transition.add_argument("--reason", metavar="TEXT", help="closure or reopen reason (redacted)")
    transition.add_argument("--reopen", action="store_true", help="allow leaving closed")
    transition.set_defaults(handler=_transition)

    note = commands.add_parser(
        "note",
        parents=[mutation_parent()],
        help="add an analyst note",
        description="Add a redacted note to an open incident. The note text is shown by "
        "'incident timeline' and is never written to the audit log.",
    )
    note.add_argument("incident_id", metavar="INCIDENT_ID")
    note.add_argument("--text", required=True, metavar="TEXT")
    note.set_defaults(handler=_note)

    link = commands.add_parser(
        "link", parents=[mutation_parent()], help="link a finding to an open incident"
    )
    link.add_argument("incident_id", metavar="INCIDENT_ID")
    link.add_argument("--finding-id", required=True, metavar="FND-NNNNNN")
    link.set_defaults(handler=_link)

    timeline = commands.add_parser(
        "timeline", parents=[read_parent()], help="status events and notes in time order"
    )
    timeline.add_argument("incident_id", metavar="INCIDENT_ID")
    timeline.set_defaults(handler=_timeline)

    register_incident_playbook(commands)
