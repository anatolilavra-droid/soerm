"""``soerm playbook list | show | load`` and ``soerm incident playbook attach | status | step``.

Playbooks are instructions for people: no command here runs a step, sends a message or
changes a system. Marking a step done records who did it and when.
"""

import argparse
from datetime import datetime

from soerm.cli.common import mutation_parent, open_workspace, print_mutation, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.domain.playbook import Playbook
from soerm.services import playbooks as service

__all__ = ["register", "register_incident_playbook"]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def _step_dict(step: object) -> dict[str, object]:
    return step.canonical_dict()  # type: ignore[attr-defined,no-any-return]


def playbook_to_dict(playbook: Playbook, versions: list[tuple[str, str]] | None = None) -> dict:  # type: ignore[type-arg]
    data = playbook.canonical_dict()
    if versions is not None:
        data["versions"] = [{"version": v, "config_hash": h} for v, h in versions]
    return data


# -- top level: playbook ----------------------------------------------------------------------


def _list(args: argparse.Namespace) -> int:
    items = service.list_playbooks(open_workspace(args), incident_type=args.incident_type)
    if args.json:
        write_line(
            dumps_json(
                {
                    "playbooks": [
                        {
                            "playbook_id": p.playbook_id,
                            "name": p.name,
                            "version": p.version,
                            "incident_types": list(p.incident_types),
                            "steps": len(p.steps),
                            "config_hash": p.config_hash,
                        }
                        for p in items
                    ]
                }
            )
        )
        return 0
    rows = [
        (p.playbook_id, p.version, ",".join(p.incident_types) or "-", len(p.steps), p.name)
        for p in items
    ]
    write_line(render_table(("ID", "VERSION", "INCIDENT_TYPES", "STEPS", "NAME"), rows))
    return 0


def _show(args: argparse.Namespace) -> int:
    playbook, versions = service.get_playbook(
        open_workspace(args), args.playbook_id, version=args.version
    )
    if args.json:
        write_line(dumps_json(playbook_to_dict(playbook, versions)))
        return 0
    write_line(
        render_key_values(
            [
                ("playbook_id", playbook.playbook_id),
                ("name", playbook.name),
                ("version", playbook.version),
                ("config_hash", playbook.config_hash),
                ("versions", ", ".join(v for v, _ in versions)),
                ("incident_types", ", ".join(playbook.incident_types) or "-"),
                ("roles", ", ".join(playbook.roles)),
            ]
        )
    )
    write_line("")
    write_line(
        render_table(
            ("STEP", "TYPE", "ROLE", "APPROVAL", "TITLE"),
            [
                (
                    s.step_id,
                    s.step_type,
                    s.owner_role or "-",
                    "required" if s.requires_manual_approval else "-",
                    s.title,
                )
                for s in playbook.steps
            ],
        )
    )
    for label, values in (
        ("escalation_criteria", playbook.escalation_criteria),
        ("closure_criteria", playbook.closure_criteria),
    ):
        if values:
            write_line("")
            write_line(f"{label}:")
            for value in values:
                write_line(f"  - {value}")
    return 0


def _load(args: argparse.Namespace) -> int:
    result = service.load_playbook(open_workspace(args), args.file, actor=args.actor)
    audit = result.audit
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "loaded" if result.changed else "unchanged",
                    "playbook_id": result.playbook.playbook_id,
                    "version": result.playbook.version,
                    "config_hash": result.playbook.config_hash,
                    "redaction_hits": result.redaction_hits,
                    "audit_seq": None if audit is None else audit.seq,
                }
            )
        )
        return 0
    write_line(
        render_key_values(
            [
                ("loaded" if result.changed else "unchanged", result.playbook.playbook_id),
                ("version", result.playbook.version),
                ("config_hash", result.playbook.config_hash),
                ("redaction_hits", result.redaction_hits),
                ("audit_seq", "-" if audit is None else audit.seq),
            ]
        )
    )
    return 0


# -- incident playbook ------------------------------------------------------------------------


def _attach(args: argparse.Namespace) -> int:
    attachment, changed, audit = service.attach_playbook(
        open_workspace(args),
        args.incident_id,
        args.playbook_id,
        actor=args.actor,
        version=args.version,
    )
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "attached" if changed else "unchanged",
                    "incident_id": attachment.incident_id,
                    "playbook_id": attachment.playbook_id,
                    "version": attachment.version,
                    "config_hash": attachment.config_hash,
                    "audit_seq": None if audit is None else audit.seq,
                }
            )
        )
        return 0
    write_line(
        render_key_values(
            [
                ("attached" if changed else "unchanged", attachment.incident_id),
                ("playbook", f"{attachment.playbook_id} {attachment.version}"),
                ("config_hash", attachment.config_hash),
                ("audit_seq", "-" if audit is None else audit.seq),
            ]
        )
    )
    return 0


def _status(args: argparse.Namespace) -> int:
    status = service.playbook_status(open_workspace(args), args.incident_id)
    prog = status.progress
    if args.json:
        write_line(
            dumps_json(
                {
                    "incident_id": status.incident_id,
                    "incident_status": status.incident_status.value,
                    "playbook_id": status.playbook.playbook_id,
                    "version": status.playbook.version,
                    "config_hash": status.attachment.config_hash,
                    "completed": prog.completed,
                    "total": prog.total,
                    "next_step": prog.next_step_id,
                    "ready_for_closure_review": status.ready_for_closure_review,
                    "escalation_criteria": list(status.playbook.escalation_criteria),
                    "closure_criteria": list(status.playbook.closure_criteria),
                    "steps": [
                        {
                            "step_id": s.step.step_id,
                            "type": s.step.step_type.value,
                            "title": s.step.title,
                            "owner_role": s.step.owner_role,
                            "requires_manual_approval": s.step.requires_manual_approval,
                            "done": s.done,
                            "completed_at": None
                            if s.completion is None
                            else _iso(s.completion.completed_at),
                            "completed_by": None
                            if s.completion is None
                            else s.completion.completed_by,
                            "change_id": None if s.completion is None else s.completion.change_id,
                        }
                        for s in prog.steps
                    ],
                }
            )
        )
        return 0
    write_line(
        render_key_values(
            [
                ("incident", f"{status.incident_id} ({status.incident_status.value})"),
                ("playbook", f"{status.playbook.playbook_id} {status.playbook.version}"),
                ("progress", f"{prog.completed}/{prog.total}"),
                ("next_step", prog.next_step_id or "-"),
                ("ready_for_closure_review", "yes" if status.ready_for_closure_review else "no"),
            ]
        )
    )
    write_line("")
    write_line(
        render_table(
            ("STEP", "DONE", "TYPE", "ROLE", "APPROVAL", "BY", "AT", "TITLE"),
            [
                (
                    s.step.step_id,
                    "yes" if s.done else "no",
                    s.step.step_type,
                    s.step.owner_role or "-",
                    "required" if s.step.requires_manual_approval else "-",
                    "-" if s.completion is None else s.completion.completed_by,
                    "-" if s.completion is None else _iso(s.completion.completed_at),
                    s.step.title,
                )
                for s in prog.steps
            ],
            limit=60,
        )
    )
    for label, values in (
        ("escalation_criteria (when to escalate)", status.playbook.escalation_criteria),
        ("closure_criteria (check before closing - the incident is never closed automatically)",
         status.playbook.closure_criteria),
    ):  # fmt: skip
        if values:
            write_line("")
            write_line(f"{label}:")
            for value in values:
                write_line(f"  - {value}")
    return 0


def _step(args: argparse.Namespace) -> int:
    outcome = service.complete_step(
        open_workspace(args),
        args.incident_id,
        args.step_id,
        actor=args.actor,
        change_id=args.change_id,
    )
    done = outcome.completion
    if args.json:
        write_line(
            dumps_json(
                {
                    "result": "completed" if outcome.changed else "already_completed",
                    "incident_id": outcome.incident_id,
                    "step_id": outcome.step_id,
                    "completed_by": done.completed_by,
                    "completed_at": _iso(done.completed_at),
                    "change_id": done.change_id,
                    "audit_seq": None if outcome.audit is None else outcome.audit.seq,
                }
            )
        )
        return 0
    write_line(
        render_key_values(
            [
                ("completed" if outcome.changed else "already_completed", outcome.step_id),
                ("incident", outcome.incident_id),
                ("completed_by", done.completed_by),
                ("completed_at", _iso(done.completed_at)),
                ("audit_seq", "-" if outcome.audit is None else outcome.audit.seq),
            ]
        )
    )
    return 0


def _request_approval(args: argparse.Namespace) -> int:
    result = service.request_step_approval(
        open_workspace(args),
        args.incident_id,
        args.step_id,
        actor=args.actor,
        reason=args.reason,
    )
    return print_mutation(result, verb="requested", as_json=args.json)


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    playbook = subparsers.add_parser(
        "playbook",
        help="playbooks: instructions and checklists for people",
        description="Playbooks are operating instructions for people. SOERM never runs a step: "
        "no commands, no network, no messages, no changes to systems or findings.",
    )
    commands = playbook.add_subparsers(
        dest="playbook_command", required=True, parser_class=SafeArgumentParser
    )
    list_parser = commands.add_parser("list", parents=[read_parent()], help="list playbooks")
    list_parser.add_argument("--incident-type", metavar="SLUG")
    list_parser.set_defaults(handler=_list)

    show = commands.add_parser("show", parents=[read_parent()], help="show a playbook")
    show.add_argument("playbook_id", metavar="PLAYBOOK_ID")
    show.add_argument("--version", metavar="LABEL", help="default: the latest version")
    show.set_defaults(handler=_show)

    load = commands.add_parser(
        "load",
        parents=[mutation_parent()],
        help="store a playbook version from a YAML file in the workspace",
        description="Read one YAML file inside the workspace (strict YAML, size-limited), "
        "redact every text and store it as an immutable version. Loading the same content "
        "again changes nothing; changed content needs a new playbook_version.",
    )
    load.add_argument("file", metavar="FILE", help="path relative to the workspace")
    load.set_defaults(handler=_load)


def register_incident_playbook(
    incident_commands: "argparse._SubParsersAction[SafeArgumentParser]",
) -> None:
    group = incident_commands.add_parser(
        "playbook",
        help="attach a playbook and mark its manual steps",
        description="Work through a playbook for an incident. Marking a step records who did "
        "it and when; nothing is executed and the incident is never closed automatically.",
    )
    commands = group.add_subparsers(
        dest="incident_playbook_command", required=True, parser_class=SafeArgumentParser
    )
    attach = commands.add_parser(
        "attach",
        parents=[mutation_parent()],
        help="pin an incident to a playbook version",
        description="Attach a playbook (latest version unless --version). The incident keeps "
        "that exact version. Repeating the same attach changes nothing.",
    )
    attach.add_argument("incident_id", metavar="INCIDENT_ID")
    attach.add_argument("playbook_id", metavar="PLAYBOOK_ID")
    attach.add_argument("--version", metavar="LABEL")
    attach.set_defaults(handler=_attach)

    status = commands.add_parser(
        "status", parents=[read_parent()], help="progress, next step and criteria"
    )
    status.add_argument("incident_id", metavar="INCIDENT_ID")
    status.set_defaults(handler=_status)

    step = commands.add_parser(
        "step",
        parents=[mutation_parent()],
        help="mark a step as done (idempotent)",
        description="Record that a person completed a step. Completing it again changes "
        "nothing. A step that requires manual approval needs --change-id of an approved "
        "request (see 'incident playbook request-approval'); without it the exit code is 4.",
    )
    step.add_argument("incident_id", metavar="INCIDENT_ID")
    step.add_argument("step_id", metavar="STEP_ID")
    step.add_argument("--change-id", metavar="CHG-NNNNNN")
    step.set_defaults(handler=_step)

    request = commands.add_parser(
        "request-approval",
        parents=[mutation_parent()],
        help="ask for approval to complete a gated step",
        description="Create an approval request for a step with requires_manual_approval. "
        "Another person approves it with 'approval approve'.",
    )
    request.add_argument("incident_id", metavar="INCIDENT_ID")
    request.add_argument("step_id", metavar="STEP_ID")
    request.add_argument("--reason", required=True, metavar="TEXT")
    request.set_defaults(handler=_request_approval)
