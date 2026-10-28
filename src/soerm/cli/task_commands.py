"""``soerm task create | show | list | update | transition``."""

import argparse
from datetime import datetime

from soerm.cli.common import mutation_parent, open_workspace, print_mutation, read_parent
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.domain.enums import TaskStatus
from soerm.domain.task import Task
from soerm.services import tasks as task_service

__all__ = ["register", "task_to_dict"]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def task_to_dict(task: Task) -> dict[str, object]:
    return {
        "task_id": task.task_id,
        "hash": task.digest(),
        "finding_id": task.finding_id,
        "incident_id": task.incident_id,
        "title": task.title,
        "owner": task.owner,
        "status": task.status.value,
        "due_at": _iso(task.due_at),
        "created_at": _iso(task.created_at),
        "updated_at": _iso(task.updated_at),
        "completed_at": _iso(task.completed_at),
    }


def _create(args: argparse.Namespace) -> int:
    result = task_service.create_task(
        open_workspace(args),
        actor=args.actor,
        title=args.title,
        owner=args.owner,
        finding_id=args.finding_id,
        incident_id=args.incident_id,
        due_at=args.due_at,
    )
    return print_mutation(result, verb="created", as_json=args.json)


def _show(args: argparse.Namespace) -> int:
    data = task_to_dict(task_service.get_task(open_workspace(args), args.task_id))
    if args.json:
        write_line(dumps_json(data))
    else:
        write_line(render_key_values([(k, "-" if v is None else v) for k, v in data.items()]))
    return 0


def _list(args: argparse.Namespace) -> int:
    tasks = task_service.list_tasks(
        open_workspace(args),
        status=args.status,
        finding_id=args.finding_id,
        incident_id=args.incident_id,
    )
    if args.json:
        write_line(dumps_json({"tasks": [task_to_dict(t) for t in tasks]}))
        return 0
    rows = [
        (t.task_id, t.status, t.finding_id or "-", t.incident_id or "-", t.owner, t.title)
        for t in tasks
    ]
    write_line(render_table(("ID", "STATUS", "FINDING", "INCIDENT", "OWNER", "TITLE"), rows))
    return 0


def _update(args: argparse.Namespace) -> int:
    result = task_service.update_task(
        open_workspace(args),
        args.task_id,
        actor=args.actor,
        expected_hash=args.expect_hash,
        title=args.title,
        owner=args.owner,
        due_at=args.due_at,
        clear_due=args.clear_due,
    )
    return print_mutation(result, verb="updated", as_json=args.json)


def _transition(args: argparse.Namespace) -> int:
    result = task_service.transition(
        open_workspace(args),
        args.task_id,
        args.status,
        actor=args.actor,
        expected_hash=args.expect_hash,
        reinstate=args.reinstate,
    )
    return print_mutation(result, verb="transitioned", as_json=args.json)


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    task = subparsers.add_parser(
        "task",
        help="manage remediation tasks",
        description="Remediation tasks of a finding and/or an incident. Completing a task "
        "never resolves a finding or closes an incident.",
    )
    commands = task.add_subparsers(
        dest="task_command", required=True, parser_class=SafeArgumentParser
    )

    create = commands.add_parser(
        "create",
        parents=[mutation_parent()],
        help="create a task",
        description="Create a task for a finding and/or an open incident.",
    )
    create.add_argument("--title", required=True, metavar="TEXT")
    create.add_argument("--owner", required=True, metavar="TEXT")
    create.add_argument("--finding-id", metavar="FND-NNNNNN")
    create.add_argument("--incident-id", metavar="INC-NNNNNN")
    create.add_argument(
        "--due-at", metavar="TIMESTAMP", help="UTC timestamp, e.g. 2026-01-01T00:00:00Z"
    )
    create.set_defaults(handler=_create)

    show = commands.add_parser("show", parents=[read_parent()], help="show a task")
    show.add_argument("task_id", metavar="TASK_ID")
    show.set_defaults(handler=_show)

    list_parser = commands.add_parser("list", parents=[read_parent()], help="list tasks")
    list_parser.add_argument("--status", type=TaskStatus, choices=list(TaskStatus))
    list_parser.add_argument("--finding-id", metavar="FND-NNNNNN")
    list_parser.add_argument("--incident-id", metavar="INC-NNNNNN")
    list_parser.set_defaults(handler=_list)

    update = commands.add_parser(
        "update",
        parents=[mutation_parent()],
        help="change title, owner or due date",
        description="Change a task that is not done or cancelled. The hash from 'task show' "
        "is required.",
    )
    update.add_argument("task_id", metavar="TASK_ID")
    update.add_argument("--expect-hash", required=True, metavar="SHA256")
    update.add_argument("--title", metavar="TEXT")
    update.add_argument("--owner", metavar="TEXT")
    update.add_argument("--due-at", metavar="TIMESTAMP")
    update.add_argument("--clear-due", action="store_true")
    update.set_defaults(handler=_update)

    transition = commands.add_parser(
        "transition",
        parents=[mutation_parent()],
        help="change task status",
        description="open, in_progress, done or cancelled. done sets "
        "completed_at. done and cancelled are final; a cancelled task can only be reinstated "
        "(--reinstate, to open) and never goes straight to done.",
    )
    transition.add_argument("task_id", metavar="TASK_ID")
    transition.add_argument("--expect-hash", required=True, metavar="SHA256")
    transition.add_argument("--status", required=True, type=TaskStatus, choices=list(TaskStatus))
    transition.add_argument("--reinstate", action="store_true")
    transition.set_defaults(handler=_transition)
