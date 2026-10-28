"""Snapshot of the workspace for the terminal UI, built only from the service layer.

Findings carry no description, evidence or fingerprint here; approvals carry no reason;
playbooks carry step titles and flags but no step text; incidents carry no summary. Every
string passes the same cleaner as report titles (redaction again, control characters removed,
shortened), so the screens show no more than a report does.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from soerm.domain.errors import DomainError
from soerm.domain.timestamps import format_timestamp
from soerm.services import (
    approvals,
    assets,
    audit_check,
    findings,
    incidents,
    playbooks,
    reports,
    tasks,
)
from soerm.services.workspace import Workspace

__all__ = [
    "ATTENTION_TEXT",
    "MAX_ROWS",
    "Row",
    "Snapshot",
    "Table",
    "load_snapshot",
    "render_plain",
]

MAX_ROWS: Final = 2000
_NONE: Final = "-"

Clean = Callable[[object], str]

# attention code -> (readable text, screen number that shows it, "crit" or "warn")
ATTENTION_TEXT: Final = {
    "audit_chain_broken": ("Audit chain is broken", 9, "crit"),
    "active_p1_findings": ("Active P1 findings", 3, "crit"),
    "overdue_findings": ("Findings are past their SLA", 3, "warn"),
    "overdue_tasks": ("Tasks are overdue", 5, "warn"),
    "expired_pending_approvals": ("Pending approvals have expired", 6, "warn"),
}


@dataclass(frozen=True, slots=True)
class Row:
    key: str
    cells: tuple[str, ...]
    details: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class Table:
    name: str
    title: str
    columns: tuple[str, ...]
    rows: tuple[Row, ...]
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class Snapshot:
    generated_at: str
    audit_intact: bool
    audit: tuple[tuple[str, str], ...]
    summary: tuple[tuple[str, str], ...]
    attention: tuple[str, ...]
    tables: tuple[Table, ...]
    report_markdown: str

    def table(self, name: str) -> Table:
        return next(t for t in self.tables if t.name == name)


def _cleaner(workspace: Workspace) -> Clean:
    sanitize = reports.display_sanitizer(workspace)

    def clean(value: object) -> str:
        if value is None:
            return _NONE
        text = sanitize(value.isoformat() if isinstance(value, datetime) else str(value))
        return text or _NONE

    return clean


def _stamp(value: object) -> str:
    return format_timestamp(value) if isinstance(value, datetime) else _NONE


def _cap(items: list[Any]) -> tuple[list[Any], bool]:
    return items[:MAX_ROWS], len(items) > MAX_ROWS


def _assets(workspace: Workspace, clean: Clean) -> Table:
    items, cut = _cap(assets.list_assets(workspace))
    rows = tuple(
        Row(
            a.asset_id,
            tuple(
                clean(x)
                for x in (
                    a.asset_id, a.name, a.environment, a.business_criticality, a.exposure, a.owner,
                )
            ),
            (
                ("asset", clean(a.asset_id)),
                ("name", clean(a.name)),
                ("owner", clean(a.owner)),
                ("environment", clean(a.environment)),
                ("criticality", clean(a.business_criticality)),
                ("exposure", clean(a.exposure)),
                ("data class", clean(a.data_classification)),
                ("tags", clean(", ".join(a.tags) or None)),
                ("updated", clean(_stamp(a.updated_at))),
            ),
        )
        for a in items
    )  # fmt: skip
    return Table(
        "assets", "Assets", ("ID", "Name", "Env", "Criticality", "Exposure", "Owner"), rows, cut
    )


def _findings(workspace: Workspace, clean: Clean) -> Table:
    items, cut = _cap(findings.list_findings(workspace))
    rows = tuple(
        Row(
            f.finding_id,
            tuple(
                clean(x)
                for x in (
                    f.finding_id, f.status, f.technical_severity, f.business_priority,
                    f.asset_id, _stamp(f.sla_due_at), f.title,
                )
            ),
            (
                ("finding", clean(f.finding_id)),
                ("title", clean(f.title)),
                ("asset", clean(f.asset_id)),
                ("status", clean(f.status)),
                ("severity", clean(f.technical_severity)),
                ("priority", clean(f.business_priority)),
                ("sla due", clean(_stamp(f.sla_due_at))),
                ("owner", clean(f.owner)),
                ("first seen", clean(_stamp(f.first_seen))),
                ("last seen", clean(_stamp(f.last_seen))),
                ("source", clean(f.source)),
            ),
        )
        for f in items
    )  # fmt: skip
    columns = ("ID", "Status", "Severity", "Prio", "Asset", "SLA due", "Title")
    return Table("findings", "Findings", columns, rows, cut)


def _incidents(workspace: Workspace, clean: Clean, items: list[Any]) -> Table:
    shown, cut = _cap(items)
    rows = tuple(
        Row(
            i.incident_id,
            tuple(
                clean(x)
                for x in (i.incident_id, i.status, i.severity, i.owner, i.playbook_id, i.title)
            ),
            (
                ("incident", clean(i.incident_id)),
                ("title", clean(i.title)),
                ("status", clean(i.status)),
                ("severity", clean(i.severity)),
                ("owner", clean(i.owner)),
                ("playbook", clean(i.playbook_id)),
                ("created", clean(_stamp(i.created_at))),
                ("closed", clean(_stamp(i.closed_at))),
            ),
        )
        for i in shown
    )  # fmt: skip
    columns = ("ID", "Status", "Severity", "Owner", "Playbook", "Title")
    return Table("incidents", "Incidents", columns, rows, cut)


def _tasks(workspace: Workspace, clean: Clean) -> Table:
    items, cut = _cap(tasks.list_tasks(workspace))
    rows = tuple(
        Row(
            t.task_id,
            tuple(
                clean(x)
                for x in (
                    t.task_id, t.status, t.owner, _stamp(t.due_at), t.finding_id, t.incident_id,
                    t.title,
                )
            ),
            (
                ("task", clean(t.task_id)),
                ("title", clean(t.title)),
                ("status", clean(t.status)),
                ("owner", clean(t.owner)),
                ("due", clean(_stamp(t.due_at))),
                ("finding", clean(t.finding_id)),
                ("incident", clean(t.incident_id)),
                ("created", clean(_stamp(t.created_at))),
                ("completed", clean(_stamp(t.completed_at))),
            ),
        )
        for t in items
    )  # fmt: skip
    columns = ("ID", "Status", "Owner", "Due", "Finding", "Incident", "Title")
    return Table("tasks", "Tasks", columns, rows, cut)


def _approvals(workspace: Workspace, clean: Clean) -> Table:
    items, cut = _cap(approvals.list_approvals(workspace))
    rows = tuple(
        Row(
            v.approval.change_id,
            tuple(
                clean(x)
                for x in (
                    v.approval.change_id, v.effective_status,
                    f"{v.approval.object_type}:{v.approval.object_id}", v.approval.requester,
                    v.approval.approver, _stamp(v.approval.expires_at),
                    "yes" if v.applied else "no",
                )
            ),
            (
                ("change", clean(v.approval.change_id)),
                ("status", clean(v.effective_status)),
                ("object", clean(f"{v.approval.object_type}:{v.approval.object_id}")),
                ("requester", clean(v.approval.requester)),
                ("approver", clean(v.approval.approver)),
                ("requested", clean(_stamp(v.approval.requested_at))),
                ("expires", clean(_stamp(v.approval.expires_at))),
                ("decided", clean(_stamp(v.approval.decided_at))),
                ("applied", "yes" if v.applied else "no"),
                ("distinct approver", "required" if v.approval.require_distinct_approver else "no"),
            ),
        )
        for v in items
    )  # fmt: skip
    columns = ("ID", "Status", "Object", "Requester", "Approver", "Expires", "Applied")
    return Table("approvals", "Approvals", columns, rows, cut)


def _playbooks(workspace: Workspace, clean: Clean, incident_items: list[Any]) -> Table:
    runs: dict[str, list[str]] = {}
    for incident in incident_items:
        if incident.playbook_id is None:
            continue
        try:
            status = playbooks.playbook_status(workspace, incident.incident_id)
        except DomainError:
            continue
        done, total = status.progress.completed, status.progress.total
        runs.setdefault(status.playbook.playbook_id, []).append(
            clean(f"{incident.incident_id}: {done}/{total}")
        )
    items, cut = _cap(playbooks.list_playbooks(workspace))
    rows = []
    for p in items:
        steps = tuple(
            (
                f"step {n}",
                clean(
                    f"{s.step_id} [{s.step_type}] {s.title}"
                    + (" (approval required)" if s.requires_manual_approval else "")
                ),
            )
            for n, s in enumerate(p.steps, start=1)
        )
        attached = runs.get(p.playbook_id, [])
        rows.append(
            Row(
                p.playbook_id,
                tuple(
                    clean(x)
                    for x in (
                        p.playbook_id,
                        p.version,
                        len(p.steps),
                        ", ".join(p.incident_types),
                        len(attached),
                        p.name,
                    )
                ),
                (
                    ("playbook", clean(p.playbook_id)),
                    ("name", clean(p.name)),
                    ("version", clean(p.version)),
                    ("incident types", clean(", ".join(p.incident_types) or None)),
                    ("roles", clean(", ".join(p.roles) or None)),
                    *steps,
                    ("attached to", clean("; ".join(attached) or None)),
                ),
            )
        )
    columns = ("ID", "Version", "Steps", "Types", "Attached", "Name")
    return Table("playbooks", "Playbooks", columns, tuple(rows), cut)


def load_snapshot(workspace: Workspace) -> Snapshot:
    """Read everything the screens need. Raises the usual service errors (nothing is written)."""
    clean = _cleaner(workspace)
    built = reports.build_workspace_report(workspace)
    data = built.data
    summary_keys = (
        ("active findings", "active_findings"),
        ("active P1", "active_p1"),
        ("active P2", "active_p2"),
        ("overdue findings", "overdue_findings"),
        ("open incidents", "open_incidents"),
        ("open tasks", "open_tasks"),
        ("overdue tasks", "overdue_tasks"),
        ("task completion %", "task_completion_percent"),
        ("playbooks attached", "playbooks_attached"),
        ("pending approvals", "pending_approvals"),
    )
    executive = data["executive_summary"]
    summary = tuple((label, clean(executive[key])) for label, key in summary_keys)
    audit = data["audit"]
    audit_rows = tuple(
        (label, clean(audit[key]))
        for label, key in (
            ("status", "status"),
            ("entries", "entries"),
            ("head hash", "head_hash"),
            ("broken at seq", "broken_at_seq"),
            ("reason", "reason"),
        )
    )
    incident_items = incidents.list_incidents(workspace)
    verified = audit_check.verify_workspace_audit(workspace)
    tables = (
        _assets(workspace, clean),
        _findings(workspace, clean),
        _incidents(workspace, clean, incident_items),
        _tasks(workspace, clean),
        _approvals(workspace, clean),
        _playbooks(workspace, clean, incident_items),
    )
    return Snapshot(
        generated_at=clean(data["generated_at"]),
        audit_intact=verified.intact and built.audit_intact,
        audit=audit_rows,
        summary=summary,
        attention=tuple(clean(item) for item in executive["attention"]),
        tables=tables,
        report_markdown=built.markdown,
    )


def render_plain(snapshot: Snapshot) -> str:
    """Compact text overview for terminals that cannot show the full-screen UI (about 15 lines)."""
    stamp = snapshot.generated_at
    if len(stamp) >= 17 and stamp[10] == "T":
        stamp = f"{stamp[:10]} {stamp[11:16]}Z"
    lines = [
        "SOERM overview (plain text; the full-screen UI needs a capable terminal)",
        f"audit: {'intact' if snapshot.audit_intact else 'BROKEN - run: soerm audit verify'}",
        f"generated: {stamp}",
    ]
    if any(table.truncated for table in snapshot.tables):
        lines.append("LISTS TRUNCATED: not every row is counted below")
    lines.append("")
    half = (len(snapshot.summary) + 1) // 2
    for (left, left_value), (right, right_value) in zip(
        snapshot.summary[:half], snapshot.summary[half:], strict=False
    ):
        lines.append(f"{left:<19}{left_value:<9}{right:<19}{right_value}")
    if snapshot.attention:
        lines += ["", "attention:"]
        for code in snapshot.attention:
            text, screen, level = ATTENTION_TEXT.get(code, (code, 0, "warn"))
            mark = "!!" if level == "crit" else "! "
            lines.append(
                f"  {mark} {text}" + (f" (screen {screen} in the full UI)" if screen else "")
            )
    counts = " | ".join(f"{table.title} {len(table.rows)}" for table in snapshot.tables)
    lines += ["", f"objects: {counts}"]
    return "\n".join(lines)
