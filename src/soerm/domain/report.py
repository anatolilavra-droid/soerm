"""Report content and rendering (M10). Pure: no I/O, no clock, no database.

The report is built from *facts* - small records that deliberately have no description, evidence,
note or step-text field, so those can never reach the output. Free text that is included (finding
and incident titles, asset names, owners) is passed through the ``sanitize`` callable of the
caller (the M4 redactor applied again, then cleaned of control characters and shortened).

Given the same facts, ``generated_at`` and policy the result is byte-for-byte identical: sections
and keys have a fixed order, lists have a fixed sort and numbers are rounded the same way.
"""

# ruff: noqa: RUF001
# (the Cyrillic report labels are intentional)

import json
import statistics
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any, Final

from pydantic import Field

from soerm.domain.base import DomainModel
from soerm.domain.enums import (
    ApprovalStatus,
    BusinessCriticality,
    BusinessPriority,
    Environment,
    Exposure,
    FindingStatus,
    IncidentStatus,
    TaskStatus,
    TechnicalSeverity,
)
from soerm.domain.errors import DomainError, ValidationDomainError

__all__ = [
    "REPORT_SCHEMA",
    "ApprovalFacts",
    "AssetFacts",
    "AuditFacts",
    "FindingFacts",
    "IncidentFacts",
    "OutputRejectedError",
    "PlaybookFacts",
    "ReportFormat",
    "ReportInput",
    "ReportPolicy",
    "TaskFacts",
    "build_report",
    "markdown_text",
    "render_json",
    "render_markdown",
]

REPORT_SCHEMA: Final = "soerm-report-v1"
ACTIVE_STATUSES: Final = frozenset(
    {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS}
)
_PRIORITY_ORDER: Final = [p.value for p in BusinessPriority]
_SEVERITY_ORDER: Final = [s.value for s in reversed(list(TechnicalSeverity))]
_CRITICALITY_ORDER: Final = [c.value for c in reversed(list(BusinessCriticality))]
_EXPOSURE_ORDER: Final = [e.value for e in Exposure]
_ENVIRONMENT_ORDER: Final = [e.value for e in Environment]
_AGE_BUCKETS: Final = (("0-7", 0, 7), ("8-30", 8, 30), ("31-90", 31, 90), (">90", 91, None))
_NO_PRIORITY: Final = "unprioritized"


class OutputRejectedError(DomainError):
    """Writing the report file was refused. ``reason`` is a stable code; no path is included."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"output rejected ({reason})", reason=reason)
        self.reason = reason


class ReportFormat(str):
    """Allowed output formats (a plain string constant set, validated by the service)."""

    MARKDOWN = "md"
    JSON = "json"


class ReportPolicy(DomainModel):
    """``soerm.yaml`` -> ``reports``."""

    allowed_output_dirs: tuple[Annotated[str, Field(min_length=2, max_length=512)], ...] = ()
    top_findings: Annotated[int, Field(strict=True, ge=1, le=100)] = 10
    max_listed: Annotated[int, Field(strict=True, ge=1, le=500)] = 50

    def model_post_init(self, _context: object) -> None:
        if len(self.allowed_output_dirs) > 8:
            raise ValidationDomainError.single("allowed_output_dirs", "too_many")
        for text in self.allowed_output_dirs:
            if not text.startswith("/") or not text.isprintable() or ".." in text.split("/"):
                raise ValidationDomainError.single("allowed_output_dirs", "invalid_directory")


@dataclass(frozen=True, slots=True)
class AssetFacts:
    asset_id: str
    name: str
    criticality: str
    exposure: str
    environment: str


@dataclass(frozen=True, slots=True)
class FindingFacts:
    finding_id: str
    asset_id: str
    title: str
    status: str
    severity: str
    priority: str | None
    sla_due_at: datetime | None
    first_seen: datetime


@dataclass(frozen=True, slots=True)
class IncidentFacts:
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class TaskFacts:
    task_id: str
    status: str
    due_at: datetime | None
    created_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class PlaybookFacts:
    incident_id: str
    playbook_id: str
    version: str
    completed: int
    total: int
    next_step_id: str | None


@dataclass(frozen=True, slots=True)
class ApprovalFacts:
    status: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuditFacts:
    intact: bool
    entries: int
    head_hash: str
    broken_at_seq: int | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ReportInput:
    generated_at: datetime
    tool_version: str
    schema_versions: tuple[int, ...]
    redaction_config_hash: str
    risk_config_hash: str
    policy: ReportPolicy
    sanitize: Callable[[str], str]
    assets: tuple[AssetFacts, ...] = ()
    findings: tuple[FindingFacts, ...] = ()
    incidents: tuple[IncidentFacts, ...] = ()
    tasks: tuple[TaskFacts, ...] = ()
    playbooks: tuple[PlaybookFacts, ...] = ()
    approvals: tuple[ApprovalFacts, ...] = ()
    audit: AuditFacts = AuditFacts(True, 0, "0" * 64)


# -- helpers ---------------------------------------------------------------------------------


def _stamp(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def _days(later: datetime, earlier: datetime) -> int:
    return max(int((later - earlier).total_seconds() // 86400), 0)


def _counts(values: Iterable[str], order: list[str]) -> dict[str, int]:
    found = list(values)
    return {key: found.count(key) for key in order}


def _percent(part: int, whole: int) -> float:
    return 0.0 if whole == 0 else round(100.0 * part / whole, 1)


def _median(values: list[float]) -> float | None:
    return None if not values else round(float(statistics.median(values)), 1)


def _rank(order: list[str], value: str | None) -> int:
    return order.index(value) if value in order else len(order)


# -- sections --------------------------------------------------------------------------------


def _findings_section(inp: ReportInput) -> tuple[dict[str, Any], int]:
    now = inp.generated_at
    findings = inp.findings
    active = [f for f in findings if f.status in {s.value for s in ACTIVE_STATUSES}]
    overdue = sorted(
        (f for f in active if f.sla_due_at is not None and f.sla_due_at < now),
        key=lambda f: (f.sla_due_at or now, f.finding_id),
    )
    by_priority = dict.fromkeys([*_PRIORITY_ORDER, _NO_PRIORITY], 0)
    for f in active:
        by_priority[f.priority or _NO_PRIORITY] += 1
    ages = [_days(now, f.first_seen) for f in active]
    buckets = {
        label: sum(1 for a in ages if a >= low and (high is None or a <= high))
        for label, low, high in _AGE_BUCKETS
    }

    def row(f: FindingFacts) -> dict[str, Any]:
        return {
            "finding_id": f.finding_id,
            "asset_id": f.asset_id,
            "title": inp.sanitize(f.title),
            "status": f.status,
            "severity": f.severity,
            "priority": f.priority,
            "sla_due_at": _stamp(f.sla_due_at),
            "overdue_days": None
            if f.sla_due_at is None or f.sla_due_at >= now
            else _days(now, f.sla_due_at),
            "age_days": _days(now, f.first_seen),
        }

    top = sorted(
        active,
        key=lambda f: (
            _rank(_PRIORITY_ORDER, f.priority),
            _rank(_SEVERITY_ORDER, f.severity),
            f.first_seen,
            f.finding_id,
        ),
    )[: inp.policy.top_findings]
    section = {
        "total": len(findings),
        "active": len(active),
        "by_status": _counts((f.status for f in findings), [s.value for s in FindingStatus]),
        "active_by_priority": by_priority,
        "active_by_severity": _counts((f.severity for f in active), _SEVERITY_ORDER),
        "active_age_days": {
            "buckets": buckets,
            "oldest": max(ages) if ages else None,
            "median": _median([float(a) for a in ages]),
        },
        "overdue": {
            "count": len(overdue),
            "listed": min(len(overdue), inp.policy.max_listed),
            "items": [row(f) for f in overdue[: inp.policy.max_listed]],
        },
        "top": [row(f) for f in top],
    }
    return section, len(overdue)


def _assets_section(inp: ReportInput) -> dict[str, Any]:
    assets = inp.assets
    active_ids = [f for f in inp.findings if f.status in {s.value for s in ACTIVE_STATUSES}]
    per_asset: dict[str, list[FindingFacts]] = {}
    for f in active_ids:
        per_asset.setdefault(f.asset_id, []).append(f)
    matrix = {crit: dict.fromkeys(_EXPOSURE_ORDER, 0) for crit in _CRITICALITY_ORDER}
    for a in assets:
        matrix[a.criticality][a.exposure] += 1

    def exposure_rank(a: AssetFacts) -> tuple[int, int, str]:
        return (
            -len(per_asset.get(a.asset_id, [])),
            _rank(_CRITICALITY_ORDER, a.criticality),
            a.asset_id,
        )

    ranked = [a for a in sorted(assets, key=exposure_rank) if a.asset_id in per_asset]
    return {
        "total": len(assets),
        "by_criticality": _counts((a.criticality for a in assets), _CRITICALITY_ORDER),
        "by_exposure": _counts((a.exposure for a in assets), _EXPOSURE_ORDER),
        "by_environment": _counts((a.environment for a in assets), _ENVIRONMENT_ORDER),
        "criticality_by_exposure": matrix,
        "with_active_findings": len(per_asset),
        "most_affected": [
            {
                "asset_id": a.asset_id,
                "name": inp.sanitize(a.name),
                "criticality": a.criticality,
                "exposure": a.exposure,
                "active_findings": len(per_asset[a.asset_id]),
                "p1_p2": sum(1 for f in per_asset[a.asset_id] if f.priority in {"p1", "p2"}),
            }
            for a in ranked[: inp.policy.top_findings]
        ],
    }


def _incidents_section(inp: ReportInput) -> tuple[dict[str, Any], int]:
    now = inp.generated_at
    incidents = inp.incidents
    open_items = sorted(
        (i for i in incidents if i.status != IncidentStatus.CLOSED.value),
        key=lambda i: (_rank(_SEVERITY_ORDER, i.severity), i.created_at, i.incident_id),
    )
    return {
        "total": len(incidents),
        "open": len(open_items),
        "by_status": _counts((i.status for i in incidents), [s.value for s in IncidentStatus]),
        "open_items": [
            {
                "incident_id": i.incident_id,
                "title": inp.sanitize(i.title),
                "severity": i.severity,
                "status": i.status,
                "age_days": _days(now, i.created_at),
            }
            for i in open_items[: inp.policy.max_listed]
        ],
    }, len(open_items)


def _tasks_section(inp: ReportInput) -> tuple[dict[str, Any], int, int]:
    now = inp.generated_at
    tasks = inp.tasks
    unfinished = {TaskStatus.OPEN.value, TaskStatus.IN_PROGRESS.value}
    overdue = sum(1 for t in tasks if t.status in unfinished and t.due_at and t.due_at < now)
    done = [t for t in tasks if t.status == TaskStatus.DONE.value and t.completed_at]
    hours = [
        round((t.completed_at - t.created_at).total_seconds() / 3600, 1)
        for t in done
        if t.completed_at is not None
    ]
    cancelled = sum(1 for t in tasks if t.status == TaskStatus.CANCELLED.value)
    scope = len(tasks) - cancelled
    open_count = sum(1 for t in tasks if t.status in unfinished)
    return (
        {
            "total": len(tasks),
            "by_status": _counts((t.status for t in tasks), [s.value for s in TaskStatus]),
            "open": open_count,
            "overdue": overdue,
            "completion_percent": _percent(len(done), scope),
            "time_to_complete_hours": {
                "count": len(hours),
                "mean": round(sum(hours) / len(hours), 1) if hours else None,
                "median": _median(hours),
                "max": max(hours) if hours else None,
            },
        },
        open_count,
        overdue,
    )


def _playbooks_section(inp: ReportInput) -> dict[str, Any]:
    items = sorted(inp.playbooks, key=lambda p: p.incident_id)
    return {
        "attached": len(items),
        "completed_steps": sum(p.completed for p in items),
        "total_steps": sum(p.total for p in items),
        "items": [
            {
                "incident_id": p.incident_id,
                "playbook_id": p.playbook_id,
                "version": p.version,
                "completed": p.completed,
                "total": p.total,
                "percent": _percent(p.completed, p.total),
                "next_step": p.next_step_id,
                "ready_for_closure_review": p.total > 0 and p.completed == p.total,
            }
            for p in items[: inp.policy.max_listed]
        ],
    }


def build_report(inp: ReportInput) -> dict[str, Any]:
    """The report as a JSON-compatible dict with a fixed key order."""
    findings, overdue = _findings_section(inp)
    incidents, open_incidents = _incidents_section(inp)
    tasks, open_tasks, overdue_tasks = _tasks_section(inp)
    pending = sum(1 for a in inp.approvals if a.status == ApprovalStatus.PENDING.value)
    stale = sum(
        1
        for a in inp.approvals
        if a.status == ApprovalStatus.PENDING.value and a.expires_at <= inp.generated_at
    )
    p1_active = findings["active_by_priority"]["p1"]
    p2_active = findings["active_by_priority"]["p2"]
    attention: list[str] = []
    if not inp.audit.intact:
        attention.append("audit_chain_broken")
    if p1_active:
        attention.append("active_p1_findings")
    if overdue:
        attention.append("overdue_findings")
    if overdue_tasks:
        attention.append("overdue_tasks")
    if stale:
        attention.append("expired_pending_approvals")
    return {
        "report_schema": REPORT_SCHEMA,
        "generated_at": _stamp(inp.generated_at),
        "tool_version": inp.tool_version,
        "database_schema_versions": list(inp.schema_versions),
        "config": {
            "redaction_config_hash": inp.redaction_config_hash,
            "risk_config_hash": inp.risk_config_hash,
        },
        "audit": {
            "status": "intact" if inp.audit.intact else "broken",
            "entries": inp.audit.entries,
            "head_hash": inp.audit.head_hash,
            "broken_at_seq": inp.audit.broken_at_seq,
            "reason": inp.audit.reason,
        },
        "executive_summary": {
            "active_findings": findings["active"],
            "active_p1": p1_active,
            "active_p2": p2_active,
            "overdue_findings": overdue,
            "open_incidents": open_incidents,
            "open_tasks": open_tasks,
            "overdue_tasks": overdue_tasks,
            "task_completion_percent": tasks["completion_percent"],
            "playbooks_attached": len(inp.playbooks),
            "pending_approvals": pending,
            "audit_status": "intact" if inp.audit.intact else "broken",
            "attention": attention,
        },
        "findings": findings,
        "assets": _assets_section(inp),
        "incidents": incidents,
        "tasks": tasks,
        "playbooks": _playbooks_section(inp),
        "approvals": {
            "by_status": _counts(
                (a.status for a in inp.approvals), [s.value for s in ApprovalStatus]
            ),
            "pending_past_expiry": stale,
        },
    }


# -- rendering -------------------------------------------------------------------------------


def render_json(report: dict[str, Any]) -> str:
    """Deterministic ASCII JSON (keys keep the order they were built in)."""
    return json.dumps(report, ensure_ascii=True, indent=2, sort_keys=False, allow_nan=False) + "\n"


_UNSAFE: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})
_MD_SPECIAL: Final = frozenset("\\|`*_[]<>#!&~")


def markdown_text(value: object) -> str:
    """One-line text safe for a Markdown table cell: no control characters, markup escaped."""
    parts: list[str] = []
    for char in str(value):
        if char == " " or unicodedata.category(char) in _UNSAFE:
            parts.append(" ")
        elif char in _MD_SPECIAL:
            parts.append("\\" + char)
        else:
            parts.append(char)
    return " ".join("".join(parts).split())


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    if not rows:
        return ["_нет данных_", ""]
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    lines += [
        "| " + " | ".join(markdown_text(c) if c is not None else "-" for c in row) + " |"
        for row in rows
    ]
    return [*lines, ""]


def _kv(pairs: list[tuple[str, object]]) -> list[str]:
    return [f"- {label}: **{markdown_text(value)}**" for label, value in pairs] + [""]


def _dict_table(title: str, data: dict[str, int]) -> list[str]:
    return [
        f"**{title}**",
        "",
        *_table(["Значение", "Количество"], [[k, v] for k, v in data.items()]),
    ]


_ATTENTION_TEXT: Final = {
    "audit_chain_broken": "цепочка audit нарушена - результаты нельзя считать доказательными",
    "active_p1_findings": "есть активные findings приоритета P1",
    "overdue_findings": "есть findings с просроченным SLA",
    "overdue_tasks": "есть просроченные задачи remediation",
    "expired_pending_approvals": "есть запросы подтверждения с истёкшим сроком",
}


def render_markdown(report: dict[str, Any]) -> str:
    """Russian Markdown report. Every value passes :func:`markdown_text`."""
    s = report["executive_summary"]
    f, a, i, t, p, ap = (
        report[k] for k in ("findings", "assets", "incidents", "tasks", "playbooks", "approvals")
    )
    out: list[str] = [
        f"<!-- {REPORT_SCHEMA} -->",
        "# Отчёт SOERM",
        "",
        *_kv(
            [
                ("Сформирован (UTC)", report["generated_at"]),
                ("Схема отчёта", report["report_schema"]),
                ("Версия SOERM", report["tool_version"]),
                ("Версии схемы БД", ", ".join(str(v) for v in report["database_schema_versions"])),
                ("Хеш redaction-конфигурации", report["config"]["redaction_config_hash"]),
                ("Хеш модели риска", report["config"]["risk_config_hash"]),
            ]
        ),
        "## Краткое резюме",
        "",
        *_kv(
            [
                ("Активные findings", s["active_findings"]),
                ("из них P1 / P2", f"{s['active_p1']} / {s['active_p2']}"),
                ("Просрочен SLA", s["overdue_findings"]),
                ("Открытые инциденты", s["open_incidents"]),
                ("Открытые задачи / просрочено", f"{s['open_tasks']} / {s['overdue_tasks']}"),
                ("Выполнение задач, %", s["task_completion_percent"]),
                ("Инцидентов с playbook", s["playbooks_attached"]),
                ("Запросов подтверждения в ожидании", s["pending_approvals"]),
                ("Состояние audit", s["audit_status"]),
            ]
        ),
    ]
    if s["attention"]:
        out += ["**Требует внимания:**", ""]
        out += [f"- {_ATTENTION_TEXT[code]}" for code in s["attention"]] + [""]
    else:
        out += ["Критичных отклонений не выявлено.", ""]

    out += ["## Findings", ""]
    out += _kv([("Всего", f["total"]), ("Активных", f["active"])])
    out += _dict_table("Активные по приоритету", f["active_by_priority"])
    out += _dict_table("Активные по severity", f["active_by_severity"])
    out += _dict_table("Все по статусу", f["by_status"])
    age = f["active_age_days"]
    out += _kv(
        [("Старейший активный, дней", age["oldest"]), ("Медианный возраст, дней", age["median"])]
    )
    out += _dict_table("Возраст активных, дней", age["buckets"])
    heads = ["ID", "Актив", "Приоритет", "Severity", "Статус", "SLA до", "Дней", "Название"]

    def finding_rows(items: list[dict[str, Any]]) -> list[list[object]]:
        return [
            [x["finding_id"], x["asset_id"], x["priority"], x["severity"], x["status"],
             x["sla_due_at"], x["age_days"], x["title"]]
            for x in items
        ]  # fmt: skip

    out += ["### Приоритетные findings", "", *_table(heads, finding_rows(f["top"]))]
    ov = f["overdue"]
    out += [f"### Просроченный SLA ({ov['count']}, показано {ov['listed']})", ""]
    out += _table(
        [*heads[:6], "Просрочено, дней", "Название"],
        [
            [
                x["finding_id"],
                x["asset_id"],
                x["priority"],
                x["severity"],
                x["status"],
                x["sla_due_at"],
                x["overdue_days"],
                x["title"],
            ]
            for x in ov["items"]
        ],
    )

    out += ["## Активы", ""]
    out += _kv([("Всего", a["total"]), ("С активными findings", a["with_active_findings"])])
    out += _dict_table("По критичности", a["by_criticality"])
    out += _dict_table("По экспозиции", a["by_exposure"])
    out += _dict_table("По окружению", a["by_environment"])
    out += ["**Критичность x экспозиция**", ""]
    exposures = list(next(iter(a["criticality_by_exposure"].values())).keys())
    out += _table(
        ["Критичность", *exposures],
        [
            [crit, *[row[e] for e in exposures]]
            for crit, row in a["criticality_by_exposure"].items()
        ],
    )
    out += ["### Наиболее затронутые активы", ""]
    out += _table(
        ["ID", "Название", "Критичность", "Экспозиция", "Активных findings", "P1/P2"],
        [
            [
                x["asset_id"],
                x["name"],
                x["criticality"],
                x["exposure"],
                x["active_findings"],
                x["p1_p2"],
            ]
            for x in a["most_affected"]
        ],
    )

    out += ["## Инциденты", ""]
    out += _kv([("Всего", i["total"]), ("Открытых", i["open"])])
    out += _dict_table("По статусу", i["by_status"])
    out += _table(
        ["ID", "Severity", "Статус", "Возраст, дней", "Название"],
        [
            [x["incident_id"], x["severity"], x["status"], x["age_days"], x["title"]]
            for x in i["open_items"]
        ],
    )

    out += ["## Задачи remediation", ""]
    ttc = t["time_to_complete_hours"]
    out += _kv(
        [
            ("Всего", t["total"]),
            ("Не завершено", t["open"]),
            ("Просрочено", t["overdue"]),
            ("Выполнено, % (без отменённых)", t["completion_percent"]),
            (
                "Время выполнения, ч (среднее / медиана / макс.)",
                f"{ttc['mean']} / {ttc['median']} / {ttc['max']}",
            ),
        ]
    )
    out += _dict_table("По статусу", t["by_status"])

    out += ["## Playbooks", ""]
    out += _kv(
        [
            ("Инцидентов с playbook", p["attached"]),
            ("Шагов выполнено / всего", f"{p['completed_steps']} / {p['total_steps']}"),
        ]
    )
    out += _table(
        [
            "Инцидент",
            "Playbook",
            "Версия",
            "Выполнено",
            "Всего",
            "%",
            "Следующий шаг",
            "К проверке закрытия",
        ],
        [
            [
                x["incident_id"],
                x["playbook_id"],
                x["version"],
                x["completed"],
                x["total"],
                x["percent"],
                x["next_step"],
                "да" if x["ready_for_closure_review"] else "нет",
            ]
            for x in p["items"]
        ],
    )
    out += [
        "_Завершение всех шагов не закрывает инцидент: закрытие - отдельное решение человека._",
        "",
    ]

    out += ["## Подтверждения", ""]
    out += _dict_table("По статусу", ap["by_status"])
    out += _kv([("Ожидают, но срок истёк", ap["pending_past_expiry"])])

    au = report["audit"]
    out += ["## Audit", ""]
    out += _kv(
        [
            ("Состояние цепочки", au["status"]),
            ("Записей", au["entries"]),
            ("Хеш последней записи", au["head_hash"]),
            ("Нарушение на записи", "-" if au["broken_at_seq"] is None else au["broken_at_seq"]),
            ("Код причины", au["reason"] or "-"),
        ]
    )
    out += [
        "---",
        "_Отчёт не содержит evidence, полных описаний, заметок и текстов playbook; тексты "
        "прошли redaction._",
        "",
    ]
    return "\n".join(out)
