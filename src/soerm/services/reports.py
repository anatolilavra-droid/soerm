"""Report service (M10): build a snapshot report and write it safely.

* Building reads the database in one read transaction and changes nothing: no lock, no audit
  entry, no domain object is touched. A missing or outdated database is reported as for any
  other read command.
* The facts handed to the pure builder have no description, evidence, note or playbook-text
  field. Free text that is shown (titles, names) goes through the workspace redactor *again*,
  is cleaned of control characters and shortened.
* A broken audit chain does not stop the report - it is reported (``audit.status: broken``).
* Writing goes through :mod:`soerm.outputs.safe_write` (path checks, no symlinks, atomic,
  read-back). Overwriting needs ``force`` and an actor. Generating a report is not recorded in
  the audit log, which keeps the report reproducible from the same snapshot.
"""

import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from soerm import __version__
from soerm.domain.errors import DomainError, IntegrityDomainError
from soerm.domain.playbook_run import progress
from soerm.domain.redaction import RedactionError, Redactor
from soerm.domain.report import (
    ApprovalFacts,
    AssetFacts,
    AuditFacts,
    FindingFacts,
    IncidentFacts,
    OutputRejectedError,
    PlaybookFacts,
    ReportFormat,
    ReportInput,
    TaskFacts,
    build_report,
    render_json,
    render_markdown,
)
from soerm.domain.risk import risk_config_hash
from soerm.domain.timestamps import parse_timestamp
from soerm.outputs.safe_write import write_report_file
from soerm.services.common import require_actor
from soerm.services.errors import (
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import load_runtime
from soerm.services.workspace import Workspace
from soerm.storage.approvals import ApprovalRepository
from soerm.storage.assets import AssetRepository
from soerm.storage.audit import get_audit_head, verify_audit_chain
from soerm.storage.findings import FindingRepository
from soerm.storage.incidents import IncidentRepository
from soerm.storage.migrations import applied_versions
from soerm.storage.playbooks import PlaybookRepository
from soerm.storage.tasks import TaskRepository

__all__ = [
    "BuiltReport",
    "GeneratedReport",
    "build_workspace_report",
    "display_sanitizer",
    "generate_report",
]

_TEXT_LIMIT: Final = 120
_UNSAFE: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})
_FORMATS: Final = (ReportFormat.MARKDOWN, ReportFormat.JSON)
_UNAVAILABLE: Final = "[unavailable]"


@dataclass(frozen=True, slots=True)
class BuiltReport:
    data: dict[str, Any]
    markdown: str
    json: str
    audit_intact: bool

    def render(self, fmt: str) -> str:
        return self.markdown if fmt == ReportFormat.MARKDOWN else self.json


@dataclass(frozen=True, slots=True)
class GeneratedReport:
    path: str
    format: str
    size: int
    sha256: str
    replaced: bool
    audit_intact: bool
    readback_verified: bool


def _format(value: object) -> str:
    if value not in _FORMATS:
        raise InvalidInputError("format: invalid_choice")
    return str(value)


def _generated_at(value: datetime | str | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return parse_timestamp(value, field="generated_at")
    except DomainError as exc:
        raise to_service_error(exc) from None


def _sanitizer(redactor: Redactor) -> Callable[[str], str]:
    def sanitize(text: str) -> str:
        try:
            clean = redactor.redact(text, max_chars=_TEXT_LIMIT * 4).text
        except RedactionError:
            return _UNAVAILABLE
        cleaned = "".join(" " if unicodedata.category(c) in _UNSAFE else c for c in clean)
        cleaned = " ".join(cleaned.split())
        if len(cleaned) > _TEXT_LIMIT:
            cleaned = cleaned[: _TEXT_LIMIT - 3] + "..."
        return cleaned

    return sanitize


def display_sanitizer(workspace: Workspace) -> Callable[[str], str]:
    """Text cleaner for anything shown on a screen: redaction again, no control characters,
    shortened. Used by the terminal UI so that it prints no more than a report does."""
    _, redactor = load_runtime(workspace.path)
    return _sanitizer(redactor)


def build_workspace_report(
    workspace: Workspace, *, generated_at: datetime | str | None = None
) -> BuiltReport:
    """Build the report of the current database snapshot (read-only)."""
    config, redactor = load_runtime(workspace.path)
    fixed_time = _generated_at(generated_at)
    with workspace.read() as session:
        connection = session.connection
        findings = FindingRepository(connection).list()
        facts_findings = tuple(
            FindingFacts(
                f.finding_id,
                f.asset_id,
                f.title,
                f.status.value,
                f.technical_severity.value,
                None if f.business_priority is None else f.business_priority.value,
                f.sla_due_at,
                f.first_seen,
            )
            for f in findings
        )
        del findings  # descriptions and evidence are not carried any further
        assets = tuple(
            AssetFacts(
                a.asset_id,
                a.name,
                a.business_criticality.value,
                a.exposure.value,
                a.environment.value,
            )
            for a in AssetRepository(connection).list()
        )
        incident_repo = IncidentRepository(connection)
        incidents = incident_repo.list_all()
        playbook_repo = PlaybookRepository(connection)
        playbooks: list[PlaybookFacts] = []
        for incident in incidents:
            attachment = playbook_repo.get_attachment(incident.incident_id)
            if attachment is None:
                continue
            playbook = playbook_repo.get(attachment.playbook_id, attachment.version)
            if playbook is None:
                continue
            state = progress(playbook, playbook_repo.completions(incident.incident_id))
            playbooks.append(
                PlaybookFacts(
                    incident.incident_id,
                    attachment.playbook_id,
                    attachment.version,
                    state.completed,
                    state.total,
                    state.next_step_id,
                )
            )
        tasks = tuple(
            TaskFacts(t.task_id, t.status.value, t.due_at, t.created_at, t.completed_at)
            for t in TaskRepository(connection).list_all()
        )
        approvals = tuple(
            ApprovalFacts(a.status.value, a.expires_at)
            for a in ApprovalRepository(connection).list_all()
        )
        try:
            head = verify_audit_chain(connection)
            audit = AuditFacts(True, head.seq, head.entry_hash)
        except IntegrityDomainError as exc:
            head = get_audit_head(connection)
            raw_seq = str(exc.details.get("seq", ""))
            audit = AuditFacts(
                False,
                head.seq,
                head.entry_hash,
                int(raw_seq) if raw_seq.isdigit() else None,
                str(exc.details.get("reason", "integrity")),
            )
        versions = applied_versions(connection)
        facts = ReportInput(
            generated_at=fixed_time or session.now,
            tool_version=__version__,
            schema_versions=versions,
            redaction_config_hash=redactor.config_hash,
            risk_config_hash=risk_config_hash(config.risk),
            policy=config.reports,
            sanitize=_sanitizer(redactor),
            assets=assets,
            findings=facts_findings,
            incidents=tuple(
                IncidentFacts(
                    i.incident_id, i.title, i.severity.value, i.status.value, i.created_at
                )
                for i in incidents
            ),
            tasks=tasks,
            playbooks=tuple(playbooks),
            approvals=approvals,
            audit=audit,
        )
    data = build_report(facts)
    return BuiltReport(data, render_markdown(data), render_json(data), audit.intact)


def generate_report(
    workspace: Workspace,
    output: str,
    *,
    fmt: str = ReportFormat.MARKDOWN,
    force: bool = False,
    actor: str | None = None,
    generated_at: datetime | str | None = None,
) -> GeneratedReport:
    """Write the report to ``output`` (inside the workspace or an allowed directory)."""
    chosen = _format(fmt)
    if force:
        if actor is None:
            raise InvalidInputError("actor: required_with_force")
        require_actor(actor)
    elif actor is not None:
        require_actor(actor)
    config, _ = load_runtime(workspace.path)
    built = build_workspace_report(workspace, generated_at=generated_at)
    payload = built.render(chosen).encode("utf-8")
    try:
        written = write_report_file(
            workspace.path,
            output,
            payload,
            force=force,
            allowed_dirs=config.reports.allowed_output_dirs,
        )
    except OutputRejectedError as exc:
        if exc.reason == "output_exists":
            raise ConflictServiceError("output_exists", object_type="report") from None
        if exc.reason == "workspace_missing":
            raise NotFoundServiceError("workspace_missing", object_type="workspace") from None
        raise InvalidInputError(f"output: {exc.reason}") from None
    return GeneratedReport(
        written.path,
        chosen,
        written.size,
        written.sha256,
        written.replaced,
        built.audit_intact,
        True,
    )
