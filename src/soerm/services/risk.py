"""Risk service: CVSS check, business priority P1-P4, SLA due date (M7).

* :func:`preview_risk` only reads. It computes what a recalculation *would* store and explains
  it; nothing is written, no lock is taken, the database is not created.
* :func:`recalculate_risk` is the only writer. It recalculates under the workspace lock in one
  transaction, writes one ``finding.risk_recalculate`` audit entry per finding that actually
  changes (identifiers and hashes only) and writes nothing when the result is identical, so
  repeating it is a no-op.

What a recalculation may change: ``business_priority``, ``risk_factors``,
``risk_formula_version``, ``risk_config_hash``, ``sla_due_at`` (and ``updated_at``) - plus
``technical_severity`` only when the caller asks for ``sync_severity``. It never changes the
status, the owner, the text fields or anything else an analyst decided, never closes or reopens
a finding, and skips:

* findings that are not active (``resolved``, ``accepted_risk``, ``false_positive``);
* findings whose ``business_priority`` was set without a risk calculation (no
  ``risk_config_hash``): that value is not ours to overwrite.

The stored ``technical_severity`` is the input of the risk calculation. The CVSS v4.0 vector (if
any) is parsed strictly and scored; the result is a cross-check (``severity_differs``,
``score_matches``). The imported ``cvss_score`` is never overwritten by the computed one.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from soerm.domain.asset import Asset
from soerm.domain.cvss import cvss_v4_score, parse_cvss_v4, severity_from_cvss_score
from soerm.domain.enums import BusinessPriority, FindingStatus, TechnicalSeverity
from soerm.domain.errors import DomainError, ValidationDomainError
from soerm.domain.finding import Finding
from soerm.domain.identifiers import check_identifier
from soerm.domain.risk import (
    RISK_FORMULA_VERSION,
    ExplanationLine,
    RiskAssessment,
    RiskConfig,
    RiskInput,
    assess_risk,
    risk_config_hash,
)
from soerm.services.common import require_actor
from soerm.services.errors import InvalidInputError, NotFoundServiceError, to_service_error
from soerm.services.redaction import load_runtime
from soerm.services.workspace import Session, Workspace
from soerm.storage.assets import AssetRepository
from soerm.storage.findings import FindingRepository

__all__ = [
    "ACTIVE_STATUSES",
    "CvssCheck",
    "RiskItem",
    "RiskRun",
    "preview_risk",
    "recalculate_risk",
]

ACTIVE_STATUSES: Final = frozenset(
    {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS}
)
_SCORE_TOLERANCE: Final = 0.05


@dataclass(frozen=True, slots=True)
class CvssCheck:
    """Result of validating the vector and comparing it with the imported score."""

    vector: str  # "none" | "valid" | "invalid"
    nomenclature: str | None = None
    computed_score: float | None = None
    derived_severity: TechnicalSeverity | None = None
    imported_score: float | None = None
    score_matches: bool | None = None  # None: nothing to compare
    severity_differs: bool = False


@dataclass(frozen=True, slots=True)
class RiskItem:
    finding_id: str
    outcome: str  # "changed" | "unchanged" | "skipped"
    reason: str | None
    severity: TechnicalSeverity
    cvss: CvssCheck
    assessment: RiskAssessment | None = None
    priority_before: BusinessPriority | None = None
    sla_before: datetime | None = None
    severity_sync: str | None = None  # "applied" | "available" | "skipped_none"
    warnings: tuple[str, ...] = ()
    before_hash: str | None = None
    after_hash: str | None = None
    explanation: tuple[ExplanationLine, ...] = ()
    updated: Finding | None = field(default=None, repr=False)

    @property
    def sla_due_at(self) -> datetime | None:
        return None if self.assessment is None else self.assessment.sla_due_at


@dataclass(frozen=True, slots=True)
class RiskRun:
    items: tuple[RiskItem, ...]
    config_hash: str
    formula_version: str
    changed: int
    unchanged: int
    skipped: int
    audit_entries: int = 0
    last_audit_seq: int | None = None
    last_audit_hash: str | None = None


def check_cvss(finding: Finding) -> CvssCheck:
    """Strictly validate the finding's vector and compare it with its imported score."""
    imported = finding.cvss_score
    if finding.cvss_vector is None:
        return CvssCheck("none", imported_score=imported)
    try:
        parsed = parse_cvss_v4(finding.cvss_vector)
    except ValidationDomainError:
        return CvssCheck("invalid", imported_score=imported)
    computed = cvss_v4_score(parsed)
    matches = None if imported is None else abs(imported - computed) < _SCORE_TOLERANCE
    derived = severity_from_cvss_score(computed)
    return CvssCheck(
        "valid",
        parsed.nomenclature,
        computed,
        derived,
        imported,
        matches,
        severity_differs=derived is not finding.technical_severity,
    )


def _sync(
    finding: Finding, cvss: CvssCheck, requested: bool
) -> tuple[TechnicalSeverity, str | None]:
    """The severity to use and the state of the (explicit) severity synchronisation."""
    derived = cvss.derived_severity
    if derived is None or derived is finding.technical_severity:
        return finding.technical_severity, None
    if not requested:
        return finding.technical_severity, "available"
    if derived is TechnicalSeverity.NONE and finding.cvss_score != 0.0:
        return finding.technical_severity, "skipped_none"
    return derived, "applied"


def _warnings(cvss: CvssCheck, sync: str | None) -> tuple[str, ...]:
    found: list[str] = []
    if cvss.vector == "invalid":
        found.append("invalid_cvss_vector")
    if cvss.score_matches is False:
        found.append("cvss_score_mismatch")
    if sync == "available":
        found.append("severity_differs_from_cvss")
    if sync == "skipped_none":
        found.append("severity_sync_skipped_none")
    return tuple(found)


def evaluate(
    finding: Finding,
    asset: Asset,
    config: RiskConfig,
    config_hash: str,
    *,
    now: datetime,
    sync_severity: bool,
) -> RiskItem:
    cvss = check_cvss(finding)
    common = {"finding_id": finding.finding_id, "severity": finding.technical_severity}
    if finding.status not in ACTIVE_STATUSES:
        return RiskItem(outcome="skipped", reason="status_not_active", cvss=cvss, **common)  # type: ignore[arg-type]
    if finding.business_priority is not None and finding.risk_config_hash is None:
        return RiskItem(
            outcome="skipped",
            reason="priority_set_externally",
            cvss=cvss,
            **common,  # type: ignore[arg-type]
        )
    severity, sync = _sync(finding, cvss, sync_severity)
    assessment = assess_risk(
        RiskInput(
            severity,
            asset.business_criticality,
            asset.exposure,
            asset.data_classification,
            asset.environment,
            finding.first_seen,
        ),
        config,
    )
    factors = dict(assessment.factors)
    if cvss.computed_score is not None:
        factors["cvss_computed_score"] = cvss.computed_score
    if cvss.score_matches is not None:
        factors["cvss_score_matches"] = 1.0 if cvss.score_matches else 0.0
    changes: dict[str, object] = {
        "business_priority": assessment.priority,
        "risk_factors": factors,
        "risk_formula_version": RISK_FORMULA_VERSION,
        "risk_config_hash": config_hash,
        "sla_due_at": assessment.sla_due_at,
        "technical_severity": severity,
    }
    current = {name: getattr(finding, name) for name in changes}
    different = any(current[name] != value for name, value in changes.items())
    updated = (
        finding.with_changes(updated_at=max(now, finding.updated_at), **changes)
        if different
        else None
    )
    return RiskItem(
        outcome="changed" if different else "unchanged",
        reason=None,
        cvss=cvss,
        assessment=assessment,
        priority_before=finding.business_priority,
        sla_before=finding.sla_due_at,
        severity_sync=sync,
        warnings=_warnings(cvss, sync),
        before_hash=finding.digest(),
        after_hash=None if updated is None else updated.digest(),
        explanation=assessment.explanation,
        updated=updated,
        **common,  # type: ignore[arg-type]
    )


def _targets(
    session: Session, finding_id: str | None, all_findings: bool
) -> tuple[list[Finding], dict[str, Asset]]:
    if (finding_id is None) == (not all_findings):
        raise InvalidInputError("target: exactly_one_of_finding_id_or_all")
    findings_repo = FindingRepository(session.connection)
    if finding_id is not None:
        try:
            finding_id = check_identifier("FND", finding_id, field="finding_id")
        except DomainError as exc:
            raise to_service_error(exc) from None
        found = findings_repo.get(finding_id)
        if found is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        findings = [found]
    else:
        findings = findings_repo.list()
    assets: dict[str, Asset] = {}
    assets_repo = AssetRepository(session.connection)
    for finding in findings:
        if finding.asset_id not in assets:
            asset = assets_repo.get(finding.asset_id)
            if asset is None:  # the foreign key makes this unreachable; fail closed anyway
                raise NotFoundServiceError("object_not_found", object_type="asset")
            assets[finding.asset_id] = asset
    return findings, assets


def _run(
    session: Session,
    config: RiskConfig,
    finding_id: str | None,
    all_findings: bool,
    sync_severity: bool,
) -> list[RiskItem]:
    findings, assets = _targets(session, finding_id, all_findings)
    digest = risk_config_hash(config)
    return [
        evaluate(
            f, assets[f.asset_id], config, digest, now=session.now, sync_severity=sync_severity
        )
        for f in findings
    ]


def _load_config(workspace: Workspace) -> RiskConfig:
    if not workspace.path.is_dir():
        raise NotFoundServiceError("workspace_missing", object_type="workspace")
    config, _ = load_runtime(workspace.path)
    return config.risk


def _summary(items: list[RiskItem], config: RiskConfig, **audit: object) -> RiskRun:
    return RiskRun(
        items=tuple(items),
        config_hash=risk_config_hash(config),
        formula_version=RISK_FORMULA_VERSION,
        changed=sum(1 for i in items if i.outcome == "changed"),
        unchanged=sum(1 for i in items if i.outcome == "unchanged"),
        skipped=sum(1 for i in items if i.outcome == "skipped"),
        **audit,  # type: ignore[arg-type]
    )


def preview_risk(
    workspace: Workspace,
    *,
    finding_id: str | None = None,
    all_findings: bool = False,
    sync_severity: bool = False,
) -> RiskRun:
    """What a recalculation would do. Read-only."""
    config = _load_config(workspace)
    with workspace.read() as session:
        items = _run(session, config, finding_id, all_findings, sync_severity)
    return _summary(items, config)


def recalculate_risk(
    workspace: Workspace,
    *,
    actor: str,
    finding_id: str | None = None,
    all_findings: bool = False,
    sync_severity: bool = False,
) -> RiskRun:
    """Recalculate and store. Only changed findings are written and audited."""
    actor = require_actor(actor)
    if (finding_id is None) == (not all_findings):
        raise InvalidInputError("target: exactly_one_of_finding_id_or_all")
    config = _load_config(workspace)
    with workspace.write() as session:
        items = _run(session, config, finding_id, all_findings, sync_severity)
        repo = FindingRepository(session.connection)
        entries = [
            repo.update(
                item.updated,
                actor=actor,
                at=session.now,
                expected_before_hash=item.before_hash,
                action="finding.risk_recalculate",
            )
            for item in items
            if item.updated is not None
        ]
    last = entries[-1] if entries else None
    return _summary(
        items,
        config,
        audit_entries=len(entries),
        last_audit_seq=None if last is None else last.seq,
        last_audit_hash=None if last is None else last.entry_hash,
    )
