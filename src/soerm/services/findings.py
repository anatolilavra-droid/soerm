"""Finding service: create, read, list and update findings.

M3 scope, deliberately narrow:

* identifiers come from the storage counters; the caller supplies a fingerprint;
* every text value (title, description, evidence, owner) is normalized, redacted and then
  shortened to its field limit before validation and storage (M4); ``source`` is an enum, not
  free text;
* technical severity is entered by the caller; business priority and CVSS scores are never
  computed (M7), and a CVSS score is never derived from a vector;
* changing business priority, or moving a finding to ``accepted_risk`` / ``false_positive``
  (or out of those states), is an approval-gated action that does not exist before M8, so it
  is refused with ``approval_required``;
* updates are optimistic: the caller passes the hash it read, a different stored hash is a
  ``conflict``.

Audit entries carry identifiers and hashes only - never titles, descriptions or evidence.
"""

from enum import StrEnum
from typing import Final

from soerm.domain.enums import (
    BusinessPriority,
    FindingStatus,
    ImportSource,
    TechnicalSeverity,
)
from soerm.domain.errors import DomainError
from soerm.domain.finding import Finding
from soerm.domain.identifiers import check_identifier
from soerm.services.approvals import (
    GATED_STATUSES,
    candidate_for,
    proposed_changes,
    verify_for_application,
)
from soerm.services.common import (
    PLACEHOLDER_TIME,
    MutationResult,
    require_actor,
    require_expected_hash,
)
from soerm.services.errors import (
    ApprovalRequiredError,
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_redactor
from soerm.services.workspace import Workspace
from soerm.storage.approvals import ApprovalRepository
from soerm.storage.assets import AssetRepository
from soerm.storage.counters import CounterRepository
from soerm.storage.findings import FindingOrder, FindingRepository

__all__ = [
    "APPROVAL_GATED_STATUSES",
    "FindingSort",
    "create_finding",
    "get_finding",
    "list_findings",
    "update_finding",
]

APPROVAL_GATED_STATUSES: Final = GATED_STATUSES
_PLACEHOLDER_FINDING_ID = "FND-000001"
_CVSS_VERSION: Final = "4.0"


class FindingSort(StrEnum):
    """Allowed sort orders for :func:`list_findings`."""

    ID = "id"
    LAST_SEEN = "last_seen"


def _finding_id(finding_id: object) -> str:
    try:
        return check_identifier("FND", finding_id, field="finding_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def _cvss_fields(vector: str | None, score: float | None) -> dict[str, object]:
    return {
        "cvss_version": _CVSS_VERSION if vector is not None else None,
        "cvss_vector": vector,
        "cvss_score": score,
        # The only allowed source: the score is supplied by the caller, never calculated.
        "cvss_score_source": "imported" if score is not None else None,
    }


def create_finding(
    workspace: Workspace,
    *,
    actor: str,
    asset_id: str,
    fingerprint: str,
    title: str,
    technical_severity: TechnicalSeverity,
    description: str = "",
    evidence: str = "",
    owner: str | None = None,
    cvss_vector: str | None = None,
    cvss_score: float | None = None,
    source: ImportSource = ImportSource.MANUAL,
) -> MutationResult:
    """Create a finding for an existing asset (status ``open``, no business priority)."""
    actor = require_actor(actor)
    redactor = FieldRedactor(load_redactor(workspace.path))
    fields: dict[str, object] = {
        "fingerprint": fingerprint,
        "title": redactor.field("title", title, "title"),
        "description": redactor.field("description", description, "text"),
        "asset_id": asset_id,
        "source": source,
        "evidence": redactor.field("evidence", evidence, "evidence"),
        "technical_severity": technical_severity,
        "owner": redactor.optional("owner", owner, "name"),
        **_cvss_fields(cvss_vector, cvss_score),
    }
    try:  # fail before anything is created in the workspace
        Finding(
            finding_id=_PLACEHOLDER_FINDING_ID,
            first_seen=PLACEHOLDER_TIME,
            last_seen=PLACEHOLDER_TIME,
            created_at=PLACEHOLDER_TIME,
            updated_at=PLACEHOLDER_TIME,
            **fields,  # type: ignore[arg-type]
        )
    except DomainError as exc:
        raise to_service_error(exc) from None
    with workspace.write() as session:
        if AssetRepository(session.connection).get(asset_id) is None:
            raise NotFoundServiceError("object_not_found", object_type="asset")
        finding_id = CounterRepository(session.connection).next_identifier("FND")
        finding = Finding(
            finding_id=finding_id,
            first_seen=session.now,
            last_seen=session.now,
            created_at=session.now,
            updated_at=session.now,
            **fields,  # type: ignore[arg-type]
        )
        entry = FindingRepository(session.connection).add(finding, actor=actor, at=session.now)
    return MutationResult("finding", finding_id, None, finding.digest(), entry, redactor.report())


def get_finding(workspace: Workspace, finding_id: str) -> Finding:
    finding_id = _finding_id(finding_id)
    with workspace.read() as session:
        finding = FindingRepository(session.connection).get(finding_id)
    if finding is None:
        raise NotFoundServiceError("object_not_found", object_type="finding")
    return finding


def list_findings(
    workspace: Workspace,
    *,
    status: FindingStatus | None = None,
    asset_id: str | None = None,
    severity: TechnicalSeverity | None = None,
    sort: FindingSort = FindingSort.ID,
) -> list[Finding]:
    """List findings; only the allowlisted filters and sort orders are accepted."""
    try:
        order = FindingOrder(FindingSort(sort).value)
        status_filter = None if status is None else FindingStatus(status)
        severity_filter = None if severity is None else TechnicalSeverity(severity)
    except ValueError:
        raise InvalidInputError("filter: invalid_enum") from None
    if asset_id is not None:
        try:
            asset_id = check_identifier("AST", asset_id, field="asset_id")
        except DomainError as exc:
            raise to_service_error(exc) from None
    with workspace.read() as session:
        return FindingRepository(session.connection).list(
            status=status_filter, asset_id=asset_id, severity=severity_filter, order=order
        )


def _apply_approved(
    workspace: Workspace,
    finding_id: str,
    actor: str,
    expected: str,
    change_id: str,
    status: FindingStatus | None,
    business_priority: BusinessPriority | None,
) -> MutationResult:
    """Make a gated change that an approval covers; the approval is consumed (audit)."""
    changes = proposed_changes(status, business_priority)
    if not changes:
        raise InvalidInputError("change_id: nothing_to_apply")
    with workspace.write() as session:
        repo = FindingRepository(session.connection)
        current = repo.get(finding_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        before = current.digest()
        if before != expected:
            raise ConflictServiceError("hash_mismatch", object_type="finding")
        approvals = ApprovalRepository(session.connection)
        verify_for_application(approvals, change_id, current, changes, session.now)
        try:
            updated = candidate_for(current, changes, session.now)
        except DomainError as exc:
            raise to_service_error(exc) from None
        entry = repo.update(updated, actor=actor, at=session.now, expected_before_hash=expected)
        after = updated.digest()
        approvals.record_application(
            change_id, before_hash=before, after_hash=after, actor=actor, at=session.now
        )
    return MutationResult("finding", finding_id, before, after, entry)


def update_finding(
    workspace: Workspace,
    finding_id: str,
    *,
    actor: str,
    expected_hash: str,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
    owner: str | None = None,
    clear_owner: bool = False,
    technical_severity: TechnicalSeverity | None = None,
    status: FindingStatus | None = None,
    business_priority: BusinessPriority | None = None,
    change_id: str | None = None,
) -> MutationResult:
    """Change fields of a finding, but only if it still has the hash the caller read.

    Changing ``business_priority``, or moving a finding to or from ``accepted_risk`` /
    ``false_positive``, needs an approved change (``soerm approval request``/``approve``) that
    is presented with ``change_id``; without it the call is refused (``approval_required``).
    With ``change_id`` only these two fields may be given.
    """
    actor = require_actor(actor)
    finding_id = _finding_id(finding_id)
    expected = require_expected_hash(expected_hash)
    if change_id is not None:
        other = (title, description, evidence, owner, technical_severity)
        if clear_owner or any(value is not None for value in other):
            raise InvalidInputError("change_id: only_gated_fields")
        return _apply_approved(
            workspace, finding_id, actor, expected, change_id, status, business_priority
        )
    if business_priority is not None:
        raise ApprovalRequiredError("business_priority_change")
    try:
        status_target = None if status is None else FindingStatus(status)
    except ValueError:
        raise InvalidInputError("status: invalid_enum") from None
    if status_target in APPROVAL_GATED_STATUSES:
        raise ApprovalRequiredError("status_change", status=status_target.value)
    if clear_owner and owner is not None:
        raise InvalidInputError("owner: conflicting_options")
    redactor = FieldRedactor(load_redactor(workspace.path))
    changes: dict[str, object] = {
        key: value
        for key, value in (
            ("title", redactor.optional("title", title, "title")),
            ("description", redactor.optional("description", description, "text")),
            ("evidence", redactor.optional("evidence", evidence, "evidence")),
            ("owner", redactor.optional("owner", owner, "name")),
            ("technical_severity", technical_severity),
            ("status", status_target),
        )
        if value is not None
    }
    if clear_owner:
        changes["owner"] = None
    if not changes:
        raise InvalidInputError("no_changes")
    with workspace.write() as session:
        repo = FindingRepository(session.connection)
        current = repo.get(finding_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        before = current.digest()
        if before != expected:
            raise ConflictServiceError("hash_mismatch", object_type="finding")
        if (
            current.status in APPROVAL_GATED_STATUSES
            and status_target is not None
            and status_target is not current.status
        ):
            raise ApprovalRequiredError("status_change", status=current.status.value)
        candidate = current.with_changes(**changes)
        if candidate == current:
            raise InvalidInputError("no_changes")
        updated = candidate.with_changes(updated_at=session.now)
        entry = repo.update(updated, actor=actor, at=session.now, expected_before_hash=expected)
    return MutationResult("finding", finding_id, before, updated.digest(), entry, redactor.report())
