"""Approvals of critical finding changes (M8).

* **What needs an approval**: moving a finding to or from ``accepted_risk`` / ``false_positive``
  and setting its business priority by hand. ``finding update`` refuses these with
  ``approval_required`` (exit 4) unless an approved change is presented with ``--change-id``.
* **Request**: stores identifiers, hashes and a short redacted reason - never the change
  itself, a description or evidence. ``before_hash`` is the target's digest at request time;
  ``proposed_after_hash`` is the hash of the proposed field changes (enum codes), see
  :func:`~soerm.domain.approval.change_hash`. The policy in force (time to live, distinct
  approver) is read from ``soerm.yaml`` -> ``approvals`` and the flag is stored with the
  approval.
* **Decision**: approve / reject only while pending and before expiry; the requester cannot
  decide their own request unless the stored policy flag allows it. A repeated decision is
  refused (the update is guarded in SQL). A decision after expiry records ``expired`` instead
  (committed) and then refuses.
* **Application**: the change is made by ``finding update --change-id``; it must match the
  approved hash, the target must still have the ``before_hash`` digest, the approval must be
  approved, unexpired and not yet applied (audit ``approval.apply``). One approval, one use.

Every write is one transaction with its audit entry.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from soerm.domain.approval import (
    Approval,
    approve,
    change_hash,
    expire,
    new_approval,
    reject,
)
from soerm.domain.enums import ApprovalStatus, BusinessPriority, FindingStatus
from soerm.domain.errors import DomainError, ExpiredApprovalError
from soerm.domain.finding import Finding
from soerm.domain.identifiers import check_identifier
from soerm.services.common import MutationResult, require_actor
from soerm.services.errors import (
    ApprovalDeniedError,
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
    to_service_error,
)
from soerm.services.redaction import FieldRedactor, load_runtime
from soerm.services.workspace import Workspace
from soerm.storage.approvals import ApprovalRepository
from soerm.storage.counters import CounterRepository
from soerm.storage.findings import FindingRepository

__all__ = [
    "GATED_STATUSES",
    "ApprovalView",
    "ExpireResult",
    "decide_approval",
    "expire_pending",
    "get_approval",
    "list_approvals",
    "proposed_changes",
    "request_change",
    "verify_approval",
    "verify_for_application",
]

GATED_STATUSES: Final = frozenset({FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE})
_OBJECT_TYPE: Final = "finding"


@dataclass(frozen=True, slots=True)
class ApprovalView:
    approval: Approval
    effective_status: str  # "expired" when pending past its expiry (not yet recorded)
    applied: bool


@dataclass(frozen=True, slots=True)
class ExpireResult:
    expired: tuple[str, ...]
    audit_entries: int


def _change_id(value: object) -> str:
    try:
        return check_identifier("CHG", value, field="change_id")
    except DomainError as exc:
        raise to_service_error(exc) from None


def proposed_changes(
    status: FindingStatus | None, business_priority: BusinessPriority | None
) -> dict[str, str]:
    """The gated part of a request as enum codes (the input of the change hash)."""
    changes: dict[str, str] = {}
    try:
        if status is not None:
            changes["status"] = FindingStatus(status).value
        if business_priority is not None:
            changes["business_priority"] = BusinessPriority(business_priority).value
    except ValueError:
        raise InvalidInputError("change: invalid_enum") from None
    return changes


def _is_gated(finding: Finding, changes: dict[str, str]) -> bool:
    """True if every field of ``changes`` is a real, approval-gated change of ``finding``."""
    if not changes:
        return False
    if "status" in changes:
        target = FindingStatus(changes["status"])
        if target is finding.status or not (
            target in GATED_STATUSES or finding.status in GATED_STATUSES
        ):
            return False
    same_priority = (
        "business_priority" in changes
        and finding.business_priority is not None
        and finding.business_priority.value == changes["business_priority"]
    )
    return not same_priority


def candidate_for(finding: Finding, changes: dict[str, str], now: datetime) -> Finding:
    """The finding after applying an approved change. A manual priority is never presented as
    a computed one: the risk model markers are cleared."""
    fields: dict[str, object] = {}
    if "status" in changes:
        fields["status"] = FindingStatus(changes["status"])
    if "business_priority" in changes:
        fields.update(
            business_priority=BusinessPriority(changes["business_priority"]),
            risk_config_hash=None,
            risk_formula_version=None,
            risk_factors={},
        )
    return finding.with_changes(updated_at=max(now, finding.updated_at), **fields)


def request_change(
    workspace: Workspace,
    finding_id: str,
    *,
    actor: str,
    reason: str,
    status: FindingStatus | None = None,
    business_priority: BusinessPriority | None = None,
) -> MutationResult:
    """Ask for approval of a gated change of a finding."""
    requester = require_actor(actor)
    try:
        finding_id = check_identifier("FND", finding_id, field="finding_id")
    except DomainError as exc:
        raise to_service_error(exc) from None
    changes = proposed_changes(status, business_priority)
    if not changes:
        raise InvalidInputError("change: required")
    config, redactor_engine = load_runtime(workspace.path)
    redactor = FieldRedactor(redactor_engine)
    clean_reason = redactor.field("reason", reason, "reason")
    policy = config.approvals
    with workspace.write() as session:
        findings = FindingRepository(session.connection)
        finding = findings.get(finding_id)
        if finding is None:
            raise NotFoundServiceError("object_not_found", object_type="finding")
        if not _is_gated(finding, changes):
            raise InvalidInputError("change: approval_not_applicable")
        try:  # the change must produce a valid finding
            candidate_for(finding, changes, session.now)
            proposed = change_hash(_OBJECT_TYPE, finding_id, changes)
            repo = ApprovalRepository(session.connection)
            if repo.find_pending(_OBJECT_TYPE, finding_id, proposed) is not None:
                raise ConflictServiceError("duplicate_pending_request", object_type="approval")
            approval = new_approval(
                change_id=CounterRepository(session.connection).next_identifier("CHG"),
                object_type=_OBJECT_TYPE,
                object_id=finding_id,
                requester=requester,
                reason=clean_reason,
                before_hash=finding.digest(),
                proposed_after_hash=proposed,
                requested_at=session.now,
                ttl=timedelta(hours=policy.ttl_hours),
                require_distinct_approver=policy.require_distinct_approver,
            )
        except DomainError as exc:
            raise to_service_error(exc) from None
        entry = repo.add(approval, actor=requester, at=session.now)
    return MutationResult(
        "approval", approval.change_id, None, approval.digest(), entry, redactor.report()
    )


def decide_approval(
    workspace: Workspace, change_id: str, *, actor: str, approved: bool
) -> MutationResult:
    """Approve or reject a pending approval (one decision only)."""
    approver = require_actor(actor)
    change_id = _change_id(change_id)
    expired = False
    with workspace.write() as session:
        repo = ApprovalRepository(session.connection)
        current = repo.get(change_id)
        if current is None:
            raise NotFoundServiceError("object_not_found", object_type="approval")
        before = current.digest()
        try:
            decided = (approve if approved else reject)(current, approver=approver, now=session.now)
            action = "approval.approve" if approved else "approval.reject"
        except ExpiredApprovalError:
            decided = expire(current, now=session.now)  # record the expiry, then refuse
            action = "approval.expire"
            expired = True
        except DomainError as exc:
            raise to_service_error(exc) from None
        entry = repo.decide(decided, actor=approver, at=session.now, action=action)
    if expired:
        raise ApprovalDeniedError("approval_expired")
    return MutationResult("approval", change_id, before, decided.digest(), entry)


def expire_pending(workspace: Workspace, *, actor: str) -> ExpireResult:
    """Record the expiry of every pending approval whose time has passed."""
    who = require_actor(actor)
    done: list[str] = []
    with workspace.write() as session:
        repo = ApprovalRepository(session.connection)
        for approval in repo.list_all(status=ApprovalStatus.PENDING):
            if session.now >= approval.expires_at:
                repo.decide(
                    expire(approval, now=session.now),
                    actor=who,
                    at=session.now,
                    action="approval.expire",
                )
                done.append(approval.change_id)
    return ExpireResult(tuple(done), len(done))


def _view(repo: ApprovalRepository, approval: Approval, now: datetime) -> ApprovalView:
    effective = approval.status.value
    if approval.status is ApprovalStatus.PENDING and now >= approval.expires_at:
        effective = ApprovalStatus.EXPIRED.value
    applied = approval.status is ApprovalStatus.APPROVED and repo.was_applied(approval.change_id)
    return ApprovalView(approval, effective, applied)


def get_approval(workspace: Workspace, change_id: str) -> ApprovalView:
    change_id = _change_id(change_id)
    with workspace.read() as session:
        repo = ApprovalRepository(session.connection)
        approval = repo.get(change_id)
        if approval is None:
            raise NotFoundServiceError("object_not_found", object_type="approval")
        return _view(repo, approval, session.now)


def list_approvals(
    workspace: Workspace, *, status: ApprovalStatus | None = None, finding_id: str | None = None
) -> list[ApprovalView]:
    if finding_id is not None:
        try:
            finding_id = check_identifier("FND", finding_id, field="finding_id")
        except DomainError as exc:
            raise to_service_error(exc) from None
    try:
        status_filter = None if status is None else ApprovalStatus(status)
    except ValueError:
        raise InvalidInputError("filter: invalid_enum") from None
    with workspace.read() as session:
        repo = ApprovalRepository(session.connection)
        return [
            _view(repo, a, session.now)
            for a in repo.list_all(status=status_filter, object_id=finding_id)
        ]


def verify_approval(
    repo: ApprovalRepository,
    change_id: str,
    *,
    object_type: str,
    object_id: str,
    proposed_hash: str,
    before_hash: str,
    now: datetime,
) -> Approval:
    """Check that an approved ``change_id`` covers exactly this change of this object state.

    Raises :class:`ApprovalDeniedError` with a stable reason; nothing is modified."""
    change_id = _change_id(change_id)
    approval = repo.get(change_id)
    if approval is None:
        raise NotFoundServiceError("object_not_found", object_type="approval")
    if approval.status is not ApprovalStatus.APPROVED:
        raise ApprovalDeniedError("approval_not_approved")
    if repo.was_applied(change_id):
        raise ApprovalDeniedError("approval_already_applied")
    if now >= approval.expires_at:
        raise ApprovalDeniedError("approval_expired")
    if approval.object_type != object_type or approval.object_id != object_id:
        raise ApprovalDeniedError("approval_other_object")
    if approval.proposed_after_hash != proposed_hash:
        raise ApprovalDeniedError("approval_change_mismatch")
    if approval.before_hash != before_hash:
        raise ApprovalDeniedError("approval_stale_target")
    return approval


def verify_for_application(
    repo: ApprovalRepository,
    change_id: str,
    finding: Finding,
    changes: dict[str, str],
    now: datetime,
) -> Approval:
    """Check that ``changes`` on ``finding`` are covered by the approved ``change_id``."""
    return verify_approval(
        repo,
        change_id,
        object_type=_OBJECT_TYPE,
        object_id=finding.finding_id,
        proposed_hash=change_hash(_OBJECT_TYPE, finding.finding_id, changes),
        before_hash=finding.digest(),
        now=now,
    )
