"""Approval of a critical change: a pure record plus pure decision functions.

An approval stores only identifiers, hashes and a short reason. It never carries the change
payload, raw evidence or a description.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Annotated, Final, Self

from pydantic import Field, StrictBool, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import ApprovalStatus
from soerm.domain.errors import (
    ApprovalError,
    ExpiredApprovalError,
    ValidationDomainError,
)
from soerm.domain.hashing import Sha256, hash_canonical
from soerm.domain.identifiers import ChangeId, ObjectId, Slug
from soerm.domain.text import Actor, Reason, normalize_actor
from soerm.domain.timestamps import UtcTimestamp, to_utc

__all__ = [
    "CHANGE_SCHEME",
    "DEFAULT_APPROVAL_TTL",
    "GATED_FIELDS",
    "Approval",
    "ApprovalPolicy",
    "approve",
    "change_hash",
    "expire",
    "new_approval",
    "reject",
]

CHANGE_SCHEME: Final = "soerm-change-v1"
# Fields of a finding that only an approved change may modify (values are enum codes).
GATED_FIELDS: Final = frozenset({"status", "business_priority"})

DEFAULT_APPROVAL_TTL: Final = timedelta(days=7)
_DECIDED: Final = frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED})


class ApprovalPolicy(DomainModel):
    """``soerm.yaml`` -> ``approvals``. Switching ``require_distinct_approver`` off is an
    administrative decision of the workspace owner; the value in force is stored per approval."""

    ttl_hours: Annotated[int, Field(strict=True, ge=1, le=8760)] = 168
    require_distinct_approver: StrictBool = True


def change_hash(object_type: str, object_id: str, changes: Mapping[str, str]) -> str:
    """Hash of the *proposed field changes* (enum codes only, never free text).

    It identifies what is being approved without storing it and does not depend on the time of
    application, so an approval can be matched with the change when it is finally made.
    """
    return hash_canonical(
        {
            "scheme": CHANGE_SCHEME,
            "object_type": object_type,
            "object_id": object_id,
            "changes": {key: str(changes[key]) for key in sorted(changes)},
        }
    )


class Approval(DomainModel):
    change_id: ChangeId
    object_type: Slug
    object_id: ObjectId
    requester: Actor
    approver: Actor | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    reason: Reason
    before_hash: Sha256 | None = None
    proposed_after_hash: Sha256
    requested_at: UtcTimestamp
    expires_at: UtcTimestamp
    decided_at: UtcTimestamp | None = None
    # Policy recorded with the approval; True unless configuration (M8) switches it off.
    require_distinct_approver: bool = True

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.expires_at <= self.requested_at:
            raise ValidationDomainError.single("expires_at", "not_after_requested_at")
        if self.status in _DECIDED:
            if self.decided_at is None:
                raise ValidationDomainError.single("decided_at", "required_when_decided")
            if self.approver is None:
                raise ValidationDomainError.single("approver", "required_when_decided")
        else:
            if self.decided_at is not None:
                raise ValidationDomainError.single("decided_at", "forbidden_unless_decided")
            if self.approver is not None:
                raise ValidationDomainError.single("approver", "forbidden_unless_decided")
        if (
            self.require_distinct_approver
            and self.approver is not None
            and self.approver == self.requester
        ):
            raise ApprovalError("self_approval")
        if self.decided_at is not None and self.decided_at < self.requested_at:
            raise ValidationDomainError.single("decided_at", "before_requested_at")
        if (
            self.status is ApprovalStatus.APPROVED
            and self.decided_at is not None
            and self.decided_at >= self.expires_at
        ):
            raise ExpiredApprovalError("approved_after_expiry")
        return self


def new_approval(
    *,
    change_id: str,
    object_type: str,
    object_id: str,
    requester: str,
    reason: str,
    before_hash: str | None,
    proposed_after_hash: str,
    requested_at: datetime,
    ttl: timedelta = DEFAULT_APPROVAL_TTL,
    require_distinct_approver: bool = True,
) -> Approval:
    """Create a pending approval that expires ``ttl`` (default 7 days) after the request."""
    if ttl <= timedelta(0):
        raise ValidationDomainError.single("ttl", "not_positive")
    requested = to_utc(requested_at, field="requested_at")
    return Approval(
        change_id=change_id,
        object_type=object_type,
        object_id=object_id,
        requester=requester,
        reason=reason,
        before_hash=before_hash,
        proposed_after_hash=proposed_after_hash,
        requested_at=requested,
        expires_at=requested + ttl,
        require_distinct_approver=require_distinct_approver,
    )


def _decide(approval: Approval, status: ApprovalStatus, approver: str, now: datetime) -> Approval:
    if approval.status is not ApprovalStatus.PENDING:
        raise ApprovalError("not_pending")
    decided_at = to_utc(now, field="now")
    if decided_at < approval.requested_at:
        raise ApprovalError("decision_before_request")
    if decided_at >= approval.expires_at:
        raise ExpiredApprovalError("pending_approval_expired")
    actor = normalize_actor(approver)
    if approval.require_distinct_approver and actor == approval.requester:
        raise ApprovalError("self_approval")
    return approval.with_changes(status=status, approver=actor, decided_at=decided_at)


def approve(approval: Approval, *, approver: str, now: datetime) -> Approval:
    """Approve a pending approval. Refused if expired or if ``approver`` is the requester."""
    return _decide(approval, ApprovalStatus.APPROVED, approver, now)


def reject(approval: Approval, *, approver: str, now: datetime) -> Approval:
    """Reject a pending approval. Subject to the same rules as :func:`approve`."""
    return _decide(approval, ApprovalStatus.REJECTED, approver, now)


def expire(approval: Approval, *, now: datetime) -> Approval:
    """Mark a pending approval as expired once its time to live has passed."""
    if approval.status is not ApprovalStatus.PENDING:
        raise ApprovalError("not_pending")
    if to_utc(now, field="now") < approval.expires_at:
        raise ApprovalError("not_yet_expired")
    return approval.with_changes(status=ApprovalStatus.EXPIRED)
