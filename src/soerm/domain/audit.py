"""Audit entry: identifiers, actions and hashes only; never a user payload."""

from collections.abc import Sequence
from datetime import datetime
from typing import Final, Self

from pydantic import model_validator

from soerm.domain.base import DomainModel
from soerm.domain.errors import IntegrityDomainError
from soerm.domain.hashing import Sha256, hash_canonical
from soerm.domain.identifiers import ActionName, ObjectId, Slug
from soerm.domain.text import Actor
from soerm.domain.timestamps import UtcTimestamp, format_timestamp

__all__ = [
    "AUDIT_HASH_SCHEMA",
    "GENESIS_HASH",
    "AuditEntry",
    "compute_entry_hash",
    "create_audit_entry",
    "verify_audit_chain",
]

AUDIT_HASH_SCHEMA: Final = "soerm-audit-v1"
GENESIS_HASH: Final = "0" * 64


def compute_entry_hash(
    *,
    seq: int,
    timestamp: datetime,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    before_hash: str | None,
    after_hash: str | None,
    prev_hash: str,
) -> str:
    """SHA-256 over the canonical JSON of every field except ``entry_hash`` itself."""
    return hash_canonical(
        {
            "schema": AUDIT_HASH_SCHEMA,
            "seq": seq,
            "timestamp": format_timestamp(timestamp),
            "actor": actor,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "prev_hash": prev_hash,
        }
    )


class AuditEntry(DomainModel):
    seq: int
    timestamp: UtcTimestamp
    actor: Actor
    action: ActionName
    object_type: Slug
    object_id: ObjectId
    before_hash: Sha256 | None = None
    after_hash: Sha256 | None = None
    prev_hash: Sha256
    entry_hash: Sha256

    @model_validator(mode="after")
    def _check_hash(self) -> Self:
        if self.seq < 1:
            raise IntegrityDomainError("invalid_sequence")
        if self.entry_hash != compute_entry_hash(
            seq=self.seq,
            timestamp=self.timestamp,
            actor=self.actor,
            action=self.action,
            object_type=self.object_type,
            object_id=self.object_id,
            before_hash=self.before_hash,
            after_hash=self.after_hash,
            prev_hash=self.prev_hash,
        ):
            raise IntegrityDomainError("entry_hash_mismatch")
        return self


class _Fields(DomainModel):
    """Field validation of an audit entry without the hash consistency check."""

    seq: int
    timestamp: UtcTimestamp
    actor: Actor
    action: ActionName
    object_type: Slug
    object_id: ObjectId
    before_hash: Sha256 | None = None
    after_hash: Sha256 | None = None
    prev_hash: Sha256
    entry_hash: Sha256


def create_audit_entry(
    *,
    seq: int,
    timestamp: datetime,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    before_hash: str | None,
    after_hash: str | None,
    prev_hash: str,
) -> AuditEntry:
    """Build an entry and compute its ``entry_hash`` from the validated fields."""
    fields = _Fields(
        seq=seq,
        timestamp=timestamp,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        before_hash=before_hash,
        after_hash=after_hash,
        prev_hash=prev_hash,
        entry_hash=GENESIS_HASH,  # placeholder, replaced below
    )
    entry_hash = compute_entry_hash(
        seq=fields.seq,
        timestamp=fields.timestamp,
        actor=fields.actor,
        action=fields.action,
        object_type=fields.object_type,
        object_id=fields.object_id,
        before_hash=fields.before_hash,
        after_hash=fields.after_hash,
        prev_hash=fields.prev_hash,
    )
    return AuditEntry(**{**dict(fields), "entry_hash": entry_hash})


def verify_audit_chain(entries: Sequence[AuditEntry]) -> None:
    """Check that ``entries`` form an unbroken chain starting at sequence 1.

    Each entry's hash is recomputed (entries built with ``model_construct`` are not trusted),
    sequence numbers must be consecutive and ``prev_hash`` must equal the previous
    ``entry_hash`` (``GENESIS_HASH`` for the first entry).
    """
    previous = GENESIS_HASH
    for index, entry in enumerate(entries, start=1):
        if entry.seq != index:
            raise IntegrityDomainError("sequence_gap")
        if entry.prev_hash != previous:
            raise IntegrityDomainError("chain_broken")
        expected = compute_entry_hash(
            seq=entry.seq,
            timestamp=entry.timestamp,
            actor=entry.actor,
            action=entry.action,
            object_type=entry.object_type,
            object_id=entry.object_id,
            before_hash=entry.before_hash,
            after_hash=entry.after_hash,
            prev_hash=entry.prev_hash,
        )
        if entry.entry_hash != expected:
            raise IntegrityDomainError("entry_hash_mismatch")
        previous = entry.entry_hash
