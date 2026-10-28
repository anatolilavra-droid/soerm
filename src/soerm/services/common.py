"""Shared service helpers: actor and hash checks, mutation results."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from soerm.domain.audit import AuditEntry
from soerm.domain.errors import ValidationDomainError
from soerm.domain.hashing import is_sha256
from soerm.domain.text import normalize_actor
from soerm.services.errors import InvalidInputError
from soerm.services.redaction import RedactionReport

__all__ = ["PLACEHOLDER_TIME", "MutationResult", "require_actor", "require_expected_hash"]

# Used only to validate input before the workspace is touched; never stored.
PLACEHOLDER_TIME: Final = datetime(2000, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class MutationResult:
    """What a mutating service call reports: identifiers, hashes and the audit entry."""

    object_type: str
    object_id: str
    before_hash: str | None
    after_hash: str
    audit: AuditEntry
    redaction: RedactionReport | None = None


def require_actor(actor: object) -> str:
    """Normalize the actor (NFKC, casefold, trim, ASCII allowlist); never echo the value."""
    try:
        return normalize_actor(actor)
    except ValidationDomainError:
        raise InvalidInputError("actor: invalid_actor") from None


def require_expected_hash(value: object) -> str:
    """The hash the caller read the object with (lowercase hex SHA-256)."""
    if not isinstance(value, str) or not is_sha256(value):
        raise InvalidInputError("expected_hash: invalid_sha256")
    return value
