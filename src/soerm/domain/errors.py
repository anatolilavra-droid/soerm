"""Domain exceptions.

Every exception carries a stable machine-readable ``code`` and a message assembled from
constants, field names and validated identifiers only. User-supplied values (titles,
descriptions, evidence, anything that may hold a secret) are never interpolated into
messages or details, so the errors are safe to print in the CLI and to write to logs.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar, Self

__all__ = [
    "ApprovalError",
    "DomainError",
    "ExpiredApprovalError",
    "IntegrityDomainError",
    "InvalidIdentifierError",
    "InvalidTimestampError",
    "InvalidTransitionError",
    "ValidationDomainError",
    "ValidationIssue",
    "safe_token",
]

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9_.:\[\]*/ -]{0,80}")
_OMITTED = "<omitted>"
_MAX_MESSAGE_LENGTH = 400


def safe_token(value: object) -> str:
    """Return ``value`` only if it is a short, harmless token; otherwise a placeholder."""
    if isinstance(value, (str, int)):
        text = str(value)
        if _SAFE_TOKEN.fullmatch(text):
            return text
    return _OMITTED


def _safe_message(message: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in message)
    return cleaned[:_MAX_MESSAGE_LENGTH]


class DomainError(Exception):
    """Base class of all domain errors."""

    code: ClassVar[str] = "domain_error"

    def __init__(self, message: str, **details: object) -> None:
        self.message = _safe_message(message)
        self.details: dict[str, str] = {
            key: safe_token(value) for key, value in sorted(details.items())
        }
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict[str, object]:
        """Structured form for the CLI (no user-supplied values)."""
        return {"error": self.code, "message": self.message, "details": dict(self.details)}


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One failed rule: the field it concerns and a stable rule code."""

    field: str
    code: str


class ValidationDomainError(DomainError, ValueError):
    """Input failed domain validation. Subclasses ``ValueError`` so that it can be raised
    from inside Pydantic validators; the model boundary converts it into this form."""

    code: ClassVar[str] = "validation_error"

    def __init__(self, issues: Iterable[ValidationIssue] = (), **details: object) -> None:
        self.issues: tuple[ValidationIssue, ...] = tuple(
            ValidationIssue(safe_token(item.field), safe_token(item.code)) for item in issues
        )
        summary = "; ".join(f"{item.field or '<value>'}: {item.code}" for item in self.issues[:10])
        super().__init__(
            f"validation failed ({summary})" if summary else "validation failed", **details
        )

    @classmethod
    def single(cls, field: str, rule: str) -> Self:
        """Build an error with exactly one issue."""
        return cls([ValidationIssue(field, rule)])


class InvalidIdentifierError(ValidationDomainError):
    """An identifier does not have the required format."""

    code: ClassVar[str] = "invalid_identifier"


class InvalidTimestampError(ValidationDomainError):
    """A timestamp is naive, malformed or out of range."""

    code: ClassVar[str] = "invalid_timestamp"


class InvalidTransitionError(DomainError):
    """A state transition is not allowed."""

    code: ClassVar[str] = "invalid_transition"

    def __init__(self, entity: str, current: object, target: object, reason: str) -> None:
        super().__init__(
            f"{safe_token(entity)}: transition {safe_token(current)} -> {safe_token(target)} "
            f"is not allowed ({safe_token(reason)})",
            reason=reason,
        )


class ApprovalError(DomainError):
    """An approval operation is not permitted."""

    code: ClassVar[str] = "approval_error"

    def __init__(self, reason: str) -> None:
        super().__init__(f"approval operation refused ({safe_token(reason)})", reason=reason)


class ExpiredApprovalError(ApprovalError):
    """The approval is no longer valid because its time to live has passed."""

    code: ClassVar[str] = "approval_expired"


class IntegrityDomainError(DomainError):
    """A hash or chain invariant is violated."""

    code: ClassVar[str] = "integrity_error"

    def __init__(self, reason: str, **details: object) -> None:
        super().__init__(f"integrity check failed ({safe_token(reason)})", reason=reason, **details)
