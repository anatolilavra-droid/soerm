"""Service-level errors with stable codes.

Every service error is raised from constants, field names and validated identifiers only,
so its message is safe to print: it never contains titles, descriptions, evidence, SQL or
any rejected input. :func:`to_service_error` is the single place where domain and storage
errors are mapped to the stable codes the CLI reports.
"""

from typing import ClassVar, Final

from soerm.config import ConfigError
from soerm.domain.errors import (
    ApprovalError,
    DomainError,
    IntegrityDomainError,
    InvalidTransitionError,
    ValidationDomainError,
)
from soerm.domain.imports import ImportRejectedError
from soerm.storage.errors import (
    ConflictError,
    ConstraintViolationError,
    DatabaseBusyError,
    MigrationError,
    NotFoundError,
    StorageError,
    UnsupportedPlatformError,
    WorkspaceLockError,
)

__all__ = [
    "SERVICE_ERROR_CODES",
    "ApprovalDeniedError",
    "ApprovalRequiredError",
    "BusyError",
    "ConfigServiceError",
    "ConflictServiceError",
    "ConstraintViolationServiceError",
    "ImportServiceError",
    "IntegrityServiceError",
    "InvalidInputError",
    "NotFoundServiceError",
    "ServiceError",
    "UsageServiceError",
    "to_service_error",
]


class ServiceError(DomainError):
    """Base class of errors reported to the user by the service layer."""

    code: ClassVar[str] = "service_error"
    label: ClassVar[str] = "service error"

    def __init__(self, reason: str, **details: object) -> None:
        super().__init__(f"{self.label} ({reason})", reason=reason, **details)


class NotFoundServiceError(ServiceError):
    code: ClassVar[str] = "not_found"
    label: ClassVar[str] = "not found"


class ConflictServiceError(ServiceError):
    code: ClassVar[str] = "conflict"
    label: ClassVar[str] = "the object changed since it was read"


class InvalidInputError(ServiceError):
    code: ClassVar[str] = "invalid_input"
    label: ClassVar[str] = "invalid input"


class ConstraintViolationServiceError(ServiceError):
    code: ClassVar[str] = "constraint_violation"
    label: ClassVar[str] = "constraint violated"


class IntegrityServiceError(ServiceError):
    code: ClassVar[str] = "integrity_error"
    label: ClassVar[str] = "integrity error"


class BusyError(ServiceError):
    code: ClassVar[str] = "busy"
    label: ClassVar[str] = "busy"


class ApprovalRequiredError(ServiceError):
    code: ClassVar[str] = "approval_required"
    label: ClassVar[str] = "approval required"


class ApprovalDeniedError(ServiceError):
    """An approval operation is not permitted (self-approval, expired, already decided...)."""

    code: ClassVar[str] = "approval_denied"
    label: ClassVar[str] = "approval refused"


class ConfigServiceError(ServiceError):
    code: ClassVar[str] = "config_error"
    label: ClassVar[str] = "configuration error"

    def __init__(self, reason: str, *, issues: int = 0) -> None:
        super().__init__(reason, issues=issues)


class ImportServiceError(ServiceError):
    """An import was refused: the reason is a stable code such as ``import_file_too_large``."""

    code: ClassVar[str] = "import_error"
    label: ClassVar[str] = "import error"


class UsageServiceError(ServiceError):
    code: ClassVar[str] = "usage_error"
    label: ClassVar[str] = "usage error"


SERVICE_ERROR_CODES: Final = frozenset(
    cls.code
    for cls in (
        NotFoundServiceError,
        ConflictServiceError,
        InvalidInputError,
        ConstraintViolationServiceError,
        ConfigServiceError,
        ImportServiceError,
        IntegrityServiceError,
        BusyError,
        ApprovalRequiredError,
        ApprovalDeniedError,
        UsageServiceError,
    )
)

_MISSING_DATABASE: Final = frozenset({"database_missing", "database_directory_missing"})


def _reason(exc: DomainError) -> str:
    return exc.details.get("reason", exc.code)


def _validation(exc: ValidationDomainError) -> InvalidInputError:
    issues = "; ".join(f"{item.field or '<value>'}: {item.code}" for item in exc.issues[:10])
    return InvalidInputError(issues or "validation_failed")


def _storage(exc: StorageError) -> ServiceError:
    if isinstance(exc, NotFoundError):
        return NotFoundServiceError("object_not_found", object_type=exc.details["object_type"])
    if isinstance(exc, ConflictError):
        return ConflictServiceError("hash_mismatch", object_type=exc.details["object_type"])
    if isinstance(exc, DatabaseBusyError):
        return BusyError("database_busy")
    if isinstance(exc, ConstraintViolationError):
        return ConstraintViolationServiceError(
            "constraint_violation", kind=exc.details.get("kind", "other")
        )
    if isinstance(exc, MigrationError):
        return IntegrityServiceError(f"migration:{_reason(exc)}")
    if isinstance(exc, WorkspaceLockError):
        reason = _reason(exc)
        if reason == "workspace_missing":
            return NotFoundServiceError("workspace_missing", object_type="workspace")
        if reason == "workspace_locked":
            return BusyError("workspace_locked")
        return IntegrityServiceError(f"lock:{reason}")
    if isinstance(exc, UnsupportedPlatformError):
        return InvalidInputError("posix_required")
    reason = _reason(exc)
    if reason in _MISSING_DATABASE:
        return NotFoundServiceError("workspace_not_initialized", object_type="workspace")
    return IntegrityServiceError(f"storage:{reason}")


def to_service_error(exc: DomainError) -> ServiceError:
    """Map a domain or storage error to a service error (service errors pass through)."""
    if isinstance(exc, ServiceError):
        return exc
    if isinstance(exc, ImportRejectedError):
        if exc.reason == "workspace_missing":
            return NotFoundServiceError("workspace_missing", object_type="workspace")
        shown = exc.reason if exc.detail is None else f"{exc.reason}: {exc.detail}"
        return ImportServiceError(shown)
    if isinstance(exc, ConfigError):
        reason = exc.reason if not exc.issues else f"{exc.reason}: {'; '.join(exc.issues)}"
        return ConfigServiceError(reason[:300], issues=len(exc.issues))
    if isinstance(exc, ValidationDomainError):
        return _validation(exc)
    if isinstance(exc, ApprovalError):
        return ApprovalDeniedError(_reason(exc))
    if isinstance(exc, InvalidTransitionError):
        return InvalidInputError(f"transition: {_reason(exc)}")
    if isinstance(exc, IntegrityDomainError):
        return IntegrityServiceError(_reason(exc))
    if isinstance(exc, StorageError):
        return _storage(exc)
    return InvalidInputError(exc.code)
