"""Mapping of domain/storage errors to the stable service error codes."""

import pytest

from soerm.domain.errors import (
    ApprovalError,
    DomainError,
    ExpiredApprovalError,
    IntegrityDomainError,
    InvalidIdentifierError,
    InvalidTimestampError,
    InvalidTransitionError,
    ValidationDomainError,
)
from soerm.services.errors import SERVICE_ERROR_CODES, ServiceError, to_service_error
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
from tests.unit.services.helpers import SECRET

CASES: list[tuple[DomainError, str]] = [
    (ValidationDomainError.single("name", "required"), "invalid_input"),
    (InvalidIdentifierError.single("asset_id", "invalid_identifier"), "invalid_input"),
    (InvalidTimestampError.single("created_at", "naive"), "invalid_input"),
    (InvalidTransitionError("incident", "new", "closed", "skip"), "invalid_input"),
    (ApprovalError("self_approval"), "approval_denied"),
    (ExpiredApprovalError("expired"), "approval_denied"),
    (IntegrityDomainError("chain_broken", seq=3), "integrity_error"),
    (NotFoundError("asset"), "not_found"),
    (ConflictError("finding"), "conflict"),
    (DatabaseBusyError(), "busy"),
    (ConstraintViolationError("unique"), "constraint_violation"),
    (ConstraintViolationError("foreign_key"), "constraint_violation"),
    (MigrationError("migration_checksum_mismatch", version=1), "integrity_error"),
    (WorkspaceLockError("workspace_missing"), "not_found"),
    (WorkspaceLockError("workspace_locked"), "busy"),
    (WorkspaceLockError("lock_file_not_regular"), "integrity_error"),
    (UnsupportedPlatformError("posix_required"), "invalid_input"),
    (StorageError("database_missing"), "not_found"),
    (StorageError("corrupt_row", object_type="asset"), "integrity_error"),
    (StorageError("something_else"), "integrity_error"),
    (DomainError("generic"), "invalid_input"),
]


@pytest.mark.parametrize(("error", "code"), CASES, ids=lambda v: v if isinstance(v, str) else "")
def test_mapping(error: DomainError, code: str) -> None:
    mapped = to_service_error(error)
    assert isinstance(mapped, ServiceError)
    assert mapped.code == code
    assert code in SERVICE_ERROR_CODES


def test_service_errors_pass_through_unchanged() -> None:
    error = to_service_error(NotFoundError("asset"))
    assert to_service_error(error) is error


def test_codes_are_the_documented_set() -> None:
    assert {
        "not_found", "conflict", "invalid_input", "constraint_violation", "integrity_error",
        "busy", "approval_required", "approval_denied", "usage_error", "config_error",
        "import_error",
    } == SERVICE_ERROR_CODES  # fmt: skip


def test_messages_contain_no_sql_and_no_input() -> None:
    for error, _ in CASES:
        text = str(to_service_error(error))
        assert "\n" not in text
        assert SECRET not in text


def test_validation_messages_list_fields_and_rules_only() -> None:
    mapped = to_service_error(ValidationDomainError.single("name", "text_too_long"))
    assert "name: text_too_long" in str(mapped)
    assert mapped.to_dict()["error"] == "invalid_input"
