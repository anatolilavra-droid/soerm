"""Exception design and the domain layer's dependency boundaries."""

import ast
import sys
from pathlib import Path

import pytest

from soerm.domain import (
    ApprovalError,
    Asset,
    DomainError,
    ExpiredApprovalError,
    IntegrityDomainError,
    InvalidIdentifierError,
    InvalidTimestampError,
    InvalidTransitionError,
    ValidationDomainError,
)

from .factories import SECRET, asset_data

DOMAIN_ROOT = Path(__file__).resolve().parents[3] / "src" / "soerm" / "domain"
ALLOWED_THIRD_PARTY = {"pydantic"}
FORBIDDEN_INTERNAL = {"storage", "importers", "services", "cli", "config"}
FORBIDDEN_STDLIB = {
    "socket", "ssl", "urllib", "http", "subprocess", "importlib", "runpy", "sqlite3", "yaml",
    "os", "pathlib", "shutil", "tempfile", "io", "fcntl", "ctypes", "pickle", "asyncio",
}  # fmt: skip


def test_error_hierarchy() -> None:
    for error_class in (
        ValidationDomainError,
        InvalidTransitionError,
        ApprovalError,
        IntegrityDomainError,
    ):
        assert issubclass(error_class, DomainError)
    assert issubclass(InvalidIdentifierError, ValidationDomainError)
    assert issubclass(InvalidTimestampError, ValidationDomainError)
    assert issubclass(ExpiredApprovalError, ApprovalError)
    codes = {
        c.code
        for c in (
            DomainError, ValidationDomainError, InvalidTransitionError, InvalidIdentifierError,
            InvalidTimestampError, ApprovalError, ExpiredApprovalError, IntegrityDomainError,
        )
    }  # fmt: skip
    assert len(codes) == 8


def test_errors_are_cli_friendly() -> None:
    error = InvalidTransitionError("incident", "new", "closed", "step_skipped")
    assert (
        str(error)
        == "invalid_transition: incident: transition new -> closed is not allowed (step_skipped)"
    )
    assert error.to_dict() == {
        "error": "invalid_transition",
        "message": error.message,
        "details": {"reason": "step_skipped"},
    }


def test_error_details_and_messages_never_carry_arbitrary_values() -> None:
    error = DomainError("boom\x00\x1b[31m", token=SECRET * 10, short="ok", number=5)
    assert "\x00" not in error.message
    assert "\x1b" not in error.message
    assert error.details["token"] == "<omitted>"
    assert error.details["short"] == "ok"
    assert error.details["number"] == "5"
    assert InvalidTransitionError("incident", SECRET, SECRET, "x").details["reason"] == "x"
    assert SECRET not in str(InvalidTransitionError("incident", SECRET * 5, SECRET * 5, "x"))
    assert "<omitted>" in str(InvalidTransitionError("incident", SECRET * 5, "closed", "x"))


def test_validation_error_is_a_value_error() -> None:
    assert isinstance(ValidationDomainError.single("f", "r"), ValueError)
    assert not isinstance(ApprovalError("x"), ValueError)


def test_unknown_field_names_are_not_reported() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Asset(**asset_data(**{SECRET.lower(): "x"}))
    assert [i.field for i in excinfo.value.issues] == ["*"]
    assert SECRET.lower() not in str(excinfo.value)


def test_model_validate_json_errors_are_translated() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Asset.model_validate_json('{"asset_id": "' + SECRET + '"}')
    assert SECRET not in str(excinfo.value)
    with pytest.raises(ValidationDomainError):
        Asset.model_validate_json("not json " + SECRET)


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
    return names


def test_domain_imports_only_stdlib_pydantic_and_itself() -> None:
    files = sorted(DOMAIN_ROOT.glob("*.py"))
    assert len(files) >= 14
    problems: list[str] = []
    for path in files:
        for module in _imports(path):
            root = module.split(".")[0]
            if root == "soerm":
                parts = module.split(".")
                if len(parts) < 2 or parts[1] != "domain":
                    problems.append(f"{path.name}: {module}")
            elif root in FORBIDDEN_STDLIB or root in FORBIDDEN_INTERNAL:
                problems.append(f"{path.name}: {module}")
            elif root not in ALLOWED_THIRD_PARTY and root not in sys.stdlib_module_names:
                problems.append(f"{path.name}: unexpected third-party import {module}")
    assert not problems, problems
