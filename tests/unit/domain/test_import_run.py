"""Fingerprint recipe and the ImportRun model."""

import pytest

from soerm.domain.enums import ImportSource
from soerm.domain.errors import ValidationDomainError
from soerm.domain.import_run import FINGERPRINT_SCHEME, ImportRun, compute_fingerprint

BASE = {
    "source": ImportSource.SARIF,
    "asset_id": "AST-000001",
    "title": "SQL injection",
    "external_rule_id": "R1",
    "location": "src/db.py:12",
}


def fp(**overrides: object) -> str:
    return compute_fingerprint(**{**BASE, **overrides})  # type: ignore[arg-type]


def test_fingerprint_is_stable_hex() -> None:
    assert fp() == fp()
    assert len(fp()) == 64
    assert FINGERPRINT_SCHEME == "soerm-fingerprint-v1"


@pytest.mark.parametrize(
    "change",
    [
        {"source": ImportSource.CSV},
        {"asset_id": "AST-000002"},
        {"external_rule_id": "R2"},
        {"external_rule_id": None, "title": "other"},
        {"location": "src/db.py:13"},
        {"location": None},
    ],
)
def test_identity_fields_change_the_fingerprint(change: dict[str, object]) -> None:
    assert fp(**change) != fp()


def test_normalization_ignores_case_width_and_spacing() -> None:
    assert fp(external_rule_id="  r1 ", location="SRC/DB.PY:12") == fp()
    assert fp(external_rule_id="\uff32\uff11") == fp()


def test_title_is_not_identity_when_a_rule_id_exists() -> None:
    assert fp(title="Reworded title") == fp()


def test_title_is_identity_without_a_rule_id() -> None:
    a = fp(external_rule_id=None, title="Weak  TLS")
    assert a == fp(external_rule_id=None, title="weak tls")
    assert a != fp(external_rule_id=None, title="weak tls 1.0")
    assert fp(external_rule_id="  ", title="x") == fp(external_rule_id=None, title="x")


def test_unknown_source_is_refused() -> None:
    with pytest.raises(ValueError, match="nope"):
        fp(source="nope")


def test_import_run_validation() -> None:
    good = {
        "run_id": "RUN-000001",
        "source": ImportSource.CSV,
        "file_sha256": "a" * 64,
        "source_path": "in/a.csv",
        "imported_at": "2026-03-01T12:00:00Z",
        "record_count": 3,
    }
    assert ImportRun(**good).digest() == ImportRun(**good).digest()  # type: ignore[arg-type]
    for bad in (
        {"record_count": -1},
        {"source_path": "../x"},
        {"source_path": "/abs"},
        {"run_id": "FND-000001"},
        {"file_sha256": "A" * 64},
    ):
        with pytest.raises(ValidationDomainError):
            ImportRun(**{**good, **bad})  # type: ignore[arg-type]
