"""Asset, Finding, Occurrence and error-safety tests."""

import math
from datetime import datetime, timedelta

import pytest

from soerm.domain import (
    Asset,
    BusinessPriority,
    Finding,
    InvalidIdentifierError,
    InvalidTimestampError,
    Occurrence,
    TechnicalSeverity,
    ValidationDomainError,
    severity_from_cvss_score,
)
from soerm.domain.text import EVIDENCE_MAX_BYTES

from .factories import SECRET, SHA_A, T0, T1, asset_data, finding_data

# ---- Asset --------------------------------------------------------------------------------


def test_valid_asset_and_canonical_form() -> None:
    asset = Asset(**asset_data())
    dumped = asset.canonical_dict()
    assert dumped["created_at"] == "2026-03-01T12:00:00Z"
    assert dumped["environment"] == "production"
    assert asset.tags == ("api", "pci")


def test_asset_tags_are_normalized_and_deduplicated() -> None:
    asset = Asset(**asset_data(tags=["PCI", " pci ", "Prod  DB", "prod db", "api"]))
    assert asset.tags == ("api", "pci", "prod-db")
    assert Asset(**asset_data(tags=("b", "a"))).tags == ("a", "b")
    assert Asset(**asset_data(tags=[])).tags == ()


@pytest.mark.parametrize(
    "tags", ["pci", None, 5, [""], [" "], [1], ["x" * 65], [str(i) for i in range(33)]]
)
def test_asset_rejects_bad_tags(tags: object) -> None:
    with pytest.raises(ValidationDomainError):
        Asset(**asset_data(tags=tags))


@pytest.mark.parametrize("field", ["name", "owner"])
@pytest.mark.parametrize("value", ["", "  ", "\x00\t"])
def test_asset_required_strings_not_empty(field: str, value: str) -> None:
    with pytest.raises(ValidationDomainError):
        Asset(**asset_data(**{field: value}))


def test_asset_control_characters_are_normalized() -> None:
    assert Asset(**asset_data(name="Bill\x00ing\tAPI\n")).name == "Bill ing API"


def test_asset_name_length_limit() -> None:
    assert len(Asset(**asset_data(name="x" * 200)).name) == 200
    with pytest.raises(ValidationDomainError):
        Asset(**asset_data(name="x" * 201))


@pytest.mark.parametrize("value", ["AST-1", "FND-000001", "", None, "AST-000001 "])
def test_asset_id_format(value: object) -> None:
    with pytest.raises(InvalidIdentifierError):
        Asset(**asset_data(asset_id=value))


def test_asset_naive_datetime_rejected_and_aware_accepted() -> None:
    with pytest.raises(InvalidTimestampError):
        Asset(**asset_data(created_at=datetime(2026, 1, 1)))  # noqa: DTZ001
    assert Asset(**asset_data(created_at="2026-03-01T14:00:00+02:00")).created_at == T0
    with pytest.raises(InvalidTimestampError):
        Asset(**asset_data(created_at="2026-03-01T12:00:00"))


def test_asset_updated_before_created_rejected() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Asset(**asset_data(updated_at=T0 - timedelta(seconds=1)))
    assert excinfo.value.issues[0].code == "before_created_at"


def test_asset_rejects_unknown_enum_and_extra_fields() -> None:
    with pytest.raises(ValidationDomainError):
        Asset(**asset_data(environment="prod"))
    with pytest.raises(ValidationDomainError) as excinfo:
        Asset(**asset_data(password="hunter2"))
    assert "hunter2" not in str(excinfo.value)
    assert "password" not in str(excinfo.value)


def test_asset_is_immutable_and_with_changes_revalidates() -> None:
    asset = Asset(**asset_data())
    with pytest.raises(ValueError, match="frozen"):
        asset.name = "other"  # type: ignore[misc]
    assert asset.with_changes(name="New name").name == "New name"
    with pytest.raises(ValidationDomainError):
        asset.with_changes(name="")


# ---- Finding ------------------------------------------------------------------------------


def test_valid_finding_defaults() -> None:
    finding = Finding(**finding_data())
    assert finding.status == "open"
    assert finding.business_priority is None
    assert finding.cvss_score is None
    assert finding.risk_factors == {}
    assert finding.evidence == ""


@pytest.mark.parametrize("score", [0, 0.0, 10, 10.0, 5.5, 0.1, 9.9])
def test_cvss_score_boundaries_accepted(score: float) -> None:
    finding = Finding(**finding_data(cvss_score=score, cvss_score_source="imported"))
    assert finding.cvss_score == float(score)


@pytest.mark.parametrize("score", [-0.1, 10.1, -1, 11, 1e9, -1e9])
def test_cvss_score_out_of_range_rejected(score: float) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(cvss_score=score, cvss_score_source="imported"))
    assert excinfo.value.issues[0].code == "cvss_score_out_of_range"


@pytest.mark.parametrize("score", [math.nan, math.inf, -math.inf])
def test_non_finite_cvss_score_rejected(score: float) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(cvss_score=score, cvss_score_source="imported"))
    assert excinfo.value.issues[0].code == "non_finite_number"


@pytest.mark.parametrize("score", ["5.0", True, [5], {"a": 1}])
def test_cvss_score_must_be_a_number(score: object) -> None:
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_score=score, cvss_score_source="imported"))


def test_negative_zero_score_is_normalized() -> None:
    finding = Finding(**finding_data(cvss_score=-0.0, cvss_score_source="imported"))
    assert str(finding.cvss_score) == "0.0"


def test_cvss_score_source_may_only_be_imported() -> None:
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_score=5.0, cvss_score_source="calculated"))
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(cvss_score=5.0))
    assert excinfo.value.issues[0].field == "cvss_score_source"
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_score_source="imported"))


VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_cvss_vector_shape() -> None:
    finding = Finding(**finding_data(cvss_version="4.0", cvss_vector=VECTOR))
    assert finding.cvss_vector == VECTOR


@pytest.mark.parametrize(
    "vector",
    ["", " ", "CVSS:3.1/AV:N/AC:L", "cvss:4.0/AV:N", "CVSS:4.0/", "CVSS:4.0/AV", "CVSS:4.0/AV:N/",
     "CVSS:4.0/AV:N AC:L", "CVSS:4.0/AV:N\n", "AV:N/AC:L", "CVSS:4.0/" + "A:B/" * 200 + "A:B", 5],
)  # fmt: skip
def test_cvss_vector_rejects_bad_shape(vector: object) -> None:
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_version="4.0", cvss_vector=vector))


def test_cvss_vector_needs_version_and_version_is_4_only() -> None:
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_vector=VECTOR))
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(cvss_version="3.1", cvss_vector=VECTOR))


def test_severity_and_priority_are_independent() -> None:
    for severity in TechnicalSeverity:
        for priority in (None, *BusinessPriority):
            # severity "none" is valid only together with the imported score 0.0
            score = (
                {"cvss_score": 0.0, "cvss_score_source": "imported"} if severity == "none" else {}
            )
            finding = Finding(
                **finding_data(technical_severity=severity, business_priority=priority, **score)
            )
            assert finding.technical_severity == severity
            assert finding.business_priority == priority


def test_severity_none_only_for_score_zero() -> None:
    imported = {"cvss_score_source": "imported"}
    zero = Finding(**finding_data(technical_severity="none", cvss_score=0.0, **imported))
    assert zero.cvss_score == 0.0
    for kwargs in ({}, {"cvss_score": 0.1, **imported}, {"cvss_score": 10, **imported}):
        with pytest.raises(ValidationDomainError) as excinfo:
            Finding(**finding_data(technical_severity="none", **kwargs))
        assert excinfo.value.issues[0].code == "none_requires_zero_score"
    # any other severity is accepted with or without a score (no automatic derivation)
    low = Finding(**finding_data(technical_severity="low", cvss_score=0.0, **imported))
    assert low.technical_severity == "low"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "none"), (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
        (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10, "critical"), (10.0, "critical"),
    ],
)  # fmt: skip
def test_score_to_severity_helper(score: float, expected: str) -> None:
    assert severity_from_cvss_score(score) == expected


@pytest.mark.parametrize("score", [-0.1, 10.1, math.nan, math.inf, "5", True, None])
def test_score_to_severity_rejects_bad_input(score: object) -> None:
    with pytest.raises(ValidationDomainError):
        severity_from_cvss_score(score)  # type: ignore[arg-type]


def test_finding_computes_nothing() -> None:
    finding = Finding(**finding_data(technical_severity="critical"))
    assert finding.business_priority is None
    assert finding.cvss_score is None


@pytest.mark.parametrize(
    "fingerprint", ["A" * 64, "a" * 63, "a" * 65, "g" * 64, "", None, "a" * 63 + "\n"]
)
def test_fingerprint_must_be_lowercase_sha256(fingerprint: object) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(fingerprint=fingerprint))
    assert excinfo.value.issues[0].code == "invalid_sha256"


def test_evidence_limit_is_4096_bytes() -> None:
    assert Finding(**finding_data(evidence="a" * EVIDENCE_MAX_BYTES)).evidence == "a" * 4096
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(evidence="a" * (EVIDENCE_MAX_BYTES + 1)))
    assert excinfo.value.issues[0].code == "text_too_large"
    # 2048 two-byte characters fit exactly, one more does not
    assert Finding(**finding_data(evidence="é" * 2048)).evidence == "é" * 2048
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(evidence="é" * 2049))


def test_evidence_error_does_not_leak_content() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(evidence=SECRET * 500))
    rendered = str(excinfo.value) + repr(excinfo.value.to_dict()) + repr(excinfo.value.issues)
    assert SECRET not in rendered
    assert "AKIA" not in rendered


def test_finding_error_chain_does_not_leak() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(title=SECRET, fingerprint=SECRET, technical_severity=SECRET))
    error = excinfo.value
    assert error.__cause__ is None
    assert error.__suppress_context__
    assert SECRET not in str(error) + repr(error.to_dict())


def test_finding_time_ordering() -> None:
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(first_seen=T1, last_seen=T0))
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(created_at=T1, updated_at=T0))


def test_risk_factors_validation() -> None:
    finding = Finding(**finding_data(risk_factors={"exploit_maturity": 0.5, "age_days": 30}))
    assert finding.risk_factors == {"age_days": 30.0, "exploit_maturity": 0.5}
    for bad in [
        {"Bad Name": 1},
        {"a": math.nan},
        {"a": "x"},
        {"a": True},
        {"a": 1e9},
        {1: 1},
        [("a", 1)],
    ]:
        with pytest.raises(ValidationDomainError):
            Finding(**finding_data(risk_factors=bad))
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(risk_factors={f"f{i}": 1 for i in range(33)}))


def test_risk_factor_names_are_not_echoed() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Finding(**finding_data(risk_factors={SECRET: 1}))
    assert SECRET not in str(excinfo.value)


def test_risk_metadata_fields() -> None:
    finding = Finding(**finding_data(risk_formula_version="1", risk_config_hash=SHA_A))
    assert finding.risk_formula_version == "1"
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(risk_config_hash="X" * 64))
    with pytest.raises(ValidationDomainError):
        Finding(**finding_data(risk_formula_version="bad version"))


def test_finding_description_is_multiline_text() -> None:
    finding = Finding(**finding_data(description="line1\r\nline2\x00"))
    assert finding.description == "line1\nline2"


# ---- Occurrence ---------------------------------------------------------------------------


def occurrence_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "import_run_id": "RUN-000001",
        "file_sha256": SHA_A,
        "source_path": "imports/scan.sarif",
        "location": "runs[0].results[3]",
        "observed_at": T0,
    }
    data.update(overrides)
    return data


def test_valid_occurrence() -> None:
    occurrence = Occurrence(**occurrence_data())  # type: ignore[arg-type]
    assert occurrence.canonical_dict()["observed_at"] == "2026-03-01T12:00:00Z"
    assert Occurrence(**occurrence_data(location=None)).location is None  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["A" * 64, "a" * 63, "", None])
def test_occurrence_hash_format(value: object) -> None:
    with pytest.raises(ValidationDomainError):
        Occurrence(**occurrence_data(file_sha256=value))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "path",
    ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a\\b", "a/b\x00", "a/‮b", "x" * 1025, 5],
)
def test_occurrence_path_must_be_safe_relative(path: object) -> None:
    with pytest.raises(ValidationDomainError):
        Occurrence(**occurrence_data(source_path=path))  # type: ignore[arg-type]


def test_occurrence_run_id_and_time() -> None:
    with pytest.raises(InvalidIdentifierError):
        Occurrence(**occurrence_data(import_run_id="RUN-1"))  # type: ignore[arg-type]
    with pytest.raises(InvalidTimestampError):
        Occurrence(**occurrence_data(observed_at=datetime(2026, 1, 1)))  # type: ignore[arg-type]  # noqa: DTZ001
