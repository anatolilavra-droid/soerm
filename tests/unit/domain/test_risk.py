"""Risk model: defaults, validation, monotonicity, hash, calculation, priority and SLA."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from soerm.domain.enums import (
    BusinessCriticality,
    BusinessPriority,
    DataClassification,
    Environment,
    Exposure,
    TechnicalSeverity,
)
from soerm.domain.errors import ValidationDomainError
from soerm.domain.risk import (
    RISK_FORMULA_VERSION,
    RiskConfig,
    RiskInput,
    assess_risk,
    risk_config_hash,
)

FIRST_SEEN = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)


def data(**overrides: Any) -> RiskInput:
    fields: dict[str, Any] = {
        "severity": TechnicalSeverity.HIGH,
        "criticality": BusinessCriticality.MEDIUM,
        "exposure": Exposure.INTERNAL,
        "data_classification": DataClassification.INTERNAL,
        "environment": Environment.PRODUCTION,
        "first_seen": FIRST_SEEN,
    }
    fields.update(overrides)
    return RiskInput(**fields)


CONFIG = RiskConfig()


def test_defaults_are_a_valid_monotonic_model() -> None:
    assert RiskConfig.model_validate({}) == CONFIG
    assert CONFIG.thresholds.p1 > CONFIG.thresholds.p2 > CONFIG.thresholds.p3


def test_neutral_asset_maps_severity_to_priority() -> None:
    expected = {
        TechnicalSeverity.NONE: BusinessPriority.P4,
        TechnicalSeverity.LOW: BusinessPriority.P4,
        TechnicalSeverity.MEDIUM: BusinessPriority.P3,
        TechnicalSeverity.HIGH: BusinessPriority.P2,
        TechnicalSeverity.CRITICAL: BusinessPriority.P1,
    }
    for severity, priority in expected.items():
        assert assess_risk(data(severity=severity), CONFIG).priority is priority


def test_business_context_changes_priority_independently_of_severity() -> None:
    quiet = assess_risk(
        data(
            severity=TechnicalSeverity.MEDIUM,
            exposure=Exposure.ISOLATED,
            environment=Environment.TEST,
        ),
        CONFIG,
    )
    exposed = assess_risk(
        data(
            severity=TechnicalSeverity.MEDIUM,
            criticality=BusinessCriticality.CRITICAL,
            exposure=Exposure.INTERNET,
            data_classification=DataClassification.RESTRICTED,
        ),
        CONFIG,
    )
    assert quiet.priority is BusinessPriority.P4
    assert exposed.priority is BusinessPriority.P1
    assert exposed.score > quiet.score


def test_score_is_capped_and_rounded_and_explained() -> None:
    result = assess_risk(
        data(
            severity=TechnicalSeverity.CRITICAL,
            criticality=BusinessCriticality.CRITICAL,
            exposure=Exposure.INTERNET,
            data_classification=DataClassification.RESTRICTED,
        ),
        CONFIG,
    )
    assert result.score == 100.0
    names = [line.name for line in result.explanation]
    assert names == [
        "severity",
        "asset_criticality",
        "exposure",
        "data_classification",
        "environment",
        "risk_score",
        "priority",
        "sla",
    ]
    assert "capped" in next(line for line in result.explanation if line.name == "risk_score").effect
    assert result.factors["risk_score"] == 100.0
    assert all(isinstance(value, float) for value in result.factors.values())


def test_sla_is_first_seen_plus_priority_hours() -> None:
    for severity, hours in (
        (TechnicalSeverity.CRITICAL, 72),
        (TechnicalSeverity.HIGH, 336),
        (TechnicalSeverity.MEDIUM, 720),
        (TechnicalSeverity.LOW, 2160),
    ):
        result = assess_risk(data(severity=severity), CONFIG)
        assert result.sla_hours == hours
        assert result.sla_due_at == FIRST_SEEN + timedelta(hours=hours)


def test_calculation_is_deterministic() -> None:
    assert assess_risk(data(), CONFIG) == assess_risk(data(), CONFIG)


def test_custom_configuration_changes_the_result_and_the_hash() -> None:
    custom = RiskConfig.model_validate({"thresholds": {"p1": 90, "p2": 70, "p3": 40}})
    assert risk_config_hash(custom) != risk_config_hash(CONFIG)
    assert assess_risk(data(), custom).priority is BusinessPriority.P3
    assert assess_risk(data(), CONFIG).priority is BusinessPriority.P2


def test_hash_is_stable_versioned_and_independent_of_key_order() -> None:
    assert risk_config_hash(CONFIG) == risk_config_hash(RiskConfig())
    assert len(risk_config_hash(CONFIG)) == 64
    reordered = RiskConfig.model_validate(
        {
            "sla_hours": {"p4": 2160, "p3": 720, "p2": 336, "p1": 72},
            "thresholds": {"p3": 30, "p1": 80, "p2": 55},
        }
    )
    assert risk_config_hash(reordered) == risk_config_hash(CONFIG)
    assert RISK_FORMULA_VERSION == "risk-v1"


@pytest.mark.parametrize(
    "bad",
    [
        {"unknown": 1},
        {"criticality": {"extreme": 2}},
        {"criticality": {"low": 0}},
        {"criticality": {"low": -1}},
        {"criticality": {"low": 6}},
        {"criticality": {"low": "1.2"}},
        {"criticality": {"low": True}},
        {"criticality": {"low": float("nan")}},
        {"criticality": {"low": float("inf")}},
        {"criticality": {"low": 1.5, "medium": 1.0}},  # more critical must not lower the score
        {"exposure": {"internet": 0.5}},
        {"data_classification": {"restricted": 0.5}},
        {"environment": {"production": 0.1}},
        {"severity_points": {"critical": 10}},
        {"severity_points": {"critical": 101}},
        {"thresholds": {"p1": 50}},
        {"thresholds": {"p1": 55, "p2": 55}},
        {"thresholds": {"p3": 0}},
        {"sla_hours": {"p1": 0}},
        {"sla_hours": {"p1": 400}},  # a higher priority must not wait longer
        {"sla_hours": {"p4": 87601}},
        {"sla_hours": {"p1": 1.5}},
        {"sla_hours": {"p1": "72"}},
        {"severity_points": [1, 2]},
    ],
)
def test_invalid_configuration_is_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationDomainError):
        RiskConfig.model_validate(bad)


def test_config_errors_do_not_echo_values() -> None:
    with pytest.raises(ValidationDomainError) as caught:
        RiskConfig.model_validate({"criticality": {"low": "hunter2-SECRET"}})
    assert "hunter2" not in repr(caught.value) + str(caught.value)
