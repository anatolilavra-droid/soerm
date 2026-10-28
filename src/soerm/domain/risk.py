"""Business risk model (M7): configuration, calculation, priority P1-P4 and SLA due dates.

Business risk is deliberately separate from CVSS. CVSS describes the technical severity of a
weakness; risk here combines that severity with what the organization knows about the asset
(criticality, exposure, data classification, environment)::

    risk_score = min(100, severity_points[severity] * criticality * exposure * data * environment)
    priority   = P1 if score >= p1, P2 if >= p2, P3 if >= p3, else P4
    sla_due_at = first_seen + sla_hours[priority]

All numbers come from :class:`RiskConfig` (``soerm.yaml`` -> ``risk``; built-in defaults when
absent). The configuration is validated for monotonicity - a more severe, more critical or more
exposed input can never lower the score, and a higher priority never gets a longer SLA - so a
typo cannot invert the model. :func:`risk_config_hash` versions the configuration together with
the formula label, so a stored result says exactly which model produced it.

Pure functions; no I/O, no clock. Nothing here knows about external threat intelligence.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Annotated, Final, Self

from pydantic import BeforeValidator, Field, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.enums import (
    BusinessCriticality,
    BusinessPriority,
    DataClassification,
    Environment,
    Exposure,
    TechnicalSeverity,
)
from soerm.domain.errors import ValidationDomainError
from soerm.domain.hashing import compute_config_hash

__all__ = [
    "RISK_FORMULA_VERSION",
    "ExplanationLine",
    "RiskAssessment",
    "RiskConfig",
    "RiskInput",
    "assess_risk",
    "risk_config_hash",
]

RISK_FORMULA_VERSION: Final = "risk-v1"
_MAX_WEIGHT: Final = 5.0
_MAX_SLA_HOURS: Final = 87_600  # ten years


def _number(value: object, *, low: float, high: float, low_open: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationDomainError.single("", "invalid_number")
    number = float(value)
    if not math.isfinite(number):
        raise ValidationDomainError.single("", "non_finite_number")
    if number > high or number < low or (low_open and number == low):
        raise ValidationDomainError.single("", "number_out_of_range")
    return number + 0.0


def _weight(value: object) -> float:
    return _number(value, low=0.0, high=_MAX_WEIGHT, low_open=True)


def _points(value: object) -> float:
    return _number(value, low=0.0, high=100.0, low_open=False)


Weight = Annotated[float, BeforeValidator(_weight)]
Points = Annotated[float, BeforeValidator(_points)]
Hours = Annotated[int, Field(strict=True, ge=1, le=_MAX_SLA_HOURS)]


def _ordered(values: tuple[float, ...], field: str, *, rising: bool) -> None:
    if not all((a <= b) if rising else (a >= b) for a, b in pairwise(values)):
        raise ValidationDomainError.single(field, "not_monotonic")


class SeverityPoints(DomainModel):
    none: Points = 0.0
    low: Points = 15.0
    medium: Points = 35.0
    high: Points = 60.0
    critical: Points = 85.0


class CriticalityWeights(DomainModel):
    low: Weight = 0.8
    medium: Weight = 1.0
    high: Weight = 1.2
    critical: Weight = 1.4


class ExposureWeights(DomainModel):
    internet: Weight = 1.3
    partner: Weight = 1.1
    internal: Weight = 1.0
    isolated: Weight = 0.7


class DataWeights(DomainModel):
    public: Weight = 0.9
    internal: Weight = 1.0
    confidential: Weight = 1.15
    restricted: Weight = 1.3


class EnvironmentWeights(DomainModel):
    production: Weight = 1.0
    staging: Weight = 0.7
    development: Weight = 0.5
    test: Weight = 0.4


class PriorityThresholds(DomainModel):
    """Minimum score for P1, P2 and P3; everything below is P4."""

    p1: Points = 80.0
    p2: Points = 55.0
    p3: Points = 30.0


class SlaHours(DomainModel):
    p1: Hours = 72
    p2: Hours = 336
    p3: Hours = 720
    p4: Hours = 2160


class RiskConfig(DomainModel):
    """``soerm.yaml`` -> ``risk``. Every part is optional; unknown keys are rejected."""

    severity_points: SeverityPoints = Field(default_factory=SeverityPoints)
    criticality: CriticalityWeights = Field(default_factory=CriticalityWeights)
    exposure: ExposureWeights = Field(default_factory=ExposureWeights)
    data_classification: DataWeights = Field(default_factory=DataWeights)
    environment: EnvironmentWeights = Field(default_factory=EnvironmentWeights)
    thresholds: PriorityThresholds = Field(default_factory=PriorityThresholds)
    sla_hours: SlaHours = Field(default_factory=SlaHours)

    @model_validator(mode="after")
    def _monotonic(self) -> Self:
        s, c, e = self.severity_points, self.criticality, self.exposure
        d, v, t = self.data_classification, self.environment, self.thresholds
        _ordered((s.none, s.low, s.medium, s.high, s.critical), "severity_points", rising=True)
        _ordered((c.low, c.medium, c.high, c.critical), "criticality", rising=True)
        _ordered((e.isolated, e.internal, e.partner, e.internet), "exposure", rising=True)
        _ordered(
            (d.public, d.internal, d.confidential, d.restricted), "data_classification", rising=True
        )
        _ordered((v.test, v.development, v.staging, v.production), "environment", rising=True)
        _ordered((t.p1, t.p2, t.p3), "thresholds", rising=False)
        if not t.p1 > t.p2 > t.p3 > 0:
            raise ValidationDomainError.single("thresholds", "not_strictly_decreasing")
        h = self.sla_hours
        _ordered((float(h.p1), float(h.p2), float(h.p3), float(h.p4)), "sla_hours", rising=True)
        return self


def risk_config_hash(config: RiskConfig) -> str:
    """Hash of the formula label and the whole risk configuration (canonical JSON)."""
    return compute_config_hash(
        name="risk", version=RISK_FORMULA_VERSION, payload=config.canonical_dict()
    )


@dataclass(frozen=True, slots=True)
class RiskInput:
    severity: TechnicalSeverity
    criticality: BusinessCriticality
    exposure: Exposure
    data_classification: DataClassification
    environment: Environment
    first_seen: datetime


@dataclass(frozen=True, slots=True)
class ExplanationLine:
    """One factor of the calculation: ``name`` and ``value`` are enum values/constants."""

    name: str
    value: str
    effect: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    priority: BusinessPriority
    factors: dict[str, float]  # what is stored in findings.risk_factors
    explanation: tuple[ExplanationLine, ...]
    sla_hours: int
    sla_due_at: datetime


def _fmt(number: float) -> str:
    return f"{number:g}"


def assess_risk(data: RiskInput, config: RiskConfig) -> RiskAssessment:
    """Compute score, priority, SLA due date and the explanation. Deterministic."""
    points = getattr(config.severity_points, TechnicalSeverity(data.severity).value)
    crit = getattr(config.criticality, BusinessCriticality(data.criticality).value)
    exposure = getattr(config.exposure, Exposure(data.exposure).value)
    classification = getattr(
        config.data_classification, DataClassification(data.data_classification).value
    )
    environment = getattr(config.environment, Environment(data.environment).value)
    raw = points * crit * exposure * classification * environment
    score = round(min(100.0, raw), 2)
    t = config.thresholds
    if score >= t.p1:
        priority, limit = BusinessPriority.P1, t.p1
    elif score >= t.p2:
        priority, limit = BusinessPriority.P2, t.p2
    elif score >= t.p3:
        priority, limit = BusinessPriority.P3, t.p3
    else:
        priority, limit = BusinessPriority.P4, None
    hours = getattr(config.sla_hours, priority.value)
    due = data.first_seen + timedelta(hours=hours)
    capped = " (capped at 100)" if raw > 100.0 else ""
    explanation = (
        ExplanationLine("severity", data.severity.value, f"{_fmt(points)} points"),
        ExplanationLine("asset_criticality", data.criticality.value, f"x{_fmt(crit)}"),
        ExplanationLine("exposure", data.exposure.value, f"x{_fmt(exposure)}"),
        ExplanationLine(
            "data_classification", data.data_classification.value, f"x{_fmt(classification)}"
        ),
        ExplanationLine("environment", data.environment.value, f"x{_fmt(environment)}"),
        ExplanationLine("risk_score", _fmt(score), f"{_fmt(raw)}{capped}".strip()),
        ExplanationLine(
            "priority",
            priority.value.upper(),
            f"score >= {_fmt(limit)}" if limit is not None else f"score < {_fmt(t.p3)}",
        ),
        ExplanationLine("sla", f"{hours}h", "due = first_seen + sla_hours"),
    )
    factors = {
        "severity_points": float(points),
        "criticality_weight": float(crit),
        "exposure_weight": float(exposure),
        "data_weight": float(classification),
        "environment_weight": float(environment),
        "risk_score": score,
        "sla_hours": float(hours),
    }
    return RiskAssessment(score, priority, factors, explanation, hours, due)
