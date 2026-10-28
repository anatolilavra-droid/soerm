"""Finding model.

The model validates shape and the CVSS v4.0 vector syntax (strictly, M7). It neither calculates
a CVSS score nor a business priority itself (see ``soerm.domain.cvss`` and ``soerm.domain.risk``)
and performs no redaction.
"""

import math
import re
from typing import Annotated, Final, Literal, Self

from pydantic import BeforeValidator, Field, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.cvss import parse_cvss_v4
from soerm.domain.enums import BusinessPriority, FindingStatus, ImportSource, TechnicalSeverity
from soerm.domain.errors import ValidationDomainError
from soerm.domain.hashing import Sha256
from soerm.domain.identifiers import AssetId, FindingId, VersionLabel
from soerm.domain.text import Evidence, LongText, Name, Title
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["CVSS_V4_PREFIX", "CvssScore", "CvssVector", "Finding", "RiskFactors"]

CVSS_V4_PREFIX: Final = "CVSS:4.0/"
_FACTOR_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MAX_FACTORS = 32
_FACTOR_LIMIT = 1_000_000.0


def _cvss_vector(value: object) -> str:
    """Strict CVSS v4.0 syntax (every Base metric, known values, specification order)."""
    parse_cvss_v4(value)
    assert isinstance(value, str)  # noqa: S101 - narrowed by the parser
    return value


def _cvss_score(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationDomainError.single("", "invalid_cvss_score")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationDomainError.single("", "non_finite_number")
    if value < 0 or value > 10:
        raise ValidationDomainError.single("", "cvss_score_out_of_range")
    return float(value) + 0.0  # -0.0 becomes 0.0


def _risk_factors(value: object) -> dict[str, float]:
    if not isinstance(value, dict) or len(value) > _MAX_FACTORS:
        raise ValidationDomainError.single("", "invalid_risk_factors")
    result: dict[str, float] = {}
    for key in sorted(value, key=str):
        number = value[key]
        if not isinstance(key, str) or _FACTOR_NAME.fullmatch(key) is None:
            raise ValidationDomainError.single("", "invalid_risk_factor_name")
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise ValidationDomainError.single("", "invalid_risk_factor_value")
        if isinstance(number, float) and not math.isfinite(number):
            raise ValidationDomainError.single("", "non_finite_number")
        if abs(number) > _FACTOR_LIMIT:
            raise ValidationDomainError.single("", "risk_factor_out_of_range")
        result[key] = float(number) + 0.0
    return result


CvssVector = Annotated[str, BeforeValidator(_cvss_vector)]
CvssScore = Annotated[float, BeforeValidator(_cvss_score)]
RiskFactors = Annotated[dict[str, float], BeforeValidator(_risk_factors)]


class Finding(DomainModel):
    finding_id: FindingId
    fingerprint: Sha256
    title: Title
    description: LongText = ""
    asset_id: AssetId
    source: ImportSource
    evidence: Evidence = ""
    cvss_version: Literal["4.0"] | None = None
    cvss_vector: CvssVector | None = None
    cvss_score: CvssScore | None = None
    cvss_score_source: Literal["imported"] | None = None
    technical_severity: TechnicalSeverity
    business_priority: BusinessPriority | None = None
    risk_factors: RiskFactors = Field(default_factory=dict)
    risk_formula_version: VersionLabel | None = None
    risk_config_hash: Sha256 | None = None
    status: FindingStatus = FindingStatus.OPEN
    owner: Name | None = None
    sla_due_at: UtcTimestamp | None = None
    first_seen: UtcTimestamp
    last_seen: UtcTimestamp
    created_at: UtcTimestamp
    updated_at: UtcTimestamp

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.cvss_vector is not None and self.cvss_version != "4.0":
            raise ValidationDomainError.single("cvss_version", "required_with_vector")
        if self.cvss_score is not None and self.cvss_score_source != "imported":
            raise ValidationDomainError.single("cvss_score_source", "required_with_score")
        if self.cvss_score is None and self.cvss_score_source is not None:
            raise ValidationDomainError.single("cvss_score", "required_with_score_source")
        if self.technical_severity is TechnicalSeverity.NONE and self.cvss_score != 0.0:
            raise ValidationDomainError.single("technical_severity", "none_requires_zero_score")
        if self.last_seen < self.first_seen:
            raise ValidationDomainError.single("last_seen", "before_first_seen")
        if self.updated_at < self.created_at:
            raise ValidationDomainError.single("updated_at", "before_created_at")
        return self
