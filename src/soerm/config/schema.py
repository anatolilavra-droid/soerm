"""Schema of the workspace configuration file ``soerm.yaml``.

::

    version: 1
    redaction:
      max_input_bytes: 65536          # 1024 .. 1048576
      builtin_rules:                  # optional: switch built-in rules off (or on) by name
        bearer: false
      rules:                          # optional custom rules, at most 32
        - name: employee_id           # [a-z][a-z0-9_]{0,47}, unique, not a built-in name
          pattern: '\\bEMP-\\d{6}\\b'    # restricted regular expression, see validate_pattern
          replacement: '[EMPLOYEE]'   # printable, at most 64 characters (default [REDACTED])
          enabled: true               # default true
          max_match_length: 64        # 1 .. 16384, default 1024

    imports:                          # limits of the local importers (M5), all optional
      max_import_file_bytes: 10485760   # 1024 .. 67108864
      max_records: 50000                # 1 .. 1000000
      max_json_depth: 64                # 2 .. 256
      max_field_bytes: 65536            # 64 .. 1048576
      max_csv_row_bytes: 262144         # 256 .. 4194304
      max_csv_columns: 64               # 1 .. 1024

    risk:                             # business risk model (M7), all parts optional
      severity_points: {none: 0, low: 15, medium: 35, high: 60, critical: 85}   # 0 .. 100
      criticality: {low: 0.8, medium: 1.0, high: 1.2, critical: 1.4}            # (0 .. 5]
      exposure: {internet: 1.3, partner: 1.1, internal: 1.0, isolated: 0.7}
      data_classification: {public: 0.9, internal: 1.0, confidential: 1.15, restricted: 1.3}
      environment: {production: 1.0, staging: 0.7, development: 0.5, test: 0.4}
      thresholds: {p1: 80, p2: 55, p3: 30}   # strictly decreasing minimum scores
      sla_hours: {p1: 72, p2: 336, p3: 720, p4: 2160}   # non-decreasing, 1 .. 87600

    approvals:                        # approval policy (M8)
      ttl_hours: 168                  # 1 .. 8760: time to decide (and to apply) a request
      require_distinct_approver: true # false allows self-approval (administrative decision)

    reports:                          # report generation (M10)
      allowed_output_dirs: []         # absolute directories outside the workspace that
                                      # `report generate --output` may write into (at most 8)
      top_findings: 10                # 1 .. 100 rows in "top" tables
      max_listed: 50                  # 1 .. 500 rows in overdue / incident / playbook lists

Unknown fields are rejected at every level. The risk weights must be monotonic (a more severe,
critical or exposed input never lowers the score).
"""

from typing import Annotated, Final

from pydantic import Field

from soerm.config.errors import ConfigError
from soerm.domain.approval import ApprovalPolicy
from soerm.domain.base import DomainModel
from soerm.domain.errors import DomainError
from soerm.domain.imports import ImportLimits
from soerm.domain.redaction import RedactionConfig
from soerm.domain.report import ReportPolicy
from soerm.domain.risk import RiskConfig

__all__ = ["CONFIG_VERSION", "SoermConfig", "parse_config"]

CONFIG_VERSION: Final = 1


class SoermConfig(DomainModel):
    """The whole configuration file."""

    version: Annotated[int, Field(strict=True, ge=1, le=1)]
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    imports: ImportLimits = Field(default_factory=ImportLimits)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    approvals: ApprovalPolicy = Field(default_factory=ApprovalPolicy)
    reports: ReportPolicy = Field(default_factory=ReportPolicy)


def parse_config(data: object) -> SoermConfig:
    """Validate parsed YAML. Raises :class:`ConfigError` with field names and rule codes only."""
    if not isinstance(data, dict):
        raise ConfigError("config_not_a_mapping")
    try:
        return SoermConfig.model_validate(data)
    except DomainError as exc:
        issues = tuple(
            f"{item.field or '<value>'}: {item.code}" for item in getattr(exc, "issues", ())[:10]
        )
        raise ConfigError("config_invalid", issues=issues) from None
