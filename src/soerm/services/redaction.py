"""Redaction in the service layer: every text value passes through here before storage.

Flow per value: raw text -> normalize -> redact -> shorten the *redacted* result to the field
limit -> domain validation -> storage. The report that comes back holds rule names, counts,
field names and the configuration hash - never a matched value.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from soerm.config import ConfigError, SoermConfig, load_config
from soerm.domain.errors import ValidationDomainError
from soerm.domain.redaction import RedactionError, Redactor, build_policy
from soerm.domain.risk import risk_config_hash
from soerm.domain.text import EVIDENCE_MAX_BYTES
from soerm.services.errors import ConfigServiceError, InvalidInputError, NotFoundServiceError
from soerm.services.workspace import Workspace

__all__ = [
    "FIELD_LIMITS",
    "FieldRedactor",
    "RedactionReport",
    "load_redactor",
    "validate_workspace_config",
]

# field kind -> (max characters, max UTF-8 bytes); the domain limits are the same numbers.
FIELD_LIMITS: Final = {
    "name": (200, None),
    "title": (300, None),
    "text": (8000, None),
    "tag": (64, None),
    "evidence": (None, EVIDENCE_MAX_BYTES),
    "location": (500, None),
    "hint": (200, None),
    "reason": (500, None),
}


@dataclass(frozen=True, slots=True)
class RedactionReport:
    """Metadata of one operation. No matched values, no text."""

    config_hash: str
    rule_hits: tuple[tuple[str, int], ...]
    truncated_fields: tuple[str, ...]

    @property
    def total_hits(self) -> int:
        return sum(count for _, count in self.rule_hits)


@dataclass(frozen=True, slots=True)
class ConfigSummary:
    """What ``config validate`` shows: no patterns, no replacements, no values."""

    file_found: bool
    config_hash: str
    max_input_bytes: int
    rules: tuple[tuple[str, bool, bool], ...]  # name, enabled, built-in
    risk_config_hash: str = ""


def _config_error(exc: ConfigError) -> ConfigServiceError:
    """Field names and rule codes are safe to show: they help fix the file, hold no values."""
    reason = exc.reason if not exc.issues else f"{exc.reason}: {'; '.join(exc.issues)}"
    return ConfigServiceError(reason[:300], issues=len(exc.issues))


def load_redactor(workspace_path: Path) -> Redactor:
    """The redactor configured in ``<workspace>/soerm.yaml`` (built-in rules if absent)."""
    try:
        config, _ = load_config(workspace_path)
        return Redactor(build_policy(config.redaction))
    except ConfigError as exc:
        raise _config_error(exc) from None
    except ValidationDomainError as exc:
        raise ConfigServiceError("redactor_invalid", issues=len(exc.issues)) from None


def load_runtime(workspace_path: Path) -> tuple[SoermConfig, Redactor]:
    """The whole configuration and the redactor built from it."""
    try:
        config, _ = load_config(workspace_path)
        return config, Redactor(build_policy(config.redaction))
    except ConfigError as exc:
        raise _config_error(exc) from None
    except ValidationDomainError as exc:
        raise ConfigServiceError("redactor_invalid", issues=len(exc.issues)) from None


def validate_workspace_config(workspace: Workspace) -> ConfigSummary:
    """Read and check the configuration only. Creates no database and no lock."""
    if not workspace.path.is_dir():
        raise NotFoundServiceError("workspace_missing", object_type="workspace")
    try:
        config, found = load_config(workspace.path)
        redactor = Redactor(build_policy(config.redaction))
    except ConfigError as exc:
        raise _config_error(exc) from None
    except ValidationDomainError as exc:
        raise ConfigServiceError("redactor_invalid", issues=len(exc.issues)) from None
    policy = redactor.policy
    rules = tuple((rule.name, rule.enabled, rule.builtin) for rule in policy.rules)
    return ConfigSummary(
        found, policy.config_hash, policy.max_input_bytes, rules, risk_config_hash(config.risk)
    )


class FieldRedactor:
    """Redacts the fields of one operation and accumulates the report."""

    def __init__(self, redactor: Redactor) -> None:
        self._redactor = redactor
        self._hits: dict[str, int] = {}
        self._truncated: list[str] = []

    def field(self, name: str, value: object, kind: str) -> str:
        """Redacted, length-limited text of one field. ``name`` is a constant field name."""
        max_chars, max_bytes = FIELD_LIMITS[kind]
        try:
            result = self._redactor.redact(value, max_chars=max_chars, max_bytes=max_bytes)
        except RedactionError as exc:
            raise InvalidInputError("; ".join(f"{name}: {i.code}" for i in exc.issues)) from None
        for rule, count in result.hits:
            self._hits[rule] = self._hits.get(rule, 0) + count
        if result.was_truncated:
            self._truncated.append(name)
        return result.text

    def optional(self, name: str, value: object, kind: str) -> str | None:
        return None if value is None else self.field(name, value, kind)

    def report(self) -> RedactionReport:
        order = {rule.name: index for index, rule in enumerate(self._redactor.policy.rules)}
        hits = tuple(sorted(self._hits.items(), key=lambda item: order[item[0]]))
        return RedactionReport(self._redactor.config_hash, hits, tuple(self._truncated))
