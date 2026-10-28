"""Configuration errors. Messages hold constants and field names only - never file content."""

from typing import ClassVar

from soerm.domain.errors import DomainError

__all__ = ["ConfigError"]


class ConfigError(DomainError):
    """The configuration file is missing, unsafe, too large, malformed or invalid."""

    code: ClassVar[str] = "config_error"

    def __init__(self, reason: str, *, issues: tuple[str, ...] = ()) -> None:
        self.reason = reason
        self.issues = issues
        detail = f"; {'; '.join(issues)}" if issues else ""
        super().__init__(f"configuration rejected ({reason}{detail})", reason=reason)
