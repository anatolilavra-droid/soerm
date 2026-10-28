"""Identifier formats. Server-assigned ids look like ``AST-000001`` (prefix, dash, 6+ digits)."""

import re
from collections.abc import Callable
from typing import Annotated, Final

from pydantic import BeforeValidator

from soerm.domain.errors import InvalidIdentifierError, ValidationDomainError

__all__ = [
    "ActionName",
    "AssetId",
    "ChangeId",
    "FindingId",
    "IncidentId",
    "ObjectId",
    "PlaybookId",
    "RunId",
    "Slug",
    "TaskId",
    "VersionLabel",
    "check_identifier",
    "format_identifier",
]

PREFIXES: Final = frozenset({"AST", "FND", "INC", "TSK", "CHG", "RUN", "PBK"})
_MAX_NUMBER = 10**12 - 1

_SLUG = re.compile(r"[a-z][a-z0-9_-]{1,63}")
_ACTION = re.compile(r"[a-z][a-z0-9_.]{1,63}")
_OBJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,31}")


def check_identifier(prefix: str, value: object, *, field: str = "") -> str:
    """Return ``value`` if it is ``<prefix>-<6..12 ASCII digits>``; otherwise raise."""
    if (
        prefix not in PREFIXES
        or not isinstance(value, str)
        or re.fullmatch(prefix + r"-[0-9]{6,12}", value) is None
    ):
        raise InvalidIdentifierError.single(field, "invalid_identifier")
    return value


def format_identifier(prefix: str, number: int) -> str:
    """Build an identifier such as ``AST-000001`` from a positive number."""
    if prefix not in PREFIXES or isinstance(number, bool) or not 1 <= number <= _MAX_NUMBER:
        raise InvalidIdentifierError.single("", "invalid_identifier")
    return f"{prefix}-{number:06d}"


def _id_validator(prefix: str) -> Callable[[object], str]:
    def validate(value: object) -> str:
        return check_identifier(prefix, value)

    return validate


def _pattern_validator(
    pattern: re.Pattern[str], rule: str, *, identifier: bool = False
) -> Callable[[object], str]:
    def validate(value: object) -> str:
        if isinstance(value, str) and pattern.fullmatch(value):
            return value
        if identifier:
            raise InvalidIdentifierError.single("", rule)
        raise ValidationDomainError.single("", rule)

    return validate


AssetId = Annotated[str, BeforeValidator(_id_validator("AST"))]
FindingId = Annotated[str, BeforeValidator(_id_validator("FND"))]
IncidentId = Annotated[str, BeforeValidator(_id_validator("INC"))]
TaskId = Annotated[str, BeforeValidator(_id_validator("TSK"))]
ChangeId = Annotated[str, BeforeValidator(_id_validator("CHG"))]
RunId = Annotated[str, BeforeValidator(_id_validator("RUN"))]

# Human-chosen ids (playbooks come from configuration, so they are slugs, not numbers).
PlaybookId = Annotated[
    str, BeforeValidator(_pattern_validator(_SLUG, "invalid_identifier", identifier=True))
]
# Generic ids: roles, step ids, object types, audit actions, audited object ids, versions.
Slug = Annotated[str, BeforeValidator(_pattern_validator(_SLUG, "invalid_slug"))]
ActionName = Annotated[str, BeforeValidator(_pattern_validator(_ACTION, "invalid_action"))]
ObjectId = Annotated[
    str, BeforeValidator(_pattern_validator(_OBJECT_ID, "invalid_identifier", identifier=True))
]
VersionLabel = Annotated[str, BeforeValidator(_pattern_validator(_VERSION, "invalid_version"))]
