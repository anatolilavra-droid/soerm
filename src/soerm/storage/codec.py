"""Conversions between domain values and database columns."""

from datetime import datetime
from enum import StrEnum

from soerm.domain.errors import ValidationDomainError
from soerm.domain.timestamps import parse_timestamp, to_utc

__all__ = ["coerce_enum", "from_db_timestamp", "to_db_timestamp"]


def coerce_enum[E: StrEnum](enum_type: type[E], value: object, field: str) -> E:
    """Allowlist check for filters and sort orders. The error never echoes ``value``."""
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError:
            pass
    raise ValidationDomainError.single(field, "invalid_enum")


def to_db_timestamp(value: datetime) -> str:
    """Fixed-width UTC text ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` (27 characters).

    Unlike the canonical domain form it always carries the fraction, so the text sorts and
    compares correctly as a string and can be checked by a simple GLOB in the schema.
    """
    return to_utc(value).replace(tzinfo=None).isoformat(timespec="microseconds") + "Z"


def from_db_timestamp(text: str) -> datetime:
    """Parse a stored timestamp back into an aware UTC datetime."""
    return parse_timestamp(text)
