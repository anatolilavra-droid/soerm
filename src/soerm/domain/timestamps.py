"""UTC-aware timestamps. Stored and serialized as ISO-8601 UTC with a ``Z`` suffix."""

from datetime import UTC, datetime
from typing import Annotated

from pydantic import BeforeValidator, PlainSerializer

from soerm.domain.errors import InvalidTimestampError

__all__ = ["UtcTimestamp", "format_timestamp", "parse_timestamp", "to_utc"]

_MAX_TIMESTAMP_TEXT = 40


def to_utc(value: datetime, *, field: str = "") -> datetime:
    """Convert an aware datetime to UTC. Naive datetimes are rejected."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise InvalidTimestampError.single(field, "naive_timestamp")
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise InvalidTimestampError.single(field, "timestamp_out_of_range") from None


def parse_timestamp(text: str, *, field: str = "") -> datetime:
    """Parse an ISO-8601 string that carries a UTC offset (``Z`` or ``+hh:mm``)."""
    if len(text) > _MAX_TIMESTAMP_TEXT:
        raise InvalidTimestampError.single(field, "invalid_timestamp")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise InvalidTimestampError.single(field, "invalid_timestamp") from None
    return to_utc(parsed, field=field)


def format_timestamp(value: datetime) -> str:
    """Canonical text form: ``YYYY-MM-DDTHH:MM:SS[.ffffff]Z`` (fraction only when non-zero)."""
    utc = to_utc(value)
    naive = utc.replace(tzinfo=None)
    return naive.isoformat(timespec="microseconds" if utc.microsecond else "seconds") + "Z"


def _coerce(value: object) -> datetime:
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, str):
        return parse_timestamp(value)
    raise InvalidTimestampError.single("", "invalid_timestamp")


UtcTimestamp = Annotated[
    datetime,
    BeforeValidator(_coerce),
    PlainSerializer(format_timestamp, return_type=str),
]
