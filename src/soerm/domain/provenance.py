"""Provenance of imported data: where and when a finding was observed."""

import unicodedata
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator

from soerm.domain.base import DomainModel
from soerm.domain.errors import ValidationDomainError
from soerm.domain.hashing import Sha256
from soerm.domain.identifiers import RunId
from soerm.domain.text import normalize_text
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["Location", "Occurrence", "Provenance", "RelativePath"]

_MAX_PATH_LENGTH = 1024


def _relative_path(value: object) -> str:
    """A workspace-relative POSIX path as a pure string check (no filesystem access)."""
    if not isinstance(value, str) or not value or len(value) > _MAX_PATH_LENGTH:
        raise ValidationDomainError.single("", "unsafe_path")
    text = unicodedata.normalize("NFC", value)
    if any(unicodedata.category(char)[0] in {"C", "Z"} and char != " " for char in text):
        raise ValidationDomainError.single("", "unsafe_path")
    parts = text.split("/")
    if text.startswith("/") or "\\" in text or any(p in {"", ".", ".."} for p in parts):
        raise ValidationDomainError.single("", "unsafe_path")
    return text


def _location(value: object) -> str:
    return normalize_text(value)


def _max_512(text: str) -> str:
    if len(text) > 512:
        raise ValidationDomainError.single("", "text_too_long")
    return text


RelativePath = Annotated[str, BeforeValidator(_relative_path)]
Location = Annotated[str, BeforeValidator(_location), AfterValidator(_max_512)]


class Provenance(DomainModel):
    """Which import run and which file a record came from."""

    import_run_id: RunId
    file_sha256: Sha256
    source_path: RelativePath
    observed_at: UtcTimestamp


class Occurrence(Provenance):
    """One observation of a finding, with the location inside the source file."""

    location: Location | None = None
