"""Import run model and the finding fingerprint (M6).

The fingerprint is the *identity* of a finding across imports. It is computed by SOERM from
normalized, already redacted fields and a scheme label::

    sha256(canonical_json({scheme, source, asset_id, rule, title, location}))

* ``asset_id`` is part of the identity: the same defect on two assets is two findings.
* ``rule`` is the source's rule/check id when it has one. With a rule id the title is *not*
  part of the identity (tools reword titles between versions); without one the normalized
  title is.
* ``location`` is the normalized location text (file/line/URL as the source states it).
* Fingerprints the source supplies (SARIF ``partialFingerprints``) are never used here; they
  are kept as provenance hints only. A changed scheme label changes every fingerprint, so a
  future scheme must ship with a migration.

No I/O, no randomness, no clock: the same input always yields the same fingerprint.
"""

import unicodedata
from typing import Annotated, Final

from pydantic import Field

from soerm.domain.base import DomainModel
from soerm.domain.enums import ImportSource
from soerm.domain.hashing import Sha256, hash_canonical
from soerm.domain.identifiers import RunId
from soerm.domain.provenance import RelativePath
from soerm.domain.timestamps import UtcTimestamp

__all__ = ["FINGERPRINT_SCHEME", "ImportRun", "compute_fingerprint"]

FINGERPRINT_SCHEME: Final = "soerm-fingerprint-v1"


def _identity_text(value: str | None) -> str | None:
    """NFKC + casefold + collapsed whitespace; ``None`` for empty text."""
    if value is None:
        return None
    text = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
    return text or None


def compute_fingerprint(
    *,
    source: ImportSource,
    asset_id: str,
    title: str,
    external_rule_id: str | None = None,
    location: str | None = None,
) -> str:
    """Stable identity of a finding. See the module docstring for the recipe."""
    rule = _identity_text(external_rule_id)
    return hash_canonical(
        {
            "scheme": FINGERPRINT_SCHEME,
            "source": ImportSource(source).value,
            "asset_id": asset_id,
            "rule": rule,
            "title": _identity_text(title) if rule is None else None,
            "location": _identity_text(location),
        }
    )


class ImportRun(DomainModel):
    """One applied import: the file (by hash and workspace-relative path) and its size."""

    run_id: RunId
    source: ImportSource
    file_sha256: Sha256
    source_path: RelativePath
    imported_at: UtcTimestamp
    record_count: Annotated[int, Field(strict=True, ge=0, le=1_000_000)]
