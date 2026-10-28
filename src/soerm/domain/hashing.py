"""SHA-256 helpers, canonical JSON and versioned configuration hashes."""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Annotated, Final

from pydantic import BeforeValidator

from soerm.domain.errors import ValidationDomainError

__all__ = [
    "CONFIG_HASH_SCHEME",
    "Sha256",
    "canonical_json",
    "compute_config_hash",
    "hash_canonical",
    "is_sha256",
    "sha256_hex",
]

CONFIG_HASH_SCHEME: Final = "soerm-config-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_DEPTH = 32


def is_sha256(value: object) -> bool:
    """True for a lowercase hex SHA-256 string."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _validate_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValidationDomainError.single("", "invalid_sha256")
    return value


Sha256 = Annotated[str, BeforeValidator(_validate_sha256)]


def sha256_hex(data: bytes | str) -> str:
    """Lowercase hex SHA-256 of bytes, or of a string encoded as UTF-8."""
    if isinstance(data, str):
        try:
            data = data.encode("utf-8")
        except UnicodeEncodeError:
            raise ValidationDomainError.single("", "invalid_character") from None
    return hashlib.sha256(data).hexdigest()


def _check(value: object, depth: int) -> object:
    if depth > _MAX_DEPTH:
        raise ValidationDomainError.single("", "structure_too_deep")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationDomainError.single("", "non_finite_number")
        return value + 0.0  # turns -0.0 into 0.0
    if isinstance(value, (list, tuple)):
        return [_check(item, depth + 1) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationDomainError.single("", "non_string_key")
            result[key] = _check(item, depth + 1)
        return result
    raise ValidationDomainError.single("", "unsupported_type")


def canonical_json(value: object) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only, finite numbers only.

    Accepts ``None``, ``bool``, ``int``, finite ``float``, ``str``, lists/tuples and mappings
    with string keys. ``1`` and ``1.0`` serialize differently; datetimes must be formatted by
    the caller first.
    """
    return json.dumps(
        _check(value, 0),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def hash_canonical(value: object) -> str:
    """SHA-256 of the canonical JSON of ``value``."""
    return sha256_hex(canonical_json(value))


def compute_config_hash(*, name: str, version: str, payload: Mapping[str, object]) -> str:
    """Versioned hash of an already validated configuration structure.

    The hash covers a scheme tag, the configuration name and version, and the canonical
    JSON of the payload, so identical payloads under different names or versions differ.
    """
    return hash_canonical(
        {"scheme": CONFIG_HASH_SCHEME, "name": name, "version": version, "payload": payload}
    )
