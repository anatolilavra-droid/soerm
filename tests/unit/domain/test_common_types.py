"""Text normalization, timestamps, identifiers, hashing and canonical JSON."""
# ruff: noqa: RUF001  (look-alike characters are the point of these tests)

import math
from datetime import UTC, datetime, timedelta, timezone

import pytest

from soerm.domain import (
    InvalidIdentifierError,
    InvalidTimestampError,
    ValidationDomainError,
    canonical_json,
    compute_config_hash,
    format_timestamp,
    hash_canonical,
    parse_timestamp,
    sha256_hex,
)
from soerm.domain.identifiers import check_identifier, format_identifier
from soerm.domain.text import (
    EVIDENCE_MAX_BYTES,
    normalize_actor,
    normalize_tag,
    normalize_text,
    utf8_length,
)
from soerm.domain.timestamps import to_utc

# ---- text ---------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "   ", "\t\n", "​", "   ", "\x00\x01"])
def test_blank_required_text_is_rejected(value: str) -> None:
    from soerm.domain import Asset

    from .factories import asset_data

    with pytest.raises(ValidationDomainError) as excinfo:
        Asset(**asset_data(name=value))
    assert [i.code for i in excinfo.value.issues] == ["empty_text"]
    assert excinfo.value.issues[0].field == "name"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\tb\nc\rd", "a b c d"),
        ("  many   spaces  ", "many spaces"),
        ("nul\x00inside", "nul inside"),
        ("esc\x1b[31mred", "esc [31mred"),
        ("tab para", "tab para"),
        ("no break", "no break"),
        ("bidi‮evil‬", "bidievil"),
        ("zero​width﻿", "zerowidth"),
        ("é", "é"),  # NFC composition
    ],
)
def test_control_characters_are_normalized(raw: str, expected: str) -> None:
    assert normalize_text(raw) == expected


def test_multiline_keeps_newlines_and_indentation() -> None:
    raw = "\n\nline1  \r\n    indented\rline3\x00x\n\n"
    assert normalize_text(raw, multiline=True) == "line1\n    indented\nline3 x"


def test_lone_surrogate_is_rejected() -> None:
    with pytest.raises(ValidationDomainError):
        normalize_text("bad\ud800")


@pytest.mark.parametrize("value", [None, 5, b"bytes", ["a"], 1.5])
def test_non_string_is_rejected(value: object) -> None:
    with pytest.raises(ValidationDomainError):
        normalize_text(value)


def test_utf8_length_counts_bytes() -> None:
    assert utf8_length("a") == 1
    assert utf8_length("é") == 2
    assert utf8_length("€") == 3
    assert EVIDENCE_MAX_BYTES == 4096


def test_actor_normalization_folds_case_and_width() -> None:
    assert normalize_actor("  Alice ") == "alice"
    assert normalize_actor("ＡＬＩＣＥ") == "alice"  # full-width
    assert normalize_actor("a.b@example+x-y") == "a.b@example+x-y"


@pytest.mark.parametrize("value", ["", "al ice", "аlice", "-alice", "a" * 129, "al/ice", 5])
def test_actor_rejects_unsafe_values(value: object) -> None:
    with pytest.raises(ValidationDomainError):
        normalize_actor(value)


def test_tag_normalization() -> None:
    assert normalize_tag("  Prod  DB ") == "prod-db"
    with pytest.raises(ValidationDomainError):
        normalize_tag("x" * 65)


# ---- timestamps ---------------------------------------------------------------------------


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(InvalidTimestampError) as excinfo:
        to_utc(datetime(2026, 1, 1))  # noqa: DTZ001
    assert excinfo.value.issues[0].code == "naive_timestamp"


def test_aware_datetime_is_converted_to_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    result = to_utc(datetime(2026, 1, 1, 12, 0, tzinfo=plus_two))
    assert result == datetime(2026, 1, 1, 10, 0, tzinfo=UTC)
    assert result.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "2026-01-02T03:04:05Z"),
        (datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC), "2026-01-02T03:04:05.123456Z"),
        (
            datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2))),
            "2026-01-02T03:04:05Z",
        ),
    ],
)
def test_timestamp_format_is_utc_with_z(value: datetime, text: str) -> None:
    assert format_timestamp(value) == text
    assert parse_timestamp(text) == value


@pytest.mark.parametrize("text", ["2026-01-01T00:00:00", "2026-01-01", "yesterday", "", "x" * 50])
def test_parse_timestamp_rejects_naive_and_malformed(text: str) -> None:
    with pytest.raises(InvalidTimestampError):
        parse_timestamp(text)


def test_timestamp_error_does_not_echo_value() -> None:
    with pytest.raises(InvalidTimestampError) as excinfo:
        parse_timestamp("TOKEN-hunter2")
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value.to_dict())


# ---- identifiers --------------------------------------------------------------------------


def test_identifier_format() -> None:
    assert format_identifier("AST", 1) == "AST-000001"
    assert format_identifier("INC", 1234567) == "INC-1234567"
    assert check_identifier("AST", "AST-000001") == "AST-000001"


@pytest.mark.parametrize(
    "value",
    ["AST-1", "ast-000001", "FND-000001", "AST-00000a", "AST-١٢٣٤٥٦",
     "AST-000001\n", " AST-000001", "AST-0000000000000", None, 1],
)  # fmt: skip
def test_invalid_identifiers(value: object) -> None:
    with pytest.raises(InvalidIdentifierError):
        check_identifier("AST", value)


@pytest.mark.parametrize(("prefix", "number"), [("AST", 0), ("AST", -1), ("XXX", 1), ("AST", True)])
def test_format_identifier_rejects_bad_input(prefix: str, number: int) -> None:
    with pytest.raises(InvalidIdentifierError):
        format_identifier(prefix, number)


# ---- hashing and canonical JSON -----------------------------------------------------------


def test_sha256_matches_known_vector() -> None:
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex(b"abc") == sha256_hex("abc")


def test_canonical_json_is_deterministic() -> None:
    first = {"b": 1, "a": [1, 2, {"z": None, "y": True}], "c": "é"}
    second = {"c": "é", "a": [1, 2, {"y": True, "z": None}], "b": 1}
    assert canonical_json(first) == canonical_json(second)
    assert canonical_json(first) == '{"a":[1,2,{"y":true,"z":null}],"b":1,"c":"\\u00e9"}'
    assert hash_canonical(first) == hash_canonical(second)
    assert canonical_json((1, 2)) == canonical_json([1, 2])


def test_canonical_json_normalizes_negative_zero() -> None:
    assert canonical_json({"v": -0.0}) == canonical_json({"v": 0.0})


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_floats_are_rejected(value: float) -> None:
    with pytest.raises(ValidationDomainError):
        canonical_json({"v": value})
    with pytest.raises(ValidationDomainError):
        canonical_json([value])


@pytest.mark.parametrize(
    "value", [{1: "a"}, {"a": {1, 2}}, {"a": datetime(2026, 1, 1, tzinfo=UTC)}, object()]
)
def test_canonical_json_rejects_unsupported(value: object) -> None:
    with pytest.raises(ValidationDomainError):
        canonical_json(value)


def test_canonical_json_rejects_deep_nesting() -> None:
    value: object = "x"
    for _ in range(40):
        value = [value]
    with pytest.raises(ValidationDomainError):
        canonical_json(value)


def test_config_hash_is_versioned_and_deterministic() -> None:
    payload = {"weights": {"a": 1, "b": 2}}
    base = compute_config_hash(name="risk", version="1", payload=payload)
    assert base == compute_config_hash(
        name="risk", version="1", payload={"weights": {"b": 2, "a": 1}}
    )
    assert base != compute_config_hash(name="risk", version="2", payload=payload)
    assert base != compute_config_hash(name="sla", version="1", payload=payload)
    assert base != compute_config_hash(
        name="risk", version="1", payload={"weights": {"a": 1, "b": 3}}
    )
    assert len(base) == 64
