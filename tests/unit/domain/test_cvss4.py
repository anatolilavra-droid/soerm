"""CVSS v4.0: strict parser and score calculation.

``cvss4_golden.json`` holds vectors with scores produced by the FIRST reference algorithm
(RedHat's ``cvss`` library, run once outside the project); the project itself has no such
dependency.
"""

import json
from pathlib import Path

import pytest

from soerm.domain.cvss import (
    BASE_METRICS,
    cvss_v4_score,
    parse_cvss_v4,
    severity_from_cvss_score,
)
from soerm.domain.enums import TechnicalSeverity
from soerm.domain.errors import ValidationDomainError

GOLDEN = json.loads((Path(__file__).parent / "cvss4_golden.json").read_text(encoding="utf-8"))
BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def score(vector: str) -> float:
    return cvss_v4_score(parse_cvss_v4(vector))


@pytest.mark.parametrize(("vector", "expected"), GOLDEN)
def test_golden_scores_match_the_reference(vector: str, expected: float) -> None:
    assert score(vector) == expected


def test_known_scores() -> None:
    assert score(BASE) == 9.3  # the example of the FIRST specification
    assert score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N") == 0.0


def test_threat_environmental_and_supplemental_groups() -> None:
    assert parse_cvss_v4(BASE).nomenclature == "CVSS-B"
    assert parse_cvss_v4(BASE + "/E:P").nomenclature == "CVSS-BT"
    assert parse_cvss_v4(BASE + "/CR:L").nomenclature == "CVSS-BE"
    assert parse_cvss_v4(BASE + "/E:A/MAV:P").nomenclature == "CVSS-BTE"
    assert score(BASE + "/E:P") < score(BASE)  # proof-of-concept is less severe than attacked
    assert score(BASE + "/E:A") == score(BASE)  # attacked is the default
    assert score(BASE + "/MAV:P") < score(BASE)
    # supplemental metrics never change the score
    assert score(BASE + "/S:P/AU:Y/R:I/V:C/RE:H/U:Red") == score(BASE)
    assert parse_cvss_v4(BASE + "/E:X/CR:X").nomenclature == "CVSS-B"


def test_explicit_not_defined_equals_omitted() -> None:
    assert score(BASE + "/E:X/CR:X/MAV:X") == score(BASE)


def test_parser_roundtrip_keeps_the_text() -> None:
    parsed = parse_cvss_v4(BASE + "/E:P/S:N")
    assert parsed.vector == BASE + "/E:P/S:N"
    assert parsed.get("E") == "P"
    assert parsed.get("CR") == "X"


@pytest.mark.parametrize(
    ("vector", "code"),
    [
        ("", "invalid_cvss_prefix"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "invalid_cvss_prefix"),
        ("cvss:4.0/AV:N", "invalid_cvss_prefix"),
        ("AV:N/AC:L", "invalid_cvss_prefix"),
        (BASE + "/", "cvss_unknown_metric"),
        (BASE.replace("/SA:N", ""), "cvss_missing_base_metric"),
        (BASE + "/AV:N", "cvss_duplicate_metric"),
        (BASE.replace("AV:N", "AV:Z"), "cvss_invalid_value"),
        (BASE.replace("AV:N", "AV:n"), "cvss_invalid_value"),
        (BASE.replace("SI:N", "SI:S"), "cvss_invalid_value"),  # S only exists for modified SI
        (BASE + "/ZZ:N", "cvss_unknown_metric"),
        (BASE + "/E", "cvss_unknown_metric"),
        (BASE + "/E:", "cvss_invalid_value"),
        (BASE + "//E:P", "cvss_unknown_metric"),
        (BASE + "/E:P/AV:N", "cvss_duplicate_metric"),
        (BASE + "/CR:H/E:P", "cvss_metric_order"),
        (BASE.replace("AV:N/AC:L", "AC:L/AV:N"), "cvss_metric_order"),
        (BASE + "/E:P ", "cvss_invalid_value"),
        (BASE + "\n", "cvss_invalid_value"),
        (BASE + "/" + chr(0x415) + ":P", "invalid_cvss_vector"),
        (BASE + "/" + "E:P/" * 300, "invalid_cvss_vector"),
        (None, "invalid_cvss_vector"),
        (5, "invalid_cvss_vector"),
    ],
)
def test_parser_rejects(vector: object, code: str) -> None:
    with pytest.raises(ValidationDomainError) as caught:
        parse_cvss_v4(vector)
    assert [issue.code for issue in caught.value.issues] == [code]


def test_errors_never_echo_the_input() -> None:
    secret = "hunter2-SECRET"
    with pytest.raises(ValidationDomainError) as caught:
        parse_cvss_v4(f"CVSS:4.0/{secret}:N")
    assert secret not in repr(caught.value) + str(caught.value)


def test_all_base_metrics_are_required() -> None:
    assert len(BASE_METRICS) == 11
    for name in BASE_METRICS:
        parts = [
            p for p in BASE.removeprefix("CVSS:4.0/").split("/") if not p.startswith(name + ":")
        ]
        with pytest.raises(ValidationDomainError):
            parse_cvss_v4("CVSS:4.0/" + "/".join(parts))


def test_score_is_in_range_with_one_decimal_and_ordered_by_impact() -> None:
    high = score(BASE)
    lower = score(BASE.replace("VC:H/VI:H/VA:H", "VC:L/VI:L/VA:L"))
    none = score(BASE.replace("VC:H/VI:H/VA:H", "VC:N/VI:N/VA:N"))
    assert high > lower > none == 0.0
    for vector, _ in GOLDEN:
        value = score(vector)
        assert 0.0 <= value <= 10.0
        assert round(value, 1) == value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, TechnicalSeverity.NONE),
        (0.1, TechnicalSeverity.LOW),
        (3.9, TechnicalSeverity.LOW),
        (4.0, TechnicalSeverity.MEDIUM),
        (6.9, TechnicalSeverity.MEDIUM),
        (7.0, TechnicalSeverity.HIGH),
        (8.9, TechnicalSeverity.HIGH),
        (9.0, TechnicalSeverity.CRITICAL),
        (10.0, TechnicalSeverity.CRITICAL),
    ],
)
def test_qualitative_scale(value: float, expected: TechnicalSeverity) -> None:
    assert severity_from_cvss_score(value) is expected
