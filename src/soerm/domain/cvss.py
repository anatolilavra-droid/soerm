"""CVSS v4.0: strict vector parser, score calculation and the qualitative scale.

* The parser accepts only ``CVSS:4.0/`` vectors with every Base metric present, only known
  metrics and values, no duplicates and the metrics in the order of the specification. Optional
  metrics (Threat, Environmental, Supplemental) may be omitted or given as ``X``.
* The vector carries no score. The score is calculated here from the macro-vector tables of the
  FIRST specification (:mod:`soerm.domain.cvss4_data`) with the specification's severity-distance
  interpolation. The result is the score of the *whole* vector: CVSS-B, -BT, -BE or -BTE
  (:attr:`CvssV4Vector.nomenclature`).
* Supplemental metrics never change the score.

Pure functions; no I/O. Errors carry rule codes only and never echo the input.
"""

import math
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from itertools import product
from typing import Final

from soerm.domain.cvss4_data import LOOKUP, MAX_COMPOSED, MAX_SEVERITY
from soerm.domain.enums import TechnicalSeverity
from soerm.domain.errors import ValidationDomainError

__all__ = [
    "BASE_METRICS",
    "CvssV4Vector",
    "cvss_v4_score",
    "parse_cvss_v4",
    "severity_from_cvss_score",
]

PREFIX: Final = "CVSS:4.0/"
MAX_VECTOR_LENGTH: Final = 512
_EPSILON: Final = 10**-6

_NOT_DEFINED = ("X",)
_RATING = ("X", "H", "M", "L")
_IMPACT = ("H", "L", "N")
_MODIFIED_IMPACT = ("X", "H", "L", "N")
# (abbreviation, allowed values) in the order the specification requires.
_METRICS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("AV", ("N", "A", "L", "P")),
    ("AC", ("L", "H")),
    ("AT", ("N", "P")),
    ("PR", ("N", "L", "H")),
    ("UI", ("N", "P", "A")),
    ("VC", _IMPACT),
    ("VI", _IMPACT),
    ("VA", _IMPACT),
    ("SC", _IMPACT),
    ("SI", _IMPACT),
    ("SA", _IMPACT),
    ("E", ("X", "A", "P", "U")),
    ("CR", _RATING),
    ("IR", _RATING),
    ("AR", _RATING),
    ("MAV", ("X", "N", "A", "L", "P")),
    ("MAC", ("X", "L", "H")),
    ("MAT", ("X", "N", "P")),
    ("MPR", ("X", "N", "L", "H")),
    ("MUI", ("X", "N", "P", "A")),
    ("MVC", _MODIFIED_IMPACT),
    ("MVI", _MODIFIED_IMPACT),
    ("MVA", _MODIFIED_IMPACT),
    ("MSC", _MODIFIED_IMPACT),
    ("MSI", ("X", "S", "H", "L", "N")),
    ("MSA", ("X", "S", "H", "L", "N")),
    ("S", ("X", "N", "P")),
    ("AU", ("X", "N", "Y")),
    ("R", ("X", "A", "U", "I")),
    ("V", ("X", "D", "C")),
    ("RE", ("X", "L", "M", "H")),
    ("U", ("X", "Clear", "Green", "Amber", "Red")),
)
_ORDER: Final = {name: index for index, (name, _) in enumerate(_METRICS)}
_ALLOWED: Final = dict(_METRICS)
BASE_METRICS: Final = tuple(name for name, _ in _METRICS[:11])
_ENVIRONMENTAL: Final = frozenset(name for name, _ in _METRICS[12:26])

# severity levels (the smaller, the more severe) used by the distance interpolation
_LEVELS: Final = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_EQ1_METRICS: Final = ("AV", "PR", "UI")
_EQ2_METRICS: Final = ("AC", "AT")
_EQ36_METRICS: Final = ("VC", "VI", "VA", "CR", "IR", "AR")
_EQ4_METRICS: Final = ("SC", "SI", "SA")


def _bad(code: str) -> ValidationDomainError:
    return ValidationDomainError.single("", code)


@dataclass(frozen=True, slots=True)
class CvssV4Vector:
    """A parsed vector: the metrics as written (``X`` values dropped), in canonical order."""

    metrics: tuple[tuple[str, str], ...]

    def get(self, name: str) -> str:
        """Value of a metric, ``X`` when it is not defined."""
        return dict(self.metrics).get(name, "X")

    @property
    def vector(self) -> str:
        return PREFIX + "/".join(f"{name}:{value}" for name, value in self.metrics)

    @property
    def nomenclature(self) -> str:
        """``CVSS-B``, ``CVSS-BT``, ``CVSS-BE`` or ``CVSS-BTE``."""
        threat = self.get("E") != "X"
        environmental = any(name in _ENVIRONMENTAL and value != "X" for name, value in self.metrics)
        return "CVSS-B" + ("T" if threat else "") + ("E" if environmental else "")


def parse_cvss_v4(vector: object) -> CvssV4Vector:
    """Strictly parse a CVSS v4.0 vector string. Raises :class:`ValidationDomainError`."""
    if not isinstance(vector, str):
        raise _bad("invalid_cvss_vector")
    if not vector.startswith(PREFIX):
        raise _bad("invalid_cvss_prefix")
    if len(vector) > MAX_VECTOR_LENGTH or not vector.isascii():
        raise _bad("invalid_cvss_vector")
    seen: dict[str, str] = {}
    last_index = -1
    for part in vector[len(PREFIX) :].split("/"):
        name, separator, value = part.partition(":")
        if not separator or name not in _ALLOWED:
            raise _bad("cvss_unknown_metric")
        if name in seen:
            raise _bad("cvss_duplicate_metric")
        if value not in _ALLOWED[name]:
            raise _bad("cvss_invalid_value")
        if _ORDER[name] < last_index:
            raise _bad("cvss_metric_order")
        last_index = _ORDER[name]
        seen[name] = value
    if any(name not in seen for name in BASE_METRICS):
        raise _bad("cvss_missing_base_metric")
    return CvssV4Vector(tuple((n, v) for n, v in seen.items() if v != "X" or n in BASE_METRICS))


def _effective(parsed: CvssV4Vector) -> dict[str, str]:
    """Metric values after applying the Environmental overrides and the defaults of the
    specification (E=A, CR/IR/AR=H when not defined)."""
    values = {name: parsed.get(name) for name in BASE_METRICS}
    for name in BASE_METRICS:
        modified = parsed.get("M" + name)
        if modified != "X":
            values[name] = modified
    values["E"] = "A" if parsed.get("E") == "X" else parsed.get("E")
    for name in ("CR", "IR", "AR"):
        values[name] = "H" if parsed.get(name) == "X" else parsed.get(name)
    return values


def _macro_vector(m: dict[str, str]) -> str:
    av, pr, ui = m["AV"], m["PR"], m["UI"]
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if m["AC"] == "L" and m["AT"] == "N" else 1
    if m["VC"] == "H" and m["VI"] == "H":
        eq3 = 0
    elif "H" in (m["VC"], m["VI"], m["VA"]):
        eq3 = 1
    else:
        eq3 = 2
    if "S" in (m["SI"], m["SA"]):
        eq4 = 0
    elif "H" in (m["SC"], m["SI"], m["SA"]):
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m["E"]]
    high_requirement = (
        (m["CR"] == "H" and m["VC"] == "H")
        or (m["IR"] == "H" and m["VI"] == "H")
        or (m["AR"] == "H" and m["VA"] == "H")
    )
    eq6 = 0 if high_requirement else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _lower_macros(macro: str) -> tuple[str, str, tuple[str, ...], str, str]:
    eq = [int(char) for char in macro]

    def build(index: int, *extra: int) -> str:
        changed = list(eq)
        for position in (index, *extra):
            changed[position] += 1
        return "".join(map(str, changed))

    eq3, eq6 = eq[2], eq[5]
    both: tuple[str, ...]
    if eq6 == 1 and eq3 in {0, 1}:
        both = (build(2),)
    elif eq3 == 1 and eq6 == 0:
        both = (build(5),)
    elif eq3 == 0 and eq6 == 0:
        both = (build(5), build(2))
    else:
        both = (build(2, 5),)
    return build(0), build(1), both, build(3), build(4)


def _maximal_vectors(macro: str) -> list[dict[str, str]]:
    groups = [
        MAX_COMPOSED["eq1"][macro[0]],
        MAX_COMPOSED["eq2"][macro[1]],
        MAX_COMPOSED["eq3"][macro[2]][macro[5]],
        MAX_COMPOSED["eq4"][macro[3]],
        MAX_COMPOSED["eq5"][macro[4]],
    ]
    result: list[dict[str, str]] = []
    for parts in product(*groups):
        pairs = "".join(parts).rstrip("/").split("/")
        result.append(dict(pair.split(":") for pair in pairs))
    return result


def _distances(m: dict[str, str], maximal: dict[str, str]) -> dict[str, float]:
    return {
        name: round(_LEVELS[name][m[name]] - _LEVELS[name][maximal[name]], 10) for name in _LEVELS
    }


def _final_rounding(value: float) -> float:
    return float(Decimal(value + _EPSILON).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _lookup(macro: str) -> float:
    return LOOKUP.get(macro, math.nan)


def cvss_v4_score(parsed: CvssV4Vector) -> float:
    """The CVSS v4.0 score (0.0 - 10.0, one decimal) of a parsed vector."""
    m = _effective(parsed)
    if all(m[name] == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = _macro_vector(m)
    value = LOOKUP[macro]
    eq1_low, eq2_low, both_low, eq4_low, eq5_low = _lower_macros(macro)
    score_both = max(_lookup(key) for key in both_low)
    available = [
        value - _lookup(eq1_low),
        value - _lookup(eq2_low),
        value - score_both,
        value - _lookup(eq4_low),
        value - _lookup(eq5_low),
    ]
    distances: dict[str, float] = {}
    for maximal in _maximal_vectors(macro):
        distances = _distances(m, maximal)
        if all(distance >= 0 for distance in distances.values()):
            break  # the first maximal vector that is not less severe than the vector
    current = [
        sum(distances[name] for name in _EQ1_METRICS),
        sum(distances[name] for name in _EQ2_METRICS),
        sum(distances[name] for name in _EQ36_METRICS),
        sum(distances[name] for name in _EQ4_METRICS),
    ]
    step = 0.1
    maxima = [
        MAX_SEVERITY["eq1"][int(macro[0])] * step,
        MAX_SEVERITY["eq2"][int(macro[1])] * step,
        MAX_SEVERITY["eq3eq6"][int(macro[2])][int(macro[5])] * step,
        MAX_SEVERITY["eq4"][int(macro[3])] * step,
    ]
    existing = 0
    total = 0.0
    for index, room in enumerate(available):
        if room >= 0:  # False for NaN: that lower macro vector does not exist
            existing += 1
            if index < 4:
                total += room * (current[index] / maxima[index])
    mean_distance = 0.0 if existing == 0 else total / existing
    return _final_rounding(min(10.0, max(0.0, value - mean_distance)))


def severity_from_cvss_score(score: float) -> TechnicalSeverity:
    """Qualitative rating of a score: 0.0 none, 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high,
    9.0-10.0 critical."""
    value: object = score  # callers may pass anything at runtime
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationDomainError.single("cvss_score", "invalid_cvss_score")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationDomainError.single("cvss_score", "non_finite_number")
    if score < 0 or score > 10:
        raise ValidationDomainError.single("cvss_score", "cvss_score_out_of_range")
    if score == 0:
        return TechnicalSeverity.NONE
    if score < 4:
        return TechnicalSeverity.LOW
    if score < 7:
        return TechnicalSeverity.MEDIUM
    if score < 9:
        return TechnicalSeverity.HIGH
    return TechnicalSeverity.CRITICAL
