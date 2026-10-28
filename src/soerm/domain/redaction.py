"""Redaction: removal of secrets and PII from text before it is stored, hashed or printed.

Flow for every text value::

    raw text -> normalize -> redact -> length-limit the redacted result -> persist that only

This module is pure (no YAML, no files). It holds

* the configuration models (:class:`RedactionRuleSpec`, :class:`RedactionConfig`),
* the pattern validator that keeps user-supplied regular expressions inside a small, safe
  subset (:func:`validate_pattern`),
* the built-in rules (:data:`BUILTIN_RULES`) and
* the engine (:class:`Redactor`).

What this does **not** do: prove that a text holds no secret. Redaction is pattern based; a
secret in an unrecognized form passes through. Python's ``re`` has no timeout, so the
protection against catastrophic backtracking is structural (bounded quantifiers, no nested
repetition, size limits) and best effort - see the README for the residual risk.

Errors never contain the input text; metadata never contains a matched value.
"""

import re
import unicodedata
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Final, Self

from pydantic import BeforeValidator, Field, model_validator

from soerm.domain.base import DomainModel
from soerm.domain.errors import ValidationDomainError, ValidationIssue
from soerm.domain.hashing import compute_config_hash

__all__ = [
    "BUILTIN_NAMES",
    "BUILTIN_RULES",
    "DEFAULT_MAX_INPUT_BYTES",
    "DEFAULT_REPLACEMENT",
    "MAX_CUSTOM_RULES",
    "MAX_PATTERN_LENGTH",
    "REDACTION_CONFIG_VERSION",
    "RedactionConfig",
    "RedactionError",
    "RedactionPolicy",
    "RedactionResult",
    "RedactionRule",
    "RedactionRuleSpec",
    "Redactor",
    "build_policy",
    "normalize_for_redaction",
    "validate_pattern",
]

REDACTION_CONFIG_VERSION: Final = "1"
DEFAULT_REPLACEMENT: Final = "[REDACTED]"
DEFAULT_MAX_INPUT_BYTES: Final = 65536
MAX_PATTERN_LENGTH: Final = 512
MAX_CUSTOM_RULES: Final = 32
MAX_QUANTIFIER: Final = 4096
MAX_REPEATING_QUANTIFIERS: Final = 12
MAX_REPLACEMENT_LENGTH: Final = 64
MAX_MATCH_LENGTH_LIMIT: Final = 16384
DEFAULT_MATCH_LENGTH: Final = 1024
_MIN_INPUT_BYTES: Final = 1024
_MAX_INPUT_BYTES: Final = 1_048_576
_CAPTURE: Final = "secret"
_RULE_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,47}")
_QUANTIFIER: Final = re.compile(r"\{(\d{0,5})(?:(,)(\d{0,5}))?\}")


class RedactionError(ValidationDomainError):
    """Text cannot be redacted safely (too large, bad character, rule failure)."""

    code = "redaction_error"


def _error(field: str, rule: str) -> RedactionError:
    return RedactionError([ValidationIssue(field, rule)])


# ---------------------------------------------------------------------------------------
# Pattern validation
# ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Frame:
    """What a group (or the whole pattern) contains, at any depth."""

    repeat: bool = False  # a quantifier with an upper bound above 1
    alt: bool = False  # an alternation


@dataclass(slots=True)
class _Atom:
    """The last complete element, the target of a following quantifier."""

    group: _Frame | None = None


def _reject(rule: str) -> ValidationDomainError:
    return ValidationDomainError.single("pattern", rule)


def _skip_class(pattern: str, start: int) -> int:
    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern) and pattern[index] != "]":
        index += 2 if pattern[index] == "\\" else 1
    return index + 1


def _open_group(pattern: str, start: int) -> int:
    """Index after the group opener; only a small set of group kinds is supported."""
    if not pattern.startswith("(?", start):
        return start + 1
    for opener in ("(?:", "(?=", "(?!"):
        if pattern.startswith(opener, start):
            return start + len(opener)
    for opener in ("(?<=", "(?<!"):
        if pattern.startswith(opener, start):
            return start + len(opener)
    if pattern.startswith("(?P<", start):
        end = pattern.find(">", start)
        if end == -1:
            raise _reject("pattern_invalid")
        return end + 1
    # comments, atomic groups, conditionals, backreferences, scoped or late flags ...
    raise _reject("pattern_unsupported_group")


def _scan(pattern: str) -> None:
    """Reject unbounded or nested repetition, backreferences and unsupported groups.

    The pattern already compiled, so its syntax is valid; this walk only looks at structure.
    """
    frames = [_Frame()]
    last: _Atom | None = None
    after_quantifier = False
    repeats = 0
    index = 4 if pattern.startswith("(?i)") else 0

    def quantify(upper: int) -> None:
        nonlocal repeats, after_quantifier
        if last is None:
            raise _reject("pattern_invalid")
        if upper > MAX_QUANTIFIER:
            raise _reject("pattern_quantifier_too_large")
        if upper > 1:
            repeats += 1
            if repeats > MAX_REPEATING_QUANTIFIERS:
                raise _reject("pattern_too_many_repeats")
            if last.group is not None and (last.group.repeat or last.group.alt):
                raise _reject("pattern_nested_quantifier")
            frames[-1].repeat = True
        after_quantifier = True

    while index < len(pattern):
        char = pattern[index]
        was_quantified = after_quantifier
        after_quantifier = False
        if char == "\\":
            following = pattern[index + 1 : index + 2]
            if following.isdigit() and following != "0":
                raise _reject("pattern_backreference")
            if following in {"N", "k", "g", "Z"} and following != "Z":
                raise _reject("pattern_unsupported_escape")
            last = _Atom()
            index += 2
        elif char == "[":
            last = _Atom()
            index = _skip_class(pattern, index)
        elif char == "(":
            index = _open_group(pattern, index)
            frames.append(_Frame())
            last = None
        elif char == ")":
            frame = frames.pop()
            frames[-1].repeat = frames[-1].repeat or frame.repeat
            frames[-1].alt = frames[-1].alt or frame.alt
            last = _Atom(frame)
            index += 1
        elif char == "|":
            frames[-1].alt = True
            last = None
            index += 1
        elif char in "*+":
            raise _reject(
                "pattern_possessive" if was_quantified else "pattern_unbounded_quantifier"
            )
        elif char == "?":
            if was_quantified:  # lazy marker of the previous quantifier
                index += 1
                continue
            quantify(1)
            index += 1
        elif char == "{":
            match = _QUANTIFIER.match(pattern, index)
            if match is None or (not match.group(1) and not match.group(3) and not match.group(2)):
                last = _Atom()  # a literal brace
                index += 1
                continue
            lower, comma, upper = match.groups()
            if comma and not upper:
                raise _reject("pattern_unbounded_quantifier")
            quantify(int(upper if comma else lower or "0"))
            index = match.end()
        else:
            last = _Atom()
            index += 1


def validate_pattern(pattern: object) -> str:
    """Return ``pattern`` if it is inside the supported regular-expression subset.

    Allowed: literals, classes, escapes, anchors, ``(?:...)``, lookarounds, one optional
    named group called ``secret`` and a leading ``(?i)``. Quantifiers must be bounded
    (``?`` or ``{m,n}`` up to 4096); a group repeated more than once may contain neither a
    repetition nor an alternation; backreferences and every other inline flag or group
    construct are refused; a pattern that matches the empty string is refused.
    """
    if not isinstance(pattern, str):
        raise _reject("pattern_type")
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        raise _reject("pattern_length")
    if not pattern.isprintable():
        raise _reject("pattern_control_character")
    compiled = _compile(pattern)
    _scan(pattern)
    extra = set(compiled.groupindex) - {_CAPTURE}
    if extra:
        raise _reject("pattern_group_name")
    if compiled.search("") is not None:
        raise _reject("pattern_matches_empty")
    return pattern


def _compile(pattern: str) -> re.Pattern[str]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return re.compile(pattern, re.MULTILINE)
    except (re.error, RecursionError, OverflowError, Warning):
        raise _reject("pattern_invalid") from None


# ---------------------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------------------


def _rule_name(value: object) -> str:
    if not isinstance(value, str) or _RULE_NAME.fullmatch(value) is None:
        raise ValidationDomainError.single("name", "invalid_rule_name")
    return value


def _replacement(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_REPLACEMENT_LENGTH
        or not value.isprintable()
    ):
        raise ValidationDomainError.single("replacement", "invalid_replacement")
    return value


RuleName = Annotated[str, BeforeValidator(_rule_name)]
RulePattern = Annotated[str, BeforeValidator(validate_pattern)]
Replacement = Annotated[str, BeforeValidator(_replacement)]
MatchLength = Annotated[int, Field(strict=True, ge=1, le=MAX_MATCH_LENGTH_LIMIT)]
StrictFlag = Annotated[bool, Field(strict=True)]


class RedactionRuleSpec(DomainModel):
    """A user-defined rule. If the pattern has a group named ``secret`` only that group is
    replaced, otherwise the whole match is."""

    name: RuleName
    pattern: RulePattern
    replacement: Replacement = DEFAULT_REPLACEMENT
    enabled: StrictFlag = True
    max_match_length: MatchLength = DEFAULT_MATCH_LENGTH


@dataclass(frozen=True, slots=True)
class RedactionRule:
    """An effective rule (built-in or custom)."""

    name: str
    pattern: str
    replacement: str = DEFAULT_REPLACEMENT
    enabled: bool = True
    max_match_length: int = MAX_MATCH_LENGTH_LIMIT
    builtin: bool = False


def _builtin_names() -> frozenset[str]:
    return frozenset(rule.name for rule in BUILTIN_RULES)


class RedactionConfig(DomainModel):
    """The ``redaction`` section of the configuration file."""

    max_input_bytes: Annotated[
        int, Field(strict=True, ge=_MIN_INPUT_BYTES, le=_MAX_INPUT_BYTES)
    ] = DEFAULT_MAX_INPUT_BYTES
    builtin_rules: dict[str, StrictFlag] = Field(default_factory=dict)
    rules: tuple[RedactionRuleSpec, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> Self:
        if any(name not in _builtin_names() for name in self.builtin_rules):
            raise ValidationDomainError.single("builtin_rules", "unknown_builtin_rule")
        if len(self.rules) > MAX_CUSTOM_RULES:
            raise ValidationDomainError.single("rules", "too_many_rules")
        names = [rule.name for rule in self.rules]
        if len(set(names)) != len(names) or set(names) & _builtin_names():
            raise ValidationDomainError.single("rules", "duplicate_rule_name")
        return self


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """The ordered effective rules, the input limit and the hash of both."""

    rules: tuple[RedactionRule, ...]
    max_input_bytes: int
    config_hash: str


def build_policy(config: RedactionConfig | None = None) -> RedactionPolicy:
    """Built-in rules (in fixed order, minus the disabled ones) followed by custom rules."""
    config = config or RedactionConfig()
    rules: list[RedactionRule] = []
    for rule in BUILTIN_RULES:
        enabled = config.builtin_rules.get(rule.name, rule.enabled)
        rules.append(
            RedactionRule(
                rule.name, rule.pattern, rule.replacement, enabled, rule.max_match_length, True
            )
        )
    rules.extend(
        RedactionRule(
            spec.name, spec.pattern, spec.replacement, spec.enabled, spec.max_match_length, False
        )
        for spec in config.rules
    )
    payload = {
        "max_input_bytes": config.max_input_bytes,
        "rules": [
            {
                "name": rule.name,
                "pattern": rule.pattern,
                "replacement": rule.replacement,
                "enabled": rule.enabled,
                "max_match_length": rule.max_match_length,
            }
            for rule in rules
        ],
    }
    config_hash = compute_config_hash(
        name="redaction", version=REDACTION_CONFIG_VERSION, payload=payload
    )
    return RedactionPolicy(tuple(rules), config.max_input_bytes, config_hash)


# ---------------------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------------------
# These are reviewed by hand and covered by pathological-input tests. They are *not* passed
# through ``validate_pattern`` (they use an escape-aware quoted-string alternation and a
# backreference, which user patterns may not), but they use bounded quantifiers only.

_SPACE = r"[ \t]{0,8}"
# A value is consumed up to its natural end. The repetitions below are single-character-class
# (or disjoint-alternative) loops: linear, never nested. They are unbounded on purpose - a
# bound would leave the tail of a long secret in the text - and the per-rule
# ``max_match_length`` turns an absurdly long value into a refusal (fail closed).
_VALUE = (
    r"(?P<secret>"
    r'"(?:[^"\\\n]|\\.)*"'  # "double quoted", escapes allowed
    r"|'(?:[^'\\\n]|\\.)*'"  # 'single quoted'
    r"""|["'][^\n]*"""  # unterminated quote: mask to the end of the line
    r"""|[^\s,;&"']+"""  # bare value
    r")"
)
_WORD_PREFIX = r"(?<![\w-])[A-Za-z0-9_-]{0,32}"
_KEY_PW = r"(?:password|passwd|passphrase|pwd)"
_KEY_TOK = r"token"
_KEY_AUTH = r"auth[_-]?token"
_KEYS_API_KEY = (
    r"(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?key|private[_-]?key)"
)
_KEYS_JSON = (
    r"(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|secret[_-]?key|"
    r"client[_-]?secret|access[_-]?key|private[_-]?key|authorization|proxy-authorization|"
    r"cookie|set-cookie)"
)


def _assignment(keys: str) -> str:
    return rf"(?i){_WORD_PREFIX}{keys}[\"']?{_SPACE}[=:]{_SPACE}{_VALUE}"


def _header(name: str) -> str:
    # No quote after the key: a quoted JSON key is handled by ``json_string_secret``.
    return rf"(?i)(?<![\w-]){name}{_SPACE}[:=]{_SPACE}(?P<secret>[^\s][^\n]*)"


BUILTIN_RULES: Final[tuple[RedactionRule, ...]] = (
    RedactionRule(
        "json_string_secret",
        r"""(?i)(?P<q>["'])[A-Za-z0-9_-]{0,32}"""
        + _KEYS_JSON
        + r"""(?P=q)"""
        + _SPACE
        + r""":"""
        + _SPACE
        + r"""(?P=q)(?P<secret>(?:(?!(?P=q))[^\\\n]|\\.)*)(?P=q)""",
        builtin=True,
    ),
    RedactionRule("authorization", _header(r"(?:proxy-)?authorization"), builtin=True),
    RedactionRule("cookie", _header("cookie"), builtin=True),
    RedactionRule("set_cookie", _header("set-cookie"), builtin=True),
    RedactionRule("password", _assignment(_KEY_PW), builtin=True),
    RedactionRule("auth_token", _assignment(_KEY_AUTH), builtin=True),
    RedactionRule("token", _assignment(_KEY_TOK), builtin=True),
    RedactionRule("api_key", _assignment(_KEYS_API_KEY), builtin=True),
    RedactionRule(
        "bearer",
        r"(?i)\bbearer[ \t]{1,8}(?P<secret>[A-Za-z0-9._~+/=-]+)",
        builtin=True,
    ),
)
BUILTIN_NAMES: Final = tuple(rule.name for rule in BUILTIN_RULES)


# ---------------------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------------------

_LINE_BREAK_PATTERN: Final = re.compile(r"\r\n|[\r\x0b\x0c\x85\u2028\u2029]")
_ALLOWED_CONTROLS: Final = frozenset("\n\t")


def _utf8_size(text: str) -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise _error("text", "invalid_character") from None


def normalize_for_redaction(text: object, *, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> str:
    """NFKC, uniform ``\\n`` line ends, no control or invisible format characters.

    Only ``\\n`` and ``\\t`` survive among the control characters. Oversized text (before or
    after normalization, which can expand it) is refused without echoing it.
    """
    if not isinstance(text, str):
        raise _error("text", "string_type")
    if len(text) > max_input_bytes or _utf8_size(text) > max_input_bytes:
        raise _error("text", "input_too_large")
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _LINE_BREAK_PATTERN.sub("\n", normalized)
    kept = [
        char
        for char in normalized
        if char in _ALLOWED_CONTROLS or unicodedata.category(char) not in {"Cc", "Cf"}
    ]
    result = "".join(kept)
    if _utf8_size(result) > max_input_bytes:
        raise _error("text", "input_too_large")
    return result


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Redacted text plus metadata that never contains a matched value."""

    text: str
    hits: tuple[tuple[str, int], ...]
    was_truncated: bool
    output_bytes: int

    @property
    def total_hits(self) -> int:
        return sum(count for _, count in self.hits)


def _truncate(text: str, max_chars: int | None, max_bytes: int | None) -> tuple[str, bool]:
    truncated = False
    if max_chars is not None and len(text) > max_chars:
        text, truncated = text[:max_chars], True
    if max_bytes is not None and len(text.encode("utf-8")) > max_bytes:
        text = text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
        truncated = True
    return text, truncated


class _CompiledRule:
    __slots__ = ("pattern", "rule", "secret_group")

    def __init__(self, rule: RedactionRule) -> None:
        self.rule = rule
        self.pattern = _compile(rule.pattern)
        self.secret_group = _CAPTURE in self.pattern.groupindex

    def apply(self, text: str) -> tuple[str, int]:
        rule = self.rule
        marker = rule.replacement
        hits = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal hits
            whole = match.group(0)
            if len(whole) > rule.max_match_length:
                raise RedactionError([ValidationIssue(f"rule.{rule.name}", "match_too_long")])
            if self.secret_group:
                start, end = match.span(_CAPTURE)
                if start == -1:
                    return whole
                secret = match.group(_CAPTURE)
            else:
                start, end = match.span()
                secret = whole
            if not secret or secret == marker or secret.strip("\"'") == marker:
                return whole  # empty, or already redacted by this very rule
            hits += 1
            offset = match.start()
            return whole[: start - offset] + marker + whole[end - offset :]

        return self.pattern.sub(replace, text), hits


class Redactor:
    """Applies a policy's enabled rules, in order, to normalized text."""

    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self._policy = policy or build_policy()
        self._rules = tuple(_CompiledRule(r) for r in self._policy.rules if r.enabled)
        self._check_idempotence()

    @property
    def policy(self) -> RedactionPolicy:
        return self._policy

    @property
    def config_hash(self) -> str:
        return self._policy.config_hash

    def _check_idempotence(self) -> None:
        """Markers must be stable under the rules, or repeated redaction would keep growing."""
        sample = "\n".join(rule.rule.replacement for rule in self._rules)
        text = sample
        for compiled in self._rules:
            text, hits = compiled.apply(text)
            if hits:
                raise _error(f"rule.{compiled.rule.name}", "rule_matches_marker")

    def redact(
        self,
        text: object,
        *,
        max_chars: int | None = None,
        max_bytes: int | None = None,
    ) -> RedactionResult:
        """Normalize, redact, then shorten the redacted text to the given limits."""
        current = normalize_for_redaction(text, max_input_bytes=self._policy.max_input_bytes)
        hits: list[tuple[str, int]] = []
        for compiled in self._rules:
            current, count = compiled.apply(current)
            if count:
                hits.append((compiled.rule.name, count))
        current, truncated = _truncate(current, max_chars, max_bytes)
        return RedactionResult(current, tuple(hits), truncated, len(current.encode("utf-8")))

    def redact_text(self, text: object, **limits: int | None) -> str:
        """Convenience: only the redacted text."""
        return self.redact(text, **limits).text


Transform = Callable[[str], str]
