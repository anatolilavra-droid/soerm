# ruff: noqa: RUF001
"""Redaction engine: built-in rules, normalization, idempotence, limits, pattern validation."""

import time
from typing import Any

import pytest

from soerm.domain.errors import DomainError, ValidationDomainError
from soerm.domain.redaction import (
    BUILTIN_NAMES,
    BUILTIN_RULES,
    DEFAULT_REPLACEMENT,
    RedactionConfig,
    RedactionError,
    RedactionRuleSpec,
    Redactor,
    build_policy,
    normalize_for_redaction,
    validate_pattern,
)

SECRET = "S3cr3t-Value-9f2c"
R = DEFAULT_REPLACEMENT


@pytest.fixture(scope="module")
def redactor() -> Redactor:
    return Redactor()


# ---- built-in rules: one case table, one idempotence test per rule ----------------------

CASES: dict[str, list[tuple[str, str]]] = {
    "authorization": [
        (f"Authorization: Basic {SECRET}", f"Authorization: {R}"),
        (f"authorization:Bearer {SECRET}", f"authorization:{R}"),
        (f"Proxy-Authorization: Digest {SECRET}", f"Proxy-Authorization: {R}"),
    ],
    "cookie": [
        (f"Cookie: sid={SECRET}; theme=dark", f"Cookie: {R}"),
        (f"GET / HTTP/1.1\nCookie: a={SECRET}\nHost: x", f"GET / HTTP/1.1\nCookie: {R}\nHost: x"),
    ],
    "set_cookie": [
        (f"Set-Cookie: sid={SECRET}; Path=/; HttpOnly", f"Set-Cookie: {R}"),
    ],
    "password": [
        (f"password={SECRET}", f"password={R}"),
        (f"password: {SECRET}", f"password: {R}"),
        (f"Password = {SECRET}", f"Password = {R}"),
        (f'password="{SECRET} with spaces"', f"password={R}"),
        (f"password='{SECRET}'", f"password={R}"),
        (f"db_password={SECRET}&user=x", f"db_password={R}&user=x"),
        (f"passwd={SECRET}, other=1", f"passwd={R}, other=1"),
    ],
    "auth_token": [
        (f"auth_token={SECRET}", f"auth_token={R}"),
        (f"auth-token: {SECRET}", f"auth-token: {R}"),
    ],
    "token": [
        (f"token={SECRET}", f"token={R}"),
        (f"access_token: {SECRET}", f"access_token: {R}"),
        (f'token = "{SECRET}"', f"token = {R}"),
    ],
    "api_key": [
        (f"api_key={SECRET}", f"api_key={R}"),
        (f"X-Api-Key: {SECRET}", f"X-Api-Key: {R}"),
        (f"apikey={SECRET};x=1", f"apikey={R};x=1"),
        (f"client_secret={SECRET}", f"client_secret={R}"),
    ],
    "bearer": [
        (f"curl -H 'x: Bearer {SECRET}'", f"curl -H 'x: Bearer {R}'"),
        (f"bearer   {SECRET}", f"bearer   {R}"),
    ],
    "json_string_secret": [
        (f'{{"password": "{SECRET}"}}', f'{{"password": "{R}"}}'),
        (f'{{"api_key":"{SECRET}","user":"bob"}}', f'{{"api_key":"{R}","user":"bob"}}'),
        (f'{{"Authorization": "Bearer {SECRET}"}}', f'{{"Authorization": "{R}"}}'),
        (f'{{"token": "a \\" {SECRET}"}}', f'{{"token": "{R}"}}'),
    ],
}


def test_every_builtin_rule_has_cases() -> None:
    assert set(CASES) == set(BUILTIN_NAMES)


@pytest.mark.parametrize(
    ("rule", "raw", "expected"),
    [(rule, raw, expected) for rule, cases in CASES.items() for raw, expected in cases],
)
def test_builtin_rule_masks_the_value_and_keeps_the_key(
    redactor: Redactor, rule: str, raw: str, expected: str
) -> None:
    result = redactor.redact(raw)
    assert result.text == expected
    assert SECRET not in result.text
    assert result.total_hits >= 1
    assert set(dict(result.hits)) <= set(BUILTIN_NAMES)


@pytest.mark.parametrize("rule", BUILTIN_NAMES)
def test_idempotence_per_builtin_rule(redactor: Redactor, rule: str) -> None:
    for raw, _ in CASES[rule]:
        once = redactor.redact(raw)
        twice = redactor.redact(once.text)
        assert twice.text == once.text
        assert twice.hits == ()  # no new markers, no new hits


@pytest.mark.parametrize("rule", BUILTIN_NAMES)
def test_only_that_rule_is_needed(rule: str) -> None:
    only = Redactor(
        build_policy(RedactionConfig(builtin_rules={n: n == rule for n in BUILTIN_NAMES}))
    )
    for raw, expected in CASES[rule]:
        assert only.redact(raw).text == expected


def test_auth_token_is_counted_once_not_as_token(redactor: Redactor) -> None:
    assert redactor.redact(f"auth_token={SECRET}").hits == (("auth_token", 1),)


# ---- shapes --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("password=", "password="),
        ("password: ", "password: "),
        ('password=""', f"password={R}"),
        ("password=\n", "password=\n"),
        ('password="unterminated ' + SECRET, f"password={R}"),
        ("password='" + SECRET + "\nnext=line", f"password={R}\nnext=line"),
        ("password=a=b=c", f"password={R}"),
        ('{"password": "' + SECRET, '{"password": ' + R),
    ],
)
def test_empty_values_and_unterminated_quotes(redactor: Redactor, raw: str, expected: str) -> None:
    result = redactor.redact(raw)
    assert result.text == expected
    assert SECRET not in result.text


def test_quoted_value_with_escaped_quote_is_masked_to_the_end(redactor: Redactor) -> None:
    text = f'password="a\\"{SECRET}" tail'
    assert redactor.redact(text).text == f"password={R} tail"


def test_json_like_structure_survives(redactor: Redactor) -> None:
    raw = f'{{"user": "bob", "password": "{SECRET}", "n": 1}}'
    assert redactor.redact(raw).text == f'{{"user": "bob", "password": "{R}", "n": 1}}'


def test_unrelated_text_is_untouched(redactor: Redactor) -> None:
    text = "The password policy requires tokens to rotate.\nNo secrets here: nothing=1"
    result = redactor.redact(text)
    assert result.text == text
    assert result.hits == ()


def test_several_rules_in_one_text_report_counts_in_rule_order(redactor: Redactor) -> None:
    text = f"password={SECRET}\ntoken={SECRET}\nBearer {SECRET}\npassword={SECRET}"
    result = redactor.redact(text)
    assert result.hits == (("password", 2), ("token", 1), ("bearer", 1))
    assert result.total_hits == 4


# ---- normalization -------------------------------------------------------------------------


def test_unicode_is_normalized_before_matching(redactor: Redactor) -> None:
    fullwidth = "ｐａｓｓｗｏｒｄ＝" + SECRET  # NFKC folds this to "password=..."
    assert redactor.redact(fullwidth).text == f"password={R}"
    zero_width = "pass​word=" + SECRET
    assert redactor.redact(zero_width).text == f"password={R}"


def test_look_alike_letters_are_not_folded_and_documented_as_residual() -> None:
    # Cyrillic a is not NFKC-equivalent to "a": such a key is simply not recognized.
    text = "pаssword=" + SECRET
    assert Redactor().redact(text).text == text


@pytest.mark.parametrize("separator", ["\r\n", "\r", " ", "\x0b", "\x0c", "\x85"])
def test_line_endings_become_newlines(redactor: Redactor, separator: str) -> None:
    result = redactor.redact(f"a{separator}password={SECRET}{separator}b")
    assert result.text == f"a\npassword={R}\nb"


def test_control_characters_are_removed_except_newline_and_tab(redactor: Redactor) -> None:
    result = redactor.redact("a\x00b\x07c\x1bd\x7fe\tf\ng")
    assert result.text == "abcde\tf\ng"


def test_secret_cannot_hide_behind_control_characters(redactor: Redactor) -> None:
    assert redactor.redact(f"pass\x00word=\x01{SECRET}").text == f"password={R}"


def test_non_string_and_lone_surrogates_are_rejected_without_echo() -> None:
    for value in (None, 5, b"password=x", ["password=x"]):
        with pytest.raises(RedactionError):
            normalize_for_redaction(value)
    with pytest.raises(RedactionError) as excinfo:
        normalize_for_redaction("password=" + SECRET + "\ud800")
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())


# ---- limits --------------------------------------------------------------------------------


def test_oversized_text_is_refused_without_echo(redactor: Redactor) -> None:
    config = RedactionConfig(max_input_bytes=1024)
    small = Redactor(build_policy(config))
    with pytest.raises(RedactionError) as excinfo:
        small.redact("password=" + SECRET + "x" * 1100)
    text = str(excinfo.value) + repr(excinfo.value.to_dict()) + repr(excinfo.value.args)
    assert SECRET not in text
    assert "input_too_large" in text
    assert small.redact("x" * 1024).output_bytes == 1024


def test_nfkc_expansion_beyond_the_limit_is_refused() -> None:
    small = Redactor(build_policy(RedactionConfig(max_input_bytes=1024)))
    with pytest.raises(RedactionError):
        small.redact("ﷺ" * 40)  # one code point -> 18 after NFKC


def test_truncation_applies_to_the_redacted_text(redactor: Redactor) -> None:
    raw = f"password={SECRET}" + " pad" * 50
    result = redactor.redact(raw, max_chars=30)
    assert result.was_truncated
    assert len(result.text) == 30
    assert result.text.startswith(f"password={R}")
    assert SECRET not in result.text
    assert result.output_bytes == len(result.text.encode())


def test_a_secret_cut_by_the_limit_is_still_masked_first(redactor: Redactor) -> None:
    # Cutting the raw text at 14 characters would leave "password=S3cr3t"; redact-then-cut cannot.
    result = redactor.redact(f"password={SECRET}", max_chars=14)
    assert result.text == f"password={R}"[:14]
    assert "S3cr" not in result.text


def test_byte_limit_never_splits_a_character(redactor: Redactor) -> None:
    result = redactor.redact("é" * 100, max_bytes=51)
    assert result.was_truncated
    assert result.output_bytes == 50
    assert result.text == "é" * 25


def test_metadata_never_contains_matched_values(redactor: Redactor) -> None:
    result = redactor.redact(f"password={SECRET} Cookie: {SECRET}", max_chars=10_000)
    assert SECRET not in repr((result.hits, result.was_truncated, result.output_bytes))
    assert all(count > 0 for _, count in result.hits)
    assert {name for name, _ in result.hits} <= set(BUILTIN_NAMES)


def test_match_longer_than_the_rule_limit_fails_closed() -> None:
    spec = RedactionRuleSpec(name="long", pattern=r"\bX[a-z]{1,100}\b", max_match_length=10)
    redactor = Redactor(build_policy(RedactionConfig(rules=(spec,))))
    assert redactor.redact("Xabc").text == R
    with pytest.raises(RedactionError) as excinfo:
        redactor.redact("X" + "a" * 50 + " " + SECRET)
    assert "match_too_long" in str(excinfo.value)
    assert SECRET not in str(excinfo.value)


# ---- pathological input (best effort, not a proof) -----------------------------------------

PATHOLOGICAL = [
    "password=" + "a" * 16000,
    "password=" + "a" * 60000,
    'password="' + "a" * 5000 + '" tail',
    '{"authorization": "' + "a" * 6000 + '"}',
    "Authorization: " + "a" * 9000,
    "password=" + '"' * 30000,
    "password=" + "\\" * 30000,
    'password="' + "\\" * 30000,
    "Cookie:" + " " * 60000,
    "Authorization:" + "a" * 60000,
    "token" + " " * 60000,
    "=" * 60000,
    ":" * 60000,
    "a" * 60000,
    "Bearer " + "a" * 60000,
    "bearer" + " " * 60000,
    '{"' + "password" * 7000,
    ("password=\n" * 6000),
    ("api_key" + "-" * 40) * 1000,
    "password" + "\t" * 59000 + "x",
]


@pytest.mark.parametrize("text", PATHOLOGICAL, ids=[str(i) for i in range(len(PATHOLOGICAL))])
def test_pathological_inputs_finish_quickly(redactor: Redactor, text: str) -> None:
    started = time.perf_counter()
    try:
        result = redactor.redact(text)
    except RedactionError:
        pass  # failing closed is acceptable; hanging is not
    else:
        assert redactor.redact(result.text).text == result.text
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize(
    "raw",
    [
        "password=" + "a" * 5000,
        'password="' + "a" * 5000 + '"',
        "Authorization: " + "a" * 9000,
        '{"authorization": "' + "a" * 6000 + '"}',
        "Bearer " + "a" * 5000,
    ],
)
def test_long_values_are_masked_to_the_end_not_cut_at_a_bound(redactor: Redactor, raw: str) -> None:
    result = redactor.redact(raw)
    assert "aaaa" not in result.text
    assert redactor.redact(result.text).text == result.text


def test_absurdly_long_values_fail_closed(redactor: Redactor) -> None:
    with pytest.raises(RedactionError) as excinfo:
        redactor.redact("password=" + "a" * 40000)
    assert "match_too_long" in str(excinfo.value)
    assert "aaaa" not in str(excinfo.value)


# ---- rule models and pattern validation ----------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        r"\bEMP-\d{6}\b",
        r"(?i)email:\s{0,3}(?P<secret>[^\s]{1,100})",
        r"(?:ab){1,3}",
        r"\d{3}-\d{2}-\d{4}",
        r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}",
        r"(?<=ssn=)\d{9}",
    ],
)
def test_supported_patterns_are_accepted(pattern: str) -> None:
    assert validate_pattern(pattern) == pattern


@pytest.mark.parametrize(
    ("pattern", "rule"),
    [
        (r"(a+)+", "pattern_unbounded_quantifier"),
        (r"a*", "pattern_unbounded_quantifier"),
        (r"a+", "pattern_unbounded_quantifier"),
        (r"a{2,}", "pattern_unbounded_quantifier"),
        (r"(a{1,5}){1,5}", "pattern_nested_quantifier"),
        (r"(a|b){2,3}", "pattern_nested_quantifier"),
        (r"(?:a|aa){1,30}", "pattern_nested_quantifier"),
        (r"(\d{1,3}\.){1,3}\d", "pattern_nested_quantifier"),
        (r"((a{1,2})){1,2}", "pattern_nested_quantifier"),
        (r"(a)\1", "pattern_backreference"),
        (r"a{1,99999}", "pattern_quantifier_too_large"),
        (r"a{1,5000}", "pattern_quantifier_too_large"),
        (r"(?s)a", "pattern_unsupported_group"),
        (r"(?x)a b", "pattern_unsupported_group"),
        (r"(?i:a)", "pattern_unsupported_group"),
        (r"(?#comment)a", "pattern_unsupported_group"),
        (r"(?>a)", "pattern_unsupported_group"),
        (r"(?P=n)", "pattern_invalid"),
        (r"a?", "pattern_matches_empty"),
        (r"(?P<other>a)", "pattern_group_name"),
        (r"(", "pattern_invalid"),
        (r"[a", "pattern_invalid"),
        ("", "pattern_length"),
        ("a" * 513, "pattern_length"),
        ("a\nb", "pattern_control_character"),
        ("a\x00b", "pattern_control_character"),
    ],
)
def test_unsafe_patterns_are_rejected_with_a_stable_code(pattern: str, rule: str) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        validate_pattern(pattern)
    assert [issue.code for issue in excinfo.value.issues] == [rule]


def test_pattern_must_be_a_string() -> None:
    for value in (None, 1, b"a", ["a"]):
        with pytest.raises(ValidationDomainError):
            validate_pattern(value)


def test_too_many_repeating_quantifiers_are_rejected() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        validate_pattern(r"\d{1,3}" * 13)
    assert excinfo.value.issues[0].code == "pattern_too_many_repeats"
    assert validate_pattern(r"\d{1,3}" * 12)


def test_rule_fields_are_validated() -> None:
    base: dict[str, Any] = {"name": "ok", "pattern": r"\d{4}"}
    assert RedactionRuleSpec(**base).replacement == R
    for bad in (
        {"name": "Bad Name"},
        {"name": ""},
        {"name": "x" * 49},
        {"replacement": ""},
        {"replacement": "a\nb"},
        {"replacement": "a\x00"},
        {"replacement": "a\x1b[31m"},
        {"replacement": "x" * 65},
        {"enabled": "yes"},
        {"enabled": 1},
        {"max_match_length": 0},
        {"max_match_length": 16385},
        {"max_match_length": True},
        {"max_match_length": "10"},
        {"unknown": 1},
        {"flags": "i"},
    ):
        with pytest.raises(ValidationDomainError):
            RedactionRuleSpec(**{**base, **bad})


def test_config_limits() -> None:
    spec = RedactionRuleSpec(name="a", pattern=r"\d{4}")
    with pytest.raises(ValidationDomainError):
        RedactionConfig(rules=tuple(spec.with_changes(name=f"r{i}") for i in range(33)))
    RedactionConfig(rules=tuple(spec.with_changes(name=f"r{i}") for i in range(32)))
    with pytest.raises(ValidationDomainError):  # duplicate
        RedactionConfig(rules=(spec, spec))
    with pytest.raises(ValidationDomainError):  # clashes with a built-in
        RedactionConfig(rules=(spec.with_changes(name="password"),))
    with pytest.raises(ValidationDomainError):
        RedactionConfig(builtin_rules={"nope": False})
    with pytest.raises(ValidationDomainError):
        RedactionConfig(max_input_bytes=10)
    with pytest.raises(ValidationDomainError):
        RedactionConfig(max_input_bytes=2_000_000)


def test_a_custom_rule_that_matches_its_own_marker_is_refused() -> None:
    spec = RedactionRuleSpec(name="bad", pattern=r"\[[A-Z]{1,10}\]", replacement="[X]")
    with pytest.raises(DomainError):
        Redactor(build_policy(RedactionConfig(rules=(spec,))))


def test_custom_pii_rule_and_secret_group() -> None:
    rules = (
        RedactionRuleSpec(name="employee", pattern=r"\bEMP-\d{6}\b", replacement="[EMPLOYEE]"),
        RedactionRuleSpec(name="iban", pattern=r"(?i)iban:\s{0,2}(?P<secret>[A-Z0-9]{15,34})"),
    )
    redactor = Redactor(build_policy(RedactionConfig(rules=rules)))
    result = redactor.redact("EMP-123456 asked; IBAN: DE89370400440532013000; EMP-000001")
    assert result.text == f"[EMPLOYEE] asked; IBAN: {R}; [EMPLOYEE]"
    assert result.hits == (("employee", 2), ("iban", 1))
    assert redactor.redact(result.text).text == result.text


def test_disabled_rules_do_nothing() -> None:
    config = RedactionConfig(builtin_rules={"password": False})
    text = f"password={SECRET} token={SECRET}"
    assert Redactor(build_policy(config)).redact(text).text == f"password={SECRET} token={R}"
    spec = RedactionRuleSpec(name="off", pattern=r"\d{4}", enabled=False)
    assert Redactor(build_policy(RedactionConfig(rules=(spec,)))).redact("1234").text == "1234"


# ---- ordering and hash ---------------------------------------------------------------------


def test_rule_order_is_deterministic_builtins_first_then_custom_in_file_order() -> None:
    first = RedactionRuleSpec(name="zeta", pattern=r"\d{4}")
    second = RedactionRuleSpec(name="alpha", pattern=r"\d{5}")
    policy = build_policy(RedactionConfig(rules=(first, second)))
    names = [rule.name for rule in policy.rules]
    assert names == [*BUILTIN_NAMES, "zeta", "alpha"]
    assert [rule.name for rule in BUILTIN_RULES] == list(BUILTIN_NAMES)
    assert build_policy(RedactionConfig(rules=(first, second))) == policy


def test_rule_order_changes_the_result_and_the_hash() -> None:
    a = RedactionRuleSpec(name="a", pattern=r"\d{4}", replacement="[A]")
    b = RedactionRuleSpec(name="b", pattern=r"\d{4}", replacement="[B]")
    ab = build_policy(RedactionConfig(rules=(a, b)))
    ba = build_policy(RedactionConfig(rules=(b, a)))
    assert ab.config_hash != ba.config_hash
    assert Redactor(ab).redact("1234").text == "[A]"
    assert Redactor(ba).redact("1234").text == "[B]"


def test_config_hash_is_stable_and_sensitive() -> None:
    default = build_policy().config_hash
    assert default == build_policy(RedactionConfig()).config_hash
    assert len(default) == 64
    assert default == "".join(default.lower())
    changed = build_policy(RedactionConfig(builtin_rules={"bearer": False})).config_hash
    assert changed != default
    assert build_policy(RedactionConfig(max_input_bytes=2048)).config_hash != default
    spec = RedactionRuleSpec(name="a", pattern=r"\d{4}")
    h1 = build_policy(RedactionConfig(rules=(spec,))).config_hash
    h2 = build_policy(RedactionConfig(rules=(spec.with_changes(replacement="[Z]"),))).config_hash
    assert len({default, h1, h2}) == 3
