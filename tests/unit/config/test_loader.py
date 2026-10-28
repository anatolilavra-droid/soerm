"""Safe YAML loading and the configuration schema."""

import os
from pathlib import Path

import pytest

from soerm.config import (
    CONFIG_FILE_NAME,
    MAX_CONFIG_BYTES,
    ConfigError,
    load_config,
    load_yaml_text,
    parse_config,
)
from soerm.domain.redaction import BUILTIN_NAMES, build_policy

SECRET = "S3cr3t-Value-9f2c"

VALID = """\
version: 1
redaction:
  max_input_bytes: 32768
  builtin_rules:
    bearer: false
  rules:
    - name: employee_id
      pattern: '\\bEMP-\\d{6}\\b'
      replacement: '[EMPLOYEE]'
      max_match_length: 64
    - name: iban
      pattern: '(?i)iban:\\s{0,2}(?P<secret>[A-Z0-9]{15,34})'
      enabled: false
"""


def write(path: Path, text: str | bytes) -> Path:
    target = path / CONFIG_FILE_NAME
    if isinstance(text, bytes):
        target.write_bytes(text)
    else:
        target.write_text(text, encoding="utf-8")
    return path


def reason(workspace: Path) -> str:
    with pytest.raises(ConfigError) as excinfo:
        load_config(workspace)
    error = excinfo.value
    assert SECRET not in str(error) + repr(error.to_dict()) + repr(error.args)
    return error.reason


def test_missing_file_means_defaults(tmp_path: Path) -> None:
    config, found = load_config(tmp_path)
    assert not found
    assert config.redaction.rules == ()
    assert [r.name for r in build_policy(config.redaction).rules] == list(BUILTIN_NAMES)


def test_valid_file(tmp_path: Path) -> None:
    config, found = load_config(write(tmp_path, VALID))
    assert found
    policy = build_policy(config.redaction)
    assert policy.max_input_bytes == 32768
    enabled = {rule.name: rule.enabled for rule in policy.rules}
    assert enabled["bearer"] is False
    assert enabled["employee_id"] is True
    assert enabled["iban"] is False
    assert [r.name for r in policy.rules][-2:] == ["employee_id", "iban"]


def test_hash_is_stable_across_loads_and_formatting(tmp_path: Path) -> None:
    first = build_policy(load_config(write(tmp_path, VALID))[0].redaction).config_hash
    reformatted = (
        "# comment\nredaction:\n  rules:\n"
        "  - {name: employee_id, pattern: '\\bEMP-\\d{6}\\b', replacement: '[EMPLOYEE]',"
        " max_match_length: 64}\n"
        "  - name: iban\n    enabled: false\n"
        "    pattern: '(?i)iban:\\s{0,2}(?P<secret>[A-Z0-9]{15,34})'\n"
        "  builtin_rules: {bearer: false}\n  max_input_bytes: 32768\nversion: 1\n"
    )
    second = build_policy(load_config(write(tmp_path, reformatted))[0].redaction).config_hash
    third = build_policy(load_config(write(tmp_path, VALID))[0].redaction).config_hash
    assert first == second == third
    changed = build_policy(
        load_config(write(tmp_path, VALID.replace("EMPLOYEE", "PERSON")))[0].redaction
    ).config_hash
    assert changed != first


def test_minimal_file(tmp_path: Path) -> None:
    config, _ = load_config(write(tmp_path, "version: 1\n"))
    assert config.redaction.max_input_bytes == 65536


# ---- the YAML subset -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("version: 1\nversion: 2\n", "yaml_duplicate_key"),
        ("redaction:\n  rules: []\n  rules: []\n", "yaml_duplicate_key"),
        ("a: &anchor 1\nversion: 1\n", "yaml_anchor"),
        ("a: &anchor [1]\nb: *anchor\nversion: 1\n", "yaml_anchor"),
        ("a: *missing\n", "yaml_alias"),
        ("version: 1\nredaction: !!python/object/apply:os.system ['echo x']\n", "yaml_tag"),
        ("version: 1\nx: !custom value\n", "yaml_tag"),
        ("version: !!int 1\n", "yaml_tag"),
        ("version: !!str 1\n", "yaml_tag"),
        ("x: !!binary aGk=\nversion: 1\n", "yaml_tag"),
        ("%TAG ! tag:example.com,2000:\n---\nversion: 1\nx: !foo bar\n", "yaml_tag"),
        ("base: &b {x: 1}\nmerged:\n  <<: *b\n", "yaml_anchor"),
        ("version: 1\nredaction:\n  <<: {max_input_bytes: 2048}\n", "yaml_merge_key"),
        ("? [a, b]\n: c\n", "yaml_key_not_string"),
        ("1: a\n", "yaml_key_not_string"),
        ("version: 1\n---\nversion: 1\n", "yaml_syntax"),
        ("version: [\n", "yaml_syntax"),
        ("[1, 2]\n", "config_not_a_mapping"),
        ("just text\n", "config_not_a_mapping"),
        ("", "config_empty"),
        ("# only a comment\n", "config_empty"),
        ("[" * 3000 + "]" * 3000, "yaml_too_deep"),
    ],
)
def test_unsafe_or_malformed_yaml_is_rejected(tmp_path: Path, text: str, expected: str) -> None:
    assert reason(write(tmp_path, text)) == expected


def test_yaml_errors_never_quote_the_file(tmp_path: Path) -> None:
    text = f"password: {SECRET}\n  bad: [{SECRET}\n"
    assert reason(write(tmp_path, text)) == "yaml_syntax"


def test_no_python_object_is_ever_constructed() -> None:
    with pytest.raises(ConfigError):
        load_yaml_text("!!python/name:os.system")
    assert load_yaml_text("a: [1, 2.5, true, null, text]") == {"a": [1, 2.5, True, None, "text"]}


# ---- file-level protections ----------------------------------------------------------------


def test_oversized_config_is_rejected(tmp_path: Path) -> None:
    ok = "version: 1\n# " + "x" * (MAX_CONFIG_BYTES - 20) + "\n"
    assert len(ok.encode()) <= MAX_CONFIG_BYTES
    load_config(write(tmp_path, ok))
    big = "version: 1\n# " + SECRET + "x" * MAX_CONFIG_BYTES + "\n"
    assert reason(write(tmp_path, big)) == "config_too_large"


def test_bad_encoding_and_control_characters(tmp_path: Path) -> None:
    assert reason(write(tmp_path, b"version: 1\n\xff\xfe\n")) == "config_not_utf8"
    assert reason(write(tmp_path, "version: 1\n\x00\n")) == "config_control_character"
    assert reason(write(tmp_path, "version: 1\n\x1b[31m\n")) == "config_control_character"
    load_config(write(tmp_path, "﻿version: 1\n"))


def test_only_regular_files_are_read(tmp_path: Path) -> None:
    target = tmp_path / CONFIG_FILE_NAME
    target.mkdir()
    assert reason(tmp_path) in {"config_unreadable", "config_not_regular_file"}
    target.rmdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("version: 1\n", encoding="utf-8")
    target.symlink_to(outside)
    assert reason(tmp_path) == "config_unreadable"  # O_NOFOLLOW: symlinks are not followed
    target.unlink()
    os.mkfifo(target)
    assert reason(tmp_path) == "config_not_regular_file"


# ---- schema --------------------------------------------------------------------------------


def rules_yaml(*rules: str) -> str:
    return "version: 1\nredaction:\n  rules:\n" + "".join(f"    - {r}\n" for r in rules)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("version: 2\n", "version"),
        ("version: '1'\n", "version"),
        ("version: true\n", "version"),
        ("redaction: {}\n", "version"),
        ("version: 1\nunknown: 1\n", "<value>: extra_forbidden"),
        ("version: 1\nredaction:\n  unknown: 1\n", "redaction.*: extra_forbidden"),
        ("version: 1\nredaction:\n  max_input_bytes: 10\n", "max_input_bytes"),
        ("version: 1\nredaction:\n  max_input_bytes: '2048'\n", "max_input_bytes"),
        ("version: 1\nredaction:\n  builtin_rules: {nope: false}\n", "unknown_builtin_rule"),
        ("version: 1\nredaction:\n  builtin_rules: {bearer: 'no'}\n", "builtin_rules"),
        (rules_yaml("{name: a, pattern: 'x{2}', flags: i}"), "extra_forbidden"),
        (rules_yaml("{name: a, pattern: 'x{2}', regex: y}"), "extra_forbidden"),
        (rules_yaml("{name: a}"), "pattern"),
        (rules_yaml("{pattern: 'x{2}'}"), "name"),
        (rules_yaml("{name: A, pattern: 'x{2}'}"), "invalid_rule_name"),
        (rules_yaml("{name: password, pattern: 'x{2}'}"), "duplicate_rule_name"),
        (rules_yaml("{name: a, pattern: 'x{2}'}", "{name: a, pattern: 'y{2}'}"), "duplicate"),
        (rules_yaml("{name: a, pattern: '(a+)+'}"), "pattern_unbounded_quantifier"),
        (rules_yaml("{name: a, pattern: '(a{1,5}){1,5}'}"), "pattern_nested_quantifier"),
        (rules_yaml("{name: a, pattern: 'a{1,9999}'}"), "pattern_quantifier_too_large"),
        (rules_yaml("{name: a, pattern: '(?s)a{1,2}'}"), "pattern_unsupported_group"),
        (rules_yaml("{name: a, pattern: '(x{2})\\1'}"), "pattern_backreference"),
        (rules_yaml("{name: a, pattern: " + repr("a" * 600) + "}"), "pattern_length"),
        (rules_yaml("{name: a, pattern: 'x{2}', replacement: \"a\\nb\"}"), "invalid_replacement"),
        (rules_yaml("{name: a, pattern: 'x{2}', replacement: \"a\\x1bb\"}"), "invalid_replacement"),
        (rules_yaml("{name: a, pattern: 'x{2}', replacement: ''}"), "invalid_replacement"),
        (rules_yaml("{name: a, pattern: 'x{2}', replacement: 5}"), "invalid_replacement"),
        (rules_yaml("{name: a, pattern: 'x{2}', enabled: 'false'}"), "enabled"),
        (rules_yaml("{name: a, pattern: 'x{2}', max_match_length: 0}"), "max_match_length"),
        (rules_yaml("{name: a, pattern: 'x{2}', max_match_length: 1.5}"), "max_match_length"),
        ("version: 1\nredaction:\n  rules: {a: b}\n", "rules"),
    ],
)
def test_schema_violations(tmp_path: Path, text: str, fragment: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(write(tmp_path, text))
    error = excinfo.value
    rendered = str(error)
    if "*" in fragment or "<" in fragment:
        assert fragment.split(":")[-1].strip() in rendered
    else:
        assert fragment in rendered
    assert "x{2}" not in rendered  # patterns are never echoed


def test_too_many_rules(tmp_path: Path) -> None:
    many = rules_yaml(*[f"{{name: r{i}, pattern: 'x{{2}}'}}" for i in range(33)])
    with pytest.raises(ConfigError) as excinfo:
        load_config(write(tmp_path, many))
    assert "too_many_rules" in str(excinfo.value)
    ok = rules_yaml(*[f"{{name: r{i}, pattern: 'x{{2}}'}}" for i in range(32)])
    load_config(write(tmp_path, ok))


def test_errors_never_contain_values(tmp_path: Path) -> None:
    text = rules_yaml(f"{{name: {SECRET}, pattern: '{SECRET}+', replacement: '{SECRET}\\n'}}")
    with pytest.raises(ConfigError) as excinfo:
        load_config(write(tmp_path, text))
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())


def test_parse_config_requires_a_mapping() -> None:
    with pytest.raises(ConfigError):
        parse_config(["version", 1])
    assert parse_config({"version": 1}).version == 1


# ---- imports section (M5) ------------------------------------------------------------------


def test_import_limits_defaults_and_overrides(tmp_path: Path) -> None:
    config, _ = load_config(write(tmp_path, "version: 1\n"))
    limits = config.imports
    assert (limits.max_import_file_bytes, limits.max_records, limits.max_json_depth) == (
        10 * 1024 * 1024, 50_000, 64,
    )  # fmt: skip
    assert (limits.max_field_bytes, limits.max_csv_row_bytes, limits.max_csv_columns) == (
        65_536, 262_144, 64,
    )  # fmt: skip
    text = "version: 1\nimports:\n  max_records: 10\n  max_csv_columns: 8\n"
    custom, _ = load_config(write(tmp_path, text))
    assert (custom.imports.max_records, custom.imports.max_csv_columns) == (10, 8)


@pytest.mark.parametrize(
    "line",
    [
        "max_records: 0",
        "max_records: 2000000",
        "max_records: '10'",
        "max_records: 1.5",
        "max_records: true",
        "max_json_depth: 1",
        "max_json_depth: 1000",
        "max_import_file_bytes: 10",
        "max_import_file_bytes: 99999999999",
        "max_field_bytes: 1",
        "max_csv_row_bytes: 10",
        "max_csv_columns: 5000",
        "unknown_limit: 5",
    ],
)
def test_import_limits_are_validated(tmp_path: Path, line: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(write(tmp_path, f"version: 1\nimports:\n  {line}\n"))
    assert "imports" in str(excinfo.value)
