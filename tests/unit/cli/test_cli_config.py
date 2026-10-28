"""``soerm config validate`` and CLI-level redaction behaviour."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.config import CONFIG_FILE_NAME
from tests.unit.cli.conftest import Runner, add_asset, add_finding, assert_terminal_safe

SECRET = "S3cr3t-Value-9f2c"
CUSTOM = (
    "version: 1\nredaction:\n  rules:\n"
    "    - {name: employee_id, pattern: '\\bEMP-\\d{6}\\b', replacement: '[EMPLOYEE]'}\n"
    "    - {name: off_rule, pattern: '\\d{9}', enabled: false}\n"
)


def validate(cli: Runner, workspace: Path, *extra: str):  # type: ignore[no-untyped-def]
    return cli("config", "validate", "--workspace", str(workspace), *extra)


def test_validate_without_a_file_uses_defaults(cli: Runner, workspace: Path) -> None:
    result = validate(cli, workspace)
    assert result.code == 0
    assert "built-in defaults" in result.out
    assert "password" in result.out
    assert "rules: 9 (9 enabled)" in result.out
    assert list(workspace.iterdir()) == []  # no database, no lock, no file


def test_validate_shows_names_flags_and_counts_only(cli: Runner, workspace: Path) -> None:
    (workspace / CONFIG_FILE_NAME).write_text(CUSTOM, encoding="utf-8")
    result = validate(cli, workspace)
    assert result.code == 0
    assert "employee_id" in result.out
    assert "off_rule" in result.out
    assert "rules: 11 (10 enabled)" in result.out
    assert "EMP-" not in result.out  # no patterns
    assert "[EMPLOYEE]" not in result.out  # no replacements
    assert "\\d" not in result.out
    assert_terminal_safe(result.out)
    assert sorted(p.name for p in workspace.iterdir()) == [CONFIG_FILE_NAME]


def test_validate_json(cli: Runner, workspace: Path) -> None:
    (workspace / CONFIG_FILE_NAME).write_text(CUSTOM, encoding="utf-8")
    payload = validate(cli, workspace, "--json").json()
    assert payload["result"] == "valid"
    assert payload["config_file"] == "found"
    assert len(payload["config_hash"]) == 64
    names = {rule["name"]: rule for rule in payload["rules"]}
    assert names["employee_id"] == {"name": "employee_id", "enabled": True, "builtin": False}
    assert names["off_rule"]["enabled"] is False
    assert names["password"]["builtin"] is True
    assert set(payload["rules"][0]) == {"name", "enabled", "builtin"}


@pytest.mark.parametrize(
    "text",
    [
        f"password: {SECRET}\nbad: [",
        f"version: 1\nx: &a {SECRET}\n",
        f"version: 1\nx: !custom {SECRET}\n",
        f"version: 1\nversion: 1\npassword: {SECRET}\n",
        f"version: 1\nredaction:\n  rules:\n    - {{name: a, pattern: '({SECRET}+)+'}}\n",
        "version: 1\nredaction:\n  rules:\n"
        f"    - {{name: a, pattern: 'x{{2}}', replacement: \"{SECRET}\\n\"}}\n",
        f"version: 1\nunknown_{SECRET}: 1\n",
    ],
)
def test_validate_reports_errors_with_exit_1_and_no_values(
    cli: Runner, workspace: Path, text: str
) -> None:
    (workspace / CONFIG_FILE_NAME).write_text(text, encoding="utf-8")
    for extra in ((), ("--json",)):
        result = validate(cli, workspace, *extra)
        assert result.code == 1
        assert "config_error" in result.err
        assert extra == () or json.loads(result.err)["error"] == "config_error"
        assert SECRET not in result.out + result.err
        assert_terminal_safe(result.err)
    assert sorted(p.name for p in workspace.iterdir()) == [CONFIG_FILE_NAME]


def test_oversized_config_exit_1(cli: Runner, workspace: Path) -> None:
    (workspace / CONFIG_FILE_NAME).write_text("version: 1\n# " + "x" * 70000, encoding="utf-8")
    result = validate(cli, workspace)
    assert result.code == 1
    assert "config_too_large" in result.err


def test_validate_requires_an_existing_workspace(cli: Runner, tmp_path: Path) -> None:
    result = validate(cli, tmp_path / "missing")
    assert result.code != 0
    assert not (tmp_path / "missing").exists()


def test_validate_only_reads_the_workspace_file(
    cli: Runner, workspace: Path, tmp_path: Path
) -> None:
    other = tmp_path / "elsewhere.yaml"
    other.write_text("not: [valid", encoding="utf-8")
    assert validate(cli, workspace).code == 0  # a stray file elsewhere is never consulted
    result = cli("config", "validate", "--workspace", str(workspace), "--config", str(other))
    assert result.code == 2  # there is no option to point at another file


def test_there_is_no_redact_command(cli: Runner) -> None:
    result = cli("redact", SECRET)
    assert result.code == 2
    assert SECRET not in result.out + result.err
    assert "redact" not in cli("--help").out.replace("redacted", "")


def test_help_texts_warn_about_shell_history(cli: Runner) -> None:
    for command in ("add", "update"):
        out = cli("finding", command, "--help").out
        flat = " ".join(out.split())
        assert "Command-line arguments may be stored in shell history" in flat
        assert "future file-based input mechanism after M4" in flat


def test_cli_add_redacts_and_never_prints_the_secret(cli: Runner, workspace: Path) -> None:
    assert add_asset(cli, workspace).code == 0
    result = add_finding(
        cli,
        workspace,
        "--evidence", f"password={SECRET} Authorization: Bearer {SECRET}",
        "--description", f"token: {SECRET}",
        "--owner", f"api_key={SECRET}",
        "--json",
    )  # fmt: skip
    assert result.code == 0
    assert SECRET not in result.out + result.err
    redaction = result.json()["redaction"]
    assert redaction["rule_hits"] == {"authorization": 1, "password": 1, "token": 1, "api_key": 1}
    assert redaction["truncated_fields"] == []
    assert len(redaction["config_hash"]) == 64
    table = add_finding(cli, workspace, "--evidence", f"token={SECRET}", fingerprint="b" * 64)
    assert "redaction_hits" in table.out
    assert "token=1" in table.out
    assert SECRET not in table.out + table.err
    ws = str(workspace)
    shown = (
        cli("finding", "show", "--workspace", ws, "FND-000001", "--show-evidence"),
        cli("finding", "show", "--workspace", ws, "FND-000001", "--json"),
        cli("finding", "list", "--workspace", ws, "--json"),
        cli("finding", "list", "--workspace", ws),
    )
    for item in shown:
        assert SECRET not in item.out + item.err
    revealed = shown[0].out
    assert "password=[REDACTED] Authorization: [REDACTED]" in revealed
    parsed = json.loads(shown[1].out)
    assert parsed["evidence"] == {
        "present": True,
        "bytes": len(b"password=[REDACTED] Authorization: [REDACTED]"),
    }


def test_cli_database_scan(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    add_finding(cli, workspace, "--evidence", f"password={SECRET}", "--title", f"t token={SECRET}")
    with closing(sqlite3.connect(workspace / "soerm.db")) as raw:
        dump = "\n".join(
            repr(row)
            for (name,) in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for row in raw.execute(f'SELECT * FROM "{name}"').fetchall()  # noqa: S608
        )
    assert SECRET not in dump
    assert "[REDACTED]" in dump


def test_cli_update_redacts_and_a_bad_config_blocks_mutations(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    add_finding(cli, workspace)
    ws = str(workspace)
    shown = cli("finding", "show", "--workspace", ws, "FND-000001", "--json").json()
    updated = cli(
        "finding", "update", "--workspace", ws, "--actor", "bob", "FND-000001",
        "--expect-hash", shown["hash"], "--evidence", f"cookie: sid={SECRET}", "--json",
    )  # fmt: skip
    assert updated.code == 0
    assert SECRET not in updated.out + updated.err
    assert updated.json()["redaction"]["rule_hits"] == {"cookie": 1}
    (workspace / CONFIG_FILE_NAME).write_text(f"version: 1\nx: &a {SECRET}\n", encoding="utf-8")
    blocked = add_finding(cli, workspace, fingerprint="c" * 64)
    assert blocked.code == 1
    assert "config_error" in blocked.err
    assert SECRET not in blocked.out + blocked.err
