"""Parser behaviour: help, usage errors, exit codes, no echo of user values."""

import json
from pathlib import Path

import pytest

from soerm.cli import main as main_module
from soerm.services import assets as asset_service
from tests.unit.cli.conftest import (
    ASSET_ARGS,
    FP,
    Runner,
    add_asset,
    add_finding,
    assert_terminal_safe,
    current_hash,
)
from tests.unit.services.helpers import SECRET

COMMANDS = [
    (),
    ("asset",),
    ("finding",),
    ("asset", "add"),
    ("asset", "show"),
    ("asset", "list"),
    ("asset", "update"),
    ("finding", "add"),
    ("finding", "show"),
    ("finding", "list"),
    ("finding", "update"),
]


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: " ".join(c) or "soerm")
def test_every_command_has_help(cli: Runner, command: tuple[str, ...]) -> None:
    result = cli(*command, "--help")
    assert result.code == 0
    assert result.out.startswith("usage: soerm")
    assert result.err == ""
    assert_terminal_safe(result.out)


@pytest.mark.parametrize("command", [c for c in COMMANDS if len(c) == 2], ids=lambda c: " ".join(c))
def test_leaf_help_documents_the_workspace_option(cli: Runner, command: tuple[str, ...]) -> None:
    assert "--workspace" in cli(*command, "--help").out


def test_mutating_commands_document_the_actor(cli: Runner) -> None:
    for command in (
        ("asset", "add"),
        ("asset", "update"),
        ("finding", "add"),
        ("finding", "update"),
    ):
        assert "--actor" in cli(*command, "--help").out
    for command in (("asset", "show"), ("asset", "list"), ("finding", "show"), ("finding", "list")):
        assert "--actor" not in cli(*command, "--help").out


def test_version_still_works(cli: Runner) -> None:
    assert cli("--version").out.startswith("soerm ")


def test_no_command_prints_help_and_fails(cli: Runner) -> None:
    result = cli()
    assert result.code == 2
    assert "usage: soerm" in result.out


@pytest.mark.parametrize(
    "argv",
    [
        ("bogus",),
        ("asset", "bogus"),
        ("asset", "list", "--workspace", "W", "--bogus", SECRET),
        ("asset", "list", "--workspace", "W", SECRET),
        ("asset", "list", "--workspace", "W", "--environment", SECRET),
        ("asset", "list", "--workspace", "W", "--sort", SECRET),
        ("asset", "list", "--workspace", "W", "--env", "test"),  # abbreviations are refused
        ("asset", "list", "--workspace"),
        ("asset", "list"),
        ("asset", "show", "--workspace", "W"),
        ("finding", "list", "--workspace", "W", "--status", SECRET),
        ("finding", "list", "--workspace", "W", "--severity", SECRET),
        ("finding", "list", "--workspace", "W", "--asset-id"),
        ("--json", SECRET),
        (SECRET,),
        (f"--{SECRET}",),
        ("asset", "list", f"--workspace={SECRET}", "--json=1"),
    ],
)
def test_usage_errors_exit_2_and_never_echo_values(cli: Runner, argv: tuple[str, ...]) -> None:
    result = cli(*argv)
    assert result.code == 2
    assert result.out == ""
    assert SECRET not in result.err
    assert "error[usage_error]" in result.err
    assert_terminal_safe(result.err)


def test_missing_actor_is_a_usage_error_for_every_mutation(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    cases = [
        ("asset", "add", "--workspace", ws, *ASSET_ARGS),
        ("asset", "update", "--workspace", ws, "AST-000001", "--expect-hash", "0" * 64,
         "--name", "x"),
        ("finding", "add", "--workspace", ws, "--asset-id", "AST-000001", "--fingerprint", FP,
         "--title", "t", "--severity", "low"),
        ("finding", "update", "--workspace", ws, "FND-000001", "--expect-hash", "0" * 64,
         "--title", "x"),
    ]  # fmt: skip
    for argv in cases:
        result = cli(*argv)
        assert result.code == 2
        assert "--actor" in result.err
    assert list(workspace.iterdir()) == []


def test_update_requires_the_expected_hash(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    result = cli("asset", "update", "--workspace", str(workspace), "--actor", "a", "AST-000001",
                 "--name", "x")  # fmt: skip
    assert result.code == 2
    assert "--expect-hash" in result.err


def test_invalid_numbers_are_usage_errors(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    result = add_finding(cli, workspace, "--cvss-score", SECRET)
    assert result.code == 2
    assert SECRET not in result.err


def test_conflicting_options_are_usage_errors(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    h = current_hash(cli, workspace, "asset", "AST-000001")
    result = cli("asset", "update", "--workspace", str(workspace), "--actor", "a", "AST-000001",
                 "--expect-hash", h, "--tag", "x", "--clear-tags")  # fmt: skip
    assert result.code == 2
    assert "cannot be combined" in result.err


def test_exit_codes(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    assert add_asset(cli, workspace).code == 0
    assert cli("asset", "show", "--workspace", ws, "AST-000099").code == 1  # not_found
    assert cli("asset", "show", "--workspace", ws, "bogus").code == 1  # invalid_input
    assert add_finding(cli, workspace, fingerprint="bad").code == 1  # invalid_input
    assert add_finding(cli, workspace).code == 0
    assert add_finding(cli, workspace).code == 1  # constraint_violation (same fingerprint)
    h = current_hash(cli, workspace, "finding", "FND-000001")
    update = ("finding", "update", "--workspace", ws, "--actor", "a", "FND-000001")
    assert cli(*update, "--expect-hash", "0" * 64, "--title", "x").code == 1  # conflict
    assert cli(*update, "--expect-hash", h, "--business-priority", "p1").code == 4
    assert cli(*update, "--expect-hash", h, "--status", "accepted_risk").code == 4
    assert cli(*update, "--expect-hash", h, "--status", "false_positive").code == 4
    assert cli("asset", "bogus").code == 2


def test_error_codes_are_reported_on_stderr(cli: Runner, workspace: Path) -> None:
    ws = str(workspace)
    add_asset(cli, workspace)
    expectations = {
        ("asset", "show", "--workspace", ws, "AST-000099"): "not_found",
        ("asset", "show", "--workspace", ws, "x"): "invalid_input",
    }
    for argv, code in expectations.items():
        result = cli(*argv)
        assert result.out == ""
        assert result.err.startswith(f"error[{code}]:")


def test_json_errors_are_json_on_stderr(cli: Runner, workspace: Path) -> None:
    add_asset(cli, workspace)
    result = cli("asset", "show", "--workspace", str(workspace), "AST-000099", "--json")
    assert result.out == ""
    error = json.loads(result.err)
    assert list(error) == ["error", "message", "details"]
    assert error["error"] == "not_found"


def test_unexpected_exceptions_hide_details_and_traceback(
    cli: Runner,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(asset_service, "list_assets", explode)
    result = cli("asset", "list", "--workspace", str(workspace))
    assert result.code == 3
    assert SECRET not in result.err + result.out
    assert "Traceback" not in result.err
    assert result.err.startswith("error[integrity_error]")


def test_exit_code_table() -> None:
    assert (
        main_module.EXIT_OK,
        main_module.EXIT_ERROR,
        main_module.EXIT_USAGE,
        main_module.EXIT_INTEGRITY,
        main_module.EXIT_APPROVAL_REQUIRED,
    ) == (0, 1, 2, 3, 4)
