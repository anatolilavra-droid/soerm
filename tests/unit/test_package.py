"""Package smoke tests: version, layout, entry point and declared dependencies."""

import importlib
import runpy
import sys
import tomllib
from pathlib import Path

import pytest

import soerm
from soerm.cli.main import EXIT_USAGE, main

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUBPACKAGES = ["domain", "storage", "importers", "services", "config", "cli"]


def _pyproject() -> dict[str, object]:
    data: dict[str, object] = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    return data


def test_version_matches_pyproject() -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    assert project["version"] == soerm.__version__


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_is_importable(name: str) -> None:
    assert importlib.import_module(f"soerm.{name}").__name__ == f"soerm.{name}"


def test_package_ships_py_typed_marker() -> None:
    assert soerm.__file__ is not None
    assert (Path(soerm.__file__).parent / "py.typed").is_file()


def test_console_script_points_to_main() -> None:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    target = project["scripts"]["soerm"]
    module_name, _, attribute = target.partition(":")
    assert getattr(importlib.import_module(module_name), attribute) is main


def test_runtime_dependencies_are_importable() -> None:
    pydantic = importlib.import_module("pydantic")
    yaml = importlib.import_module("yaml")
    assert pydantic.VERSION.startswith("2.")
    assert callable(yaml.safe_load)


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"soerm {soerm.__version__}"


def test_cli_without_arguments_prints_help_and_returns_usage_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([]) == EXIT_USAGE
    output = capsys.readouterr().out
    assert "usage: soerm" in output
    assert "never uses the network" in output


def test_cli_rejects_unknown_option(capsys: pytest.CaptureFixture[str]) -> None:
    # Since M3 usage errors are returned (not raised) so that no user value is echoed.
    assert main(["--no-such-option"]) == EXIT_USAGE
    captured = capsys.readouterr()
    assert "no-such-option" not in captured.err + captured.out
    assert "usage_error" in captured.err


def test_module_execution_matches_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["soerm", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("soerm", run_name="__main__")
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == f"soerm {soerm.__version__}"
