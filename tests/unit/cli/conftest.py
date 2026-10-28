"""CLI fixtures: run ``soerm.cli.main.main`` in-process and capture its output."""

import json
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from soerm.cli.main import main
from tests.unit.storage.conftest import PROJECT_ROOT


@dataclass(frozen=True)
class Result:
    code: int
    out: str
    err: str

    def json(self) -> Any:
        return json.loads(self.out)


Runner = Callable[..., Result]


@pytest.fixture(autouse=True)
def _outside_repository(tmp_path: Path) -> None:
    assert PROJECT_ROOT not in tmp_path.resolve().parents, "tests must not write into the repo"


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Runner:
    def run(*argv: str) -> Result:
        try:
            code = main(list(argv))
        except SystemExit as exc:  # --help and --version
            code = exc.code if isinstance(exc.code, int) else 0
        captured = capsys.readouterr()
        return Result(code, captured.out, captured.err)

    return run


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    path = tmp_path / "workspace"
    path.mkdir()
    return path


ASSET_ARGS = (
    "--name", "Billing API", "--owner", "platform", "--environment", "production",
    "--criticality", "high", "--classification", "confidential", "--exposure", "internet",
)  # fmt: skip
FP = "a" * 64


def add_asset(cli: Runner, workspace: Path, *extra: str, actor: str = "alice") -> Result:
    return cli("asset", "add", "--workspace", str(workspace), "--actor", actor, *ASSET_ARGS, *extra)


def add_finding(cli: Runner, workspace: Path, *extra: str, fingerprint: str = FP) -> Result:
    return cli(
        "finding", "add", "--workspace", str(workspace), "--actor", "alice",
        "--asset-id", "AST-000001", "--fingerprint", fingerprint,
        "--title", "SQL injection in login", "--severity", "high", *extra,
    )  # fmt: skip


def current_hash(cli: Runner, workspace: Path, kind: str, object_id: str) -> str:
    result = cli(kind, "show", "--workspace", str(workspace), object_id, "--json")
    assert result.code == 0, result.err
    value = result.json()["hash"]
    assert isinstance(value, str)
    return value


def assert_terminal_safe(text: str) -> None:
    """No ANSI/escape sequences and no control, format or surrogate characters."""
    for char in text:
        if char == "\n":
            continue
        category = unicodedata.category(char)
        assert category not in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}, repr(char)
        assert char == " " or category != "Zs", repr(char)
    assert "\x1b" not in text
