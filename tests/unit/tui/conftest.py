"""TUI fixtures: a populated workspace and a helper that drives the app without a terminal."""

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from soerm.services.workspace import Workspace
from soerm.tui.app import SoermApp
from soerm.tui.data import Snapshot, load_snapshot
from tests.unit.cli.conftest import ASSET_ARGS, Result, Runner, cli, workspace  # noqa: F401
from tests.unit.importers.helpers import put
from tests.unit.services.test_playbook_service import PLAYBOOK

SECRET = "hunter2-TOP-SECRET-token"
DESCRIPTION_MARKER = "DESCRIPTION-MARKER-z9"
EVIDENCE_MARKER = "EVIDENCE-MARKER-z9"
SUMMARY_MARKER = "SUMMARY-MARKER-z9"
INJECTION = "[bold red]boom[/] [link=https://example.invalid]x[/link]"


def run_ok(cli_runner: Runner, *argv: str) -> Result:
    result = cli_runner(*argv)
    assert result.code == 0, (argv, result.err)
    return result


@pytest.fixture
def populated(cli: Runner, workspace: Path) -> Path:  # noqa: F811
    w = ["--workspace", str(workspace)]
    a = [*w, "--actor", "alice"]
    run_ok(cli, "asset", "add", *a, *ASSET_ARGS)
    run_ok(
        cli, "finding", "add", *a, "--asset-id", "AST-000001", "--fingerprint", "a" * 64,
        "--title", f"SQL injection {INJECTION}", "--severity", "high",
        "--description", DESCRIPTION_MARKER, "--evidence", f"{EVIDENCE_MARKER} password={SECRET}",
    )  # fmt: skip
    run_ok(
        cli, "finding", "add", *a, "--asset-id", "AST-000001", "--fingerprint", "b" * 64,
        "--title", "Weak TLS", "--severity", "low",
    )  # fmt: skip
    run_ok(cli, "risk", "recalculate", *a, "--all")
    run_ok(cli, "task", "create", *a, "--title", "Patch it", "--owner", "ops",
           "--finding-id", "FND-000001")  # fmt: skip
    run_ok(cli, "incident", "create", *a, "--title", "Phish", "--severity", "high",
           "--owner", "ir", "--summary", f"{SUMMARY_MARKER} token: {SECRET}")  # fmt: skip
    put(workspace, "pb.yaml", PLAYBOOK)
    run_ok(cli, "playbook", "load", *a, "pb.yaml")
    run_ok(cli, "incident", "playbook", "attach", *a, "INC-000001", "phishing-triage")
    run_ok(cli, "incident", "playbook", "step", *a, "INC-000001", "step-001")
    run_ok(cli, "incident", "playbook", "request-approval", *a, "INC-000001", "step-004",
           "--reason", "block the domain")  # fmt: skip
    return workspace


@pytest.fixture
def snapshot(populated: Path) -> Snapshot:
    return load_snapshot(Workspace(populated))


def drive(
    workspace_path: Path,
    scenario: Callable[..., Awaitable[None]],
    size: tuple[int, int] = (140, 45),
) -> None:
    """Run ``scenario(app, pilot)`` against the real app on a virtual screen."""

    async def main() -> None:
        workspace_object = Workspace(workspace_path)
        app = SoermApp(workspace_object, load_snapshot(workspace_object))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await scenario(app, pilot)

    asyncio.run(main())
