"""Service fixtures: a workspace directory under pytest's tmp_path with a ticking clock."""

from pathlib import Path

import pytest

from soerm.services.workspace import Workspace
from tests.unit.services.helpers import ticking_clock
from tests.unit.storage.conftest import PROJECT_ROOT


@pytest.fixture(autouse=True)
def _workspace_is_outside_repository(tmp_path: Path) -> None:
    assert PROJECT_ROOT not in tmp_path.resolve().parents, "tests must not write into the repo"


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    return Workspace(tmp_path, clock=ticking_clock())
