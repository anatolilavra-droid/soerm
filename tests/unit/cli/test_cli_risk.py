"""``soerm risk preview|recalculate``: no hidden mutation, exit codes, safe output."""

from pathlib import Path

import pytest

from tests.unit.cli.conftest import Runner, add_asset, add_finding, assert_terminal_safe
from tests.unit.importers.helpers import config, put

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    out = add_finding(
        cli,
        workspace,
        "--cvss-vector",
        VECTOR,
        "--cvss-score",
        "9.3",
        "--evidence",
        "ev-marker",
    )
    assert out.code == 0, out.err
    return workspace


def risk(cli: Runner, ws: Path, verb: str, *extra: str, actor: bool = False):  # type: ignore[no-untyped-def]
    args = ["risk", verb, "--workspace", str(ws)]
    if actor:
        args += ["--actor", "alice"]
    return cli(*args, *extra)


def show(cli: Runner, ws: Path) -> dict[str, object]:
    out = cli("finding", "show", "FND-000001", "--workspace", str(ws), "--json")
    assert out.code == 0
    data = out.json()
    assert isinstance(data, dict)
    return data


def test_preview_is_read_only_and_explains(cli: Runner, ws: Path) -> None:
    before = (ws / "soerm.db").read_bytes()
    out = risk(cli, ws, "preview", "FND-000001")
    assert out.code == 0, out.err
    assert "P1" in out.out
    assert "preview only: nothing was written" in out.out
    for factor in ("severity", "asset_criticality", "exposure", "environment", "sla"):
        assert factor in out.out
    assert "cvss_computed_score" in out.out
    assert "9.3" in out.out
    assert "ev-marker" not in out.out
    assert_terminal_safe(out.out)
    assert (ws / "soerm.db").read_bytes() == before
    assert show(cli, ws)["business_priority"] is None


def test_recalculate_requires_actor_and_stores(cli: Runner, ws: Path) -> None:
    assert risk(cli, ws, "recalculate", "--all").code == 2  # --actor is required
    out = risk(cli, ws, "recalculate", "--all", actor=True)
    assert out.code == 0, out.err
    assert "recalculated and stored" in out.out
    data = show(cli, ws)
    assert data["business_priority"] == "p1"
    assert data["risk_formula_version"] == "risk-v1"
    assert data["sla_due_at"]
    again = risk(cli, ws, "recalculate", "--all", "--json", actor=True)
    assert again.json()["changed"] == 0
    assert again.json()["audit_entries"] == 0


def test_json_output_is_value_free(cli: Runner, ws: Path) -> None:
    out = risk(cli, ws, "recalculate", "FND-000001", "--json", actor=True)
    data = out.json()
    assert data["result"] == "recalculated"
    assert data["changed"] == 1
    item = data["findings"][0]
    assert item["business_priority"] == "p1"
    assert item["cvss"]["computed_score"] == 9.3
    assert item["cvss"]["score_matches"] is True
    assert next(line["factor"] for line in item["explanation"]) == "severity"
    assert "ev-marker" not in out.out
    assert "SQL injection" not in out.out  # titles are not printed


def test_target_errors(cli: Runner, ws: Path) -> None:
    assert risk(cli, ws, "preview").code == 1  # neither id nor --all
    assert risk(cli, ws, "preview", "FND-000001", "--all").code == 1
    assert risk(cli, ws, "preview", "FND-000099").code == 1
    assert risk(cli, ws, "preview", "bogus").code == 1


def test_config_changes_flow_through(cli: Runner, ws: Path) -> None:
    config(ws, "risk:\n  severity_points: {none: 0, low: 1, medium: 2, high: 3, critical: 4}\n")
    out = risk(cli, ws, "preview", "--all", "--json")
    assert out.json()["findings"][0]["business_priority"] == "p4"
    put(ws, "soerm.yaml", "version: 1\nrisk:\n  thresholds: {p1: 1, p2: 2, p3: 3}\n")
    assert risk(cli, ws, "preview", "--all").code == 1  # invalid model is refused


def test_config_validate_shows_the_risk_hash(cli: Runner, ws: Path) -> None:
    out = cli("config", "validate", "--workspace", str(ws), "--json")
    assert len(out.json()["risk_config_hash"]) == 64


def test_invalid_vector_is_refused_on_add(cli: Runner, workspace: Path) -> None:
    assert add_asset(cli, workspace).code == 0
    out = add_finding(cli, workspace, "--cvss-vector", "CVSS:4.0/AV:N/AC:L")
    assert out.code == 1
    assert "cvss" in out.err
