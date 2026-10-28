"""``soerm finding ...`` end to end."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from tests.unit.cli.conftest import (
    FP,
    Runner,
    add_asset,
    add_finding,
    assert_terminal_safe,
    current_hash,
)
from tests.unit.services.helpers import SECRET

FINDING_KEYS = [
    "finding_id", "hash", "asset_id", "fingerprint", "title", "description", "status",
    "technical_severity", "business_priority", "risk_factors", "risk_formula_version",
    "risk_config_hash", "cvss_version", "cvss_vector", "cvss_score",
    "cvss_score_source", "owner", "source", "sla_due_at", "first_seen", "last_seen",
    "created_at", "updated_at", "evidence",
]  # fmt: skip


@pytest.fixture
def seeded(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    return workspace


def test_add_and_show(cli: Runner, seeded: Path) -> None:
    result = add_finding(cli, seeded, "--description", "Login form", "--owner", "team-a")
    assert result.code == 0
    assert "FND-000001" in result.out
    assert "audit_action:     finding.create" in result.out
    shown = cli("finding", "show", "--workspace", str(seeded), "FND-000001")
    assert shown.code == 0
    assert "SQL injection in login" in shown.out
    assert "Login form" in shown.out
    assert "status:" in shown.out
    assert_terminal_safe(shown.out)


def test_show_json_has_a_stable_field_order(cli: Runner, seeded: Path) -> None:
    add_finding(cli, seeded, "--cvss-score", "7.5",
                "--cvss-vector",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")  # fmt: skip
    data = cli("finding", "show", "--workspace", str(seeded), "FND-000001", "--json").json()
    assert list(data) == FINDING_KEYS
    assert (data["status"], data["technical_severity"], data["business_priority"]) == (
        "open",
        "high",
        None,
    )
    assert (data["cvss_version"], data["cvss_score"], data["cvss_score_source"]) == (
        "4.0",
        7.5,
        "imported",
    )


def test_unknown_asset_and_invalid_input(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    unknown = cli("finding", "add", "--workspace", ws, "--actor", "a", "--asset-id", "AST-000077",
                  "--fingerprint", FP, "--title", "t", "--severity", "low")  # fmt: skip
    assert (unknown.code, unknown.err.startswith("error[not_found]")) == (1, True)
    for fingerprint in ("A" * 64, "abc", "z" * 64):
        result = add_finding(cli, seeded, fingerprint=fingerprint)
        assert result.code == 1
        assert fingerprint not in result.err
    assert cli("finding", "list", "--workspace", ws).out.count("FND-") == 0


def test_evidence_is_shortened_after_redaction_and_oversized_input_is_refused(
    cli: Runner, seeded: Path
) -> None:
    assert add_finding(cli, seeded, "--evidence", "x" * 4096).code == 0
    shortened = add_finding(cli, seeded, "--evidence", "y" * 4100, "--json", fingerprint="b" * 64)
    assert shortened.code == 0
    assert shortened.json()["redaction"]["truncated_fields"] == ["evidence"]
    result = add_finding(cli, seeded, "--evidence", SECRET + "x" * 70000, fingerprint="c" * 64)
    assert result.code == 1
    assert "evidence: input_too_large" in result.err
    assert SECRET not in result.err


def test_the_cli_stores_redacted_evidence_and_does_not_leak_it(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    evidence = f"password={SECRET}"
    added = add_finding(cli, seeded, "--evidence", evidence, "--json")
    assert added.code == 0
    assert SECRET not in added.out + added.err
    show = cli("finding", "show", "--workspace", ws, "FND-000001")
    show_json = cli("finding", "show", "--workspace", ws, "FND-000001", "--json")
    listing = cli("finding", "list", "--workspace", ws)
    listing_json = cli("finding", "list", "--workspace", ws, "--json")
    for result in (show, show_json, listing, listing_json):
        assert SECRET not in result.out + result.err
    assert json.loads(show_json.out)["evidence"] == {
        "present": True,
        "bytes": len("password=[REDACTED]"),
    }
    assert "hidden" in show.out
    revealed = cli("finding", "show", "--workspace", ws, "FND-000001", "--show-evidence")
    assert "password=[REDACTED]" in revealed.out
    assert SECRET not in revealed.out
    combined = cli("finding", "show", "--workspace", ws, "FND-000001", "--show-evidence", "--json")
    assert combined.code == 2
    assert SECRET not in combined.out + combined.err


def test_evidence_and_text_never_reach_the_audit_log(cli: Runner, seeded: Path) -> None:
    add_finding(cli, seeded, "--evidence", f"e {SECRET}", "--description", f"d {SECRET}")
    h = current_hash(cli, seeded, "finding", "FND-000001")
    cli("finding", "update", "--workspace", str(seeded), "--actor", "bob", "FND-000001",
        "--expect-hash", h, "--evidence", f"e2 {SECRET}",
        "--title", f"t {SECRET}")  # fmt: skip
    with closing(sqlite3.connect(seeded / "soerm.db")) as raw:
        dump = repr(raw.execute("SELECT * FROM audit_log").fetchall())
    assert SECRET not in dump


def test_update_flow_and_audit_event(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    add_finding(cli, seeded)
    h = current_hash(cli, seeded, "finding", "FND-000001")
    result = cli("finding", "update", "--workspace", ws, "--actor", "Bob", "FND-000001",
                 "--expect-hash", h, "--status", "triaged", "--severity", "critical",
                 "--owner", "team-b", "--json")  # fmt: skip
    assert result.code == 0
    payload = result.json()
    assert payload["before_hash"] == h
    assert payload["audit"]["action"] == "finding.update"
    assert payload["audit"]["seq"] == 3
    shown = cli("finding", "show", "--workspace", ws, "FND-000001", "--json").json()
    assert (shown["status"], shown["technical_severity"], shown["owner"]) == (
        "triaged",
        "critical",
        "team-b",
    )
    assert shown["hash"] == payload["after_hash"]
    cleared = cli("finding", "update", "--workspace", ws, "--actor", "bob", "FND-000001",
                  "--expect-hash", str(shown["hash"]), "--clear-owner", "--json")  # fmt: skip
    assert cleared.code == 0
    assert cli("finding", "show", "--workspace", ws, "FND-000001", "--json").json()["owner"] is None


def test_update_conflict(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    add_finding(cli, seeded)
    h = current_hash(cli, seeded, "finding", "FND-000001")
    base = ("finding", "update", "--workspace", ws, "--actor", "bob", "FND-000001")
    assert cli(*base, "--expect-hash", h, "--title", "A").code == 0
    stale = cli(*base, "--expect-hash", h, "--title", "B")
    assert stale.code == 1
    assert stale.err.startswith("error[conflict]")
    assert cli("finding", "show", "--workspace", ws, "FND-000001", "--json").json()["title"] == "A"


@pytest.mark.parametrize("status", ["accepted_risk", "false_positive"])
def test_gated_statuses_exit_4(cli: Runner, seeded: Path, status: str) -> None:
    add_finding(cli, seeded)
    h = current_hash(cli, seeded, "finding", "FND-000001")
    result = cli("finding", "update", "--workspace", str(seeded), "--actor", "bob", "FND-000001",
                 "--expect-hash", h, "--status", status)  # fmt: skip
    assert result.code == 4
    assert result.err.startswith("error[approval_required]")
    assert current_hash(cli, seeded, "finding", "FND-000001") == h


@pytest.mark.parametrize("priority", ["p1", "p2", "p3", "p4"])
def test_business_priority_exit_4(cli: Runner, seeded: Path, priority: str) -> None:
    add_finding(cli, seeded)
    h = current_hash(cli, seeded, "finding", "FND-000001")
    result = cli("finding", "update", "--workspace", str(seeded), "--actor", "bob", "FND-000001",
                 "--expect-hash", h, "--business-priority", priority, "--json")  # fmt: skip
    assert result.code == 4
    assert json.loads(result.err)["error"] == "approval_required"
    assert current_hash(cli, seeded, "finding", "FND-000001") == h


def test_add_has_no_way_to_set_priority_or_gated_status(cli: Runner, seeded: Path) -> None:
    for option, value in (("--business-priority", "p1"), ("--status", "accepted_risk")):
        assert add_finding(cli, seeded, option, value).code == 2


def test_list_filters_and_sort(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    add_finding(cli, seeded, fingerprint="1" * 64)
    cli("finding", "add", "--workspace", ws, "--actor", "a", "--asset-id", "AST-000001",
        "--fingerprint", "2" * 64, "--title", "Second", "--severity", "critical")  # fmt: skip
    all_rows = cli("finding", "list", "--workspace", ws)
    assert all_rows.out.splitlines()[0].split() == [
        "ID", "STATUS", "SEVERITY", "PRIORITY", "ASSET", "TITLE",
    ]  # fmt: skip
    assert [line.split()[0] for line in all_rows.out.splitlines()[1:]] == [
        "FND-000001",
        "FND-000002",
    ]
    critical = cli("finding", "list", "--workspace", ws, "--severity", "critical", "--json").json()
    assert [f["finding_id"] for f in critical["findings"]] == ["FND-000002"]
    assert list(critical["findings"][0]) == FINDING_KEYS
    recent = cli("finding", "list", "--workspace", ws, "--sort", "last_seen", "--json").json()
    assert [f["finding_id"] for f in recent["findings"]] == ["FND-000002", "FND-000001"]
    by_asset = cli(
        "finding", "list", "--workspace", ws, "--asset-id", "AST-000001", "--status", "open"
    )
    assert by_asset.out.count("FND-") == 2
    assert cli("finding", "list", "--workspace", ws, "--asset-id", "x' OR 1=1").code == 1


def test_missing_objects(cli: Runner, seeded: Path) -> None:
    ws = str(seeded)
    assert cli("finding", "show", "--workspace", ws, "FND-000001").code == 1
    h = "0" * 64
    result = cli("finding", "update", "--workspace", ws, "--actor", "a", "FND-000001",
                 "--expect-hash", h, "--title", "x")  # fmt: skip
    assert (result.code, result.err.startswith("error[not_found]")) == (1, True)
