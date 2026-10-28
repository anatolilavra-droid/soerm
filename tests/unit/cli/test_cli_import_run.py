"""``soerm import run``: write path, exit codes, no raw values in the output."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from tests.unit.cli.conftest import Runner, add_asset, assert_terminal_safe
from tests.unit.importers.helpers import CSV_MAPPING, SECRET, put, result, sarif


@pytest.fixture
def ws(cli: Runner, workspace: Path) -> Path:
    assert add_asset(cli, workspace).code == 0
    put(
        workspace,
        "a.sarif",
        sarif([result(message={"text": f"password={SECRET} Title-Marker"}), result(ruleId="R2")]),
    )
    return workspace


def run(cli: Runner, ws: Path, *extra: str, actor: str | None = "alice", path: str = "a.sarif"):  # type: ignore[no-untyped-def]
    args = ["import", "run", path, "--workspace", str(ws), "--format", "sarif"]
    if actor is not None:
        args += ["--actor", actor]
    return cli(*args, "--asset-id", "AST-000001", *extra)


def test_run_text_output_and_idempotence(cli: Runner, ws: Path) -> None:
    first = run(cli, ws)
    assert first.code == 0, first.err
    assert "imported" in first.out
    assert "RUN-000001" in first.out
    assert "findings_created:" in first.out
    assert SECRET not in first.out + first.err
    assert "Title-Marker" not in first.out
    assert_terminal_safe(first.out)
    again = run(cli, ws)
    assert again.code == 0
    assert "unchanged" in again.out
    assert "nothing to import" in again.out
    listing = cli("finding", "list", "--workspace", str(ws), "--json").json()
    assert len(listing["findings"]) == 2


def test_run_json_has_ids_and_counts_only(cli: Runner, ws: Path) -> None:
    out = run(cli, ws, "--json")
    data = json.loads(out.out)
    assert data["result"] == "imported"
    assert data["run_id"] == "RUN-000001"
    assert data["findings_created"] == 2
    assert data["finding_ids"] == ["FND-000001", "FND-000002"]
    assert data["redaction_rule_hits"]
    for forbidden in (SECRET, "Title-Marker", "evidence", "db.py"):
        assert forbidden not in out.out


def test_database_and_audit_hold_no_secret(cli: Runner, ws: Path) -> None:
    assert run(cli, ws).code == 0
    with closing(sqlite3.connect(ws / "soerm.db")) as raw:
        for table in ("findings", "audit_log", "import_runs", "finding_occurrences"):
            assert SECRET not in repr(raw.execute(f"SELECT * FROM {table}").fetchall())  # noqa: S608
        actions = [r[0] for r in raw.execute("SELECT action FROM audit_log ORDER BY seq")]
    assert actions == ["asset.create", "import.run", "finding.create", "finding.create"]


def test_csv_run_with_mapping_and_default_severity(cli: Runner, ws: Path) -> None:
    put(ws, "m.yaml", CSV_MAPPING)
    put(ws, "a.csv", "title,description,asset,evidence,severity\nNo severity,d,x,e,\n")
    base = ["import", "run", "a.csv", "--workspace", str(ws), "--format", "csv"]
    base += ["--mapping", "m.yaml", "--actor", "alice", "--asset-id", "AST-000001", "--json"]
    skipped = cli(*base)
    assert skipped.code == 0
    assert skipped.json()["skipped"] == {"missing_severity": 1}
    assert skipped.json()["result"] == "unchanged"
    created = cli(*base, "--default-severity", "low")
    assert created.json()["findings_created"] == 1


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        (["--default-severity", "none"], 2),
        (["--default-severity", "bogus"], 2),
        (["--mapping", "x.yaml"], 2),
    ],
)
def test_usage_errors(cli: Runner, ws: Path, extra: list[str], code: int) -> None:
    assert run(cli, ws, *extra).code == code


def test_actor_is_required(cli: Runner, ws: Path) -> None:
    assert run(cli, ws, actor=None).code == 2


def test_unknown_asset_and_missing_file_exit_1(cli: Runner, ws: Path) -> None:
    args = ["import", "run", "a.sarif", "--workspace", str(ws), "--format", "sarif"]
    bad_asset = cli(*args, "--actor", "alice", "--asset-id", "AST-000099")
    assert bad_asset.code == 1
    assert "not_found" in bad_asset.err
    assert run(cli, ws, path="missing.sarif").code == 1
    assert run(cli, ws, path="../outside.sarif").code == 1


def test_help_mentions_idempotence_and_audit(cli: Runner) -> None:
    out = cli("import", "run", "--help")
    assert out.code == 0
    assert "Repeating the same import changes nothing" in " ".join(out.out.split())
