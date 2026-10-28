"""``soerm import preview``."""

import json
from pathlib import Path

import pytest

from tests.unit.cli.conftest import Runner, assert_terminal_safe
from tests.unit.importers.helpers import CSV_MAPPING, JSON_MAPPING, SECRET, put, result, sarif

CSV_TEXT = (
    "title,description,asset,evidence,severity\n"
    f'"Weak TLS","token={SECRET}",web,"Authorization: Bearer {SECRET}",high\n'
    ",no title,web,,low\n"
)


@pytest.fixture
def ws(workspace: Path) -> Path:
    put(
        workspace,
        "a.sarif",
        sarif([result(message={"text": f"password={SECRET}"}), result(message={})]),
    )
    put(workspace, "a.csv", CSV_TEXT)
    put(workspace, "csv.yaml", CSV_MAPPING)
    put(workspace, "a.json", json.dumps({"items": [{"name": f"api_key={SECRET}", "sev": "low"}]}))
    put(workspace, "json.yaml", JSON_MAPPING)
    return workspace


def preview(cli: Runner, ws: Path, path: str, *extra: str):  # type: ignore[no-untyped-def]
    return cli("import", "preview", path, "--workspace", str(ws), *extra)


def test_sarif_preview(cli: Runner, ws: Path) -> None:
    result_ = preview(cli, ws, "a.sarif", "--format", "sarif")
    assert result_.code == 0
    assert result_.err == ""
    assert "accepted_records: 1" in result_.out
    assert "rejected_records: 1" in result_.out
    assert "password=1" in result_.out
    assert "runs[0].results[1]" in result_.out
    assert "missing_message" in result_.out
    assert "preview only: nothing was written" in result_.out
    assert SECRET not in result_.out
    assert_terminal_safe(result_.out)


def test_csv_and_json_preview(cli: Runner, ws: Path) -> None:
    csv_result = preview(cli, ws, "a.csv", "--format", "csv", "--mapping", "csv.yaml")
    assert csv_result.code == 0
    assert "format:           csv" in csv_result.out
    assert "missing_required_field" in csv_result.out
    json_result = preview(cli, ws, "a.json", "--format", "json", "--mapping", "json.yaml")
    assert json_result.code == 0
    assert "format:           generic_json" in json_result.out
    for item in (csv_result, json_result):
        assert SECRET not in item.out + item.err
        assert "Weak TLS" not in item.out  # titles are never printed


def test_json_output_is_the_safe_report(cli: Runner, ws: Path) -> None:
    result_ = preview(cli, ws, "a.csv", "--format", "csv", "--mapping", "csv.yaml", "--json")
    assert result_.code == 0
    payload = result_.json()
    assert list(payload) == [
        "source_name", "source_sha256", "format", "total_records", "accepted_records",
        "rejected_records", "warnings_count", "warning_codes", "redaction_rule_hits",
        "records_with_provenance", "rejections", "rejections_omitted", "config_hash",
    ]  # fmt: skip
    assert payload["accepted_records"] == 1
    assert payload["redaction_rule_hits"] == {"authorization": 1, "token": 1}
    assert payload["rejections"] == [
        {"record_index": 1, "locator": "row 3", "field": "title", "code": "missing_required_field"}
    ]
    dumped = result_.out
    for forbidden in (SECRET, "Weak TLS", 'evidence":', 'description":', 'title":'):
        assert forbidden not in dumped


def test_preview_creates_no_database_and_takes_no_lock(cli: Runner, ws: Path) -> None:
    before = sorted(p.name for p in ws.iterdir())
    preview(cli, ws, "a.sarif", "--format", "sarif")
    preview(cli, ws, "a.csv", "--format", "csv", "--mapping", "csv.yaml")
    assert sorted(p.name for p in ws.iterdir()) == before
    assert not (ws / "soerm.db").exists()
    assert not (ws / ".soerm.lock").exists()


def test_absolute_path_inside_the_workspace_works(cli: Runner, ws: Path) -> None:
    result_ = preview(cli, ws, str(ws / "a.sarif"), "--format", "sarif")
    assert result_.code == 0


@pytest.mark.parametrize("path", ["../a.sarif", "/etc/passwd", "nope.sarif"])
def test_unsafe_or_missing_paths_exit_1_without_the_path(cli: Runner, ws: Path, path: str) -> None:
    result_ = preview(cli, ws, path, "--format", "sarif")
    assert result_.code == 1
    assert result_.err.startswith("error[import_error]")
    assert path not in result_.err
    assert str(ws) not in result_.err + result_.out


def test_symlink_and_outside_mapping(cli: Runner, ws: Path, tmp_path: Path) -> None:
    outside = put(tmp_path, "outside.yaml", CSV_MAPPING)
    (ws / "link.sarif").symlink_to(ws / "a.sarif")
    assert "symlink_not_allowed" in preview(cli, ws, "link.sarif", "--format", "sarif").err
    mapped = preview(cli, ws, "a.csv", "--format", "csv", "--mapping", str(outside))
    assert mapped.code == 1
    assert "path_outside_workspace" in mapped.err


def test_limit_errors_have_stable_codes(cli: Runner, ws: Path) -> None:
    put(ws, "soerm.yaml", "version: 1\nimports:\n  max_import_file_bytes: 1024\n")
    put(ws, "big.sarif", sarif() + " " * 2000)
    result_ = preview(cli, ws, "big.sarif", "--format", "sarif", "--json")
    assert result_.code == 1
    error = json.loads(result_.err)
    assert error["error"] == "import_error"
    assert "import_file_too_large" in error["message"]


def test_invalid_utf8_exit_code(cli: Runner, ws: Path) -> None:
    put(ws, "bad.csv", b"title\n\xff\n")
    result_ = preview(cli, ws, "bad.csv", "--format", "csv", "--mapping", "csv.yaml")
    assert result_.code == 1
    assert "invalid_utf8" in result_.err


def test_usage_errors_exit_2(cli: Runner, ws: Path) -> None:
    cases = [
        ["import", "preview", "a.sarif", "--workspace", str(ws)],  # --format is required
        ["import", "preview", "a.sarif", "--workspace", str(ws), "--format", "xml"],
        ["import", "preview", "a.sarif", "--format", "sarif"],  # --workspace is required
        ["import", "preview", "--workspace", str(ws), "--format", "sarif"],  # no PATH
        ["import", "preview", "a.sarif", "--workspace", str(ws), "--format", "sarif", "--bogus"],
        [
            "import",
            "preview",
            "a.sarif",
            "--workspace",
            str(ws),
            "--format",
            "sarif",
            "--mapping",
            "m.yaml",
        ],
        ["import", "preview", "a.csv", "--workspace", str(ws), "--format", "csv"],
        ["import", "preview", "a.json", "--workspace", str(ws), "--format", "json"],
        ["import", "run", "a.sarif", "--workspace", str(ws)],
        ["import"],
    ]
    for argv in cases:
        result_ = cli(*argv)
        assert result_.code == 2, argv
        assert SECRET not in result_.out + result_.err


def test_unknown_argument_values_are_not_echoed(cli: Runner, ws: Path) -> None:
    result_ = cli("import", "preview", "a.sarif", "--workspace", str(ws), "--format", SECRET)
    assert result_.code == 2
    assert SECRET not in result_.out + result_.err


def test_missing_workspace(cli: Runner, tmp_path: Path) -> None:
    result_ = cli(
        "import", "preview", "a.sarif", "--workspace", str(tmp_path / "gone"), "--format", "sarif"
    )
    assert result_.code == 1
    assert "not_found" in result_.err
    assert not (tmp_path / "gone").exists()


def test_a_broken_config_blocks_the_preview_without_leaking(cli: Runner, ws: Path) -> None:
    put(ws, "soerm.yaml", f"version: 1\nx: &a {SECRET}\n")
    result_ = preview(cli, ws, "a.sarif", "--format", "sarif")
    assert result_.code == 1
    assert "config_error" in result_.err
    assert SECRET not in result_.out + result_.err


def test_help_mentions_the_safety_properties(cli: Runner) -> None:
    out = " ".join(cli("import", "preview", "--help").out.split())
    assert "relative to the workspace" in out
    assert "Creates no database" in out
    assert "--format" in out
    assert "{csv,json,sarif}" in out
