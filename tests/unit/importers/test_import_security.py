"""Import safety: no leaks, no copies, no filesystem or process use outside the safe module."""

import ast
import dataclasses
import json
import tempfile
from pathlib import Path

import pytest

from soerm.domain.enums import ImportSource
from soerm.domain.imports import ImportReport
from soerm.services.errors import ImportServiceError
from tests.unit.importers.helpers import (
    CSV_MAPPING,
    JSON_MAPPING,
    SECRET,
    put,
    result,
    run,
    sarif,
    tree,
)

SRC = Path(__file__).resolve().parents[3] / "src" / "soerm"
IMPORTER_FILES = sorted((SRC / "importers").glob("*.py"))


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    put(root, "json.yaml", JSON_MAPPING)
    put(root, "csv.yaml", CSV_MAPPING)
    return root


def secret_inputs(ws: Path) -> list[tuple[str, ImportSource, str | None]]:
    leaked = f"password={SECRET} Authorization: Bearer {SECRET}"
    put(
        ws,
        "a.sarif",
        sarif(
            [
                result(
                    message={"text": leaked},
                    partialFingerprints={"k": f"token={SECRET}"},
                    locations=[
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"https://u:{SECRET}@h/p?t={SECRET}"},
                                "region": {"snippet": {"text": leaked}},
                            }
                        }
                    ],
                )
            ]
        ),
    )
    item = {
        "name": leaked,
        "detail": {"text": leaked, "evidence": leaked},
        "owner": f"api_key={SECRET}",
        "where": leaked,
    }
    put(ws, "a.json", json.dumps({"items": [item]}))
    put(
        ws,
        "a.csv",
        f'title,description,asset,evidence,severity\n"{leaked}","{leaked}","token={SECRET}","{leaked}",high\n',
    )
    return [
        ("a.sarif", ImportSource.SARIF, None),
        ("a.json", ImportSource.GENERIC_JSON, "json.yaml"),
        ("a.csv", ImportSource.CSV, "csv.yaml"),
    ]


def test_the_secret_is_absent_from_records_report_and_every_dump(ws: Path) -> None:
    for path, fmt, mapping in secret_inputs(ws):
        preview = run(ws, path, fmt, mapping)
        assert preview.report.accepted_records == 1
        assert SECRET not in repr(preview.report)
        assert SECRET not in repr(preview.records)
        for record in preview.records:
            assert SECRET not in record.model_dump_json()
            assert "REDACTED" in record.model_dump_json()
        assert preview.report.redaction_rule_hits


def test_exceptions_do_not_contain_the_secret_or_the_path(ws: Path) -> None:
    put(ws, f"{SECRET}.sarif", f'{{"version": "2.1.0", "runs": [], "x": "{SECRET}" ,}}')
    put(ws, "bad.yaml", f"format: csv\ncolumns: {{title: {SECRET}}}\nextra_{SECRET}: 1\n")
    cases = [
        (f"{SECRET}.sarif", ImportSource.SARIF, None),
        ("a.csv", ImportSource.CSV, "bad.yaml"),
        (f"../{SECRET}", ImportSource.SARIF, None),
    ]
    put(ws, "a.csv", f"title\n{SECRET}\n")
    for path, fmt, mapping in cases:
        with pytest.raises(ImportServiceError) as excinfo:
            run(ws, path, fmt, mapping)
        text = str(excinfo.value) + repr(excinfo.value.to_dict()) + repr(excinfo.value.args)
        assert SECRET not in text
        assert str(ws) not in text


def test_preview_writes_and_copies_nothing(ws: Path, tmp_path: Path) -> None:
    inputs = secret_inputs(ws)
    before = tree(tmp_path)
    temp_before = sorted(Path(tempfile.gettempdir()).glob("*"))
    for path, fmt, mapping in inputs:
        run(ws, path, fmt, mapping)
    assert tree(tmp_path) == before  # no new file, no changed file
    assert sorted(Path(tempfile.gettempdir()).glob("*")) == temp_before
    names = {p.name for p in ws.rglob("*")}
    assert "soerm.db" not in names
    assert ".soerm.lock" not in names
    assert not any(p.suffix in {".db", ".tmp", ".bak", ".orig"} for p in tmp_path.rglob("*"))


def test_input_files_are_never_modified(ws: Path) -> None:
    inputs = secret_inputs(ws)
    before = tree(ws)
    for path, fmt, mapping in inputs:
        run(ws, path, fmt, mapping)
    assert tree(ws) == before
    assert SECRET.encode() in (ws / "a.sarif").read_bytes()  # the original still has it


def test_report_has_exactly_the_documented_safe_fields() -> None:
    names = {f.name for f in dataclasses.fields(ImportReport)}
    assert names == {
        "source_name", "source_sha256", "format", "total_records", "accepted_records",
        "rejected_records", "warnings_count", "redaction_rule_hits", "records_with_provenance",
        "warning_codes", "rejections", "rejections_omitted", "config_hash",
    }  # fmt: skip
    assert not names & {"title", "description", "evidence", "path", "records"}


def test_rejections_are_capped_and_counted(ws: Path) -> None:
    put(ws, "a.json", json.dumps({"items": [{"name": None}] * 130}))
    report = run(ws, "a.json", ImportSource.GENERIC_JSON, "json.yaml").report
    assert report.rejected_records == 130
    assert len(report.rejections) == 100
    assert report.rejections_omitted == 30


def test_a_large_csv_is_processed_in_reasonable_time(ws: Path) -> None:
    rows = "".join(f"finding {i},desc {i},web,ev {i},low\n" for i in range(3000))
    put(ws, "big.csv", "title,description,asset,evidence,severity\n" + rows)
    report = run(ws, "big.csv", ImportSource.CSV, "csv.yaml").report
    assert report.accepted_records == 3000


def imports_of(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_only_the_safe_file_module_touches_the_filesystem() -> None:
    forbidden = {"os", "pathlib", "io", "tempfile", "shutil", "glob", "fileinput", "mmap"}
    for path in [
        *IMPORTER_FILES,
        SRC / "services" / "imports.py",
        SRC / "cli" / "import_commands.py",
    ]:
        if path.name == "safe_file.py":
            continue
        assert not imports_of(path) & forbidden, path.name
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Name):
                assert node.id != "open", path.name
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"open", "read_text", "read_bytes", "write_text"}, path.name


def test_no_network_process_or_dynamic_code_in_the_import_path() -> None:
    forbidden = {
        "socket", "ssl", "urllib", "http", "requests", "httpx", "subprocess", "importlib",
        "runpy", "pickle", "marshal", "shelve", "ctypes", "asyncio", "multiprocessing",
        "yaml",
    }  # fmt: skip
    for path in [*IMPORTER_FILES, SRC / "services" / "imports.py", SRC / "domain" / "imports.py"]:
        assert not imports_of(path) & forbidden, path.name
        tree_ = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree_):
            if isinstance(node, ast.Name):
                assert node.id not in {"eval", "exec", "compile", "__import__"}, path.name


def test_the_importers_never_import_the_database_or_services() -> None:
    for path in IMPORTER_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("soerm.")
            ):
                assert node.module.split(".")[1] in {"domain", "importers"}, path.name
        assert "sqlite3" not in imports_of(path)
