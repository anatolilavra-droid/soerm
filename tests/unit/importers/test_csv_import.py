"""CSV with a declarative column mapping."""

from pathlib import Path

import pytest

from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.domain.errors import ValidationDomainError
from soerm.domain.imports import CsvMapping, parse_mapping
from soerm.services.errors import ImportServiceError
from tests.unit.importers.helpers import CSV_MAPPING, SECRET, config, put, run

CSV = ImportSource.CSV
HEADER = "title,description,asset,evidence,severity\n"


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    put(root, "map.yaml", CSV_MAPPING)
    return root


def load(ws: Path, content: str | bytes, mapping: str = "map.yaml"):  # type: ignore[no-untyped-def]
    put(ws, "in.csv", content)
    return run(ws, "in.csv", CSV, mapping)


def refused(ws: Path, content: str | bytes, mapping: str = "map.yaml") -> str:
    with pytest.raises(ImportServiceError) as excinfo:
        load(ws, content, mapping)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())
    return str(excinfo.value)


def test_header_mapping(ws: Path) -> None:
    preview = load(ws, HEADER + "Weak TLS,Old protocol,web-01,cipher list,Medium\n")
    record = preview.records[0]
    assert record.title == "Weak TLS"
    assert record.description == "Old protocol"
    assert record.asset_reference == "web-01"
    assert record.evidence == "cipher list"
    assert record.technical_severity is TechnicalSeverity.MEDIUM
    assert record.source is CSV
    assert preview.report.format == "csv"


def test_columns_may_be_in_any_order_and_names_are_exact(ws: Path) -> None:
    preview = load(ws, "severity,evidence,asset,description,title\nhigh,e,a,d,t\n")
    assert (preview.records[0].title, preview.records[0].technical_severity) == (
        "t", TechnicalSeverity.HIGH,
    )  # fmt: skip


def test_quoted_values_and_embedded_newlines(ws: Path) -> None:
    content = (
        HEADER
        + '"Title, with comma","He said ""hi""",web,"line one\nline two\r\nline three",high\n'
        + "Second,plain,web,,low\n"
    )
    preview = load(ws, content)
    first, second = preview.records
    assert first.title == "Title, with comma"
    assert first.description == 'He said "hi"'
    assert first.evidence == "line one\nline two\nline three"
    assert second.title == "Second"
    assert second.evidence == ""
    assert [r.provenance.csv_row for r in preview.records] == [2, 5]


def test_row_provenance(ws: Path) -> None:
    preview = load(ws, HEADER + "a,,,,\n\nb,,,,\nc,,,,\n")
    provenance = [r.provenance for r in preview.records]
    assert [(p.record_index, p.csv_row, p.json_pointer) for p in provenance] == [
        (0, 2, None), (1, 4, None), (2, 5, None),
    ]  # fmt: skip
    assert provenance[0].source_file_name == "in.csv"
    assert provenance[0].location == "row 2"
    assert provenance[0].source_file_sha256 == preview.report.source_sha256


@pytest.mark.parametrize("delimiter", [";", "|", "\\t"])
def test_delimiters(ws: Path, delimiter: str) -> None:
    put(ws, "m.yaml", CSV_MAPPING.replace('delimiter: ","', f'delimiter: "{delimiter}"'))
    real = "\t" if delimiter == "\\t" else delimiter
    content = real.join(["title", "severity"]) + "\n" + real.join(["a, b", "low"]) + "\n"
    put(
        ws,
        "m.yaml",
        f'format: csv\ndelimiter: "{delimiter}"\ncolumns: {{title: title, severity: severity}}\n',
    )
    preview = load(ws, content, "m.yaml")
    assert (preview.records[0].title, preview.records[0].technical_severity) == (
        "a, b", TechnicalSeverity.LOW,
    )  # fmt: skip


def test_unsupported_delimiters_are_rejected(ws: Path) -> None:
    for delimiter in ("ab", "", "x", " ", "\\n"):
        put(ws, "m.yaml", f'format: csv\ndelimiter: "{delimiter}"\ncolumns: {{title: t}}\n')
        assert "invalid_mapping" in refused(ws, "t\nx\n", "m.yaml")


def test_duplicate_headers_are_rejected(ws: Path) -> None:
    assert "duplicate_header" in refused(ws, "title,title,asset\nx,y,z\n")
    assert "duplicate_header" in refused(ws, "title,TITLE ,asset\n".replace("TITLE ", "title "))


def test_header_problems(ws: Path) -> None:
    assert "mapped_column_missing" in refused(ws, "title,description\nx,y\n")
    assert "empty_header_name" in refused(ws, HEADER.rstrip() + ",\nx,,,,,\n")
    assert "missing_header" in refused(ws, "")


def test_unknown_columns_need_an_explicit_setting(ws: Path) -> None:
    content = HEADER.rstrip() + ",extra\nx,,,,,ignored\n"
    assert "unknown_column" in refused(ws, content)
    put(ws, "m.yaml", CSV_MAPPING + "ignore_unknown_columns: true\n")
    preview = load(ws, content, "m.yaml")
    assert preview.report.accepted_records == 1
    assert "extra" not in repr(preview.records[0])


def test_too_many_columns(ws: Path) -> None:
    config(ws, "imports:\n  max_csv_columns: 5\n")
    wide = ",".join(f"c{i}" for i in range(6))
    assert "too_many_columns" in refused(ws, wide + "\n" + ",".join(["x"] * 6) + "\n")
    preview = load(ws, HEADER + "a,,,,\n" + ",".join(["x"] * 6) + "\n")
    assert [(r.code) for r in preview.report.rejections] == ["too_many_columns"]
    assert preview.report.accepted_records == 1


def test_oversized_row_is_rejected_without_the_value(ws: Path) -> None:
    config(ws, "imports:\n  max_csv_row_bytes: 512\n  max_field_bytes: 256\n")
    big = "x" * 400
    preview = load(ws, HEADER + f"ok,,,,\n{SECRET},{big},{big},,\n")
    assert preview.report.accepted_records == 1
    assert [(r.field, r.code) for r in preview.report.rejections] == [("row", "row_too_large")]
    assert SECRET not in repr(preview.report)


def test_a_single_huge_field_aborts_with_a_stable_code(ws: Path) -> None:
    config(ws, "imports:\n  max_csv_row_bytes: 512\n")
    message = refused(ws, HEADER + "x," + "y" * 2000 + ",,,\n")
    assert "malformed_csv" in message or "field_too_large" in message


def test_field_too_large_rejects_the_row(ws: Path) -> None:
    config(ws, "imports:\n  max_field_bytes: 64\n")
    preview = load(ws, HEADER + "ok,,,,\n" + f"t,{SECRET}{'z' * 100},,,\n")
    assert [(r.field, r.code) for r in preview.report.rejections] == [
        ("description", "field_too_large")
    ]


def test_wrong_column_count_and_blank_title(ws: Path) -> None:
    preview = load(ws, HEADER + "a,b\n" + ",,,,\n" + "good,,,,\n" + "x,y,z,w,v,extra\n")
    assert preview.report.accepted_records == 1
    assert [(r.index, r.code) for r in preview.report.rejections] == [
        (0, "column_count"), (1, "missing_required_field"), (3, "column_count"),
    ]  # fmt: skip


def test_too_many_rows(ws: Path) -> None:
    config(ws, "imports:\n  max_records: 2\n")
    assert load(ws, HEADER + "a,,,,\nb,,,,\n").report.total_records == 2
    assert "too_many_records" in refused(ws, HEADER + "a,,,,\nb,,,,\nc,,,,\n")


def test_invalid_utf8_and_nul(ws: Path) -> None:
    assert "invalid_utf8" in refused(ws, HEADER.encode() + b"caf\xe9,,,,\n")
    assert "nul_byte" in refused(ws, HEADER.encode() + b"a\x00b,,,,\n")


def test_bom_is_dropped_and_crlf_rows_work(ws: Path) -> None:
    preview = load(ws, "﻿" + HEADER.replace("\n", "\r\n") + "a,b,c,d,low\r\ne,f,g,h,low\r\n")
    assert [r.title for r in preview.records] == ["a", "e"]


def test_malformed_quotes(ws: Path) -> None:
    assert "malformed_csv" in refused(ws, HEADER + 'a,"unterminated,,,\n')


def test_formula_like_values_stay_plain_strings(ws: Path) -> None:
    formulas = ["=1+1", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", '=HYPERLINK("http://x")']
    content = HEADER + "".join(
        f'"{f.replace(chr(34), chr(34) * 2)}",{f.replace(",", " ")[:3]},,,\n' for f in formulas
    )
    preview = load(ws, content)
    assert [r.title for r in preview.records] == formulas
    assert preview.records[0].description == "=1+"


def test_headerless_csv_uses_indexes(ws: Path) -> None:
    put(ws, "m.yaml", "format: csv\nhas_header: false\ncolumns: {title: 1, severity: 0}\n")
    preview = load(ws, "high,First\nlow,Second\n", "m.yaml")
    assert [(r.title, r.technical_severity) for r in preview.records] == [
        ("First", TechnicalSeverity.HIGH), ("Second", TechnicalSeverity.LOW),
    ]  # fmt: skip
    assert [r.provenance.csv_row for r in preview.records] == [1, 2]
    assert [r.code for r in load(ws, "high\n", "m.yaml").report.rejections] == ["column_count"]


def test_csv_mapping_validation() -> None:
    base = {"format": "csv", "columns": {"title": "t"}}
    assert isinstance(parse_mapping(base, CSV), CsvMapping)
    for variant in (
        {**base, "columns": {"title": "t", "bogus": "x"}},
        {**base, "columns": {"description": "t"}},
        {**base, "columns": {"title": 5}},  # integer columns need has_header: false
        {**base, "columns": {"title": ""}},
        {**base, "columns": {"title": " t"}},
        {**base, "has_header": False, "columns": {"title": "t"}},
        {**base, "has_header": False, "columns": {"title": -1}},
        {**base, "has_header": False, "columns": {"title": True}},
        {**base, "has_header": "yes"},
        {**base, "ignore_unknown_columns": 1},
        {**base, "delimiter": "ab"},
        {**base, "unknown": 1},
        {**base, "format": "generic_json"},
    ):
        with pytest.raises(ValidationDomainError):
            parse_mapping(variant, CSV)


def test_redaction_of_csv_values(ws: Path) -> None:
    preview = load(
        ws, HEADER + f'"password={SECRET}","token: {SECRET}",web,"Cookie: s={SECRET}",high\n'
    )
    record = preview.records[0]
    assert SECRET not in record.model_dump_json()
    assert record.title == "password=[REDACTED]"
    assert dict(preview.report.redaction_rule_hits) == {"cookie": 1, "password": 1, "token": 1}
