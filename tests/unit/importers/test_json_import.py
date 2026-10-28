"""Generic JSON with a declarative mapping."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.domain.errors import ValidationDomainError
from soerm.domain.imports import JsonMapping, parse_mapping, parse_path
from soerm.services.errors import ImportServiceError
from tests.unit.importers.helpers import JSON_MAPPING, SECRET, config, put, run

JSON = ImportSource.GENERIC_JSON


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    put(root, "map.yaml", JSON_MAPPING)
    return root


def document(*items: Any) -> str:
    return json.dumps({"items": list(items)})


def item(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "Open redirect",
        "detail": {"text": "redirect target is not checked", "evidence": "GET /r?u=evil"},
        "owner": "team-a",
        "sev": "High",
        "cvss": {
            "score": 7.5,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        },
        "where": "app/redirect.py:10",
    }
    data.update(overrides)
    return data


def test_valid_generic_json(ws: Path) -> None:
    put(ws, "in.json", document(item()))
    preview = run(ws, "in.json", JSON, "map.yaml")
    record = preview.records[0]
    assert record.title == "Open redirect"
    assert record.description == "redirect target is not checked"
    assert record.evidence == "GET /r?u=evil"
    assert record.owner == "team-a"
    assert record.technical_severity is TechnicalSeverity.HIGH
    assert record.cvss_score == 7.5
    assert record.cvss_vector is not None
    assert record.location == "app/redirect.py:10"
    assert record.source is JSON
    report = preview.report
    assert (report.total_records, report.accepted_records, report.rejected_records) == (1, 1, 0)
    assert report.format == "generic_json"


def test_source_hash_and_provenance_pointer(ws: Path) -> None:
    text = document(item(), item(name="Second"))
    put(ws, "in.json", text)
    preview = run(ws, "in.json", JSON, "map.yaml")
    assert preview.report.source_sha256 == hashlib.sha256(text.encode()).hexdigest()
    first, second = (r.provenance for r in preview.records)
    assert first.source_file_name == "in.json"
    assert first.source_file_sha256 == preview.report.source_sha256
    assert (first.record_index, first.json_pointer, first.csv_row) == (0, "/items/0", None)
    assert (second.record_index, second.json_pointer) == (1, "/items/1")
    assert second.location == "items[1]"
    assert preview.report.records_with_provenance == 2


def test_nested_records_path_pointer_and_root_array(ws: Path) -> None:
    put(ws, "map2.yaml", "format: generic_json\nrecords_path: a[].b[]\nfields: {title: t}\n")
    put(ws, "in.json", json.dumps({"a": [{"b": [{"t": "x"}, {"t": "y"}]}, {"b": [{"t": "z"}]}]}))
    preview = run(ws, "in.json", JSON, "map2.yaml")
    assert [r.provenance.json_pointer for r in preview.records] == [
        "/a/0/b/0", "/a/0/b/1", "/a/1/b/0",
    ]  # fmt: skip
    put(ws, "map3.yaml", "format: generic_json\nrecords_path: '[]'\nfields: {title: t}\n")
    put(ws, "root.json", json.dumps([{"t": "x"}]))
    assert run(ws, "root.json", JSON, "map3.yaml").records[0].provenance.json_pointer == "/0"


def test_pointer_escapes_special_characters(ws: Path) -> None:
    put(ws, "map2.yaml", "format: generic_json\nrecords_path: a-b[]\nfields: {title: t}\n")
    put(ws, "in.json", json.dumps({"a-b": [{"t": "x"}]}))
    assert run(ws, "in.json", JSON, "map2.yaml").records[0].provenance.json_pointer == "/a-b/0"


def test_optional_fields_become_none_and_nothing_is_invented(ws: Path) -> None:
    put(
        ws,
        "map2.yaml",
        "format: generic_json\nrecords_path: items[]\nfields: {title: name, owner: owner}\n",
    )
    put(ws, "in.json", document({"name": "Only a title"}))
    record = run(ws, "in.json", JSON, "map2.yaml").records[0]
    assert record.owner is None
    assert record.technical_severity is None
    assert record.cvss_score is None
    assert record.cvss_vector is None
    assert record.asset_reference is None
    assert record.description == ""
    assert record.evidence == ""


def test_missing_required_field_rejects_the_record_without_the_value(ws: Path) -> None:
    put(
        ws,
        "in.json",
        document(item(), item(name=None), {"detail": {"text": SECRET}}, item(name="  ")),
    )
    preview = run(ws, "in.json", JSON, "map.yaml")
    assert (preview.report.accepted_records, preview.report.rejected_records) == (1, 3)
    codes = {(r.index, r.field, r.code) for r in preview.report.rejections}
    assert codes == {
        (1, "title", "missing_required_field"),
        (2, "title", "missing_required_field"),
        (3, "title", "missing_required_field"),
    }
    assert SECRET not in repr(preview.report)


def test_non_object_records_and_wrong_types_are_rejected(ws: Path) -> None:
    put(ws, "in.json", document(item(), "text", 5, item(owner={"x": 1}), item(sev=["high"])))
    report = run(ws, "in.json", JSON, "map.yaml").report
    assert report.accepted_records == 1
    assert {(r.index, r.code) for r in report.rejections} == {
        (1, "record_not_object"), (2, "record_not_object"),
        (3, "invalid_field_type"), (4, "invalid_field_type"),
    }  # fmt: skip


def test_invalid_optional_values_warn_and_become_none(ws: Path) -> None:
    put(
        ws,
        "in.json",
        document(item(sev="bogus", cvss={"score": 99, "vector": "not-a-vector"}, **{"where": 5})),
    )
    preview = run(ws, "in.json", JSON, "map.yaml")
    record = preview.records[0]
    assert (record.technical_severity, record.cvss_score, record.cvss_vector) == (None, None, None)
    assert record.location == "5"
    assert dict(preview.report.warning_codes) == {
        "invalid_cvss_score": 1, "invalid_cvss_vector": 1, "invalid_severity": 1,
    }  # fmt: skip
    assert preview.report.warnings_count == 3


def test_malformed_json(ws: Path) -> None:
    for text in (
        '{"items": [',
        "",
        "not json",
        '{"items": [1,]}',
        '{"a": NaN}',
        '{"a": 1, "a": 2}',
    ):
        put(ws, "in.json", text)
        with pytest.raises(ImportServiceError) as excinfo:
            run(ws, "in.json", JSON, "map.yaml")
        assert "invalid_format" in str(excinfo.value)


def test_deep_nesting_is_refused_before_parsing(ws: Path) -> None:
    put(ws, "in.json", "[" * 5000 + "]" * 5000)
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "map.yaml")
    assert "json_too_deep" in str(excinfo.value)
    config(ws, "imports:\n  max_json_depth: 5\n")
    put(ws, "in.json", '{"items": [[[[[1]]]]]}')
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "map.yaml")
    assert "json_too_deep" in str(excinfo.value)
    put(ws, "in.json", '{"items": [{"name": "x"}]}')  # depth 3
    assert run(ws, "in.json", JSON, "map.yaml").report.accepted_records == 1


def test_brackets_inside_strings_do_not_count_as_depth(ws: Path) -> None:
    config(ws, "imports:\n  max_json_depth: 4\n")
    tricky = '[[[[[[[[[[ {{{{{{{{ \\" ]]'
    put(ws, "in.json", document(item(name=tricky)))
    assert run(ws, "in.json", JSON, "map.yaml").report.accepted_records == 1


def test_too_many_records(ws: Path) -> None:
    config(ws, "imports:\n  max_records: 3\n")
    put(ws, "in.json", document(*[item() for _ in range(3)]))
    assert run(ws, "in.json", JSON, "map.yaml").report.total_records == 3
    put(ws, "in.json", document(*[item() for _ in range(4)]))
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "map.yaml")
    assert "too_many_records" in str(excinfo.value)


def test_field_too_large_rejects_only_that_record(ws: Path) -> None:
    config(ws, "imports:\n  max_field_bytes: 64\n")
    put(ws, "in.json", document(item(), item(detail={"text": SECRET + "x" * 100})))
    report = run(ws, "in.json", JSON, "map.yaml").report
    assert (report.accepted_records, report.rejected_records) == (1, 1)
    assert [(r.field, r.code) for r in report.rejections] == [("description", "field_too_large")]
    assert SECRET not in repr(report)


def test_invalid_utf8(ws: Path) -> None:
    put(ws, "in.json", b'{"items": [{"name": "\xff\xfe"}]}')
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "map.yaml")
    assert "invalid_utf8" in str(excinfo.value)


def test_records_path_that_matches_nothing_warns(ws: Path) -> None:
    put(ws, "in.json", '{"other": []}')
    report = run(ws, "in.json", JSON, "map.yaml").report
    assert report.total_records == 0
    assert dict(report.warning_codes) == {"records_path_matched_nothing": 1}


# ---- the path grammar ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["a", "a.b", "a[].b", "a[*].b", "a[0].b", "[].a", "runs[].results[]", "a-b.c_d", "a1[12].b"],
)
def test_valid_paths(path: str) -> None:
    assert parse_path(path)


@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("", "path_length"),
        ("a" * 300, "path_length"),
        ("a..b", "path_syntax"),
        (".a", "path_syntax"),
        ("a.", "path_syntax"),
        ("a[", "path_syntax"),
        ("a[]x", "path_syntax"),
        ("a[][]", "path_syntax"),
        ("a[-1]", "path_syntax"),
        ("a[1:2]", "path_syntax"),
        ("a[?(@.x)]", "path_syntax"),
        ("a b", "path_syntax"),
        ("a;b", "path_syntax"),
        ("a()", "path_syntax"),
        ("a.b()", "path_syntax"),
        ("1a", "path_syntax"),
        ("a['x']", "path_syntax"),
        ("*", "path_syntax"),
        ("$.a", "path_syntax"),
        ("a/b", "path_syntax"),
        ("x.[]", "path_syntax"),
        ("__class__", "path_forbidden_segment"),
        ("a.__dict__", "path_forbidden_segment"),
        ("a.__globals__", "path_forbidden_segment"),
        ("__subclasses__[]", "path_forbidden_segment"),
        ("a.__anything__", "path_forbidden_segment"),
        ("a[].b[].c[]", "path_wildcard"),
        ("a[10000]", "path_syntax"),
        (".".join(["a"] * 17), "path_too_deep"),
    ],
)
def test_invalid_paths(path: str, rule: str) -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        parse_path(path)
    assert [i.code for i in excinfo.value.issues] == [rule]


def test_non_string_paths() -> None:
    for value in (None, 5, ["a"], b"a"):
        with pytest.raises(ValidationDomainError):
            parse_path(value)


def test_mapping_validation() -> None:
    base: dict[str, Any] = {
        "format": "generic_json",
        "records_path": "a[]",
        "fields": {"title": "t"},
    }
    assert isinstance(parse_mapping(base, JSON), JsonMapping)
    bad_variants: list[dict[str, Any]] = [
        {**base, "records_path": "a.b"},  # needs a wildcard
        {**base, "records_path": "__class__[]"},
        {**base, "fields": {"title": "a[]"}},  # wildcards only in records_path
        {**base, "fields": {"title": "t", "bogus": "x"}},
        {**base, "fields": {"description": "t"}},  # title is required
        {**base, "fields": {"title": "__dict__"}},
        {**base, "fields": {"title": "t()"}},
        {**base, "fields": {"title": 5}},
        {**base, "extra": 1},
        {**base, "format": "csv"},
    ]
    for variant in bad_variants:
        with pytest.raises(ValidationDomainError):
            parse_mapping(variant, JSON)
    with pytest.raises(ValidationDomainError):
        parse_mapping([1], JSON)


def test_unsafe_mapping_files_are_rejected_through_the_service(ws: Path) -> None:
    put(ws, "in.json", document(item()))
    for text in (
        "format: generic_json\nrecords_path: items[]\nfields: {title: __class__}\n",
        "format: generic_json\nrecords_path: items[]\nfields: {title: 'a.b()'}\n",
        "format: generic_json\nrecords_path: &a items[]\nfields: {title: t}\n",
        "format: generic_json\nfields: {title: t}\n"
        "records_path: !!python/object/apply:os.system [x]\n",
        "format: generic_json\nformat: generic_json\nrecords_path: items[]\nfields: {title: t}\n",
        "format: generic_json\nrecords_path: items[]\nfields: {title: t}\nunknown: 1\n",
        "format: csv\ncolumns: {title: t}\n",
        "- not\n- a mapping\n",
    ):
        put(ws, "bad.yaml", text)
        with pytest.raises(ImportServiceError) as excinfo:
            run(ws, "in.json", JSON, "bad.yaml")
        assert "invalid_mapping" in str(excinfo.value)


def test_mapping_must_be_inside_the_workspace(ws: Path) -> None:
    put(ws, "in.json", document(item()))
    outside = put(ws.parent, "outside.yaml", JSON_MAPPING)
    for path in (str(outside), "../outside.yaml"):
        with pytest.raises(ImportServiceError) as excinfo:
            run(ws, "in.json", JSON, path)
        assert "path_" in str(excinfo.value)
    (ws / "link.yaml").symlink_to(outside)
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "link.yaml")
    assert "symlink_not_allowed" in str(excinfo.value)


def test_oversized_mapping_is_refused(ws: Path) -> None:
    put(ws, "in.json", document(item()))
    put(ws, "big.yaml", JSON_MAPPING + "# " + "x" * 70000 + "\n")
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.json", JSON, "big.yaml")
    assert "import_file_too_large" in str(excinfo.value)


def test_values_that_look_like_code_stay_plain_text(ws: Path) -> None:
    marker = ws.parent / "pwned"
    put(ws, "in.json", document(item(name="__import__('os').system('touch pwned')")))
    put(ws, "map2.yaml", "format: generic_json\nrecords_path: items[]\nfields: {title: name}\n")
    record = run(ws, "in.json", JSON, "map2.yaml").records[0]
    assert record.title == "__import__('os').system('touch pwned')"
    assert not marker.exists()
