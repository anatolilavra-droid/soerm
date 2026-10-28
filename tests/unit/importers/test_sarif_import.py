"""SARIF 2.1.0."""

import json
from pathlib import Path
from typing import Any

import pytest

from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.importers.sarif import safe_uri
from soerm.services.errors import ImportServiceError
from tests.unit.importers.helpers import SECRET, config, put, result, run, sarif

SARIF = ImportSource.SARIF


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    return root


def load(ws: Path, text: str) -> Any:
    put(ws, "in.sarif", text)
    return run(ws, "in.sarif", SARIF)


def refused(ws: Path, text: str) -> str:
    put(ws, "in.sarif", text)
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.sarif", SARIF)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())
    return str(excinfo.value)


def test_valid_sarif(ws: Path) -> None:
    preview = load(ws, sarif())
    record = preview.records[0]
    assert record.title == "SQL injection"  # the rule's shortDescription
    assert (
        record.description == "user input flows into a query\n\nRule: Tainted data reaches a query"
    )
    assert record.external_rule_id == "R1"
    assert record.technical_severity is TechnicalSeverity.HIGH
    assert record.location == "src/app/db.py:12:5"
    assert record.source is SARIF
    assert record.asset_reference is None
    assert record.owner is None
    assert record.cvss_score is None
    report = preview.report
    assert (report.total_records, report.accepted_records, report.rejected_records) == (1, 1, 0)
    assert report.format == "sarif"


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("error", TechnicalSeverity.HIGH),
        ("warning", TechnicalSeverity.MEDIUM),
        ("note", TechnicalSeverity.LOW),
        ("none", None),
        (None, None),
    ],
)
def test_level_mapping_and_no_invented_default(
    ws: Path, level: str | None, severity: TechnicalSeverity | None
) -> None:
    item = result()
    if level is None:
        del item["level"]
    else:
        item["level"] = level
    assert load(ws, sarif([item])).records[0].technical_severity is severity


def test_unknown_level_warns(ws: Path) -> None:
    preview = load(ws, sarif([result(level="catastrophic")]))
    assert preview.records[0].technical_severity is None
    assert dict(preview.report.warning_codes) == {"invalid_level": 1}


@pytest.mark.parametrize("version", ["2.0.0", "2.1", "2.1.1", 2.1, None, ""])
def test_only_version_2_1_0_is_accepted(ws: Path, version: Any) -> None:
    document = json.loads(sarif())
    if version is None:
        del document["version"]
    else:
        document["version"] = version
    assert "unsupported_sarif_version" in refused(ws, json.dumps(document))


@pytest.mark.parametrize(
    ("mutation", "detail"),
    [
        (lambda d: d.pop("runs"), "sarif_runs_missing"),
        (lambda d: d.update(runs={"a": 1}), "sarif_runs_missing"),
        (lambda d: d.update(runs="x"), "sarif_runs_missing"),
        (lambda d: d.update({"$schema": 5}), "sarif_schema_type"),
        (lambda d: d["runs"][0].pop("tool"), "sarif_tool_driver_name_missing"),
        (lambda d: d["runs"][0]["tool"]["driver"].pop("name"), "sarif_tool_driver_name_missing"),
        (
            lambda d: d["runs"][0]["tool"]["driver"].update(name=" "),
            "sarif_tool_driver_name_missing",
        ),
        (lambda d: d["runs"][0]["tool"]["driver"].update(rules={}), "sarif_rules_invalid"),
        (lambda d: d["runs"][0].update(results={}), "sarif_results_invalid"),
        (lambda d: d["runs"][0].update(results="x"), "sarif_results_invalid"),
        (lambda d: d["runs"].append(5), "sarif_tool_driver_name_missing"),
    ],
)
def test_structural_errors(ws: Path, mutation: Any, detail: str) -> None:
    document = json.loads(sarif())
    mutation(document)
    message = refused(ws, json.dumps(document))
    assert "invalid_format" in message
    assert detail in message


def test_top_level_must_be_an_object(ws: Path) -> None:
    assert "sarif_not_an_object" in refused(ws, "[1]")
    assert "malformed_json" in refused(ws, "{")


def test_missing_results_is_a_warning_not_an_error(ws: Path) -> None:
    document = json.loads(sarif())
    del document["runs"][0]["results"]
    preview = load(ws, json.dumps(document))
    assert preview.report.total_records == 0
    assert dict(preview.report.warning_codes) == {"sarif_run_without_results": 1}


def test_malformed_results_are_rejected_one_by_one(ws: Path) -> None:
    good = result()
    items = [good, 5, "x", {"ruleId": "R1"}, {"message": {"text": "  "}}, {"message": "text"}, good]
    preview = load(ws, sarif(items))
    assert (preview.report.accepted_records, preview.report.rejected_records) == (2, 5)
    assert [(r.index, r.code) for r in preview.report.rejections] == [
        (1, "result_not_object"), (2, "result_not_object"), (3, "missing_message"),
        (4, "missing_message"), (5, "missing_message"),
    ]  # fmt: skip


def test_rule_id_selects_the_title_and_external_rule_id(ws: Path) -> None:
    items = [
        result(ruleId="R1"),
        result(ruleId="UNKNOWN-RULE"),
        result(ruleId=None, rule={"id": "R1"}),
        result(ruleId=None, message={"text": "first line\nsecond line"}),
        result(ruleId="R1", ruleIndex=0),
        result(ruleId="X", ruleIndex=0),  # mismatching ruleIndex is not trusted
    ]
    records = load(ws, sarif(items)).records
    assert [r.title for r in records] == [
        "SQL injection", "UNKNOWN-RULE", "SQL injection", "first line", "SQL injection", "X",
    ]  # fmt: skip
    assert [r.external_rule_id for r in records] == ["R1", "UNKNOWN-RULE", "R1", None, "R1", "X"]


def test_message_text_unicode(ws: Path) -> None:
    text = "Ошибка: пароль “тест” \U0001f510 - 日本語"
    record = load(ws, sarif([result(message={"text": text})])).records[0]
    assert "Ошибка: пароль" in record.description
    assert "日本語" in record.description


def test_location_variants(ws: Path) -> None:
    def loc(uri: Any, **region: Any) -> dict[str, Any]:
        return {
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
            ]
        }

    items = [
        result(**loc("a/b.py", startLine=3)),
        result(**loc("a/b.py")),
        result(**loc("a/b.py", startLine=0, startColumn=4)),
        result(**loc("a/b.py", startLine=True)),
        result(locations=[]),
        result(locations=[{"message": {"text": "x"}}]),
        result(locations="nope"),
        result(**loc(5)),
        result(**loc("https://user:pw@example.com/p/f.py?token=abc#frag", startLine=1)),
        result(
            locations=[
                {"logicalLocations": []},
                {"physicalLocation": {"artifactLocation": {"uri": "second.py"}}},
            ]
        ),
    ]
    records = load(ws, sarif(items)).records
    assert [r.location for r in records] == [
        "a/b.py:3", "a/b.py", "a/b.py", "a/b.py", None, None, None, None,
        "https://example.com/p/f.py:1", "second.py",
    ]  # fmt: skip


def test_safe_uri_never_keeps_credentials_query_or_fragment() -> None:
    assert safe_uri("https://u:p@h.example/a?x=1#f") == "https://h.example/a"
    assert safe_uri("file:///etc/passwd") == "file:///etc/passwd"
    assert safe_uri("  rel/path.py?token=abc  ") == "rel/path.py"
    assert safe_uri("a" * 5000) == "a" * 1000


def test_artifact_uri_is_never_opened(ws: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = ws.parent / "secret-target.txt"
    target.write_text("do not read", encoding="utf-8")
    uris = [str(target), target.as_uri(), "../secret-target.txt", "/etc/passwd", "http://x/y"]
    items = [
        result(locations=[{"physicalLocation": {"artifactLocation": {"uri": u}}}]) for u in uris
    ]
    put(ws, "in.sarif", sarif(items))
    opened: list[str] = []
    import os as real_os

    real_open = real_os.open

    def spy(path: Any, *args: Any, **kwargs: Any) -> int:
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("soerm.importers.safe_file.os.open", spy)
    preview = run(ws, "in.sarif", SARIF)
    assert preview.report.accepted_records == len(uris)
    assert {Path(p).name for p in opened} == {"soerm.yaml", "in.sarif"}  # config + the input
    assert target.read_text(encoding="utf-8") == "do not read"


def test_partial_fingerprints_are_only_provenance_hints(ws: Path) -> None:
    item = result(
        partialFingerprints={"primaryLocationLineHash": "abc123:1", "bad key!": "x"},
        fingerprints={"v1": "def456"},
    )
    other = result(partialFingerprints={"primaryLocationLineHash": "different"})
    preview = load(ws, sarif([item, other, result()]))
    first, second, third = (r.provenance for r in preview.records)
    assert "partialFingerprints:primaryLocationLineHash=abc123:1" in first.hints
    assert "fingerprints:v1=def456" in first.hints
    assert all("bad key" not in hint for hint in first.hints)
    assert second.hints == ("partialFingerprints:primaryLocationLineHash=different",)
    assert third.hints == ()
    # not part of the record itself: no fingerprint, no identity
    assert not hasattr(preview.records[0], "fingerprint")
    assert preview.report.warning_codes == (("fingerprint_hint_skipped", 1),)


def test_baseline_state_is_kept_as_a_hint(ws: Path) -> None:
    items = [result(baselineState=s) for s in ("new", "unchanged", "updated", "absent", "weird")]
    preview = load(ws, sarif(items))
    assert [r.provenance.hints for r in preview.records[:4]] == [
        ("baselineState=new",), ("baselineState=unchanged",), ("baselineState=updated",),
        ("baselineState=absent",),
    ]  # fmt: skip
    assert preview.records[4].provenance.hints == ()
    assert dict(preview.report.warning_codes) == {"invalid_baseline_state": 1}


def test_provenance(ws: Path) -> None:
    text = sarif([result(), result()])
    preview = load(ws, text)
    second = preview.records[1].provenance
    assert second.source_file_name == "in.sarif"
    assert second.source_file_sha256 == preview.report.source_sha256
    assert second.record_index == 1
    assert second.json_pointer == "/runs/0/results/1"
    assert second.location == "runs[0].results[1]"
    assert second.csv_row is None


def test_unknown_fields_are_ignored(ws: Path) -> None:
    document = json.loads(sarif())
    document["extra"] = {"anything": [1, 2]}
    document["runs"][0]["results"][0]["properties"] = {"x": "y"}
    document["runs"][0]["unknown"] = 1
    assert load(ws, json.dumps(document)).report.accepted_records == 1


def test_snippet_becomes_redacted_evidence(ws: Path) -> None:
    item = result(
        locations=[
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1, "snippet": {"text": f"password={SECRET}"}},
                }
            }
        ]
    )
    record = load(ws, sarif([item])).records[0]
    assert record.evidence == "password=[REDACTED]"


def test_redaction_of_message_rule_descriptions_and_location(ws: Path) -> None:
    document = json.loads(sarif([result(message={"text": f"token={SECRET} leaked"})]))
    document["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"] = (
        f"api_key={SECRET}"
    )
    document["runs"][0]["tool"]["driver"]["rules"][0]["fullDescription"]["text"] = (
        f"Authorization: Bearer {SECRET}"
    )
    preview = load(ws, json.dumps(document))
    record = preview.records[0]
    assert SECRET not in record.model_dump_json()
    assert record.title == "api_key=[REDACTED]"
    assert "token=[REDACTED] leaked" in record.description
    assert "Authorization: [REDACTED]" in record.description
    assert {name for name, _ in preview.report.redaction_rule_hits} >= {"token", "api_key"}
    assert SECRET not in repr(preview.report)


def test_too_many_results_across_runs(ws: Path) -> None:
    config(ws, "imports:\n  max_records: 3\n")
    document = json.loads(sarif([result(), result()]))
    document["runs"].append(json.loads(json.dumps(document["runs"][0])))
    with pytest.raises(ImportServiceError) as excinfo:
        load(ws, json.dumps(document))
    assert "too_many_records" in str(excinfo.value)


def test_invalid_utf8_sarif(ws: Path) -> None:
    put(ws, "in.sarif", b'{"version": "2.1.0", "runs": [], "x": "\xff"}')
    with pytest.raises(ImportServiceError) as excinfo:
        run(ws, "in.sarif", SARIF)
    assert "invalid_utf8" in str(excinfo.value)
