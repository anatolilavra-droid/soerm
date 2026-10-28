"""M6: fingerprint -> lookup -> finding + occurrence -> run -> audit; idempotent re-import."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from typing import Any

import pytest

from soerm.domain.enums import ImportSource, TechnicalSeverity
from soerm.services.errors import InvalidInputError, NotFoundServiceError
from soerm.services.findings import list_findings
from soerm.services.import_apply import apply_import
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.audit import verify_audit_chain
from soerm.storage.imports import ImportRunRepository, OccurrenceRepository
from tests.unit.importers.helpers import CSV_MAPPING, SECRET, put, result, sarif
from tests.unit.services.helpers import audit_entries, make_asset

CSV_WITH_DATES = """\
format: csv
delimiter: ","
has_header: true
columns:
  title: title
  severity: severity
  observed_at: seen
  evidence: evidence
  location: where
"""


@pytest.fixture
def asset(ws: Workspace) -> str:
    return make_asset(ws).object_id


def run_sarif(ws: Workspace, asset_id: str, name: str = "a.sarif", **extra: Any) -> Any:
    return apply_import(ws, name, actor="alice", fmt=ImportSource.SARIF, asset_id=asset_id, **extra)


def rows(ws: Workspace, sql: str) -> list[tuple[Any, ...]]:
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as raw:
        return raw.execute(sql).fetchall()


def snapshot(ws: Workspace) -> dict[str, list[tuple[Any, ...]]]:
    return {
        table: rows(ws, f"SELECT * FROM {table}")  # noqa: S608 - fixed table names
        for table in ("findings", "import_runs", "finding_occurrences", "audit_log", "counters")
    }


def test_first_import_creates_finding_occurrence_run_and_audit(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(), result(ruleId="R2", level="warning")]))
    out = run_sarif(ws, asset)
    assert (out.status, out.run_id, out.created, out.updated) == ("imported", "RUN-000001", 2, 0)
    assert out.occurrences_added == 2
    findings = list_findings(ws)
    assert len(findings) == 2
    assert {f.asset_id for f in findings} == {asset}
    assert {f.technical_severity for f in findings} == {
        TechnicalSeverity.HIGH,
        TechnicalSeverity.MEDIUM,
    }
    assert rows(ws, "SELECT source_path, record_count FROM import_runs") == [("a.sarif", 2)]
    assert len(rows(ws, "SELECT * FROM finding_occurrences")) == 2
    actions = [e.action for e in audit_entries(ws)]
    assert actions == ["asset.create", "import.run", "finding.create", "finding.create"]
    assert out.audit_entries == 3
    with ws.read() as session:
        verify_audit_chain(session.connection)
        run = ImportRunRepository(session.connection).get("RUN-000001")
        occurrences = OccurrenceRepository(session.connection).list_for_finding(
            findings[0].finding_id
        )
    assert run is not None
    assert run.digest() == out.run_hash
    assert occurrences[0].source_path == "a.sarif"
    assert occurrences[0].file_sha256 == out.report.source_sha256
    assert occurrences[0].location is not None


def test_repeated_import_is_idempotent(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(), result(ruleId="R2")]))
    run_sarif(ws, asset)
    before = snapshot(ws)
    again = run_sarif(ws, asset)
    assert (again.status, again.run_id, again.created, again.occurrences_added) == (
        "unchanged",
        None,
        0,
        0,
    )
    assert again.unchanged == 2
    assert snapshot(ws) == before  # not even a run, an audit entry or a counter tick


def test_changed_file_updates_known_finding_and_adds_one(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result()]))
    first = run_sarif(ws, asset)
    put(ws.path, "a.sarif", sarif([result(), result(ruleId="R9")]))
    second = run_sarif(ws, asset)
    assert second.run_id == "RUN-000002"
    assert (second.created, second.updated, second.seen_again) == (1, 1, 0)
    assert second.occurrences_added == 2
    findings = list_findings(ws)
    assert len(findings) == 2  # the known one was not duplicated
    known = next(f for f in findings if f.finding_id == first.finding_ids[0])
    assert known.last_seen > known.first_seen
    assert len(rows(ws, "SELECT * FROM finding_occurrences WHERE finding_id = 'FND-000001'")) == 2
    actions = [e.action for e in audit_entries(ws)]
    assert actions.count("finding.update") == 1
    assert actions.count("import.run") == 2


def test_same_finding_in_second_file_gets_its_own_occurrence(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result()]))
    put(ws.path, "copy.sarif", sarif([result()]))
    run_sarif(ws, asset)
    out = run_sarif(ws, asset, "copy.sarif")
    # identical content = identical hash, but another path is another observation
    assert out.status == "imported"
    assert len(list_findings(ws)) == 1
    assert len(rows(ws, "SELECT * FROM finding_occurrences")) == 2


def test_source_fingerprints_are_not_the_identity(ws: Workspace, asset: str) -> None:
    same_hint_different_defects = [
        result(partialFingerprints={"k": "same"}),
        result(ruleId="R2", partialFingerprints={"k": "same"}),
    ]
    put(ws.path, "a.sarif", sarif(same_hint_different_defects))
    assert run_sarif(ws, asset).created == 2
    # the same defect with a changed source fingerprint is still the same finding
    put(ws.path, "b.sarif", sarif([result(partialFingerprints={"k": "changed"})]))
    out = run_sarif(ws, asset, "b.sarif")
    assert out.created == 0
    assert len(list_findings(ws)) == 2


def test_same_defect_on_another_asset_is_another_finding(ws: Workspace, asset: str) -> None:
    other = make_asset(ws, name="Other").object_id
    put(ws.path, "a.sarif", sarif([result()]))
    run_sarif(ws, asset)
    assert run_sarif(ws, other).created == 1
    assert len(list_findings(ws)) == 2


def test_duplicates_inside_one_file(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(), result()]))
    out = run_sarif(ws, asset)
    assert (out.created, out.duplicates_in_file, out.occurrences_added) == (1, 1, 2)
    assert len(list_findings(ws)) == 1
    again = run_sarif(ws, asset)
    assert again.status == "unchanged"


def test_secret_never_reaches_database_or_audit(ws: Workspace, asset: str) -> None:
    put(
        ws.path,
        "a.sarif",
        sarif([result(message={"text": f"password={SECRET}"}, ruleId=f"api_key={SECRET}")]),
    )
    out = run_sarif(ws, asset)
    assert out.created == 1
    for table in ("findings", "import_runs", "finding_occurrences", "audit_log"):
        assert SECRET not in repr(rows(ws, f"SELECT * FROM {table}"))  # noqa: S608
    assert SECRET not in repr(out)


def test_audit_holds_only_identifiers_and_hashes(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(message={"text": "Distinctive-Title-Marker"})]))
    run_sarif(ws, asset)
    dump = repr(rows(ws, "SELECT * FROM audit_log"))
    for marker in ("Distinctive-Title-Marker", "db.py", "a.sarif", "scanner"):
        assert marker not in dump
    run_entry = next(e for e in audit_entries(ws) if e.action == "import.run")
    assert run_entry.object_type == "import_run"
    assert run_entry.object_id == "RUN-000001"
    assert run_entry.before_hash is None
    assert run_entry.actor == "alice"


def test_severity_missing_is_skipped_or_defaulted(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(level="none"), result(ruleId="R2")]))
    out = run_sarif(ws, asset)
    assert out.created == 1
    assert out.skipped == (("missing_severity", 1),)
    put(ws.path, "b.sarif", sarif([result(level="none", ruleId="R3")]))
    defaulted = run_sarif(ws, asset, "b.sarif", default_severity=TechnicalSeverity.LOW)
    assert defaulted.created == 1
    assert list_findings(ws)[-1].technical_severity is TechnicalSeverity.LOW
    with pytest.raises(InvalidInputError):
        run_sarif(ws, asset, "b.sarif", default_severity=TechnicalSeverity.NONE)
    with pytest.raises(InvalidInputError):
        run_sarif(ws, asset, "b.sarif", default_severity="bogus")


def test_nothing_importable_writes_no_run(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result(level="none")]))
    out = run_sarif(ws, asset)
    assert (out.status, out.run_id, out.skipped) == ("unchanged", None, (("missing_severity", 1),))
    assert rows(ws, "SELECT * FROM import_runs") == []


def test_unknown_asset_creates_nothing(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result()]))
    with pytest.raises(NotFoundServiceError):
        run_sarif(ws, "AST-000099")
    with pytest.raises(InvalidInputError):
        run_sarif(ws, "bogus")
    assert rows(ws, "SELECT * FROM findings") == []
    assert rows(ws, "SELECT * FROM import_runs") == []


def test_failure_in_the_middle_rolls_everything_back(
    ws: Workspace, asset: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    put(ws.path, "a.sarif", sarif([result(), result(ruleId="R2"), result(ruleId="R3")]))
    before = snapshot(ws)
    original = OccurrenceRepository.add
    calls = {"n": 0}

    def flaky(self: OccurrenceRepository, finding_id: str, occurrence: Any) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        original(self, finding_id, occurrence)

    monkeypatch.setattr(OccurrenceRepository, "add", flaky)
    with pytest.raises(RuntimeError):
        run_sarif(ws, asset)
    assert snapshot(ws) == before  # run, findings, occurrences, audit and counters
    monkeypatch.setattr(OccurrenceRepository, "add", original)
    assert run_sarif(ws, asset).run_id == "RUN-000001"  # no number was consumed


def test_csv_dates_clamp_and_extend_first_seen(ws: Workspace, asset: str) -> None:
    put(ws.path, "m.yaml", CSV_WITH_DATES)
    put(
        ws.path,
        "a.csv",
        "title,severity,seen,evidence,where\n"
        "Weak TLS,high,2026-02-01T00:00:00Z,e1,host1\n"
        "Old thing,low,2999-01-01T00:00:00Z,e2,host2\n",
    )
    out = apply_import(
        ws, "a.csv", actor="alice", fmt=ImportSource.CSV, asset_id=asset, mapping_path="m.yaml"
    )
    assert out.created == 2
    by_title = {f.title: f for f in list_findings(ws)}
    assert by_title["Weak TLS"].first_seen == datetime(2026, 2, 1, tzinfo=UTC)
    future = by_title["Old thing"]
    assert future.last_seen <= future.created_at  # clamped to the moment of the import
    put(
        ws.path,
        "b.csv",
        "title,severity,seen,evidence,where\nWeak TLS,high,2026-01-01T00:00:00Z,e1,host1\n",
    )
    apply_import(
        ws, "b.csv", actor="alice", fmt=ImportSource.CSV, asset_id=asset, mapping_path="m.yaml"
    )
    weak = next(f for f in list_findings(ws) if f.title == "Weak TLS")
    assert weak.first_seen == datetime(2026, 1, 1, tzinfo=UTC)
    assert weak.last_seen == datetime(2026, 2, 1, tzinfo=UTC)  # never moves backwards


def test_existing_finding_content_is_not_overwritten(ws: Workspace, asset: str) -> None:
    put(ws.path, "m.yaml", CSV_MAPPING)
    put(ws.path, "a.csv", "title,description,asset,evidence,severity\nT,first,x,ev1,high\n")
    put(ws.path, "b.csv", "title,description,asset,evidence,severity\nT,second,x,ev2,low\n")
    for name in ("a.csv", "b.csv"):
        apply_import(
            ws, name, actor="alice", fmt=ImportSource.CSV, asset_id=asset, mapping_path="m.yaml"
        )
    (finding,) = list_findings(ws)
    assert (finding.description, finding.evidence) == ("first", "ev1")
    assert finding.technical_severity is TechnicalSeverity.HIGH


def test_actor_is_required_and_validated(ws: Workspace, asset: str) -> None:
    put(ws.path, "a.sarif", sarif([result()]))
    with pytest.raises(InvalidInputError):
        apply_import(ws, "a.sarif", actor="", fmt=ImportSource.SARIF, asset_id=asset)


def test_import_run_audit_chain_survives_many_imports(ws: Workspace, asset: str) -> None:
    for i in range(3):
        put(ws.path, f"{i}.sarif", sarif([result(ruleId=f"R{i}")]))
        run_sarif(ws, asset, f"{i}.sarif")
    with ws.read() as session:
        head = verify_audit_chain(session.connection)
    assert head.seq == 1 + 3 * 2
