"""Risk service: preview is read-only, recalculation is explicit, audited and idempotent."""

import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import Any

import pytest

from soerm.domain.cvss import severity_from_cvss_score
from soerm.domain.enums import (
    BusinessCriticality,
    BusinessPriority,
    DataClassification,
    Environment,
    Exposure,
    FindingStatus,
    TechnicalSeverity,
)
from soerm.domain.finding import Finding
from soerm.domain.risk import RISK_FORMULA_VERSION, RiskConfig, risk_config_hash
from soerm.services.errors import InvalidInputError, NotFoundServiceError, ServiceError
from soerm.services.findings import get_finding, update_finding
from soerm.services.risk import check_cvss, preview_risk, recalculate_risk
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.audit import verify_audit_chain
from soerm.storage.findings import FindingRepository
from tests.unit.importers.helpers import config, tree
from tests.unit.services.helpers import (
    FP_A,
    FP_B,
    SECRET,
    audit_entries,
    make_asset,
    make_finding,
)

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3


@pytest.fixture
def seeded(ws: Workspace) -> Workspace:
    make_asset(ws)
    make_finding(ws, title=f"Title-Marker password={SECRET}", evidence="ev-marker")
    return ws


def snapshot(ws: Workspace) -> dict[str, list[tuple[Any, ...]]]:
    out: dict[str, list[tuple[Any, ...]]] = {}
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as raw:
        for table in ("assets", "findings", "audit_log", "counters"):
            out[table] = raw.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
    return out


def force_finding(ws: Workspace, finding_id: str, **changes: Any) -> None:
    """Change fields the way a future workflow (or an outside editor via the repository) would."""
    with ws.write() as session:
        repo = FindingRepository(session.connection)
        current = repo.get(finding_id)
        assert current is not None
        repo.update(current.with_changes(**changes), actor="admin", at=session.now)


def test_preview_writes_nothing(seeded: Workspace) -> None:
    before = snapshot(seeded)
    files = tree(seeded.path)
    run = preview_risk(seeded, all_findings=True)
    assert snapshot(seeded) == before
    assert tree(seeded.path).keys() == files.keys()  # no lock file, no new file
    (item,) = run.items
    assert item.outcome == "changed"
    assert item.assessment is not None
    assert item.assessment.priority is BusinessPriority.P1  # high on a critical-ish asset
    assert get_finding(seeded, "FND-000001").business_priority is None


def test_preview_needs_an_initialized_workspace(ws: Workspace) -> None:
    with pytest.raises(NotFoundServiceError):
        preview_risk(ws, all_findings=True)
    assert not (ws.path / DATABASE_FILE_NAME).exists()


def test_recalculate_stores_result_hash_and_audit(seeded: Workspace) -> None:
    run = recalculate_risk(seeded, actor="alice", all_findings=True)
    assert (run.changed, run.unchanged, run.skipped, run.audit_entries) == (1, 0, 0, 1)
    finding = get_finding(seeded, "FND-000001")
    assert finding.business_priority is BusinessPriority.P1
    assert finding.risk_formula_version == RISK_FORMULA_VERSION
    assert finding.risk_config_hash == risk_config_hash(RiskConfig())
    assert finding.sla_due_at == finding.first_seen + timedelta(hours=72)
    assert finding.risk_factors["risk_score"] >= 80
    assert finding.risk_factors["criticality_weight"] == 1.2
    entry = audit_entries(seeded)[-1]
    assert entry.action == "finding.risk_recalculate"
    assert (entry.object_type, entry.object_id, entry.actor) == ("finding", "FND-000001", "alice")
    assert entry.before_hash == run.items[0].before_hash
    assert entry.after_hash == finding.digest()
    with seeded.read() as session:
        verify_audit_chain(session.connection)


def test_audit_and_database_audit_hold_no_text(seeded: Workspace) -> None:
    recalculate_risk(seeded, actor="alice", finding_id="FND-000001")
    with closing(sqlite3.connect(seeded.path / DATABASE_FILE_NAME)) as raw:
        dump = repr(raw.execute("SELECT * FROM audit_log").fetchall())
    for marker in ("Title-Marker", "ev-marker", SECRET, "Billing"):
        assert marker not in dump


def test_recalculation_is_idempotent(seeded: Workspace) -> None:
    recalculate_risk(seeded, actor="alice", all_findings=True)
    before = snapshot(seeded)
    again = recalculate_risk(seeded, actor="alice", all_findings=True)
    assert (again.changed, again.unchanged, again.audit_entries) == (0, 1, 0)
    assert snapshot(seeded) == before  # not even updated_at or an audit entry


def test_analyst_decisions_are_never_touched(seeded: Workspace) -> None:
    updated = update_finding(
        seeded,
        "FND-000001",
        actor="alice",
        expected_hash=get_finding(seeded, "FND-000001").digest(),
        owner="Dana",
        status=FindingStatus.TRIAGED,
        description="analyst note",
    )
    before = get_finding(seeded, "FND-000001")
    assert updated.after_hash == before.digest()
    recalculate_risk(seeded, actor="alice", all_findings=True)
    after = get_finding(seeded, "FND-000001")
    changed = {
        name for name in Finding.model_fields if getattr(before, name) != getattr(after, name)
    }
    assert changed == {
        "business_priority",
        "risk_factors",
        "risk_formula_version",
        "risk_config_hash",
        "sla_due_at",
        "updated_at",
    }
    assert (after.status, after.owner, after.description, after.title) == (
        FindingStatus.TRIAGED,
        "Dana",
        "analyst note",
        before.title,
    )


@pytest.mark.parametrize(
    "status", [FindingStatus.RESOLVED, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE]
)
def test_inactive_findings_are_skipped_and_never_reopened(
    seeded: Workspace, status: FindingStatus
) -> None:
    force_finding(seeded, "FND-000001", status=status)
    before = snapshot(seeded)
    run = recalculate_risk(seeded, actor="alice", all_findings=True)
    assert (run.skipped, run.changed, run.audit_entries) == (1, 0, 0)
    assert run.items[0].reason == "status_not_active"
    assert snapshot(seeded) == before
    assert get_finding(seeded, "FND-000001").status is status


def test_priority_set_outside_the_risk_model_is_not_overwritten(seeded: Workspace) -> None:
    force_finding(seeded, "FND-000001", business_priority=BusinessPriority.P4)
    run = recalculate_risk(seeded, actor="alice", all_findings=True)
    assert run.items[0].reason == "priority_set_externally"
    finding = get_finding(seeded, "FND-000001")
    assert finding.business_priority is BusinessPriority.P4
    assert finding.risk_config_hash is None


def test_nothing_computes_risk_implicitly(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws)
    finding = get_finding(ws, "FND-000001")
    assert finding.business_priority is None
    assert finding.sla_due_at is None
    assert finding.risk_config_hash is None


def test_business_context_comes_from_the_asset(ws: Workspace) -> None:
    make_asset(
        ws,
        business_criticality=BusinessCriticality.LOW,
        exposure=Exposure.ISOLATED,
        data_classification=DataClassification.PUBLIC,
        environment=Environment.TEST,
    )
    make_finding(ws)  # high severity
    recalculate_risk(ws, actor="alice", all_findings=True)
    assert get_finding(ws, "FND-000001").business_priority is BusinessPriority.P4


def test_cvss_vector_is_scored_and_compared_with_the_imported_score(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws, cvss_vector=VECTOR, cvss_score=9.3)
    make_finding(ws, fingerprint=FP_B, cvss_vector=VECTOR, cvss_score=5.0)
    run = recalculate_risk(ws, actor="alice", all_findings=True)
    good, bad = run.items
    assert (good.cvss.vector, good.cvss.computed_score, good.cvss.score_matches) == (
        "valid",
        9.3,
        True,
    )
    assert good.cvss.nomenclature == "CVSS-B"
    assert bad.cvss.score_matches is False
    assert "cvss_score_mismatch" in bad.warnings
    stored = get_finding(ws, "FND-000002")
    assert stored.cvss_score == 5.0  # the imported score is never overwritten
    assert stored.cvss_score_source == "imported"
    assert stored.risk_factors["cvss_computed_score"] == 9.3
    assert stored.risk_factors["cvss_score_matches"] == 0.0


def test_severity_from_cvss_is_reported_and_only_applied_on_request(ws: Workspace) -> None:
    make_asset(ws)
    make_finding(ws, technical_severity=TechnicalSeverity.LOW, cvss_vector=VECTOR, cvss_score=9.3)
    preview = preview_risk(ws, finding_id="FND-000001")
    assert preview.items[0].severity_sync == "available"
    assert "severity_differs_from_cvss" in preview.items[0].warnings
    recalculate_risk(ws, actor="alice", finding_id="FND-000001")
    kept = get_finding(ws, "FND-000001")
    assert kept.technical_severity is TechnicalSeverity.LOW  # risk used the stored severity
    assert kept.business_priority is BusinessPriority.P4
    run = recalculate_risk(ws, actor="alice", finding_id="FND-000001", sync_severity=True)
    synced = get_finding(ws, "FND-000001")
    assert run.items[0].severity_sync == "applied"
    assert synced.technical_severity is severity_from_cvss_score(9.3)
    assert synced.business_priority is BusinessPriority.P1
    assert synced.cvss_score == 9.3


def test_invalid_vector_is_reported_without_failing() -> None:
    broken = Finding.model_construct(cvss_vector="CVSS:4.0/AV:N", cvss_score=None)  # type: ignore[call-arg]
    check = check_cvss(broken)
    assert check.vector == "invalid"
    assert check.computed_score is None


def test_configuration_drives_the_result_and_the_hash(seeded: Workspace) -> None:
    recalculate_risk(seeded, actor="alice", all_findings=True)
    first = get_finding(seeded, "FND-000001")
    config(
        seeded.path,
        "risk:\n  severity_points: {none: 0, low: 1, medium: 2, high: 3, critical: 4}\n",
    )
    preview = preview_risk(seeded, all_findings=True)
    assert preview.config_hash != first.risk_config_hash
    assert preview.items[0].outcome == "changed"
    recalculate_risk(seeded, actor="alice", all_findings=True)
    second = get_finding(seeded, "FND-000001")
    assert second.business_priority is BusinessPriority.P4
    assert second.risk_config_hash == preview.config_hash
    assert [e.action for e in audit_entries(seeded)].count("finding.risk_recalculate") == 2


def test_invalid_configuration_is_refused_before_anything_is_written(seeded: Workspace) -> None:
    config(seeded.path, "risk:\n  thresholds: {p1: 10, p2: 20, p3: 30}\n")
    before = snapshot(seeded)
    with pytest.raises(ServiceError):
        recalculate_risk(seeded, actor="alice", all_findings=True)
    assert snapshot(seeded) == before


def test_target_validation(seeded: Workspace) -> None:
    both: tuple[dict[str, Any], ...] = ({}, {"finding_id": "FND-000001", "all_findings": True})
    for kwargs in both:
        with pytest.raises(InvalidInputError):
            preview_risk(seeded, **kwargs)
        with pytest.raises(InvalidInputError):
            recalculate_risk(seeded, actor="alice", **kwargs)
    with pytest.raises(NotFoundServiceError):
        preview_risk(seeded, finding_id="FND-000099")
    with pytest.raises(InvalidInputError):
        preview_risk(seeded, finding_id="bogus")
    with pytest.raises(InvalidInputError):
        recalculate_risk(seeded, actor="", all_findings=True)


def test_failure_in_the_middle_rolls_everything_back(
    ws: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_asset(ws)
    make_finding(ws)
    make_finding(ws, fingerprint=FP_B)
    before = snapshot(ws)
    original = FindingRepository.update
    calls = {"n": 0}

    def flaky(self: FindingRepository, *args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FindingRepository, "update", flaky)
    with pytest.raises(RuntimeError):
        recalculate_risk(ws, actor="alice", all_findings=True)
    assert snapshot(ws) == before


def test_unknown_audit_action_is_refused(seeded: Workspace) -> None:
    with seeded.write() as session:
        repo = FindingRepository(session.connection)
        finding = repo.get("FND-000001")
        assert finding is not None
        with pytest.raises(Exception, match="invalid_action"):
            repo.update(finding, actor="alice", at=session.now, action="finding.delete")


def test_second_run_after_new_finding_only_touches_the_new_one(seeded: Workspace) -> None:
    recalculate_risk(seeded, actor="alice", all_findings=True)
    make_finding(seeded, fingerprint=FP_A.replace("a", "c"))
    run = recalculate_risk(seeded, actor="alice", all_findings=True)
    assert [i.outcome for i in run.items] == ["unchanged", "changed"]
    assert run.audit_entries == 1
