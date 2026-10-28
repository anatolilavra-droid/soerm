"""Finding service: validation, no redaction/derivation, approval gates, audit, rollback."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from soerm.domain.enums import (
    BusinessPriority,
    FindingStatus,
    TechnicalSeverity,
)
from soerm.domain.finding import Finding
from soerm.services.errors import (
    ApprovalRequiredError,
    ConflictServiceError,
    ConstraintViolationServiceError,
    IntegrityServiceError,
    InvalidInputError,
    NotFoundServiceError,
    ServiceError,
)
from soerm.services.findings import (
    APPROVAL_GATED_STATUSES,
    FindingSort,
    get_finding,
    list_findings,
    update_finding,
)
from soerm.services.workspace import Workspace
from soerm.storage.audit import verify_audit_chain
from soerm.storage.errors import StorageError
from soerm.storage.findings import FindingRepository
from tests.unit.services.helpers import (
    FP_A,
    FP_B,
    SECRET,
    audit_entries,
    make_asset,
    make_finding,
    table_dump,
)


@pytest.fixture
def seeded(ws: Workspace) -> Workspace:
    make_asset(ws)
    return ws


def test_create_with_a_valid_asset(seeded: Workspace) -> None:
    result = make_finding(seeded)
    assert (result.object_id, result.object_type, result.before_hash) == (
        "FND-000001",
        "finding",
        None,
    )
    finding = get_finding(seeded, "FND-000001")
    assert finding.digest() == result.after_hash
    assert finding.status is FindingStatus.OPEN
    assert finding.business_priority is None
    assert finding.source.value == "manual"
    assert finding.first_seen == finding.last_seen == finding.created_at
    assert result.audit.action == "finding.create"
    assert result.audit.object_id == "FND-000001"
    with seeded.read() as session:
        assert verify_audit_chain(session.connection).seq == 2


def test_unknown_asset_is_not_found_and_consumes_no_number(seeded: Workspace) -> None:
    with pytest.raises(NotFoundServiceError):
        make_finding(seeded, asset_id="AST-000099")
    assert make_finding(seeded).object_id == "FND-000001"
    assert [e.seq for e in audit_entries(seeded)] == [1, 2]


@pytest.mark.parametrize(
    "fingerprint", ["", "A" * 64, "a" * 63, "a" * 65, "g" * 64, "a" * 63 + "\n", "' OR 1=1 --"]
)
def test_invalid_fingerprint_is_rejected_before_the_workspace_is_touched(
    ws: Workspace, tmp_path: Path, fingerprint: str
) -> None:
    with pytest.raises(InvalidInputError) as excinfo:
        make_finding(ws, fingerprint=fingerprint)
    assert "fingerprint" in str(excinfo.value)
    assert fingerprint.strip() == "" or fingerprint not in str(excinfo.value)
    assert list(tmp_path.iterdir()) == []


def test_evidence_is_shortened_after_redaction_and_oversized_input_is_refused(
    seeded: Workspace,
) -> None:
    make_finding(seeded, evidence="x" * 4096)
    shortened = make_finding(seeded, fingerprint=FP_B, evidence="é" * 3000)
    assert shortened.redaction is not None
    assert shortened.redaction.truncated_fields == ("evidence",)
    assert len(get_finding(seeded, shortened.object_id).evidence.encode()) <= 4096
    with pytest.raises(InvalidInputError) as excinfo:
        make_finding(seeded, fingerprint="c" * 64, evidence=SECRET + "x" * 70000)
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())
    assert "evidence: input_too_large" in str(excinfo.value)
    assert len(list_findings(seeded)) == 2


def test_evidence_is_redacted_before_it_is_stored(seeded: Workspace) -> None:
    text = f"password={SECRET} Authorization: Bearer abc.def.ghi"
    made = make_finding(seeded, evidence=text, description=f"token={SECRET}")
    stored = get_finding(seeded, "FND-000001")
    assert stored.evidence == "password=[REDACTED] Authorization: [REDACTED]"
    assert stored.description == "token=[REDACTED]"
    assert made.redaction is not None
    assert dict(made.redaction.rule_hits) == {"authorization": 1, "password": 1, "token": 1}


def test_nothing_user_supplied_reaches_the_audit_log(seeded: Workspace) -> None:
    made = make_finding(
        seeded,
        title=f"title {SECRET}",
        description=f"description {SECRET}",
        evidence=f"evidence {SECRET}",
        owner=f"owner {SECRET}",
    )
    update_finding(
        seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
        title=f"title2 {SECRET}", evidence=f"evidence2 {SECRET}",
    )  # fmt: skip
    dump = table_dump(seeded, "audit_log")
    assert SECRET not in dump
    for entry in audit_entries(seeded):
        assert set(entry.model_dump()) == {
            "seq", "timestamp", "actor", "action", "object_type", "object_id", "before_hash",
            "after_hash", "prev_hash", "entry_hash",
        }  # fmt: skip


def test_severity_priority_and_score_are_never_derived(seeded: Workspace) -> None:
    made = make_finding(
        seeded,
        technical_severity=TechnicalSeverity.LOW,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    finding = get_finding(seeded, "FND-000001")
    assert finding.technical_severity is TechnicalSeverity.LOW  # not derived from the vector
    assert finding.cvss_score is None  # not computed from the vector
    assert finding.cvss_score_source is None
    assert (finding.cvss_version, finding.business_priority) == ("4.0", None)
    assert finding.risk_factors == {}
    assert finding.risk_formula_version is None
    assert made.after_hash == finding.digest()


def test_supplied_score_is_stored_as_is(seeded: Workspace) -> None:
    make_finding(seeded, technical_severity=TechnicalSeverity.LOW, cvss_score=9.9)
    finding = get_finding(seeded, "FND-000001")
    assert (finding.cvss_score, finding.cvss_score_source) == (9.9, "imported")
    assert finding.technical_severity is TechnicalSeverity.LOW  # no automatic severity


@pytest.mark.parametrize("score", [-0.1, 10.1, float("nan"), float("inf")])
def test_invalid_score_is_rejected(seeded: Workspace, score: float) -> None:
    with pytest.raises(InvalidInputError):
        make_finding(seeded, cvss_score=score)


def test_severity_none_needs_a_zero_score(seeded: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        make_finding(seeded, technical_severity=TechnicalSeverity.NONE)
    make_finding(seeded, technical_severity=TechnicalSeverity.NONE, cvss_score=0.0)


def test_duplicate_fingerprint_is_a_constraint_violation(seeded: Workspace) -> None:
    make_finding(seeded)
    with pytest.raises(ConstraintViolationServiceError):
        make_finding(seeded, title="Another")
    assert [f.finding_id for f in list_findings(seeded)] == ["FND-000001"]
    assert make_finding(seeded, fingerprint=FP_B).object_id == "FND-000002"
    assert [e.seq for e in audit_entries(seeded)] == [1, 2, 3]


def test_failed_audit_rolls_back_the_finding(
    seeded: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise StorageError("simulated")

    monkeypatch.setattr("soerm.storage.findings.append_audit", boom)
    with pytest.raises(ServiceError):
        make_finding(seeded)
    monkeypatch.undo()
    assert list_findings(seeded) == []
    assert make_finding(seeded).object_id == "FND-000001"


# ---- update -------------------------------------------------------------------------------


def test_update_records_hashes_and_changes_fields(seeded: Workspace) -> None:
    made = make_finding(seeded, owner="team-a")
    result = update_finding(
        seeded, "FND-000001", actor="Bob", expected_hash=made.after_hash,
        title="New title", description="More", technical_severity=TechnicalSeverity.CRITICAL,
        status=FindingStatus.TRIAGED, evidence="redacted evidence",
    )  # fmt: skip
    finding = get_finding(seeded, "FND-000001")
    assert (finding.title, finding.status) == ("New title", FindingStatus.TRIAGED)
    assert finding.technical_severity is TechnicalSeverity.CRITICAL
    assert (finding.owner, finding.evidence) == ("team-a", "redacted evidence")
    assert finding.updated_at > finding.created_at
    assert finding.fingerprint == FP_A
    assert (result.before_hash, result.after_hash) == (made.after_hash, finding.digest())
    assert result.audit.action == "finding.update"
    assert (result.audit.before_hash, result.audit.after_hash) == (
        made.after_hash,
        finding.digest(),
    )
    assert [e.seq for e in audit_entries(seeded)] == [1, 2, 3]


def test_update_can_clear_the_owner(seeded: Workspace) -> None:
    made = make_finding(seeded, owner="team-a")
    update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                   clear_owner=True)  # fmt: skip
    assert get_finding(seeded, "FND-000001").owner is None
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash="0" * 64, owner="x",
                       clear_owner=True)  # fmt: skip


def test_update_conflict_leaves_everything_unchanged(seeded: Workspace) -> None:
    made = make_finding(seeded)
    update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash, title="A")
    snapshot = get_finding(seeded, "FND-000001")
    with pytest.raises(ConflictServiceError):
        update_finding(seeded, "FND-000001", actor="eve", expected_hash=made.after_hash, title="B")
    assert get_finding(seeded, "FND-000001") == snapshot
    assert [e.seq for e in audit_entries(seeded)] == [1, 2, 3]


def test_repository_level_hash_check(seeded: Workspace) -> None:
    make_finding(seeded)
    finding = get_finding(seeded, "FND-000001")
    changed = finding.with_changes(title="X", updated_at=finding.updated_at.replace(year=2031))
    with pytest.raises(ConflictServiceError), seeded.write() as session:
        FindingRepository(session.connection).update(
            changed, actor="eve", at=session.now, expected_before_hash="1" * 64
        )
    assert get_finding(seeded, "FND-000001") == finding


def test_update_needs_a_real_change_a_valid_hash_and_an_existing_finding(seeded: Workspace) -> None:
    made = make_finding(seeded)
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash)
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                       title="SQL injection in login")  # fmt: skip
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash="nope", title="x")
    with pytest.raises(NotFoundServiceError):
        update_finding(seeded, "FND-000009", actor="bob", expected_hash=made.after_hash, title="x")
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-1", actor="bob", expected_hash=made.after_hash, title="x")
    assert [e.seq for e in audit_entries(seeded)] == [1, 2]


@pytest.mark.parametrize("status", sorted(APPROVAL_GATED_STATUSES))
def test_gated_statuses_need_approval(seeded: Workspace, status: FindingStatus) -> None:
    made = make_finding(seeded)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                       status=status)  # fmt: skip
    assert excinfo.value.code == "approval_required"
    assert get_finding(seeded, "FND-000001").status is FindingStatus.OPEN
    assert [e.seq for e in audit_entries(seeded)] == [1, 2]


@pytest.mark.parametrize("status", [FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS,
                                    FindingStatus.RESOLVED])  # fmt: skip
def test_ordinary_status_changes_are_allowed(seeded: Workspace, status: FindingStatus) -> None:
    made = make_finding(seeded)
    update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash, status=status)
    assert get_finding(seeded, "FND-000001").status is status


def test_leaving_a_gated_status_needs_approval(seeded: Workspace, tmp_path: Path) -> None:
    made = make_finding(seeded)
    finding = get_finding(seeded, "FND-000001")
    gated = finding.with_changes(status=FindingStatus.ACCEPTED_RISK)
    with seeded.write() as session:  # a state that M3 cannot reach by itself (set up directly)
        FindingRepository(session.connection).update(gated, actor="setup", at=session.now)
    assert made.after_hash != gated.digest()
    with pytest.raises(ApprovalRequiredError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=gated.digest(),
                       status=FindingStatus.OPEN)  # fmt: skip
    update_finding(seeded, "FND-000001", actor="bob", expected_hash=gated.digest(), title="T")
    assert get_finding(seeded, "FND-000001").status is FindingStatus.ACCEPTED_RISK


@pytest.mark.parametrize("priority", list(BusinessPriority))
def test_business_priority_cannot_be_changed(seeded: Workspace, priority: BusinessPriority) -> None:
    made = make_finding(seeded)
    with pytest.raises(ApprovalRequiredError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                       business_priority=priority)  # fmt: skip
    assert get_finding(seeded, "FND-000001").business_priority is None
    assert [e.seq for e in audit_entries(seeded)] == [1, 2]


def test_priority_attempt_is_refused_even_together_with_other_changes(seeded: Workspace) -> None:
    made = make_finding(seeded)
    with pytest.raises(ApprovalRequiredError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                       title="Changed", business_priority=BusinessPriority.P1)  # fmt: skip
    assert get_finding(seeded, "FND-000001").title == "SQL injection in login"


def test_failed_audit_rolls_back_an_update(
    seeded: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    made = make_finding(seeded)

    def boom(*args: object, **kwargs: object) -> None:
        raise StorageError("simulated")

    monkeypatch.setattr("soerm.storage.findings.append_audit", boom)
    with pytest.raises(ServiceError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash, title="N")
    monkeypatch.undo()
    assert get_finding(seeded, "FND-000001").digest() == made.after_hash


def test_invalid_update_value_rolls_back(seeded: Workspace) -> None:
    made = make_finding(seeded)
    with pytest.raises(InvalidInputError):
        update_finding(seeded, "FND-000001", actor="bob", expected_hash=made.after_hash,
                       evidence="x" * 70000)  # fmt: skip
    assert get_finding(seeded, "FND-000001").digest() == made.after_hash


# ---- reading ------------------------------------------------------------------------------


def test_list_filters_and_sorting(seeded: Workspace) -> None:
    make_asset(seeded, name="Second asset")
    make_finding(seeded, fingerprint="1" * 64, title="one")
    make_finding(seeded, fingerprint="2" * 64, asset_id="AST-000002",
                 technical_severity=TechnicalSeverity.CRITICAL, title="two")  # fmt: skip
    third = make_finding(seeded, fingerprint="3" * 64, title="three")
    update_finding(seeded, "FND-000003", actor="bob", expected_hash=third.after_hash,
                   status=FindingStatus.TRIAGED)  # fmt: skip

    def ids(items: list[Finding]) -> list[str]:
        return [f.finding_id for f in items]

    assert ids(list_findings(seeded)) == ["FND-000001", "FND-000002", "FND-000003"]
    assert ids(list_findings(seeded, sort=FindingSort.LAST_SEEN)) == [
        "FND-000003", "FND-000002", "FND-000001",
    ]  # most recently seen first  # fmt: skip
    assert ids(list_findings(seeded, status=FindingStatus.TRIAGED)) == ["FND-000003"]
    assert ids(list_findings(seeded, asset_id="AST-000002")) == ["FND-000002"]
    assert ids(list_findings(seeded, severity=TechnicalSeverity.CRITICAL)) == ["FND-000002"]
    assert ids(list_findings(seeded, status=FindingStatus.OPEN, asset_id="AST-000001")) == [
        "FND-000001"
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "open' OR '1'='1"},
        {"severity": "high; DROP TABLE findings"},
        {"sort": "last_seen; DROP TABLE findings"},
        {"sort": "title"},
        {"asset_id": "AST-000001' OR '1'='1"},
        {"asset_id": "FND-000001"},
    ],
)
def test_list_rejects_non_allowlisted_input(seeded: Workspace, kwargs: dict[str, object]) -> None:
    make_finding(seeded)
    with pytest.raises(InvalidInputError):
        list_findings(seeded, **kwargs)  # type: ignore[arg-type]
    assert len(list_findings(seeded)) == 1


def test_get_rejects_bad_ids_and_reports_missing(seeded: Workspace) -> None:
    make_finding(seeded)
    for bad in ("FND-1", "x' OR '1'='1", "AST-000001", ""):
        with pytest.raises(InvalidInputError):
            get_finding(seeded, bad)
    with pytest.raises(NotFoundServiceError):
        get_finding(seeded, "FND-000077")


def test_unknown_asset_filter_returns_nothing(seeded: Workspace) -> None:
    make_finding(seeded)
    assert list_findings(seeded, asset_id="AST-000050") == []


def test_quotes_newlines_and_sql_text_in_text_fields(seeded: Workspace) -> None:
    nasty = 'O\'Brien "q"; DROP TABLE findings; --\nsecond'
    make_finding(seeded, title=nasty, description=nasty, owner="a'b", evidence=nasty)
    finding = get_finding(seeded, "FND-000001")
    assert "DROP TABLE" in finding.title
    assert finding.evidence.startswith("O'Brien")
    assert len(list_findings(seeded)) == 1


def test_corrupt_stored_row_is_an_integrity_error(seeded: Workspace, tmp_path: Path) -> None:
    make_finding(seeded)
    with closing(sqlite3.connect(tmp_path / "soerm.db", isolation_level=None)) as raw:
        raw.execute("PRAGMA ignore_check_constraints = ON")
        raw.execute("UPDATE findings SET risk_factors = '{\"BAD KEY\": 1}'")
    with pytest.raises(IntegrityServiceError):
        get_finding(seeded, "FND-000001")
