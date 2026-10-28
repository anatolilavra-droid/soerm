"""Approvals (M8): request, distinct approver, expiry, single use, application, audit."""

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soerm.domain.enums import ApprovalStatus, BusinessPriority, FindingStatus
from soerm.services import approvals as svc
from soerm.services.errors import (
    ApprovalDeniedError,
    ApprovalRequiredError,
    ConfigServiceError,
    ConflictServiceError,
    InvalidInputError,
    NotFoundServiceError,
)
from soerm.services.findings import get_finding, update_finding
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from tests.unit.importers.helpers import put
from tests.unit.services.helpers import BASE_TIME, SECRET, make_asset, make_finding


class Clock:
    def __init__(self) -> None:
        self.now = BASE_TIME

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now

    def jump(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def seeded(tmp_path: Path, clock: Clock) -> Workspace:
    ws = Workspace(tmp_path, clock=clock)
    make_asset(ws)
    make_finding(ws)
    return ws


def request(ws: Workspace, **kw: object) -> str:
    args: dict[str, object] = {
        "actor": "alice",
        "reason": "vendor confirmed",
        "status": FindingStatus.ACCEPTED_RISK,
    }
    args.update(kw)
    return svc.request_change(ws, "FND-000001", **args).object_id  # type: ignore[arg-type]


def apply(ws: Workspace, change_id: str, actor: str = "carol", **kw: object) -> None:
    args: dict[str, object] = {"status": FindingStatus.ACCEPTED_RISK}
    args.update(kw)
    update_finding(
        ws,
        "FND-000001",
        actor=actor,
        expected_hash=get_finding(ws, "FND-000001").digest(),
        change_id=change_id,
        **args,  # type: ignore[arg-type]
    )


def actions(ws: Workspace) -> list[str]:
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as conn:
        return [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY seq")]


def test_gated_update_without_approval_is_refused(seeded: Workspace) -> None:
    with pytest.raises(ApprovalRequiredError):
        update_finding(
            seeded, "FND-000001", actor="a",
            expected_hash=get_finding(seeded, "FND-000001").digest(),
            status=FindingStatus.ACCEPTED_RISK,
        )  # fmt: skip


def test_full_flow_request_approve_apply(seeded: Workspace) -> None:
    cid = request(seeded)
    view = svc.get_approval(seeded, cid)
    assert view.approval.status is ApprovalStatus.PENDING
    assert view.approval.require_distinct_approver is True
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    apply(seeded, cid)
    finding = get_finding(seeded, "FND-000001")
    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert svc.get_approval(seeded, cid).applied is True
    assert actions(seeded)[-3:] == ["approval.approve", "finding.update", "approval.apply"]


def test_self_approval_forbidden_by_default(seeded: Workspace) -> None:
    cid = request(seeded)
    with pytest.raises(ApprovalDeniedError, match="self_approval"):
        svc.decide_approval(seeded, cid, actor="alice", approved=True)
    with pytest.raises(ApprovalDeniedError, match="self_approval"):
        svc.decide_approval(seeded, cid, actor="Alice", approved=False)
    assert svc.get_approval(seeded, cid).approval.status is ApprovalStatus.PENDING


def test_policy_allows_self_approval_and_stores_flag(tmp_path: Path, clock: Clock) -> None:
    put(tmp_path, "soerm.yaml", "version: 1\napprovals:\n  require_distinct_approver: false\n")
    ws = Workspace(tmp_path, clock=clock)
    make_asset(ws)
    make_finding(ws)
    cid = request(ws)
    assert svc.get_approval(ws, cid).approval.require_distinct_approver is False
    svc.decide_approval(ws, cid, actor="alice", approved=True)
    assert svc.get_approval(ws, cid).approval.status is ApprovalStatus.APPROVED


def test_flag_is_snapshotted_at_request_time(tmp_path: Path, clock: Clock) -> None:
    ws = Workspace(tmp_path, clock=clock)
    make_asset(ws)
    make_finding(ws)
    cid = request(ws)  # default policy: distinct required
    put(tmp_path, "soerm.yaml", "version: 1\napprovals:\n  require_distinct_approver: false\n")
    with pytest.raises(ApprovalDeniedError, match="self_approval"):
        svc.decide_approval(ws, cid, actor="alice", approved=True)


def test_ttl_from_policy(tmp_path: Path, clock: Clock) -> None:
    put(tmp_path, "soerm.yaml", "version: 1\napprovals:\n  ttl_hours: 2\n")
    ws = Workspace(tmp_path, clock=clock)
    make_asset(ws)
    make_finding(ws)
    cid = request(ws)
    a = svc.get_approval(ws, cid).approval
    assert a.expires_at - a.requested_at == timedelta(hours=2)


def test_bad_policy_rejected(tmp_path: Path, clock: Clock) -> None:
    ws = Workspace(tmp_path, clock=clock)
    make_asset(ws)
    make_finding(ws)
    put(tmp_path, "soerm.yaml", "version: 1\napprovals:\n  ttl_hours: 0\n")
    with pytest.raises(ConfigServiceError, match=r"approvals\.ttl_hours"):
        request(ws)
    assert svc.list_approvals(ws) == []


def test_decision_is_single(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    with pytest.raises(ApprovalDeniedError):
        svc.decide_approval(seeded, cid, actor="carol", approved=True)
    with pytest.raises(ApprovalDeniedError):
        svc.decide_approval(seeded, cid, actor="carol", approved=False)
    assert svc.get_approval(seeded, cid).approval.approver == "bob"


def test_reject_then_nothing_applies(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=False)
    assert svc.get_approval(seeded, cid).approval.status is ApprovalStatus.REJECTED
    with pytest.raises(ApprovalDeniedError, match="approval_not_approved"):
        apply(seeded, cid)


def test_pending_cannot_be_applied(seeded: Workspace) -> None:
    cid = request(seeded)
    with pytest.raises(ApprovalDeniedError, match="approval_not_approved"):
        apply(seeded, cid)


def test_approve_after_expiry_refused_and_recorded(seeded: Workspace, clock: Clock) -> None:
    cid = request(seeded)
    clock.jump(hours=24 * 30)
    with pytest.raises(ApprovalDeniedError, match="approval_expired"):
        svc.decide_approval(seeded, cid, actor="bob", approved=True)
    approval = svc.get_approval(seeded, cid).approval
    assert approval.status is ApprovalStatus.EXPIRED
    assert approval.approver is None
    assert "approval.expire" in actions(seeded)
    with pytest.raises(ApprovalDeniedError):
        svc.decide_approval(seeded, cid, actor="bob", approved=True)


def test_effective_status_shows_expiry_before_recording(seeded: Workspace, clock: Clock) -> None:
    cid = request(seeded)
    clock.jump(hours=24 * 30)
    view = svc.get_approval(seeded, cid)
    assert view.approval.status is ApprovalStatus.PENDING
    assert view.effective_status == "expired"


def test_expire_pending_sweep(seeded: Workspace, clock: Clock) -> None:
    cid = request(seeded)
    assert svc.expire_pending(seeded, actor="sys").expired == ()
    clock.jump(hours=24 * 30)
    result = svc.expire_pending(seeded, actor="sys")
    assert result.expired == (cid,)
    assert result.audit_entries == 1
    assert svc.expire_pending(seeded, actor="sys").expired == ()


def test_approved_but_expired_cannot_be_applied(seeded: Workspace, clock: Clock) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    clock.jump(hours=24 * 30)
    with pytest.raises(ApprovalDeniedError, match="approval_expired"):
        apply(seeded, cid)
    assert get_finding(seeded, "FND-000001").status is FindingStatus.OPEN


def test_single_use(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    apply(seeded, cid)
    # move back out of the gated state through a second approval, then try the old one again
    cid2 = request(seeded, status=FindingStatus.OPEN)
    svc.decide_approval(seeded, cid2, actor="bob", approved=True)
    apply(seeded, cid2, status=FindingStatus.OPEN)
    with pytest.raises(ApprovalDeniedError, match="approval_already_applied"):
        apply(seeded, cid)


def test_change_mismatch(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    with pytest.raises(ApprovalDeniedError, match="approval_change_mismatch"):
        apply(seeded, cid, status=FindingStatus.FALSE_POSITIVE)
    with pytest.raises(ApprovalDeniedError, match="approval_change_mismatch"):
        apply(seeded, cid, status=FindingStatus.ACCEPTED_RISK,
              business_priority=BusinessPriority.P1)  # fmt: skip
    assert get_finding(seeded, "FND-000001").status is FindingStatus.OPEN


def test_stale_target(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    update_finding(
        seeded, "FND-000001", actor="a",
        expected_hash=get_finding(seeded, "FND-000001").digest(), title="Reworded",
    )  # fmt: skip
    with pytest.raises(ApprovalDeniedError, match="approval_stale_target"):
        apply(seeded, cid)


def test_other_object(seeded: Workspace) -> None:
    make_finding(seeded, fingerprint="b" * 64, title="Other")
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    with pytest.raises(ApprovalDeniedError, match="approval_other_object"):
        update_finding(
            seeded, "FND-000002", actor="c",
            expected_hash=get_finding(seeded, "FND-000002").digest(),
            change_id=cid, status=FindingStatus.ACCEPTED_RISK,
        )  # fmt: skip


def test_manual_priority_via_approval_has_no_risk_config_hash(seeded: Workspace) -> None:
    cid = request(seeded, status=None, business_priority=BusinessPriority.P1)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    apply(seeded, cid, status=None, business_priority=BusinessPriority.P1)
    finding = get_finding(seeded, "FND-000001")
    assert finding.business_priority is BusinessPriority.P1
    assert finding.risk_config_hash is None


def test_change_id_allows_only_gated_fields(seeded: Workspace) -> None:
    cid = request(seeded)
    svc.decide_approval(seeded, cid, actor="bob", approved=True)
    with pytest.raises(InvalidInputError, match="only_gated_fields"):
        apply(seeded, cid, title="sneaky")
    with pytest.raises(InvalidInputError, match="nothing_to_apply"):
        apply(seeded, cid, status=None)


def test_request_validation(seeded: Workspace) -> None:
    with pytest.raises(InvalidInputError, match="required"):
        request(seeded, status=None)
    with pytest.raises(InvalidInputError, match="approval_not_applicable"):
        request(seeded, status=FindingStatus.RESOLVED)
    with pytest.raises(NotFoundServiceError):
        svc.request_change(
            seeded, "FND-000099", actor="a", reason="r", status=FindingStatus.ACCEPTED_RISK
        )
    request(seeded)
    with pytest.raises(ConflictServiceError, match="duplicate_pending_request"):
        request(seeded)


def test_approval_holds_no_raw_text(seeded: Workspace) -> None:
    cid = request(seeded, reason=f"token={SECRET} was rotated")
    reason = svc.get_approval(seeded, cid).approval.reason
    assert SECRET not in reason
    with closing(sqlite3.connect(seeded.path / DATABASE_FILE_NAME)) as conn:
        dump = "\n".join(conn.iterdump())
        audit = repr(conn.execute("SELECT * FROM audit_log").fetchall())
        pending = repr(conn.execute("SELECT * FROM pending_changes").fetchall())
    assert SECRET not in dump
    assert "vendor" not in audit
    assert "rotated" not in audit
    # the stored proposal is a hash of enum codes; neither title nor evidence is present
    assert "SQL injection" not in pending


def test_approval_list_filters(seeded: Workspace) -> None:
    cid = request(seeded)
    assert [v.approval.change_id for v in svc.list_approvals(seeded)] == [cid]
    assert svc.list_approvals(seeded, status=ApprovalStatus.APPROVED) == []
    assert len(svc.list_approvals(seeded, finding_id="FND-000001")) == 1
    with pytest.raises(NotFoundServiceError):
        svc.get_approval(seeded, "CHG-000099")


def test_failed_decision_writes_no_audit(seeded: Workspace) -> None:
    cid = request(seeded)
    before = actions(seeded)
    with pytest.raises(ApprovalDeniedError):
        svc.decide_approval(seeded, cid, actor="alice", approved=True)
    assert actions(seeded) == before
