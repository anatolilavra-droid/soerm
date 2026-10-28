"""Approval, Playbook and AuditEntry tests."""
# ruff: noqa: RUF001  (look-alike characters are the point of these tests)

from datetime import timedelta
from typing import Any

import pytest

from soerm.domain import (
    DEFAULT_APPROVAL_TTL,
    GENESIS_HASH,
    Approval,
    ApprovalError,
    ApprovalStatus,
    AuditEntry,
    ExpiredApprovalError,
    IntegrityDomainError,
    Playbook,
    PlaybookStep,
    ValidationDomainError,
    approve,
    compute_entry_hash,
    create_audit_entry,
    expire,
    new_approval,
    reject,
    verify_audit_chain,
)
from soerm.domain.playbook import looks_destructive

from .factories import SECRET, SHA_A, SHA_B, T0, T1, approval_data, playbook_data, step_data

# ---- Approval -----------------------------------------------------------------------------


def make_pending() -> Approval:
    return new_approval(
        change_id="CHG-000001",
        object_type="incident",
        object_id="INC-000001",
        requester="Alice",
        reason="Close after verification",
        before_hash=SHA_A,
        proposed_after_hash=SHA_B,
        requested_at=T0,
    )


def test_new_approval_defaults_to_seven_days() -> None:
    approval = make_pending()
    assert timedelta(days=7) == DEFAULT_APPROVAL_TTL
    assert approval.status is ApprovalStatus.PENDING
    assert approval.requester == "alice"
    assert approval.expires_at == T0 + timedelta(days=7)
    assert approval.approver is None
    assert approval.decided_at is None


def test_new_approval_rejects_non_positive_ttl() -> None:
    for ttl in (timedelta(0), timedelta(seconds=-1)):
        with pytest.raises(ValidationDomainError):
            new_approval(
                change_id="CHG-000001", object_type="incident", object_id="INC-000001",
                requester="alice", reason="r", before_hash=None, proposed_after_hash=SHA_B,
                requested_at=T0, ttl=ttl,
            )  # fmt: skip


def test_requester_and_approver_must_differ_after_normalization() -> None:
    for approver in ("alice", "ALICE", " Alice ", "Ａlice"):
        with pytest.raises(ApprovalError):
            Approval(**approval_data(status="approved", approver=approver, decided_at=T1))
        with pytest.raises(ApprovalError):
            approve(make_pending(), approver=approver, now=T1)
    approved = approve(make_pending(), approver="Bob", now=T1)
    assert approved.approver == "bob"


def test_distinct_approver_rule_is_on_by_default_and_configurable() -> None:
    assert make_pending().require_distinct_approver is True
    relaxed = new_approval(
        change_id="CHG-000001", object_type="incident", object_id="INC-000001",
        requester="alice", reason="r", before_hash=None, proposed_after_hash=SHA_B,
        requested_at=T0, require_distinct_approver=False,
    )  # fmt: skip
    assert relaxed.require_distinct_approver is False
    assert approve(relaxed, approver="Alice", now=T1).approver == "alice"
    explicit = Approval(
        **approval_data(
            status="approved", approver="alice", decided_at=T1, require_distinct_approver=False
        )
    )
    assert explicit.approver == "alice"
    with pytest.raises(ApprovalError):
        Approval(**approval_data(status="approved", approver="alice", decided_at=T1))


def test_approve_and_reject_set_decision_fields() -> None:
    approved = approve(make_pending(), approver="bob", now=T1)
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.decided_at == T1
    rejected = reject(make_pending(), approver="bob", now=T1)
    assert rejected.status is ApprovalStatus.REJECTED


def test_decision_fields_are_required_for_decided_statuses() -> None:
    for status in ("approved", "rejected"):
        with pytest.raises(ValidationDomainError) as excinfo:
            Approval(**approval_data(status=status, approver="bob"))
        assert excinfo.value.issues[0].field == "decided_at"
        with pytest.raises(ValidationDomainError) as excinfo:
            Approval(**approval_data(status=status, decided_at=T1))
        assert excinfo.value.issues[0].field == "approver"


@pytest.mark.parametrize("status", ["pending", "expired"])
def test_undecided_statuses_must_not_have_decision_fields(status: str) -> None:
    with pytest.raises(ValidationDomainError):
        Approval(**approval_data(status=status, decided_at=T1))
    with pytest.raises(ValidationDomainError):
        Approval(**approval_data(status=status, approver="bob"))


def test_expiry_must_be_after_request() -> None:
    for expires in (T0, T0 - timedelta(seconds=1)):
        with pytest.raises(ValidationDomainError) as excinfo:
            Approval(**approval_data(expires_at=expires))
        assert excinfo.value.issues[0].code == "not_after_requested_at"


def test_expired_pending_approval_cannot_be_approved_or_rejected() -> None:
    pending = make_pending()
    late = pending.expires_at
    for decide in (approve, reject):
        with pytest.raises(ExpiredApprovalError):
            decide(pending, approver="bob", now=late)
        with pytest.raises(ExpiredApprovalError):
            decide(pending, approver="bob", now=late + timedelta(days=30))
    just_in_time = approve(pending, approver="bob", now=late - timedelta(microseconds=1))
    assert just_in_time.status is ApprovalStatus.APPROVED


def test_approved_record_cannot_be_dated_after_expiry() -> None:
    with pytest.raises(ExpiredApprovalError):
        Approval(
            **approval_data(status="approved", approver="bob", decided_at=T0 + timedelta(days=8))
        )


def test_decision_cannot_precede_request() -> None:
    with pytest.raises(ApprovalError):
        approve(make_pending(), approver="bob", now=T0 - timedelta(seconds=1))


def test_only_pending_approval_can_be_decided() -> None:
    approved = approve(make_pending(), approver="bob", now=T1)
    for decide in (approve, reject):
        with pytest.raises(ApprovalError) as excinfo:
            decide(approved, approver="carol", now=T1)
        assert excinfo.value.details["reason"] == "not_pending"


def test_expire_marks_overdue_pending_only() -> None:
    pending = make_pending()
    with pytest.raises(ApprovalError):
        expire(pending, now=pending.expires_at - timedelta(seconds=1))
    expired = expire(pending, now=pending.expires_at)
    assert expired.status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalError):
        expire(expired, now=pending.expires_at)


def test_approve_requires_aware_now() -> None:
    from datetime import datetime

    with pytest.raises(ValidationDomainError):
        approve(make_pending(), approver="bob", now=datetime(2026, 3, 2))  # noqa: DTZ001


def test_approval_stores_no_payload() -> None:
    forbidden = {"payload", "evidence", "description", "raw", "body", "diff", "content", "data"}
    assert not forbidden & set(Approval.model_fields)
    for field in ("evidence", "description", "payload"):
        with pytest.raises(ValidationDomainError):
            Approval(**approval_data(**{field: SECRET}))


def test_approval_hash_and_id_validation() -> None:
    for bad in ({"proposed_after_hash": "A" * 64}, {"before_hash": "x"}, {"change_id": "CHG-1"},
                {"object_type": "Bad Type"}, {"reason": " "}, {"requester": ""}):  # fmt: skip
        with pytest.raises(ValidationDomainError):
            Approval(**approval_data(**bad))
    assert Approval(**approval_data(before_hash=None)).before_hash is None


def test_approval_errors_do_not_leak() -> None:
    with pytest.raises(ValidationDomainError) as excinfo:
        Approval(**approval_data(reason=SECRET * 100, requester=SECRET))
    assert SECRET not in str(excinfo.value) + repr(excinfo.value.to_dict())


# ---- Playbook -----------------------------------------------------------------------------


def test_valid_playbook() -> None:
    playbook = Playbook(**playbook_data())
    assert playbook.steps[0].step_type == "manual"
    assert playbook.config_hash == SHA_A


@pytest.mark.parametrize("step_type", ["manual", "checklist", "notify_text"])
def test_allowed_step_types(step_type: str) -> None:
    data = step_data(step_type=step_type)
    if step_type == "checklist":
        data.update(text="", items=["Check mailbox", "Check forwarding rules"])
    assert PlaybookStep(**data).step_type == step_type


@pytest.mark.parametrize(
    "step_type", ["automated", "script", "shell", "http_request", "execute", ""]
)
def test_other_step_types_are_refused(step_type: str) -> None:
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(step_type=step_type))


def test_step_content_rules() -> None:
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(text=""))  # manual needs text
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(step_type="checklist", text="", items=[]))
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(step_type="checklist", items=["a"]))  # text not allowed
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(items=["a"]))  # items only for checklists


DESTRUCTIVE_TEXTS = [
    "Delete the malicious mailbox rule",
    "Disable the account",
    "Isolate the host from the network",
    "Block the sender domain",
    "Reset the password",
    "Shut down the server",
    "Revoke API tokens",
    "Удалить письмо из почтовых ящиков",
    "Отключить учётную запись",
    "Заблокировать домен",
    "Изолировать хост",
    "Сбросить пароль",
]


@pytest.mark.parametrize("text", DESTRUCTIVE_TEXTS)
def test_destructive_text_requires_manual_approval(text: str) -> None:
    assert looks_destructive(text)
    with pytest.raises(ValidationDomainError) as excinfo:
        PlaybookStep(**step_data(text=text))
    assert excinfo.value.issues[0].code == "required_for_destructive_step"
    step = PlaybookStep(**step_data(text=text, requires_manual_approval=True))
    assert step.requires_manual_approval is True


def test_declared_destructive_step_requires_manual_approval() -> None:
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(potentially_destructive=True))
    step = PlaybookStep(**step_data(potentially_destructive=True, requires_manual_approval=True))
    assert step.requires_manual_approval is True


def test_destructive_checklist_item_and_notification_are_covered() -> None:
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(step_type="checklist", text="", items=["Wipe the laptop"]))
    with pytest.raises(ValidationDomainError):
        PlaybookStep(**step_data(step_type="notify_text", text="We will block the account today"))


@pytest.mark.parametrize("text", ["Collect logs", "Notify the owner", "Review the mail headers",
                                  "Кластер проверен", "Skill assessment"])  # fmt: skip
def test_harmless_text_is_not_flagged(text: str) -> None:
    assert not looks_destructive(text)


def test_playbook_consistency_rules() -> None:
    bad_cases: list[dict[str, Any]] = [
        {"roles": []},
        {"roles": ["analyst", "analyst"]},
        {"steps": []},
        {"steps": [step_data(), step_data()]},
        {"steps": [step_data(owner_role="unknown")]},
        {"config_hash": "ABC"},
        {"playbook_id": "Bad Id"},
        {"version": "bad version"},
    ]
    for bad in bad_cases:
        with pytest.raises(ValidationDomainError):
            Playbook(**playbook_data(**bad))
    playbook = Playbook(**playbook_data(steps=[step_data(owner_role="lead")]))
    assert playbook.steps[0].owner_role == "lead"


def test_domain_never_executes_steps() -> None:
    from soerm.domain import playbook

    public = {name for name in dir(playbook) if not name.startswith("_")}
    assert not {n for n in public if n.startswith(("run", "execute", "exec", "apply"))}
    assert not {n for n in dir(PlaybookStep) if n.startswith(("run", "execute", "apply"))}
    assert not {n for n in dir(Playbook) if n.startswith(("run", "execute", "apply"))}


# ---- AuditEntry ---------------------------------------------------------------------------


def make_entry(**overrides: Any) -> AuditEntry:
    fields: dict[str, Any] = {
        "seq": 1,
        "timestamp": T0,
        "actor": "Alice",
        "action": "asset.create",
        "object_type": "asset",
        "object_id": "AST-000001",
        "before_hash": None,
        "after_hash": SHA_A,
        "prev_hash": GENESIS_HASH,
    }
    fields.update(overrides)
    return create_audit_entry(**fields)


def test_entry_hash_is_computed_from_canonical_json() -> None:
    entry = make_entry()
    expected = compute_entry_hash(
        seq=1, timestamp=T0, actor="alice", action="asset.create", object_type="asset",
        object_id="AST-000001", before_hash=None, after_hash=SHA_A, prev_hash=GENESIS_HASH,
    )  # fmt: skip
    assert entry.entry_hash == expected
    assert len(entry.entry_hash) == 64
    assert entry.entry_hash == make_entry().entry_hash  # deterministic
    assert entry.actor == "alice"


def test_every_field_influences_the_hash() -> None:
    base = make_entry().entry_hash
    changes: list[dict[str, Any]] = [
        {"actor": "bob"}, {"action": "asset.update"}, {"object_type": "finding"},
        {"object_id": "AST-000002"}, {"before_hash": SHA_B}, {"after_hash": SHA_B},
        {"timestamp": T1}, {"prev_hash": SHA_A},
    ]  # fmt: skip
    hashes = {make_entry(**change).entry_hash for change in changes}
    assert base not in hashes
    assert len(hashes) == len(changes)
    assert make_entry(seq=2).entry_hash != base


def test_tampered_entry_is_refused() -> None:
    entry = make_entry()
    data = entry.canonical_dict()
    data["after_hash"] = SHA_B
    with pytest.raises(IntegrityDomainError) as excinfo:
        AuditEntry.model_validate(data)
    assert excinfo.value.details["reason"] == "entry_hash_mismatch"
    assert AuditEntry.model_validate(entry.canonical_dict()) == entry


@pytest.mark.parametrize("field", ["prev_hash", "entry_hash", "before_hash", "after_hash"])
@pytest.mark.parametrize("value", ["A" * 64, "a" * 63, "g" * 64, "a" * 64 + "\n", 5])
def test_audit_hash_fields_must_be_lowercase_sha256(field: str, value: object) -> None:
    data = make_entry().canonical_dict()
    data[field] = value
    with pytest.raises(ValidationDomainError):
        AuditEntry.model_validate(data)


@pytest.mark.parametrize("field", ["actor", "action", "object_type", "object_id"])
@pytest.mark.parametrize("value", ["", "   ", "\x00"])
def test_audit_identity_fields_are_not_empty(field: str, value: str) -> None:
    with pytest.raises(ValidationDomainError):
        make_entry(**{field: value})


def test_audit_timestamp_must_be_utc_aware() -> None:
    from datetime import datetime

    from soerm.domain import InvalidTimestampError

    with pytest.raises(InvalidTimestampError):
        make_entry(timestamp=datetime(2026, 1, 1))  # noqa: DTZ001
    assert make_entry(timestamp="2026-03-01T14:00:00+02:00").timestamp == T0
    assert make_entry().canonical_dict()["timestamp"] == "2026-03-01T12:00:00Z"


def test_audit_entry_has_no_payload_fields() -> None:
    assert set(AuditEntry.model_fields) == {
        "seq", "timestamp", "actor", "action", "object_type", "object_id",
        "before_hash", "after_hash", "prev_hash", "entry_hash",
    }  # fmt: skip
    data = make_entry().canonical_dict()
    for extra in ("payload", "evidence", "description", "details", "message"):
        with pytest.raises(ValidationDomainError):
            AuditEntry.model_validate({**data, extra: SECRET})


def test_audit_sequence_must_be_positive() -> None:
    with pytest.raises(IntegrityDomainError):
        make_entry(seq=0)


def test_verify_audit_chain() -> None:
    first = make_entry()
    second = make_entry(seq=2, prev_hash=first.entry_hash, action="asset.update")
    third = make_entry(seq=3, prev_hash=second.entry_hash, action="asset.delete")
    verify_audit_chain([])
    verify_audit_chain([first, second, third])
    with pytest.raises(IntegrityDomainError) as excinfo:
        verify_audit_chain([first, third])
    assert excinfo.value.details["reason"] == "sequence_gap"
    with pytest.raises(IntegrityDomainError) as excinfo:
        verify_audit_chain([first, make_entry(seq=2, prev_hash=SHA_B)])
    assert excinfo.value.details["reason"] == "chain_broken"
    with pytest.raises(IntegrityDomainError):
        verify_audit_chain([second])
    forged = first.model_construct(**{**dict(first), "after_hash": SHA_B})
    with pytest.raises(IntegrityDomainError) as excinfo:
        verify_audit_chain([forged])
    assert excinfo.value.details["reason"] == "entry_hash_mismatch"
