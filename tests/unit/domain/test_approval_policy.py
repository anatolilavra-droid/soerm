"""ApprovalPolicy and change_hash (M8)."""

import pytest

from soerm.domain.approval import CHANGE_SCHEME, GATED_FIELDS, ApprovalPolicy, change_hash
from soerm.domain.errors import ValidationDomainError


def test_defaults_are_conservative() -> None:
    policy = ApprovalPolicy()
    assert policy.ttl_hours == 168
    assert policy.require_distinct_approver is True


@pytest.mark.parametrize("ttl", [0, -1, 8761, 1.5, "24", True])
def test_ttl_bounds_are_strict(ttl: object) -> None:
    with pytest.raises(ValidationDomainError):
        ApprovalPolicy(ttl_hours=ttl)  # type: ignore[arg-type]


@pytest.mark.parametrize("flag", ["false", 0, 1, None])
def test_flag_must_be_a_real_bool(flag: object) -> None:
    with pytest.raises(ValidationDomainError):
        ApprovalPolicy(require_distinct_approver=flag)  # type: ignore[arg-type]


def test_unknown_key_rejected() -> None:
    with pytest.raises(ValidationDomainError):
        ApprovalPolicy(ttl=1)  # type: ignore[call-arg]


def test_change_hash_is_stable_and_order_independent() -> None:
    a = change_hash("finding", "FND-000001", {"status": "accepted_risk", "business_priority": "p1"})
    b = change_hash("finding", "FND-000001", {"business_priority": "p1", "status": "accepted_risk"})
    assert a == b
    assert len(a) == 64
    assert CHANGE_SCHEME == "soerm-change-v1"


def test_change_hash_depends_on_every_input() -> None:
    base = change_hash("finding", "FND-000001", {"status": "accepted_risk"})
    assert base != change_hash("finding", "FND-000002", {"status": "accepted_risk"})
    assert base != change_hash("asset", "FND-000001", {"status": "accepted_risk"})
    assert base != change_hash("finding", "FND-000001", {"status": "false_positive"})
    assert base != change_hash("finding", "FND-000001", {"business_priority": "accepted_risk"})


def test_gated_fields() -> None:
    assert frozenset({"status", "business_priority"}) == GATED_FIELDS
