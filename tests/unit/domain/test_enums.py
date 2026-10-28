"""Every enum value is a stable lowercase string."""

import pytest

from soerm.domain import enums

EXPECTED: dict[str, list[str]] = {
    "Environment": ["production", "staging", "development", "test"],
    "BusinessCriticality": ["low", "medium", "high", "critical"],
    "DataClassification": ["public", "internal", "confidential", "restricted"],
    "Exposure": ["internet", "partner", "internal", "isolated"],
    "TechnicalSeverity": ["none", "low", "medium", "high", "critical"],
    "BusinessPriority": ["p1", "p2", "p3", "p4"],
    "FindingStatus": [
        "open",
        "triaged",
        "in_progress",
        "resolved",
        "accepted_risk",
        "false_positive",
    ],
    "IncidentStatus": ["new", "triaged", "investigating", "contained", "remediated", "closed"],
    "TaskStatus": ["open", "in_progress", "done", "cancelled"],
    "ApprovalStatus": ["pending", "approved", "rejected", "expired"],
    "ImportSource": ["sarif", "generic_json", "csv", "manual"],
    "StepType": ["manual", "checklist", "notify_text"],
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_enum_values(name: str) -> None:
    enum_class = getattr(enums, name)
    assert [member.value for member in enum_class] == EXPECTED[name]
    for member in enum_class:
        assert isinstance(member.value, str)
        assert member.value == member.value.lower()
        assert str(member) == member.value


def test_all_enums_are_covered() -> None:
    assert set(enums.__all__) == set(EXPECTED)


def test_enum_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="is not a valid"):
        enums.Environment("prod")
