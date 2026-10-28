"""Pure report building: aggregation, ordering, age buckets, Markdown escaping, policy."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from soerm.domain.errors import ValidationDomainError
from soerm.domain.report import (
    AssetFacts,
    AuditFacts,
    FindingFacts,
    ReportInput,
    ReportPolicy,
    build_report,
    markdown_text,
    render_json,
    render_markdown,
)

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def finding(
    n: int,
    *,
    status: str = "open",
    severity: str = "high",
    priority: str | None = "p2",
    age_days: int = 3,
    due_days: int | None = 10,
    asset: str = "AST-000001",
) -> FindingFacts:
    return FindingFacts(
        f"FND-{n:06d}",
        asset,
        f"Finding {n}",
        status,
        severity,
        priority,
        None if due_days is None else NOW + timedelta(days=due_days),
        NOW - timedelta(days=age_days),
    )


def make_input(findings: tuple[FindingFacts, ...] = (), **kwargs: object) -> ReportInput:
    values: dict[str, object] = {
        "generated_at": NOW,
        "tool_version": "0.0.0",
        "schema_versions": (1, 2),
        "redaction_config_hash": "r" * 64,
        "risk_config_hash": "k" * 64,
        "policy": ReportPolicy(),
        "sanitize": lambda text: text,
        "assets": (AssetFacts("AST-000001", "Billing", "high", "internet", "production"),),
        "findings": findings,
        "incidents": (),
        "tasks": (),
        "playbooks": (),
        "approvals": (),
        "audit": AuditFacts(True, 3, "h" * 64),
    }
    values.update(kwargs)
    return ReportInput(**values)  # type: ignore[arg-type]


def test_active_and_overdue_counts() -> None:
    data = build_report(
        make_input(
            (
                finding(1, due_days=-2),
                finding(2, status="in_progress"),
                finding(3, status="resolved", due_days=-5),
                finding(4, due_days=None),
            )
        )
    )
    assert data["findings"]["total"] == 4
    assert data["findings"]["active"] == 3
    assert data["findings"]["overdue"]["count"] == 1
    assert data["executive_summary"]["overdue_findings"] == 1


def test_age_buckets() -> None:
    findings = tuple(finding(i + 1, age_days=d) for i, d in enumerate((1, 20, 60, 200)))
    ages = build_report(make_input(findings))["findings"]["active_age_days"]
    assert ages["oldest"] == 200
    assert sum(ages["buckets"].values()) == 4
    assert all(count == 1 for count in ages["buckets"].values())


def test_unprioritized_findings_are_counted() -> None:
    data = build_report(make_input((finding(1, priority=None), finding(2, priority="p1"))))
    by_priority = data["findings"]["active_by_priority"]
    assert by_priority["unprioritized"] == 1
    assert by_priority["p1"] == 1


def test_same_input_same_output_and_key_order_is_fixed() -> None:
    inp = make_input((finding(2), finding(1)))
    first, second = build_report(inp), build_report(inp)
    assert render_json(first) == render_json(second)
    assert render_markdown(first) == render_markdown(second)
    assert list(first)[:4] == [
        "report_schema",
        "generated_at",
        "tool_version",
        "database_schema_versions",
    ]


def test_input_order_does_not_change_the_report() -> None:
    a = build_report(make_input((finding(1), finding(2, severity="low"))))
    b = build_report(make_input((finding(2, severity="low"), finding(1))))
    assert render_json(a) == render_json(b)


def test_facts_have_no_description_or_evidence_fields() -> None:
    names = set(FindingFacts.__dataclass_fields__)
    assert not names & {"description", "evidence", "notes", "summary"}


def test_sanitizer_is_applied_to_titles() -> None:
    data = build_report(make_input((finding(1),), sanitize=lambda text: "X" * len(text)))
    assert "Finding 1" not in render_json(data)
    assert "Finding 1" not in render_markdown(data)


def test_json_is_valid_ascii() -> None:
    text = render_json(build_report(make_input((finding(1),))))
    assert json.loads(text)["report_schema"] == "soerm-report-v1"
    assert text.isascii()
    assert text.endswith("\n")


@pytest.mark.parametrize(
    ("raw", "expected_absent"),
    [
        ("a|b", "a|b"),
        ("<script>", "<script>"),
        ("[x](http://e)", "[x]"),
        ("`code`", "`code`"),
        ("line\nbreak\r\x1b[31m", "\n"),
    ],
)
def test_markdown_text_escapes(raw: str, expected_absent: str) -> None:
    out = markdown_text(raw)
    assert expected_absent not in out
    assert "\n" not in out
    assert "\x1b" not in out


def test_markdown_text_collapses_whitespace_and_format_chars() -> None:
    assert markdown_text("a \u200b\u202e  b\u2028c") == "a b c"


def test_broken_audit_in_the_report() -> None:
    audit = AuditFacts(False, 5, "h" * 64, 3, "entry_hash_mismatch")
    data = build_report(make_input(audit=audit))
    assert data["audit"]["status"] == "broken"
    assert data["audit"]["broken_at_seq"] == 3
    assert data["executive_summary"]["audit_status"] == "broken"
    assert data["executive_summary"]["attention"]


def test_empty_input() -> None:
    data = build_report(make_input(assets=()))
    assert data["findings"]["total"] == 0
    assert data["assets"]["total"] == 0
    assert data["tasks"]["completion_percent"] in (0, 0.0)
    assert "<!--" in render_markdown(data)


def test_listing_is_capped() -> None:
    policy = ReportPolicy(top_findings=2, max_listed=3)
    data = build_report(
        make_input(tuple(finding(i, due_days=-1) for i in range(1, 9)), policy=policy)
    )
    assert len(data["findings"]["top"]) == 2
    assert len(data["findings"]["overdue"]["items"]) == 3
    assert data["findings"]["overdue"]["count"] == 8


def test_policy_validation() -> None:
    assert ReportPolicy().top_findings == 10
    for bad in (
        {"top_findings": 0},
        {"max_listed": 501},
        {"allowed_output_dirs": ("relative/dir",)},
        {"allowed_output_dirs": ("/a/../b",)},
        {"allowed_output_dirs": tuple(f"/d{i}" for i in range(9))},
        {"unknown": 1},
    ):
        with pytest.raises(ValidationDomainError):
            ReportPolicy(**bad)
    assert ReportPolicy(allowed_output_dirs=("/srv/exports",)).allowed_output_dirs
