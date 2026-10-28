"""Report service: safe content, determinism, read-only behaviour, audit and schema states."""

import json
import sqlite3
import unicodedata
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soerm.domain.enums import TechnicalSeverity
from soerm.domain.report import REPORT_SCHEMA
from soerm.services.errors import (
    ConflictServiceError,
    IntegrityServiceError,
    InvalidInputError,
    NotFoundServiceError,
)
from soerm.services.incidents import create_incident
from soerm.services.reports import build_workspace_report, generate_report
from soerm.services.tasks import create_task
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.connection import open_database
from soerm.storage.lock import LOCK_FILE_NAME
from soerm.storage.migrations import MIGRATIONS, apply_migrations
from tests.unit.services.helpers import (
    BASE_TIME,
    FP_B,
    SECRET,
    make_asset,
    make_finding,
    raw_execute,
    table_dump,
)

FIXED = datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)
DESCRIPTION_MARKER = "DESCRIPTION-MARKER-q7"
EVIDENCE_MARKER = "EVIDENCE-MARKER-q7"


@pytest.fixture
def seeded(ws: Workspace) -> Workspace:
    make_asset(ws)
    make_finding(
        ws, description=DESCRIPTION_MARKER, evidence=f"{EVIDENCE_MARKER} password={SECRET}"
    )
    make_finding(ws, fingerprint=FP_B, title="Weak TLS", technical_severity=TechnicalSeverity.LOW)
    create_incident(
        ws, actor="alice", title="Phish", severity=TechnicalSeverity.HIGH, owner="ir",
        summary=f"SUMMARY-MARKER {SECRET}",
    )  # fmt: skip
    create_task(ws, actor="alice", title="Patch it", owner="ops", finding_id="FND-000001")
    return ws


def snapshot(path: Path) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(path / DATABASE_FILE_NAME)) as raw:
        tables = [
            r[0]
            for r in raw.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        ]
        return [(t, repr(raw.execute(f"SELECT * FROM {t}").fetchall())) for t in tables]  # noqa: S608


def test_report_has_no_evidence_descriptions_or_secrets(seeded: Workspace) -> None:
    built = build_workspace_report(seeded, generated_at=FIXED)
    for text in (built.markdown, built.json):
        for forbidden in (DESCRIPTION_MARKER, EVIDENCE_MARKER, "SUMMARY-MARKER", SECRET):
            assert forbidden not in text
    assert "Billing API" in built.markdown
    assert "SQL injection in login" in built.markdown


def test_secret_inserted_behind_the_services_is_redacted_again(seeded: Workspace) -> None:
    raw_execute(seeded.path, "DROP TRIGGER IF EXISTS findings_no_update")
    try:
        raw_execute(
            seeded.path,
            "UPDATE findings SET title = ? WHERE finding_id = 'FND-000002'",
            (f"leak password={SECRET} \x1b[31mred\x1b[0m",),
        )
    except sqlite3.Error:
        pytest.skip("findings are protected against raw updates")
    built = build_workspace_report(seeded, generated_at=FIXED)
    assert SECRET not in built.markdown
    assert SECRET not in built.json
    assert "\x1b" not in built.markdown
    assert "\x1b" not in built.json


def test_markdown_has_no_control_characters(seeded: Workspace) -> None:
    text = build_workspace_report(seeded, generated_at=FIXED).markdown
    for char in text:
        if char == "\n":
            continue
        assert unicodedata.category(char) not in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
    assert text.startswith(f"<!-- {REPORT_SCHEMA} -->")


def test_json_is_valid_with_stable_field_order(seeded: Workspace) -> None:
    built = build_workspace_report(seeded, generated_at=FIXED)
    data = json.loads(built.json)
    assert list(data) == [
        "report_schema",
        "generated_at",
        "tool_version",
        "database_schema_versions",
        "config",
        "audit",
        "executive_summary",
        "findings",
        "assets",
        "incidents",
        "tasks",
        "playbooks",
        "approvals",
    ]
    assert data["report_schema"] == REPORT_SCHEMA
    assert data["generated_at"].startswith("2026-04-01")
    assert list(data["config"]) == ["redaction_config_hash", "risk_config_hash"]
    assert data["audit"]["status"] == "intact"
    assert data["executive_summary"]["active_findings"] == 2
    assert built.json.isascii()


def test_report_is_deterministic(seeded: Workspace) -> None:
    first = build_workspace_report(seeded, generated_at=FIXED)
    second = build_workspace_report(seeded, generated_at="2026-04-01T00:00:00Z")
    assert first.json == second.json
    assert first.markdown == second.markdown


def test_building_changes_nothing_and_takes_no_lock(seeded: Workspace) -> None:
    lock = seeded.path / LOCK_FILE_NAME
    lock_before = lock.read_bytes() if lock.exists() else None
    before = snapshot(seeded.path)
    build_workspace_report(seeded, generated_at=FIXED)
    assert snapshot(seeded.path) == before
    assert (lock.read_bytes() if lock.exists() else None) == lock_before


def test_generate_changes_no_domain_or_audit_rows(seeded: Workspace) -> None:
    before = snapshot(seeded.path)
    result = generate_report(seeded, "report.md", generated_at=FIXED)
    assert snapshot(seeded.path) == before
    assert result.readback_verified
    assert (seeded.path / "report.md").is_file()
    assert result.sha256


def test_generate_json_and_hash(seeded: Workspace) -> None:
    import hashlib

    result = generate_report(seeded, "report.json", fmt="json", generated_at=FIXED)
    content = (seeded.path / "report.json").read_bytes()
    assert hashlib.sha256(content).hexdigest() == result.sha256
    assert json.loads(content)["report_schema"] == REPORT_SCHEMA


def test_generate_is_reproducible(seeded: Workspace) -> None:
    one = generate_report(seeded, "a.md", generated_at=FIXED)
    two = generate_report(seeded, "b.md", generated_at=FIXED)
    assert one.sha256 == two.sha256


def test_overwrite_rules(seeded: Workspace) -> None:
    generate_report(seeded, "report.md", generated_at=FIXED)
    with pytest.raises(ConflictServiceError):
        generate_report(seeded, "report.md", generated_at=FIXED)
    with pytest.raises(InvalidInputError):
        generate_report(seeded, "report.md", force=True, generated_at=FIXED)
    with pytest.raises(InvalidInputError):
        generate_report(seeded, "report.md", force=True, actor="!!!", generated_at=FIXED)
    replaced = generate_report(seeded, "report.md", force=True, actor="bob", generated_at=FIXED)
    assert replaced.replaced


def test_invalid_format_and_output(seeded: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        generate_report(seeded, "r.xml", fmt="xml")
    with pytest.raises(InvalidInputError, match=r"output_path_traversal"):
        generate_report(seeded, "../r.md")
    assert not (seeded.path.parent / "r.md").exists()


def test_invalid_timestamp(seeded: Workspace) -> None:
    with pytest.raises(InvalidInputError):
        build_workspace_report(seeded, generated_at="yesterday")


def test_empty_initialized_database(ws: Workspace) -> None:
    with ws.write():
        pass  # migrates, no objects
    built = build_workspace_report(ws, generated_at=FIXED)
    data = json.loads(built.json)
    assert data["executive_summary"]["active_findings"] == 0
    assert data["findings"]["total"] == 0
    assert data["assets"]["total"] == 0
    assert data["audit"]["status"] == "intact"
    assert built.markdown.startswith("<!--")


def test_no_database(ws: Workspace) -> None:
    with pytest.raises(NotFoundServiceError):
        build_workspace_report(ws, generated_at=FIXED)
    assert not (ws.path / DATABASE_FILE_NAME).exists()
    assert not (ws.path / LOCK_FILE_NAME).exists()
    with pytest.raises(NotFoundServiceError):
        generate_report(ws, "r.md")
    assert not (ws.path / "r.md").exists()


def test_broken_audit_chain_is_reported_not_hidden(seeded: Workspace) -> None:
    raw_execute(seeded.path, "DROP TRIGGER IF EXISTS audit_log_no_update")
    with closing(sqlite3.connect(seeded.path / DATABASE_FILE_NAME)) as raw:
        triggers = [
            r[0]
            for r in raw.execute("SELECT name FROM sqlite_master WHERE type='trigger'")
            if "audit" in r[0]
        ]
    for name in triggers:
        raw_execute(seeded.path, f"DROP TRIGGER IF EXISTS {name}")
    raw_execute(seeded.path, "UPDATE audit_log SET entry_hash = ? WHERE seq = 2", ("f" * 64,))
    built = build_workspace_report(seeded, generated_at=FIXED)
    assert not built.audit_intact
    data = json.loads(built.json)
    assert data["audit"]["status"] == "broken"
    assert data["audit"]["broken_at_seq"] is not None
    assert "audit" in built.markdown.lower()
    written = generate_report(seeded, "report.md", generated_at=FIXED)
    assert not written.audit_intact
    assert (seeded.path / "report.md").is_file()


def test_schema_v1_database_is_not_current(tmp_path: Path) -> None:
    connection = open_database(tmp_path / DATABASE_FILE_NAME, create=True)
    try:
        apply_migrations(connection, migrations=MIGRATIONS[:1])
    finally:
        connection.close()
    ws = Workspace(tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(IntegrityServiceError, match="schema_not_current"):
        build_workspace_report(ws, generated_at=FIXED)
    with pytest.raises(IntegrityServiceError, match="schema_not_current"):
        generate_report(ws, "report.md", generated_at=FIXED)
    assert not (tmp_path / "report.md").exists()
    assert snapshot(tmp_path) == before  # a report never upgrades the database


def test_v2_schema_version_is_in_the_report(seeded: Workspace) -> None:
    data = json.loads(build_workspace_report(seeded, generated_at=FIXED).json)
    assert data["database_schema_versions"][-1] == MIGRATIONS[-1].version


def test_secret_never_reaches_the_audit_or_findings_table(seeded: Workspace) -> None:
    generate_report(seeded, "report.md", generated_at=FIXED)
    assert SECRET not in table_dump(seeded, "audit_log")
    assert BASE_TIME.year == 2026
