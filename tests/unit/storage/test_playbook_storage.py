"""M9 tables: versions, attachments and completed steps are insert-only."""

import sqlite3

import pytest

from soerm.storage.connection import SoermConnection

NOW = "2026-03-01T12:00:00.000000Z"
HASH = "a" * 64


@pytest.fixture
def seeded(conn: SoermConnection) -> SoermConnection:
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO playbooks (playbook_id, name, version, definition, config_hash, created_at,"
        " updated_at) VALUES ('pb-one', 'n', '1', '{}', ?, ?, ?)",
        (HASH, NOW, NOW),
    )
    conn.execute("INSERT INTO playbook_versions VALUES ('pb-one', '1', '{}', ?, ?)", (HASH, NOW))
    conn.execute(
        "INSERT INTO incidents (incident_id, title, severity, status, owner, summary, created_at,"
        " updated_at) VALUES ('INC-000001', 't', 'low', 'new', 'o', '', ?, ?)",
        (NOW, NOW),
    )
    conn.execute(
        "INSERT INTO incident_playbooks VALUES ('INC-000001', 'pb-one', '1', ?, ?, 'alice')",
        (HASH, NOW),
    )
    conn.execute(
        "INSERT INTO incident_playbook_steps VALUES ('INC-000001', 'step-001', ?, 'alice', NULL)",
        (NOW,),
    )
    conn.execute("COMMIT")
    return conn


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE playbook_versions SET definition = '{\"x\":1}'",
        "DELETE FROM playbook_versions",
        "UPDATE incident_playbooks SET version = '2'",
        "DELETE FROM incident_playbooks",
        "UPDATE incident_playbook_steps SET completed_by = 'mallory'",
        "DELETE FROM incident_playbook_steps",
    ],
)
def test_records_are_immutable(seeded: SoermConnection, statement: str) -> None:
    seeded.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.DatabaseError):
        seeded.execute(statement)
    seeded.execute("ROLLBACK")


def test_step_is_recorded_once_per_incident(seeded: SoermConnection) -> None:
    seeded.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.IntegrityError):
        seeded.execute(
            "INSERT INTO incident_playbook_steps VALUES ('INC-000001','step-001',?,'bob',NULL)",
            (NOW,),
        )
    seeded.execute("ROLLBACK")


def test_attachment_needs_an_existing_version_and_one_per_incident(
    seeded: SoermConnection,
) -> None:
    seeded.execute("BEGIN IMMEDIATE")
    with pytest.raises(sqlite3.IntegrityError):
        seeded.execute(
            "INSERT INTO incident_playbooks VALUES ('INC-000001', 'pb-one', '1', ?, ?, 'alice')",
            (HASH, NOW),
        )
    seeded.execute("ROLLBACK")
    seeded.execute("BEGIN IMMEDIATE")
    seeded.execute(
        "INSERT INTO incidents (incident_id, title, severity, status, owner, summary, created_at,"
        " updated_at) VALUES ('INC-000002', 't', 'low', 'new', 'o', '', ?, ?)",
        (NOW, NOW),
    )
    with pytest.raises(sqlite3.IntegrityError):
        seeded.execute(
            "INSERT INTO incident_playbooks VALUES ('INC-000002', 'pb-one', '9', ?, ?, 'alice')",
            (HASH, NOW),
        )
    seeded.execute("ROLLBACK")


def test_bad_values_are_rejected_by_checks(seeded: SoermConnection) -> None:
    seeded.execute("BEGIN IMMEDIATE")
    for statement in (
        "INSERT INTO incident_playbook_steps VALUES ('INC-000001','Step 2',?,'alice',NULL)",
        "INSERT INTO incident_playbook_steps VALUES ('INC-000001','step-002',?,'ALICE',NULL)",
    ):
        with pytest.raises(sqlite3.IntegrityError):
            seeded.execute(statement, (NOW,))
    seeded.execute("ROLLBACK")
