"""Versioned schema migrations.

Rules
-----
* A migration is a numbered tuple of literal SQL statements. Nothing is built at run time.
* A released migration is never edited: its SHA-256 is stored in ``schema_version`` and any
  difference stops the program. Schema changes are made by adding a new migration.
* Each migration runs in one ``BEGIN IMMEDIATE`` transaction together with its
  ``schema_version`` row, so a failure leaves no half-applied schema.
* Migration 2 (M9) adds immutable playbook versions, the incident-playbook attachment and the
  completed-step records; migration 1 is untouched.
* Migration 1 stores no raw evidence: the only evidence columns hold already redacted text
  with a hard 4096-byte limit; M2 itself never accepts unredacted text.
"""

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from soerm.domain.hashing import hash_canonical, is_sha256
from soerm.storage.codec import to_db_timestamp
from soerm.storage.errors import MigrationError
from soerm.storage.transactions import transaction

__all__ = ["MIGRATIONS", "Migration", "applied_versions", "apply_migrations"]


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable schema step."""

    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def checksum(self) -> str:
        """SHA-256 over the canonical JSON of the version, name and statements."""
        return hash_canonical(
            {"version": self.version, "name": self.name, "statements": list(self.statements)}
        )


_V1_STATEMENTS: Final = (
    """CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    checksum TEXT NOT NULL CHECK ((length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*')),
    applied_at TEXT NOT NULL CHECK (applied_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
) STRICT""",
    """CREATE TABLE counters (
    prefix TEXT PRIMARY KEY CHECK (prefix IN ('AST', 'FND', 'INC', 'TSK', 'PBK', 'CHG', 'RUN')),
    value INTEGER NOT NULL CHECK (value >= 0 AND value < 1000000000000)
) STRICT""",
    """INSERT INTO counters (prefix, value) VALUES ('AST', 0), ('FND', 0), ('INC', 0), ('TSK', 0), ('PBK', 0), ('CHG', 0), ('RUN', 0)""",
    """CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY CHECK ((asset_id GLOB 'AST-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(asset_id) BETWEEN 10 AND 16 AND substr(asset_id, 5) NOT GLOB '*[^0-9]*')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    environment TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'test')),
    business_criticality TEXT NOT NULL CHECK (business_criticality IN ('low', 'medium', 'high', 'critical')),
    data_classification TEXT NOT NULL CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted')),
    exposure TEXT NOT NULL CHECK (exposure IN ('internet', 'partner', 'internal', 'isolated')),
    tags TEXT NOT NULL CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (updated_at >= created_at)
) STRICT""",
    """CREATE TABLE import_runs (
    run_id TEXT PRIMARY KEY CHECK ((run_id GLOB 'RUN-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(run_id) BETWEEN 10 AND 16 AND substr(run_id, 5) NOT GLOB '*[^0-9]*')),
    source TEXT NOT NULL CHECK (source IN ('sarif', 'generic_json', 'csv', 'manual')),
    file_sha256 TEXT NOT NULL CHECK ((length(file_sha256) = 64 AND file_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_path TEXT NOT NULL CHECK (length(source_path) BETWEEN 1 AND 1024),
    imported_at TEXT NOT NULL CHECK (imported_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    record_count INTEGER NOT NULL CHECK (record_count >= 0)
) STRICT""",
    """CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY CHECK ((finding_id GLOB 'FND-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(finding_id) BETWEEN 10 AND 16 AND substr(finding_id, 5) NOT GLOB '*[^0-9]*')),
    fingerprint TEXT NOT NULL UNIQUE CHECK ((length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*')),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description TEXT NOT NULL CHECK (length(description) <= 8000),
    asset_id TEXT NOT NULL REFERENCES assets (asset_id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source IN ('sarif', 'generic_json', 'csv', 'manual')),
    evidence TEXT NOT NULL CHECK (length(CAST(evidence AS BLOB)) <= 4096),
    cvss_version TEXT CHECK (cvss_version IS NULL OR cvss_version = '4.0'),
    cvss_vector TEXT CHECK (cvss_vector IS NULL OR (cvss_vector GLOB 'CVSS:4.0/*' AND length(cvss_vector) <= 512)),
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0.0 AND cvss_score <= 10.0)),
    cvss_score_source TEXT CHECK (cvss_score_source IS NULL OR cvss_score_source = 'imported'),
    technical_severity TEXT NOT NULL CHECK (technical_severity IN ('none', 'low', 'medium', 'high', 'critical')),
    business_priority TEXT CHECK ((business_priority IS NULL OR business_priority IN ('p1', 'p2', 'p3', 'p4'))),
    risk_factors TEXT NOT NULL CHECK (json_valid(risk_factors) AND json_type(risk_factors) = 'object'),
    risk_formula_version TEXT CHECK ((risk_formula_version IS NULL OR length(risk_formula_version) BETWEEN 1 AND 32)),
    risk_config_hash TEXT CHECK ((risk_config_hash IS NULL OR (length(risk_config_hash) = 64 AND risk_config_hash NOT GLOB '*[^0-9a-f]*'))),
    status TEXT NOT NULL CHECK (status IN ('open', 'triaged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive')),
    owner TEXT CHECK ((owner IS NULL OR length(owner) BETWEEN 1 AND 200)),
    sla_due_at TEXT CHECK ((sla_due_at IS NULL OR sla_due_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    last_seen TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (last_seen >= first_seen),
    CHECK (updated_at >= created_at),
    CHECK ((cvss_score IS NULL) = (cvss_score_source IS NULL)),
    CHECK (cvss_vector IS NULL OR cvss_version IS NOT NULL),
    CHECK (technical_severity <> 'none' OR cvss_score = 0.0)
) STRICT""",
    """CREATE INDEX findings_asset_id ON findings (asset_id)""",
    """CREATE INDEX findings_status ON findings (status)""",
    """CREATE TABLE finding_occurrences (
    occurrence_id INTEGER PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings (finding_id) ON DELETE RESTRICT,
    import_run_id TEXT NOT NULL REFERENCES import_runs (run_id) ON DELETE RESTRICT,
    file_sha256 TEXT NOT NULL CHECK ((length(file_sha256) = 64 AND file_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_path TEXT NOT NULL CHECK (length(source_path) BETWEEN 1 AND 1024),
    location TEXT CHECK ((location IS NULL OR length(location) BETWEEN 1 AND 512)),
    observed_at TEXT NOT NULL CHECK (observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')
) STRICT""",
    """CREATE UNIQUE INDEX finding_occurrences_unique ON finding_occurrences (finding_id, import_run_id, source_path, COALESCE(location, ''))""",
    """CREATE TABLE playbooks (
    playbook_id TEXT PRIMARY KEY CHECK ((playbook_id GLOB '[a-z]*' AND length(playbook_id) BETWEEN 2 AND 64 AND playbook_id NOT GLOB '*[^a-z0-9_-]*')),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 32),
    definition TEXT NOT NULL CHECK (json_valid(definition) AND json_type(definition) = 'object'),
    config_hash TEXT NOT NULL CHECK ((length(config_hash) = 64 AND config_hash NOT GLOB '*[^0-9a-f]*')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (updated_at >= created_at)
) STRICT""",
    """CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY CHECK ((incident_id GLOB 'INC-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(incident_id) BETWEEN 10 AND 16 AND substr(incident_id, 5) NOT GLOB '*[^0-9]*')),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed')),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    summary TEXT NOT NULL CHECK (length(summary) <= 8000),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    closed_at TEXT CHECK ((closed_at IS NULL OR closed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    playbook_id TEXT REFERENCES playbooks (playbook_id) ON DELETE RESTRICT,
    closure_reason TEXT CHECK ((closure_reason IS NULL OR length(closure_reason) BETWEEN 1 AND 500)),
    CHECK (updated_at >= created_at),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((status = 'closed') = (closure_reason IS NOT NULL)),
    CHECK (closed_at IS NULL OR closed_at >= created_at)
) STRICT""",
    """CREATE TABLE incident_links (
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL REFERENCES findings (finding_id) ON DELETE RESTRICT,
    linked_at TEXT NOT NULL CHECK (linked_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (incident_id, finding_id)
) STRICT""",
    """CREATE TABLE incident_events (
    event_id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL CHECK (occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    actor TEXT NOT NULL CHECK ((actor GLOB '[a-z0-9]*' AND length(actor) BETWEEN 1 AND 128 AND actor NOT GLOB '*[^a-z0-9._@+-]*')),
    event_type TEXT NOT NULL CHECK ((event_type GLOB '[a-z]*' AND length(event_type) BETWEEN 2 AND 64 AND event_type NOT GLOB '*[^a-z0-9_.]*')),
    from_status TEXT CHECK ((from_status IS NULL OR from_status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed'))),
    to_status TEXT CHECK ((to_status IS NULL OR to_status IN ('new', 'triaged', 'investigating', 'contained', 'remediated', 'closed')))
) STRICT""",
    """CREATE TABLE incident_notes (
    note_id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    author TEXT NOT NULL CHECK ((author GLOB '[a-z0-9]*' AND length(author) BETWEEN 1 AND 128 AND author NOT GLOB '*[^a-z0-9._@+-]*')),
    redacted_body TEXT NOT NULL CHECK (length(redacted_body) BETWEEN 1 AND 8000)
) STRICT""",
    """CREATE TABLE evidence (
    evidence_id INTEGER PRIMARY KEY,
    finding_id TEXT REFERENCES findings (finding_id) ON DELETE RESTRICT,
    incident_id TEXT REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    evidence_type TEXT NOT NULL CHECK ((evidence_type GLOB '[a-z]*' AND length(evidence_type) BETWEEN 2 AND 32 AND evidence_type NOT GLOB '*[^a-z0-9_-]*')),
    redacted_text TEXT NOT NULL CHECK (length(CAST(redacted_text AS BLOB)) BETWEEN 1 AND 4096),
    content_sha256 TEXT NOT NULL CHECK ((length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    CHECK (finding_id IS NOT NULL OR incident_id IS NOT NULL)
) STRICT""",
    """CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY CHECK ((task_id GLOB 'TSK-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(task_id) BETWEEN 10 AND 16 AND substr(task_id, 5) NOT GLOB '*[^0-9]*')),
    finding_id TEXT REFERENCES findings (finding_id) ON DELETE RESTRICT,
    incident_id TEXT REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 200),
    due_at TEXT CHECK ((due_at IS NULL OR due_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    completed_at TEXT CHECK ((completed_at IS NULL OR completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    CHECK (finding_id IS NOT NULL OR incident_id IS NOT NULL),
    CHECK ((status = 'done') = (completed_at IS NOT NULL)),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
) STRICT""",
    """CREATE TABLE pending_changes (
    change_id TEXT PRIMARY KEY CHECK ((change_id GLOB 'CHG-[0-9][0-9][0-9][0-9][0-9][0-9]*' AND length(change_id) BETWEEN 10 AND 16 AND substr(change_id, 5) NOT GLOB '*[^0-9]*')),
    object_type TEXT NOT NULL CHECK ((object_type GLOB '[a-z]*' AND length(object_type) BETWEEN 2 AND 64 AND object_type NOT GLOB '*[^a-z0-9_-]*')),
    object_id TEXT NOT NULL CHECK ((length(object_id) BETWEEN 1 AND 64 AND object_id NOT GLOB '*[^A-Za-z0-9._:-]*')),
    requester TEXT NOT NULL CHECK ((requester GLOB '[a-z0-9]*' AND length(requester) BETWEEN 1 AND 128 AND requester NOT GLOB '*[^a-z0-9._@+-]*')),
    approver TEXT CHECK (approver IS NULL OR (approver GLOB '[a-z0-9]*' AND length(approver) BETWEEN 1 AND 128 AND approver NOT GLOB '*[^a-z0-9._@+-]*')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    before_hash TEXT CHECK ((before_hash IS NULL OR (length(before_hash) = 64 AND before_hash NOT GLOB '*[^0-9a-f]*'))),
    proposed_after_hash TEXT NOT NULL CHECK ((length(proposed_after_hash) = 64 AND proposed_after_hash NOT GLOB '*[^0-9a-f]*')),
    requested_at TEXT NOT NULL CHECK (requested_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    decided_at TEXT CHECK ((decided_at IS NULL OR decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z')),
    require_distinct_approver INTEGER NOT NULL DEFAULT 1 CHECK (require_distinct_approver IN (0, 1)),
    CHECK (expires_at > requested_at),
    CHECK ((status IN ('approved', 'rejected')) = (decided_at IS NOT NULL)),
    CHECK ((status IN ('approved', 'rejected')) = (approver IS NOT NULL)),
    CHECK (decided_at IS NULL OR decided_at >= requested_at),
    CHECK (require_distinct_approver = 0 OR approver IS NULL OR approver <> requester)
) STRICT""",
    """CREATE INDEX pending_changes_status ON pending_changes (status, expires_at)""",
    """CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY CHECK (seq >= 1),
    ts TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    actor TEXT NOT NULL CHECK ((actor GLOB '[a-z0-9]*' AND length(actor) BETWEEN 1 AND 128 AND actor NOT GLOB '*[^a-z0-9._@+-]*')),
    action TEXT NOT NULL CHECK ((action GLOB '[a-z]*' AND length(action) BETWEEN 2 AND 64 AND action NOT GLOB '*[^a-z0-9_.]*')),
    object_type TEXT NOT NULL CHECK ((object_type GLOB '[a-z]*' AND length(object_type) BETWEEN 2 AND 64 AND object_type NOT GLOB '*[^a-z0-9_-]*')),
    object_id TEXT NOT NULL CHECK ((length(object_id) BETWEEN 1 AND 64 AND object_id NOT GLOB '*[^A-Za-z0-9._:-]*')),
    before_hash TEXT CHECK ((before_hash IS NULL OR (length(before_hash) = 64 AND before_hash NOT GLOB '*[^0-9a-f]*'))),
    after_hash TEXT CHECK ((after_hash IS NULL OR (length(after_hash) = 64 AND after_hash NOT GLOB '*[^0-9a-f]*'))),
    prev_hash TEXT NOT NULL CHECK ((length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*')),
    entry_hash TEXT NOT NULL UNIQUE CHECK ((length(entry_hash) = 64 AND entry_hash NOT GLOB '*[^0-9a-f]*'))
) STRICT""",
    """CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log sequence must be consecutive')
    WHERE NEW.seq <> COALESCE((SELECT MAX(seq) FROM audit_log), 0) + 1;
    SELECT RAISE(ABORT, 'audit_log prev_hash must link to the previous entry')
    WHERE NEW.prev_hash <> COALESCE((SELECT entry_hash FROM audit_log WHERE seq = NEW.seq - 1), '0000000000000000000000000000000000000000000000000000000000000000');
END""",
    """CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END""",
    """CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END""",
)

_V2_STATEMENTS: Final = (
    """CREATE TABLE playbook_versions (
    playbook_id TEXT NOT NULL REFERENCES playbooks (playbook_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK ((length(version) BETWEEN 1 AND 32 AND version NOT GLOB '*[^0-9A-Za-z._-]*')),
    definition TEXT NOT NULL CHECK (json_valid(definition) AND json_type(definition) = 'object'),
    config_hash TEXT NOT NULL CHECK ((config_hash NOT GLOB '*[^0-9a-f]*' AND length(config_hash) = 64)),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    PRIMARY KEY (playbook_id, version)
) STRICT""",
    """CREATE TRIGGER playbook_versions_no_update BEFORE UPDATE ON playbook_versions
BEGIN
    SELECT RAISE(ABORT, 'playbook versions are immutable');
END""",
    """CREATE TRIGGER playbook_versions_no_delete BEFORE DELETE ON playbook_versions
BEGIN
    SELECT RAISE(ABORT, 'playbook versions are immutable');
END""",
    """CREATE TABLE incident_playbooks (
    incident_id TEXT PRIMARY KEY REFERENCES incidents (incident_id) ON DELETE RESTRICT,
    playbook_id TEXT NOT NULL,
    version TEXT NOT NULL,
    config_hash TEXT NOT NULL CHECK ((config_hash NOT GLOB '*[^0-9a-f]*' AND length(config_hash) = 64)),
    attached_at TEXT NOT NULL CHECK (attached_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    attached_by TEXT NOT NULL CHECK ((attached_by GLOB '[a-z0-9]*' AND length(attached_by) BETWEEN 1 AND 128 AND attached_by NOT GLOB '*[^a-z0-9._@+-]*')),
    FOREIGN KEY (playbook_id, version) REFERENCES playbook_versions (playbook_id, version) ON DELETE RESTRICT
) STRICT""",
    """CREATE TRIGGER incident_playbooks_no_update BEFORE UPDATE ON incident_playbooks
BEGIN
    SELECT RAISE(ABORT, 'a playbook attachment is immutable');
END""",
    """CREATE TRIGGER incident_playbooks_no_delete BEFORE DELETE ON incident_playbooks
BEGIN
    SELECT RAISE(ABORT, 'a playbook attachment is immutable');
END""",
    """CREATE TABLE incident_playbook_steps (
    incident_id TEXT NOT NULL REFERENCES incident_playbooks (incident_id) ON DELETE RESTRICT,
    step_id TEXT NOT NULL CHECK ((step_id GLOB '[a-z]*' AND length(step_id) BETWEEN 2 AND 64 AND step_id NOT GLOB '*[^a-z0-9_-]*')),
    completed_at TEXT NOT NULL CHECK (completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'),
    completed_by TEXT NOT NULL CHECK ((completed_by GLOB '[a-z0-9]*' AND length(completed_by) BETWEEN 1 AND 128 AND completed_by NOT GLOB '*[^a-z0-9._@+-]*')),
    change_id TEXT REFERENCES pending_changes (change_id) ON DELETE RESTRICT,
    PRIMARY KEY (incident_id, step_id)
) STRICT""",
    """CREATE TRIGGER incident_playbook_steps_no_update BEFORE UPDATE ON incident_playbook_steps
BEGIN
    SELECT RAISE(ABORT, 'a completed step cannot be changed');
END""",
    """CREATE TRIGGER incident_playbook_steps_no_delete BEFORE DELETE ON incident_playbook_steps
BEGIN
    SELECT RAISE(ABORT, 'a completed step cannot be changed');
END""",
)

MIGRATIONS: Final = (
    Migration(version=1, name="initial_schema", statements=_V1_STATEMENTS),
    Migration(version=2, name="playbook_runs", statements=_V2_STATEMENTS),
)

_COLUMNS: Final = ("version", "name", "checksum", "applied_at")


def _check_set(migrations: Sequence[Migration]) -> None:
    versions = [migration.version for migration in migrations]
    names = [migration.name for migration in migrations]
    if (
        not migrations
        or versions != list(range(1, len(migrations) + 1))
        or len(set(names)) != len(names)
        or any(not migration.statements for migration in migrations)
    ):
        raise MigrationError("invalid_migration_set")


def _read_applied(connection: sqlite3.Connection) -> list[tuple[int, str, str]]:
    """Read and validate the stored history; any oddity stops the program."""
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if exists is None:
        other = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        if other is not None:
            raise MigrationError("unmanaged_database")
        return []
    columns = tuple(row["name"] for row in connection.execute("PRAGMA table_info(schema_version)"))
    if columns != _COLUMNS:
        raise MigrationError("malformed_schema_version")
    history: list[tuple[int, str, str]] = []
    rows = connection.execute(
        "SELECT version, name, checksum, applied_at FROM schema_version ORDER BY version"
    ).fetchall()
    for expected, (version, name, checksum, applied_at) in enumerate(rows, start=1):
        if (
            type(version) is not int
            or version != expected
            or not isinstance(name, str)
            or not is_sha256(checksum)
            or not isinstance(applied_at, str)
        ):
            raise MigrationError("malformed_schema_version", version=expected)
        history.append((version, name, checksum))
    return history


def _verify_history(history: list[tuple[int, str, str]], migrations: Sequence[Migration]) -> None:
    if len(history) > len(migrations):
        raise MigrationError("database_newer_than_application")
    for (version, name, checksum), migration in zip(
        history, migrations[: len(history)], strict=True
    ):
        if name != migration.name:
            raise MigrationError("migration_name_mismatch", version=version)
        if checksum != migration.checksum:
            raise MigrationError("migration_checksum_mismatch", version=version)


def applied_versions(connection: sqlite3.Connection) -> tuple[int, ...]:
    """Versions recorded in ``schema_version`` (empty for a new database)."""
    with transaction(connection, write=False) as conn:
        return tuple(version for version, _, _ in _read_applied(conn))


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    migrations: Sequence[Migration] = MIGRATIONS,
    now: datetime | None = None,
) -> tuple[int, ...]:
    """Verify the stored history and apply every missing migration, in order.

    Returns the versions applied by this call (empty when the schema is up to date). The
    stored history is re-read inside each write transaction, so two processes migrating at
    the same time cannot apply the same step twice. Must not be called inside a transaction.
    """
    if getattr(connection, "tx_depth", 0) != 0:
        raise MigrationError("migrations_require_top_level")
    _check_set(migrations)
    applied_now: list[int] = []
    while True:
        with transaction(connection, write=True) as conn:
            history = _read_applied(conn)
            _verify_history(history, migrations)
            if len(history) == len(migrations):
                return tuple(applied_now)
            migration = migrations[len(history)]
            try:
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_version (version, name, checksum, applied_at)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        migration.version,
                        migration.name,
                        migration.checksum,
                        to_db_timestamp(now or datetime.now(UTC)),
                    ),
                )
            except sqlite3.Error:
                raise MigrationError("migration_failed", version=migration.version) from None
            applied_now.append(migration.version)
