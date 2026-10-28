"""Finding repository. Every write also appends an audit entry in the same transaction.

The repository stores whatever the (already validated) model holds; evidence must have been
redacted before it gets here (M4) and is limited to 4096 bytes by the model and the schema.
"""

import json
import sqlite3
from datetime import datetime
from enum import StrEnum
from typing import Final

from soerm.domain.audit import AuditEntry
from soerm.domain.enums import FindingStatus, TechnicalSeverity
from soerm.domain.finding import Finding
from soerm.domain.hashing import canonical_json
from soerm.domain.identifiers import check_identifier
from soerm.storage.audit import append_audit
from soerm.storage.codec import coerce_enum, to_db_timestamp
from soerm.storage.connection import SoermConnection
from soerm.storage.errors import ConflictError, NotFoundError, StorageError
from soerm.storage.transactions import transaction

__all__ = ["UPDATE_ACTIONS", "FindingOrder", "FindingRepository"]

# Audit actions an update may be recorded under (a fixed allowlist).
UPDATE_ACTIONS: Final = frozenset({"finding.update", "finding.risk_recalculate"})

_INSERT = (
    "INSERT INTO findings (finding_id, fingerprint, title, description, asset_id, source,"
    " evidence, cvss_version, cvss_vector, cvss_score, cvss_score_source, technical_severity,"
    " business_priority, risk_factors, risk_formula_version, risk_config_hash, status, owner,"
    " sla_due_at, first_seen, last_seen, created_at, updated_at)"
    " VALUES (:finding_id, :fingerprint, :title, :description, :asset_id, :source,"
    " :evidence, :cvss_version, :cvss_vector, :cvss_score, :cvss_score_source,"
    " :technical_severity, :business_priority, :risk_factors, :risk_formula_version,"
    " :risk_config_hash, :status, :owner, :sla_due_at, :first_seen, :last_seen,"
    " :created_at, :updated_at)"
)
_UPDATE = (
    "UPDATE findings SET title = :title, description = :description, asset_id = :asset_id,"
    " source = :source, evidence = :evidence, cvss_version = :cvss_version,"
    " cvss_vector = :cvss_vector, cvss_score = :cvss_score,"
    " cvss_score_source = :cvss_score_source, technical_severity = :technical_severity,"
    " business_priority = :business_priority, risk_factors = :risk_factors,"
    " risk_formula_version = :risk_formula_version, risk_config_hash = :risk_config_hash,"
    " status = :status, owner = :owner, sla_due_at = :sla_due_at, first_seen = :first_seen,"
    " last_seen = :last_seen, updated_at = :updated_at WHERE finding_id = :finding_id"
)
_GET = "SELECT * FROM findings WHERE finding_id = :finding_id"
_GET_BY_FINGERPRINT = "SELECT * FROM findings WHERE fingerprint = :fingerprint"
_LIST = (
    "SELECT * FROM findings WHERE (:status IS NULL OR status = :status)"
    " AND (:asset_id IS NULL OR asset_id = :asset_id)"
    " AND (:severity IS NULL OR technical_severity = :severity)"
    " ORDER BY CASE :order WHEN 'last_seen' THEN last_seen END DESC, finding_id"
)


class FindingOrder(StrEnum):
    """Allowed sort orders (the value is bound as a parameter, never spliced into SQL)."""

    ID = "id"
    LAST_SEEN = "last_seen"


def _optional_ts(value: datetime | None) -> str | None:
    return None if value is None else to_db_timestamp(value)


def _params(finding: Finding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "description": finding.description,
        "asset_id": finding.asset_id,
        "source": finding.source.value,
        "evidence": finding.evidence,
        "cvss_version": finding.cvss_version,
        "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score,
        "cvss_score_source": finding.cvss_score_source,
        "technical_severity": finding.technical_severity.value,
        "business_priority": (
            None if finding.business_priority is None else finding.business_priority.value
        ),
        "risk_factors": canonical_json(finding.risk_factors),
        "risk_formula_version": finding.risk_formula_version,
        "risk_config_hash": finding.risk_config_hash,
        "status": finding.status.value,
        "owner": finding.owner,
        "sla_due_at": _optional_ts(finding.sla_due_at),
        "first_seen": to_db_timestamp(finding.first_seen),
        "last_seen": to_db_timestamp(finding.last_seen),
        "created_at": to_db_timestamp(finding.created_at),
        "updated_at": to_db_timestamp(finding.updated_at),
    }


def _from_row(row: sqlite3.Row) -> Finding:
    try:
        return Finding(
            finding_id=row["finding_id"],
            fingerprint=row["fingerprint"],
            title=row["title"],
            description=row["description"],
            asset_id=row["asset_id"],
            source=row["source"],
            evidence=row["evidence"],
            cvss_version=row["cvss_version"],
            cvss_vector=row["cvss_vector"],
            cvss_score=row["cvss_score"],
            cvss_score_source=row["cvss_score_source"],
            technical_severity=row["technical_severity"],
            business_priority=row["business_priority"],
            risk_factors=json.loads(row["risk_factors"]),
            risk_formula_version=row["risk_formula_version"],
            risk_config_hash=row["risk_config_hash"],
            status=row["status"],
            owner=row["owner"],
            sla_due_at=row["sla_due_at"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
    except ValueError:
        raise StorageError("corrupt_row", object_type="finding") from None


def _checked(finding: object) -> Finding:
    """Re-validate the model (``model_construct`` bypasses validation); the input is not
    modified."""
    if not isinstance(finding, Finding):
        raise StorageError("invalid_model", object_type="finding")
    return finding.with_changes()


class FindingRepository:
    def __init__(self, connection: SoermConnection) -> None:
        self._connection = connection

    def add(self, finding: Finding, *, actor: str, at: datetime) -> AuditEntry:
        """Insert a new finding and its ``finding.create`` audit entry atomically."""
        model = _checked(finding)
        with transaction(self._connection, write=True) as conn:
            conn.execute(_INSERT, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action="finding.create",
                object_type="finding",
                object_id=model.finding_id,
                before_hash=None,
                after_hash=model.digest(),
            )

    def update(
        self,
        finding: Finding,
        *,
        actor: str,
        at: datetime,
        expected_before_hash: str | None = None,
        action: str = "finding.update",
    ) -> AuditEntry:
        """Replace the mutable fields of an existing finding and append ``finding.update``.

        ``finding_id``, ``fingerprint`` and ``created_at`` cannot change."""
        if action not in UPDATE_ACTIONS:
            raise StorageError("invalid_action")
        model = _checked(finding)
        with transaction(self._connection, write=True) as conn:
            row = conn.execute(_GET, {"finding_id": model.finding_id}).fetchone()
            if row is None:
                raise NotFoundError("finding")
            existing = _from_row(row)
            if expected_before_hash is not None and existing.digest() != expected_before_hash:
                raise ConflictError("finding")
            if existing.fingerprint != model.fingerprint:
                raise StorageError("immutable_field", field="fingerprint")
            if existing.created_at != model.created_at:
                raise StorageError("immutable_field", field="created_at")
            conn.execute(_UPDATE, _params(model))
            return append_audit(
                conn,
                timestamp=at,
                actor=actor,
                action=action,
                object_type="finding",
                object_id=model.finding_id,
                before_hash=existing.digest(),
                after_hash=model.digest(),
            )

    def get(self, finding_id: str) -> Finding | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET, {"finding_id": finding_id}).fetchone()
        return None if row is None else _from_row(row)

    def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        with transaction(self._connection, write=False) as conn:
            row = conn.execute(_GET_BY_FINGERPRINT, {"fingerprint": fingerprint}).fetchone()
        return None if row is None else _from_row(row)

    def list(
        self,
        *,
        status: FindingStatus | None = None,
        asset_id: str | None = None,
        severity: TechnicalSeverity | None = None,
        order: FindingOrder = FindingOrder.ID,
    ) -> list[Finding]:
        params: dict[str, object] = {
            "status": None
            if status is None
            else coerce_enum(FindingStatus, status, "status").value,
            "asset_id": None if asset_id is None else check_identifier("AST", asset_id),
            "severity": (
                None
                if severity is None
                else coerce_enum(TechnicalSeverity, severity, "severity").value
            ),
            "order": coerce_enum(FindingOrder, order, "order").value,
        }
        with transaction(self._connection, write=False) as conn:
            rows = conn.execute(_LIST, params).fetchall()
        return [_from_row(row) for row in rows]
