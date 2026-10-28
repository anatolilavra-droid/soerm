"""Helpers shared by the service and CLI tests."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

from soerm.domain.audit import AuditEntry
from soerm.domain.enums import (
    BusinessCriticality,
    DataClassification,
    Environment,
    Exposure,
    TechnicalSeverity,
)
from soerm.services.assets import create_asset
from soerm.services.common import MutationResult
from soerm.services.findings import create_finding
from soerm.services.workspace import DATABASE_FILE_NAME, Workspace
from soerm.storage.audit import list_audit_entries

SECRET = "hunter2-TOP-SECRET-token"
FP_A = "a" * 64
FP_B = "b" * 64
BASE_TIME = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def ticking_clock(start: datetime = BASE_TIME):  # type: ignore[no-untyped-def]
    """A clock that advances one second per call (one call per service operation)."""
    ticks = count()
    return lambda: start + timedelta(seconds=next(ticks))


def make_asset(ws: Workspace, **overrides: object) -> MutationResult:
    fields: dict[str, object] = {
        "actor": "alice",
        "name": "Billing API",
        "owner": "platform",
        "environment": Environment.PRODUCTION,
        "business_criticality": BusinessCriticality.HIGH,
        "data_classification": DataClassification.CONFIDENTIAL,
        "exposure": Exposure.INTERNET,
        "tags": ("api", "pci"),
    }
    fields.update(overrides)
    return create_asset(ws, **fields)  # type: ignore[arg-type]


def make_finding(ws: Workspace, **overrides: object) -> MutationResult:
    fields: dict[str, object] = {
        "actor": "alice",
        "asset_id": "AST-000001",
        "fingerprint": FP_A,
        "title": "SQL injection in login",
        "technical_severity": TechnicalSeverity.HIGH,
    }
    fields.update(overrides)
    return create_finding(ws, **fields)  # type: ignore[arg-type]


def audit_entries(ws: Workspace) -> list[AuditEntry]:
    with ws.read() as session:
        return list_audit_entries(session.connection)


def table_dump(ws: Workspace, table: str) -> str:
    """Every value of a table as one string (for 'this text must not be there' checks)."""
    queries = {"audit_log": "SELECT * FROM audit_log", "findings": "SELECT * FROM findings"}
    with closing(sqlite3.connect(ws.path / DATABASE_FILE_NAME)) as raw:
        return repr(raw.execute(queries[table]).fetchall())


def raw_execute(path: Path, statement: str, params: tuple[object, ...] = ()) -> None:
    """Run one statement on the workspace database like an outside editor would."""
    with closing(sqlite3.connect(path / DATABASE_FILE_NAME, isolation_level=None)) as raw:
        raw.execute(statement, params)
