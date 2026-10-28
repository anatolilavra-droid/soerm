"""Valid sample data for domain tests."""

from datetime import UTC, datetime, timedelta
from typing import Any

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(hours=1)
SHA_A = "a" * 64
SHA_B = "b" * 64
SECRET = "AKIAIOSFODNN7EXAMPLE-hunter2"


def asset_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "asset_id": "AST-000001",
        "name": "Billing API",
        "owner": "Payments team",
        "environment": "production",
        "business_criticality": "high",
        "data_classification": "confidential",
        "exposure": "internet",
        "tags": ["pci", "api"],
        "created_at": T0,
        "updated_at": T1,
    }
    data.update(overrides)
    return data


def finding_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": "FND-000001",
        "fingerprint": SHA_A,
        "title": "Outdated TLS configuration",
        "description": "TLS 1.0 enabled.",
        "asset_id": "AST-000001",
        "source": "sarif",
        "technical_severity": "high",
        "first_seen": T0,
        "last_seen": T1,
        "created_at": T0,
        "updated_at": T1,
    }
    data.update(overrides)
    return data


def incident_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "incident_id": "INC-000001",
        "title": "Suspicious login burst",
        "severity": "high",
        "owner": "SOC",
        "created_at": T0,
        "updated_at": T1,
    }
    data.update(overrides)
    return data


def task_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "task_id": "TSK-000001",
        "finding_id": "FND-000001",
        "title": "Upgrade TLS",
        "owner": "Platform",
        "created_at": T0,
        "updated_at": T1,
    }
    data.update(overrides)
    return data


def approval_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "change_id": "CHG-000001",
        "object_type": "incident",
        "object_id": "INC-000001",
        "requester": "alice",
        "reason": "Close after verification",
        "before_hash": SHA_A,
        "proposed_after_hash": SHA_B,
        "requested_at": T0,
        "expires_at": T0 + timedelta(days=7),
    }
    data.update(overrides)
    return data


def step_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "step_id": "collect-logs",
        "step_type": "manual",
        "title": "Collect logs",
        "text": "Export the authentication logs for the last 24 hours.",
    }
    data.update(overrides)
    return data


def playbook_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "playbook_id": "phishing-triage",
        "name": "Phishing triage",
        "version": "1.0",
        "roles": ["analyst", "lead"],
        "steps": [step_data()],
        "escalation_criteria": ["Credentials were entered"],
        "closure_criteria": ["Mailbox cleaned"],
        "config_hash": SHA_A,
    }
    data.update(overrides)
    return data
