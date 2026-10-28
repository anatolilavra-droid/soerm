"""Pure domain layer: models, enums, state machines and hashing.

Depends only on the standard library and Pydantic v2. It performs no I/O and never imports
from ``storage``, ``importers``, ``services`` or ``cli``.
"""

from soerm.domain.approval import (
    DEFAULT_APPROVAL_TTL,
    Approval,
    approve,
    expire,
    new_approval,
    reject,
)
from soerm.domain.asset import Asset
from soerm.domain.audit import (
    GENESIS_HASH,
    AuditEntry,
    compute_entry_hash,
    create_audit_entry,
    verify_audit_chain,
)
from soerm.domain.cvss import severity_from_cvss_score
from soerm.domain.enums import (
    ApprovalStatus,
    BusinessCriticality,
    BusinessPriority,
    DataClassification,
    Environment,
    Exposure,
    FindingStatus,
    ImportSource,
    IncidentStatus,
    StepType,
    TaskStatus,
    TechnicalSeverity,
)
from soerm.domain.errors import (
    ApprovalError,
    DomainError,
    ExpiredApprovalError,
    IntegrityDomainError,
    InvalidIdentifierError,
    InvalidTimestampError,
    InvalidTransitionError,
    ValidationDomainError,
)
from soerm.domain.finding import Finding
from soerm.domain.hashing import canonical_json, compute_config_hash, hash_canonical, sha256_hex
from soerm.domain.incident import Incident, transition_incident
from soerm.domain.playbook import Playbook, PlaybookStep
from soerm.domain.provenance import Occurrence, Provenance
from soerm.domain.task import Task, transition_task
from soerm.domain.timestamps import format_timestamp, parse_timestamp

__all__ = [
    "DEFAULT_APPROVAL_TTL",
    "GENESIS_HASH",
    "Approval",
    "ApprovalError",
    "ApprovalStatus",
    "Asset",
    "AuditEntry",
    "BusinessCriticality",
    "BusinessPriority",
    "DataClassification",
    "DomainError",
    "Environment",
    "ExpiredApprovalError",
    "Exposure",
    "Finding",
    "FindingStatus",
    "ImportSource",
    "Incident",
    "IncidentStatus",
    "IntegrityDomainError",
    "InvalidIdentifierError",
    "InvalidTimestampError",
    "InvalidTransitionError",
    "Occurrence",
    "Playbook",
    "PlaybookStep",
    "Provenance",
    "StepType",
    "Task",
    "TaskStatus",
    "TechnicalSeverity",
    "ValidationDomainError",
    "approve",
    "canonical_json",
    "compute_config_hash",
    "compute_entry_hash",
    "create_audit_entry",
    "expire",
    "format_timestamp",
    "hash_canonical",
    "new_approval",
    "parse_timestamp",
    "reject",
    "severity_from_cvss_score",
    "sha256_hex",
    "transition_incident",
    "transition_task",
    "verify_audit_chain",
]
