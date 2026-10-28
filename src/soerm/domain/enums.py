"""Enumerations. Values are stable lowercase strings used in JSON and, later, in SQLite."""

from enum import StrEnum

__all__ = [
    "ApprovalStatus",
    "BusinessCriticality",
    "BusinessPriority",
    "DataClassification",
    "Environment",
    "Exposure",
    "FindingStatus",
    "ImportSource",
    "IncidentStatus",
    "StepType",
    "TaskStatus",
    "TechnicalSeverity",
]


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class BusinessCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Exposure(StrEnum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class TechnicalSeverity(StrEnum):
    """Technical severity (CVSS qualitative scale). ``NONE`` is valid only for score 0.0."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BusinessPriority(StrEnum):
    """Business priority, P1 (highest) to P4. Independent of technical severity; it is
    computed in a later milestone."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class TaskStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    CANCELLED = "cancelled"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ImportSource(StrEnum):
    SARIF = "sarif"
    GENERIC_JSON = "generic_json"
    CSV = "csv"
    MANUAL = "manual"


class StepType(StrEnum):
    """Playbook step types. No step is ever executed by the domain layer."""

    MANUAL = "manual"
    CHECKLIST = "checklist"
    NOTIFY_TEXT = "notify_text"
