from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    ENDPOINT = "endpoint"
    PRIVILEGE = "privilege"


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: EventType

    source: str
    host: str | None = None

    user: str | None = None

    source_ip: str | None = None
    destination_ip: str | None = None
    destination_domain: str | None = None

    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None

    action: str
    status: str | None = None
    authentication_method: str | None = None

    severity: Severity
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationCase(BaseModel):
    case_id: str
    description: str
    events: list[SecurityEvent]


class GroundTruth(BaseModel):
    case_id: str

    expected_outcome: str
    expected_category: str
    expected_confidence: str

    required_evidence: list[str]
    required_evidence_event_ids: list[str] =  Field(default_factory=list)
    forbidden_conclusions: list[str]

    expected_next_step: str

    failure_mode: str

class InvestigationResult(BaseModel):
    case_id: str

    outcome: str
    category: str
    confidence: str

    evidence_event_ids: list[str]
    reasoning: str

    next_step: str
