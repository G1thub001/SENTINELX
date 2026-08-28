from datetime import datetime
from enum import Enum

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
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None
    action: str
    severity: Severity
    details: dict[str, str] = Field(default_factory=dict)


class IncidentCase(BaseModel):
    case_id: str
    description: str
    events: list[SecurityEvent]

    expected_incident: bool
    expected_category: str
    key_evidence: list[str]
    expected_confidence: str