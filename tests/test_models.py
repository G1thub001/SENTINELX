from datetime import datetime, timezone

from sentinelx.models import EventType, IncidentCase, SecurityEvent, Severity


def test_incident_case_schema():
    event = SecurityEvent(
        event_id="EVT-001",
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.AUTHENTICATION,
        source="auth-server-01",
        user="alice",
        source_ip="10.0.0.10",
        action="successful_login",
        severity=Severity.MEDIUM,
    )

    case = IncidentCase(
        case_id="CASE-001",
        description="Successful login from a known workstation.",
        events=[event],
        expected_incident=False,
        expected_category="benign",
        key_evidence=["Known workstation", "Normal login time"],
        expected_confidence="high",
    )

    assert case.case_id == "CASE-001"
    assert len(case.events) == 1
    assert case.events[0].event_type == EventType.AUTHENTICATION