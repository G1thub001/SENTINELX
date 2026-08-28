from datetime import datetime, timezone

from sentinelx.models import (
    EventType,
    GroundTruth,
    InvestigationCase,
    SecurityEvent,
    Severity,
)


def test_investigation_case_schema():
    event = SecurityEvent(
        event_id="EVT-001",
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.AUTHENTICATION,
        source="auth-server-01",
        host="workstation-17",
        user="alice",
        source_ip="10.0.0.10",
        action="successful_login",
        status="success",
        authentication_method="password",
        severity=Severity.LOW,
    )

    case = InvestigationCase(
        case_id="CASE-001",
        description="Successful login from a known workstation.",
        events=[event],
    )

    assert case.case_id == "CASE-001"
    assert len(case.events) == 1
    assert case.events[0].event_type == EventType.AUTHENTICATION
    assert case.events[0].host == "workstation-17"


def test_ground_truth_schema():
    ground_truth = GroundTruth(
        case_id="C01",
        expected_outcome="benign",
        expected_category="benign_authentication",
        expected_confidence="high",
        required_evidence=[
            "Known employee account",
            "Known workstation",
            "Normal working hours",
        ],
        forbidden_conclusions=[
            "Account compromise without supporting evidence",
        ],
        expected_next_step="Continue normal monitoring.",
        failure_mode="over_alerting",
    )

    assert ground_truth.case_id == "C01"
    assert ground_truth.expected_outcome == "benign"
    assert len(ground_truth.required_evidence) == 3