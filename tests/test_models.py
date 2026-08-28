from sentinelx.models import (
    EventType,
    GroundTruth,
    InvestigationCase,
    SecurityEvent,
    Severity,
)

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
        expected_next_step="continue_monitoring",
        failure_mode="over_alerting",
    )

    assert ground_truth.case_id == "C01"
    assert ground_truth.expected_outcome == "benign"
    assert len(ground_truth.required_evidence) == 3