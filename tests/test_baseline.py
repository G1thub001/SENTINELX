from pathlib import Path

from sentinelx.models import Confidence, Outcome
from baseline.investigator import investigate
from evaluation.loader import load_case


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_baseline_c01_is_benign():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C01.json"
    )

    result = investigate(case)

    assert result.case_id == "C01"
    assert result.outcome == "benign"
    assert result.confidence == "high"
    assert "EVT-001" in result.evidence_event_ids


def test_baseline_c04_is_suspicious():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C04.json"
    )

    result = investigate(case)

    assert result.case_id == "C04"
    assert result.outcome == Outcome.SUSPICIOUS
    assert result.confidence == Confidence.HIGH
    assert result.evidence_event_ids == [
        "EVT-007",
        "EVT-008",
    ]