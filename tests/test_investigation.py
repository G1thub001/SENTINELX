from pathlib import Path

from evaluation.loader import load_case
from sentinelx.investigation.engine import investigate_case


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_c13_investigation_pipeline():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    result = investigate_case(case)

    assert result.case_id == "C13"
    assert result.category == "multi_stage_attack"
    assert result.confidence == "high"
    assert result.outcome == "confirmed_incident"
    assert result.next_step == "contain"

    assert set(result.evidence_event_ids) == {
        "EVT-034",
        "EVT-035",
        "EVT-036",
        "EVT-037",
        "EVT-038",
        "EVT-039",
    }