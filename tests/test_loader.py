from pathlib import Path

from evaluation.loader import load_case, load_ground_truth, load_all_cases, load_all_ground_truth


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_load_c01_case():
    case_path = PROJECT_ROOT / "data" / "cases" / "C01.json"

    case = load_case(case_path)

    assert case.case_id == "C01"
    assert len(case.events) == 1
    assert case.events[0].event_id == "EVT-001"
    assert case.events[0].action == "successful_login"


def test_load_c01_ground_truth():
    ground_truth_path = (
        PROJECT_ROOT / "data" / "ground_truth" / "C01.json"
    )

    ground_truth = load_ground_truth(ground_truth_path)

    assert ground_truth.case_id == "C01"
    assert ground_truth.expected_outcome == "benign"
    assert ground_truth.expected_category == "benign_authentication"
    assert ground_truth.expected_confidence == "high"


def test_load_all_cases():
    cases = load_all_cases(PROJECT_ROOT / "data" / "cases")

    assert len(cases) == 6
    assert {case.case_id for case in cases} == {"C01", "C02", "C03", "C04", "C05", "C06"}


def test_load_all_ground_truth():
    ground_truth = load_all_ground_truth(
        PROJECT_ROOT / "data" / "ground_truth"
    )

    assert len(ground_truth) == 6
    assert {
        truth.case_id for truth in ground_truth
    } == {"C01", "C02", "C03", "C04", "C05", "C06"}