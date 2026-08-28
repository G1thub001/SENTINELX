from pathlib import Path

from evaluation.loader import load_case, load_ground_truth
from evaluation.scorer import score_result
from baseline.investigator import investigate


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_c01_baseline_score():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C01.json"
    )

    ground_truth = load_ground_truth(
        PROJECT_ROOT / "data" / "ground_truth" / "C01.json"
    )

    result = investigate(case)
    scores = score_result(result, ground_truth)

    assert scores["outcome"] == 30.0
    assert scores["category"] == 0.0
    assert scores["evidence"] == 30.0
    assert scores["unsupported_claims"] == 20.0
    assert scores["total"] == 80.0