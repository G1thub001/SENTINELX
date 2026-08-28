from pathlib import Path

from baseline.investigator import investigate
from evaluation.loader import load_all_cases, load_all_ground_truth
from evaluation.scorer import score_result


PROJECT_ROOT = Path(__file__).resolve().parents[1]

CASES_DIR = PROJECT_ROOT / "data" / "cases"
GROUND_TRUTH_DIR = PROJECT_ROOT / "data" / "ground_truth"


def run_baseline() -> list[dict]:
    cases = load_all_cases(CASES_DIR)
    ground_truth = load_all_ground_truth(GROUND_TRUTH_DIR)

    truth_by_case = {
        truth.case_id: truth
        for truth in ground_truth
    }

    results = []

    for case in cases:
        result = investigate(case)

        truth = truth_by_case.get(case.case_id)

        if truth is None:
            raise ValueError(
                f"No ground truth found for case {case.case_id}"
            )

        scores = score_result(result, truth)

        results.append(
            {
                "case_id": case.case_id,
                "result": result,
                "scores": scores,
            }
        )

    return results


if __name__ == "__main__":
    results = run_baseline()

    for item in results:
        print(
            f"{item['case_id']}: "
            f"{item['scores']['total']:.1f}/100"
        )