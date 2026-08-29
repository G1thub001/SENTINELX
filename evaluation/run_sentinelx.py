from pathlib import Path

from evaluation.loader import load_all_cases, load_all_ground_truth
from evaluation.scorer import score_result
from sentinelx.investigation.engine import investigate_case


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    cases = load_all_cases(
        PROJECT_ROOT / "data" / "cases"
    )

    ground_truth = load_all_ground_truth(
        PROJECT_ROOT / "data" / "ground_truth"
    )

    ground_truth_by_id = {
        item.case_id: item
        for item in ground_truth
    }

    scores = []

    for case in cases:
        result = investigate_case(case)

        score = score_result(
            result,
            ground_truth_by_id[case.case_id],
        )

        scores.append(score["total"])

        print(
            f"{case.case_id}={score['total']:.1f}",
            end=" | ",
        )

    print()
    print(f"Average: {sum(scores) / len(scores):.1f}")


if __name__ == "__main__":
    main()