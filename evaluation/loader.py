import json
from pathlib import Path

from sentinelx.models import GroundTruth, InvestigationCase


def load_case(path: str | Path) -> InvestigationCase:
    """Load a single investigation case from JSON."""
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return InvestigationCase.model_validate(data)


def load_ground_truth(path: str | Path) -> GroundTruth:
    """Load a single ground-truth definition from JSON."""
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return GroundTruth.model_validate(data)

def load_all_cases(directory: str | Path) -> list[InvestigationCase]:
    """Load all JSON investigation cases from a directory."""
    directory = Path(directory)

    cases = []

    for path in sorted(directory.glob("*.json")):
        cases.append(load_case(path))

    return cases


def load_all_ground_truth(
    directory: str | Path,
) -> list[GroundTruth]:
    """Load all JSON ground-truth files from a directory."""
    directory = Path(directory)

    ground_truth = []

    for path in sorted(directory.glob("*.json")):
        ground_truth.append(load_ground_truth(path))

    return ground_truth