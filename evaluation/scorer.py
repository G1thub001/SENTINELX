from sentinelx.models import GroundTruth, InvestigationResult


def score_result(
    result: InvestigationResult,
    ground_truth: GroundTruth,
) -> dict[str, float]:
    """Score an investigation result against its ground truth."""

    outcome_score = (
        30.0
        if result.outcome.lower() == ground_truth.expected_outcome.lower()
        else 0.0
    )

    category_score = (
        20.0
        if result.category.lower() == ground_truth.expected_category.lower()
        else 0.0
    )

    required_evidence_ids = set(
        ground_truth.required_evidence_event_ids
    )

    reported_evidence_ids = set(
        result.evidence_event_ids
    )

    if required_evidence_ids:
        matched_evidence = (
            required_evidence_ids & reported_evidence_ids
        )

        evidence_score = 30.0 * (
            len(matched_evidence) / len(required_evidence_ids)
        )
    else:
        evidence_score = 30.0

    unsupported_score = 20.0

    reasoning_lower = result.reasoning.lower()

    for forbidden in ground_truth.forbidden_conclusions:
        if forbidden.lower() in reasoning_lower:
            unsupported_score = 0.0
            break

    return {
        "outcome": outcome_score,
        "category": category_score,
        "evidence": evidence_score,
        "unsupported_claims": unsupported_score,
        "total": (
            outcome_score
            + category_score
            + evidence_score
            + unsupported_score
        ),
    }