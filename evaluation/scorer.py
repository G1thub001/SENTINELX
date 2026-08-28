from sentinelx.models import GroundTruth, InvestigationResult


def score_result(
    result: InvestigationResult,
    ground_truth: GroundTruth,
) -> dict[str, float]:
    """Score an investigation result against its ground truth."""

    outcome_score = (
        25.0
        if result.outcome == ground_truth.expected_outcome
        else 0.0
    )

    category_score = (
        15.0
        if result.category.lower()
        == ground_truth.expected_category.lower()
        else 0.0
    )

    confidence_score = (
        10.0
        if result.confidence == ground_truth.expected_confidence
        else 0.0
    )

    next_step_score = (
        10.0
        if result.next_step == ground_truth.expected_next_step
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
            len(matched_evidence)
            / len(required_evidence_ids)
        )
    else:
        evidence_score = 30.0

    unsupported_score = 10.0

    reasoning_lower = result.reasoning.lower()

    for forbidden in ground_truth.forbidden_conclusions:
        if forbidden.lower() in reasoning_lower:
            unsupported_score = 0.0
            break

    return {
        "outcome": outcome_score,
        "category": category_score,
        "evidence": evidence_score,
        "confidence": confidence_score,
        "next_step": next_step_score,
        "unsupported_claims": unsupported_score,
        "total": (
            outcome_score
            + category_score
            + evidence_score
            + confidence_score
            + next_step_score
            + unsupported_score
        ),
    }