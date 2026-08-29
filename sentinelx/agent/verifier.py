from typing import Any


REQUIRED_FIELDS = {
    "outcome",
    "classification",
    "confidence",
    "evidence_event_ids",
    "reasoning",
    "next_step",
}


def verify_result(
    proposed: dict[str, Any],
    authoritative: dict[str, Any],
) -> dict[str, Any]:
    """
    Verify an LLM-proposed investigation result against the
    authoritative deterministic SentinelX assessment.
    """

    missing_fields = sorted(REQUIRED_FIELDS - proposed.keys())

    if missing_fields:
        return {
            "verified": False,
            "reason": f"Missing required fields: {missing_fields}",
        }

    assessment = authoritative.get("assessment", authoritative)

    authoritative_outcome = assessment.get("outcome")
    authoritative_classification = assessment.get("classification")
    authoritative_confidence = assessment.get("confidence")
    authoritative_next_step = assessment.get("next_step")

    authoritative_event_ids = set(
        authoritative.get("event_ids", [])
    )

    proposed_event_ids = proposed.get(
        "evidence_event_ids",
        [],
    )

    if not isinstance(proposed_event_ids, list):
        return {
            "verified": False,
            "reason": "evidence_event_ids must be a list.",
        }

    invalid_event_ids = sorted(
        set(proposed_event_ids) - authoritative_event_ids
    )

    if invalid_event_ids:
        return {
            "verified": False,
            "reason": "LLM cited evidence events outside the authoritative cluster.",
            "invalid_event_ids": invalid_event_ids,
            "authoritative_event_ids": sorted(authoritative_event_ids),
        }

    mismatches = {}

    if proposed["outcome"] != authoritative_outcome:
        mismatches["outcome"] = {
            "proposed": proposed["outcome"],
            "authoritative": authoritative_outcome,
        }

    if proposed["classification"] != authoritative_classification:
        mismatches["classification"] = {
            "proposed": proposed["classification"],
            "authoritative": authoritative_classification,
        }

    if proposed["confidence"] != authoritative_confidence:
        mismatches["confidence"] = {
            "proposed": proposed["confidence"],
            "authoritative": authoritative_confidence,
        }

    if proposed["next_step"] != authoritative_next_step:
        mismatches["next_step"] = {
            "proposed": proposed["next_step"],
            "authoritative": authoritative_next_step,
        }

    if mismatches:
        return {
            "verified": False,
            "reason": (
                "LLM proposal conflicts with authoritative "
                "SentinelX assessment."
            ),
            "mismatches": mismatches,
            "authoritative_assessment": assessment,
        }

    return {
        "verified": True,
        "reason": (
            "LLM proposal matches the authoritative "
            "SentinelX assessment and cites valid evidence."
        ),
        "authoritative_assessment": assessment,
        "verified_evidence_event_ids": sorted(
            proposed_event_ids
        ),
    }