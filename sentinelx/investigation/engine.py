from sentinelx.models import InvestigationCase, InvestigationResult

from sentinelx.correlation.cluster import build_clusters
from sentinelx.correlation.graph import build_evidence_graph
from sentinelx.correlation.signals import derive_signals
from sentinelx.investigation.assessor import assess_cluster


def investigate_case(
    case: InvestigationCase,
) -> InvestigationResult:
    """Run the SentinelX investigation pipeline."""

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    if not clusters:
        return InvestigationResult(
            case_id=case.case_id,
            outcome="insufficient_evidence",
            category="unresolved_activity",
            confidence="low",
            evidence_event_ids=[],
            reasoning="No connected evidence clusters were identified.",
            next_step="collect_telemetry",
        )

    cluster = max(
        clusters,
        key=lambda item: item.event_count,
    )

    signals = derive_signals(
        cluster,
        case.events,
    )
    assessment = assess_cluster(signals)

    return InvestigationResult(
        case_id=case.case_id,
        outcome=assessment.outcome,
        category=assessment.classification,
        confidence=assessment.confidence,
        evidence_event_ids=sorted(cluster.event_ids),
        reasoning=assessment.rationale,
        next_step=assessment.next_step,
    )