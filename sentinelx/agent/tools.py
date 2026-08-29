import json
from pathlib import Path
from typing import Any
from dataclasses import asdict

from sentinelx.correlation.cluster import build_clusters
from sentinelx.correlation.graph import build_evidence_graph
from sentinelx.correlation.signals import derive_signals
from sentinelx.investigation.assessor import assess_cluster
from sentinelx.models import InvestigationCase


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = PROJECT_ROOT / "data" / "cases"


def inspect_case(case: InvestigationCase) -> dict[str, Any]:
    """Return a compact, agent-friendly inventory of the case evidence."""

    events = sorted(case.events, key=lambda event: event.timestamp)

    return {
        "case_id": case.case_id,
        "description": case.description,
        "event_count": len(events),
        "events": [
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "host": event.host,
                "user": event.user,
                "action": event.action,
                "status": event.status,
                "severity": event.severity.value,
                "process_name": event.process_name,
                "parent_process": event.parent_process,
            }
            for event in events
        ],
    }


def correlate_evidence(case: InvestigationCase) -> dict[str, Any]:
    """Build the SentinelX evidence graph and return its clusters."""

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    return {
        "case_id": case.case_id,
        "cluster_count": len(clusters),
        "clusters": [
            {
                "event_ids": sorted(cluster.event_ids),
                "users": sorted(cluster.users),
                "hosts": sorted(cluster.hosts),
                "event_types": sorted(
                    event_type.value
                    if hasattr(event_type, "value")
                    else str(event_type)
                    for event_type in cluster.event_types
                ),
                "start_time": cluster.start_time.isoformat(),
                "end_time": cluster.end_time.isoformat(),
                "event_count": cluster.event_count,
            }
            for cluster in clusters
        ],
    }


def derive_case_signals(
    case: InvestigationCase,
    cluster_index: int = 0,
) -> dict[str, Any]:
    """Derive security signals for one correlated evidence cluster."""

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    if not clusters:
        return {
            "case_id": case.case_id,
            "cluster_index": cluster_index,
            "error": "No evidence clusters were identified.",
        }

    if cluster_index < 0 or cluster_index >= len(clusters):
        return {
            "case_id": case.case_id,
            "cluster_index": cluster_index,
            "error": "Cluster index is out of range.",
            "cluster_count": len(clusters),
        }

    cluster = clusters[cluster_index]
    signals = derive_signals(cluster, case.events)

    return {
        "case_id": case.case_id,
        "cluster_index": cluster_index,
        "event_ids": sorted(cluster.event_ids),
        "signals": asdict(signals),
    }


def assess_case_cluster(
    case: InvestigationCase,
    cluster_index: int = 0,
) -> dict[str, Any]:
    """Run the authoritative SentinelX assessment for a cluster."""

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    if not clusters:
        return {
            "case_id": case.case_id,
            "error": "No evidence clusters were identified.",
            "outcome": "insufficient_evidence",
            "classification": "unresolved_activity",
            "confidence": "low",
            "next_step": "collect_telemetry",
        }

    if cluster_index < 0 or cluster_index >= len(clusters):
        return {
            "case_id": case.case_id,
            "cluster_index": cluster_index,
            "error": "Cluster index is out of range.",
        }

    cluster = clusters[cluster_index]
    signals = derive_signals(cluster, case.events)
    assessment = assess_cluster(signals)

    return {
        "case_id": case.case_id,
        "cluster_index": cluster_index,
        "event_ids": sorted(cluster.event_ids),
        "assessment": asdict(assessment),
    }


def load_case(case_id: str) -> InvestigationCase:
    """Load a case from the SentinelX case dataset."""

    path = CASES_DIR / f"{case_id}.json"

    if not path.exists():
        raise FileNotFoundError(f"Case not found: {case_id}")

    data = json.loads(path.read_text(encoding="utf-8"))
    return InvestigationCase.model_validate(data)