from dataclasses import dataclass
from datetime import datetime

from sentinelx.models import InvestigationCase
from sentinelx.correlation.graph import EvidenceGraph


@dataclass
class EvidenceCluster:
    event_ids: set[str]
    users: set[str]
    hosts: set[str]
    event_types: set[str]
    start_time: datetime
    end_time: datetime

    @property
    def event_count(self) -> int:
        return len(self.event_ids)

    @property
    def duration_seconds(self) -> float:
        return (
            self.end_time - self.start_time
        ).total_seconds()


def build_clusters(
    case: InvestigationCase,
    graph: EvidenceGraph,
) -> list[EvidenceCluster]:
    """Build evidence clusters from connected graph components."""

    events_by_id = {
        event.event_id: event
        for event in case.events
    }

    clusters: list[EvidenceCluster] = []

    for component in graph.connected_components():
        events = [
            events_by_id[event_id]
            for event_id in component
            if event_id in events_by_id
        ]

        if not events:
            continue

        clusters.append(
            EvidenceCluster(
                event_ids={
                    event.event_id
                    for event in events
                },
                users={
                    event.user
                    for event in events
                    if event.user
                },
                hosts={
                    event.host
                    for event in events
                    if event.host
                },
                event_types={
                    event.event_type.value
                    for event in events
                },
                start_time=min(
                    event.timestamp
                    for event in events
                ),
                end_time=max(
                    event.timestamp
                    for event in events
                ),
            )
        )

    return clusters