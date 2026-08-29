from sentinelx.models import InvestigationCase
from sentinelx.correlation.engine import EvidenceLink, correlate_events


class EvidenceGraph:
    """In-memory graph of relationships between security events."""
    

    def __init__(
        self,
        links: list[EvidenceLink] | None = None,
        event_ids: set[str] | None = None,
    ):
        self.links = links or []
        self.event_ids = event_ids or set()

    def add_link(self, link: EvidenceLink) -> None:
        self.links.append(link)

    def neighbors(self, event_id: str) -> list[str]:
        """Return event IDs directly connected to the given event."""
        neighbors: list[str] = []

        for link in self.links:
            if link.source_event_id == event_id:
                neighbors.append(link.target_event_id)

            elif link.target_event_id == event_id:
                neighbors.append(link.source_event_id)

        return neighbors

    def connected_components(self) -> list[set[str]]:
        """Return groups of event IDs connected by evidence links."""
        event_ids = set(self.event_ids)

        for link in self.links:
            event_ids.add(link.source_event_id)
            event_ids.add(link.target_event_id)

        components: list[set[str]] = []
        visited: set[str] = set()

        for event_id in event_ids:
            if event_id in visited:
                continue

            component: set[str] = set()
            stack = [event_id]

            while stack:
                current = stack.pop()

                if current in visited:
                    continue

                visited.add(current)
                component.add(current)

                for neighbor in self.neighbors(current):
                    if neighbor not in visited:
                        stack.append(neighbor)

            components.append(component)

        return components


def build_evidence_graph(case: InvestigationCase) -> EvidenceGraph:
    """Build an evidence graph from case events and correlations."""

    links = correlate_events(case)

    event_ids = {
        event.event_id
        for event in case.events
    }

    return EvidenceGraph(
        links=links,
        event_ids=event_ids,
    )