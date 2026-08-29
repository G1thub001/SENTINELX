from sentinelx.models import InvestigationCase
from sentinelx.correlation.engine import EvidenceLink, correlate_events


class EvidenceGraph:
    """In-memory graph of relationships between security events."""
    

    def __init__(self, links: list[EvidenceLink] | None = None):
        self.links = links or []

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


def build_evidence_graph(case: InvestigationCase) -> EvidenceGraph:
    """Build an evidence graph from correlated case events."""
    links = correlate_events(case)
    return EvidenceGraph(links)