from datetime import timedelta

from sentinelx.models import InvestigationCase, SecurityEvent

from sentinelx.correlation.links import LinkType


class EvidenceLink:
    def __init__(
        self,
        source_event_id: str,
        target_event_id: str,
        link_type: LinkType,
        strength: float = 1.0,
    ):
        self.source_event_id = source_event_id
        self.target_event_id = target_event_id
        self.link_type = link_type
        self.strength = strength


def correlate_events(
    case: InvestigationCase,
) -> list[EvidenceLink]:
    links: list[EvidenceLink] = []

    events = sorted(
        case.events,
        key=lambda event: event.timestamp,
    )

    for index, source in enumerate(events):
        for target in events[index + 1:]:
            if source.user and target.user:
                if source.user == target.user:
                    links.append(
                        EvidenceLink(
                            source.event_id,
                            target.event_id,
                            LinkType.SAME_USER,
                        )
                    )

            if source.host and target.host:
                if source.host == target.host:
                    links.append(
                        EvidenceLink(
                            source.event_id,
                            target.event_id,
                            LinkType.SAME_HOST,
                        )
                    )

            if (
                source.source_ip
                and target.source_ip
                and source.source_ip == target.source_ip
            ):
                links.append(
                    EvidenceLink(
                        source.event_id,
                        target.event_id,
                        LinkType.SAME_SOURCE_IP,
                    )
                )

            if target.timestamp >= source.timestamp:
                delta = target.timestamp - source.timestamp

                if delta <= timedelta(minutes=10):
                    links.append(
                        EvidenceLink(
                            source.event_id,
                            target.event_id,
                            LinkType.TEMPORAL,
                        )
                    )

    return links