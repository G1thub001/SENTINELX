from pathlib import Path

from evaluation.loader import load_case
from sentinelx.correlation.engine import correlate_events
from sentinelx.correlation.links import LinkType


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_c13_events_share_user_relationships():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    links = correlate_events(case)

    same_user_links = [
        link
        for link in links
        if link.link_type == LinkType.SAME_USER
    ]

    assert same_user_links

def test_c13_events_have_temporal_relationships():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    links = correlate_events(case)

    temporal_links = [
        link
        for link in links
        if link.link_type == LinkType.TEMPORAL
    ]

    assert temporal_links    