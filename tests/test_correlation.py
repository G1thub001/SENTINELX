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


def test_c10_detects_host_transitions():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C10.json"
    )

    links = correlate_events(case)

    host_transitions = [
        link
        for link in links
        if link.link_type == LinkType.HOST_TRANSITION
    ]

    assert host_transitions

def test_c10_host_transition_connects_expected_events():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C10.json"
    )

    links = correlate_events(case)

    host_transitions = [
        link
        for link in links
        if link.link_type == LinkType.HOST_TRANSITION
    ]

    pairs = {
        (link.source_event_id, link.target_event_id)
        for link in host_transitions
    }

    assert ("EVT-025", "EVT-026") in pairs

def test_c10_detects_host_transition():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C10.json"
    )

    links = correlate_events(case)

    host_transitions = [
        link
        for link in links
        if link.link_type == LinkType.HOST_TRANSITION
    ]

    pairs = {
        (link.source_event_id, link.target_event_id)
        for link in host_transitions
    }

    assert ("EVT-025", "EVT-026") in pairs