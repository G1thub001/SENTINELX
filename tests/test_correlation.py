from pathlib import Path

from evaluation.loader import load_case
from sentinelx.correlation.engine import correlate_events
from sentinelx.correlation.links import LinkType
from sentinelx.correlation.graph import build_evidence_graph
from sentinelx.correlation.cluster import build_clusters



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

def test_c10_builds_evidence_graph():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C10.json"
    )

    graph = build_evidence_graph(case)

    assert graph.neighbors("EVT-025")
    assert "EVT-026" in graph.neighbors("EVT-025")

def test_evidence_graph_is_bidirectional():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C10.json"
    )

    graph = build_evidence_graph(case)

    assert "EVT-025" in graph.neighbors("EVT-026")

def test_c13_events_form_connected_evidence_component():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    graph = build_evidence_graph(case)

    components = graph.connected_components()

    assert any(
        {
            "EVT-034",
            "EVT-035",
            "EVT-036",
            "EVT-037",
            "EVT-038",
            "EVT-039",
        }.issubset(component)
        for component in components
    )

def test_c13_builds_evidence_cluster():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    assert len(clusters) == 1

    cluster = clusters[0]

    assert cluster.event_count == 6
    assert cluster.users == {"jack"}
    assert len(cluster.hosts) == 4

def test_c13_cluster_has_correct_time_span():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    cluster = clusters[0]

    assert cluster.duration_seconds == 14 * 60