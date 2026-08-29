from pathlib import Path

from evaluation.loader import load_case
from sentinelx.correlation.engine import correlate_events
from sentinelx.correlation.links import LinkType
from sentinelx.correlation.graph import build_evidence_graph
from sentinelx.correlation.cluster import build_clusters
from sentinelx.correlation.signals import derive_signals
from sentinelx.investigation.assessor import assess_cluster


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


def test_c13_derives_cluster_signals():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(clusters[0], case.events)

    assert signals.multi_host is True
    assert signals.multi_stage is True
    assert signals.rapid_sequence is True
    assert signals.privilege_activity is True


def test_c13_assesses_multi_stage_attack():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C13.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assessment = assess_cluster(signals)

    assert assessment.outcome == "confirmed_incident"
    assert assessment.classification == "multi_stage_attack"
    assert assessment.confidence == "high"
    assert assessment.next_step == "contain"


def test_c01_isolated_event_forms_evidence_component():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C01.json"
    )

    graph = build_evidence_graph(case)

    components = graph.connected_components()

    assert {"EVT-001"} in components


def test_c05_isolated_event_forms_evidence_component():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C05.json"
    )

    graph = build_evidence_graph(case)

    components = graph.connected_components()

    assert len(components) == 1


def test_c08_detects_unauthorized_activity():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C08.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.unauthorized_activity is True


def test_c09_detects_malicious_execution():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C09.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.malicious_execution is True


def test_c11_detects_persistence_activity():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C11.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.persistence_activity is True

def test_c01_detects_known_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C01.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.known_context is True

def test_c02_detects_authorized_activity():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C02.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.authorized_activity is True

def test_c07_detects_suspicious_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C07.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.suspicious_context is True

def test_c14_detects_telemetry_gap():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C14.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.telemetry_gap is True

def test_c15_detects_contradictory_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C15.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.contradictory_context is True

def test_c01_detects_benign_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C01.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.benign_context is True

def test_c02_detects_benign_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C02.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.benign_context is True

def test_c03_detects_legitimate_explanation():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C03.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.legitimate_explanation is True

def test_c04_detects_authentication_anomaly():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C04.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.authentication_anomaly is True

def test_c05_detects_incomplete_process_context():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C05.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.incomplete_process_context is True

def test_c06_detects_authorized_security_scanning():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C06.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.authorized_security_scanning is True

def test_c07_detects_credential_compromise_pattern():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C07.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.credential_compromise_pattern is True

def test_c08_detects_privilege_escalation_pattern():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C08.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.privilege_escalation_pattern is True

def test_c14_detects_potential_credential_compromise():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C14.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.potential_credential_compromise is True

def test_c15_detects_unresolved_authentication_anomaly():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C15.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.unresolved_authentication_anomaly is True

def test_c03_detects_benign_vpn_activity():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C03.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.benign_vpn_activity is True

def test_c09_detects_malicious_powershell_execution():
    case = load_case(
        PROJECT_ROOT / "data" / "cases" / "C09.json"
    )

    graph = build_evidence_graph(case)
    clusters = build_clusters(case, graph)

    signals = derive_signals(
        clusters[0],
        case.events,
    )

    assert signals.malicious_powershell_execution is True