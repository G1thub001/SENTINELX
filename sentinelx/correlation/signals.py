from dataclasses import dataclass

from sentinelx.correlation.cluster import EvidenceCluster
from sentinelx.correlation.engine import correlate_events
from sentinelx.correlation.links import LinkType


@dataclass
class ClusterSignals:
    multi_host: bool
    multi_stage: bool
    rapid_sequence: bool
    privilege_activity: bool
    authentication_activity: bool
    network_activity: bool
    unauthorized_activity: bool
    malicious_execution: bool
    persistence_activity: bool
    known_context: bool
    authorized_activity: bool
    suspicious_context: bool
    telemetry_gap: bool
    contradictory_context: bool
    benign_context: bool
    legitimate_explanation: bool
    authentication_anomaly: bool
    incomplete_process_context: bool
    authorized_security_scanning: bool
    credential_compromise_pattern: bool
    privilege_escalation_pattern: bool
    potential_credential_compromise: bool
    unresolved_authentication_anomaly: bool
    benign_vpn_activity: bool
    malicious_powershell_execution: bool
    lateral_movement_pattern: bool
    phishing_account_takeover_pattern: bool


def has_unauthorized_activity(
    cluster: EvidenceCluster,
    events: list,
) -> bool:
    """Return True when cluster telemetry contains explicit authorization failures."""

    for event in events:
        details = event.details

        if (
            details.get("authorization") == "not_approved"
            or details.get("authorized") is False
        ):
            return True

    return False


def has_malicious_execution(
    cluster: EvidenceCluster,
    events: list,
) -> bool:
    """Return True when telemetry contains explicit malicious execution indicators."""

    for event in events:
        details = event.details

        if (
            details.get("reputation") == "malicious"
            or details.get("encoded_command") is True
            or details.get("parent_process_suspicious") is True
            or details.get("script_execution") is True
        ):
            return True

    return False


def has_persistence_activity(
    cluster: EvidenceCluster,
    events: list,
) -> bool:
    """Return True when telemetry indicates scheduled-task persistence."""

    for event in events:
        details = event.details

        if (
            details.get("mechanism") == "scheduled_task"
            or details.get("execution_source") == "scheduled_task"
        ):
            return True

    return False


def has_known_context(events: list) -> bool:
    """Return True when telemetry contains explicit trusted context."""

    for event in events:
        details = event.details

        if (
            details.get("device_known") is True
            or details.get("location_known") is True
            or details.get("parent_known") is True
            or details.get("user_known") is True
        ):
            return True

    return False


def has_authorized_activity(events: list) -> bool:
    """Return True when telemetry explicitly identifies activity as authorized."""

    for event in events:
        details = event.details

        if (
            details.get("authorized") is True
            or details.get("approved_gateway") is True
            or details.get("maintenance_window") is True
            or details.get("change_ticket")
        ):
            return True

    return False


def has_suspicious_context(events: list) -> bool:
    """Return True when telemetry contains explicit suspicious context."""

    for event in events:
        details = event.details

        if (
            details.get("device_known") is False
            or details.get("location_known") is False
            or details.get("impossible_travel") is True
            or details.get("risk_signal") == "high"
            or details.get("threat_intelligence_match") is True
        ):
            return True

    return False


def has_telemetry_gap(events: list) -> bool:
    """Return True when required telemetry is explicitly unavailable."""

    for event in events:
        if (
            event.action == "telemetry_gap"
            or event.status == "unavailable"
        ):
            return True

    return False


def has_contradictory_context(events: list) -> bool:
    """Return True when suspicious and legitimate explanations coexist."""

    has_suspicious = False
    has_legitimate = False

    for event in events:
        details = event.details

        if (
            details.get("device_known") is False
            or details.get("location_known") is False
            or details.get("risk_signal") in {"medium", "high"}
        ):
            has_suspicious = True

        if (
            details.get("corporate_vpn") is True
            or details.get("known_vpn_provider") is True
            or details.get("location_explanation")
            or details.get("normal_working_hours") is True
        ):
            has_legitimate = True

    return has_suspicious and has_legitimate


def has_benign_context(events: list) -> bool:
    """Return True when multiple trusted indicators support normal activity."""

    for event in events:
        details = event.details

        trusted_indicators = 0

        if details.get("device_known") is True:
            trusted_indicators += 1

        if details.get("location_known") is True:
            trusted_indicators += 1

        if details.get("normal_working_hours") is True:
            trusted_indicators += 1

        if details.get("authorized") is True:
            trusted_indicators += 1

        if details.get("maintenance_window") is True:
            trusted_indicators += 1

        if details.get("change_ticket"):
            trusted_indicators += 1

        if trusted_indicators >= 2:
            return True

    return False


def has_legitimate_explanation(events: list) -> bool:
    """Return True when telemetry explicitly explains an apparent anomaly."""

    for event in events:
        details = event.details

        if (
            details.get("corporate_vpn") is True
            or details.get("corporate_vpn_egress") is True
            or details.get("approved_gateway") is True
            or details.get("known_vpn_provider") is True
            or details.get("location_explanation")
        ):
            return True

    return False


def has_authentication_anomaly(events: list) -> bool:
    """Return True when repeated authentication failures are observed."""

    failed_authentications = sum(
        1
        for event in events
        if (
            event.event_type.value == "authentication"
            and event.status == "failure"
        )
    )

    return failed_authentications >= 2


def has_incomplete_process_context(events: list) -> bool:
    """Return True when process telemetry lacks important validation context."""

    for event in events:
        if event.event_type.value != "process":
            continue

        details = event.details

        if (
            details.get("file_signed") is None
            and details.get("parent_known") is True
            and details.get("user_known") is True
        ):
            return True

    return False


def has_authorized_security_scanning(events: list) -> bool:
    """Return True when a threat-intel hit is explained by an authorized scanner."""

    has_threat_match = False
    has_scanner_activity = False
    has_authorized_scan = False
    has_approved_asset = False

    for event in events:
        details = event.details

        if details.get("threat_intelligence_match") is True:
            has_threat_match = True

        if (
            details.get("scanner_host") is True
            or details.get("scanner_name")
        ):
            has_scanner_activity = True

        if (
            event.action == "vulnerability_scan"
            and details.get("authorized") is True
            and details.get("scan_job")
        ):
            has_authorized_scan = True

        if details.get("asset_role") == "approved_security_scanner":
            has_approved_asset = True

    return (
        has_threat_match
        and has_scanner_activity
        and has_authorized_scan
        and has_approved_asset
    )


def has_credential_compromise_pattern(events: list) -> bool:
    """Detect correlated suspicious and legitimate authentication sessions."""

    suspicious_auth = False
    legitimate_session = False

    for event in events:
        if event.event_type.value != "authentication":
            continue

        details = event.details

        if (
            event.status == "success"
            and details.get("device_known") is False
            and details.get("location_known") is False
        ):
            if (
                details.get("risk_signal") == "high"
                or details.get("impossible_travel") is True
            ):
                suspicious_auth = True

        if (
            event.status == "success"
            and details.get("device_known") is True
            and details.get("location_known") is True
            and details.get("normal_working_hours") is True
        ):
            legitimate_session = True

    return suspicious_auth and legitimate_session


def has_privilege_escalation_pattern(events: list) -> bool:
    """Detect unauthorized privilege escalation followed by privileged activity."""

    has_standard_user = False
    has_unauthorized_escalation = False
    has_privileged_action = False

    for event in events:
        details = event.details

        if details.get("account_role") == "standard_user":
            has_standard_user = True

        if (
            details.get("previous_role") == "standard_user"
            and details.get("new_role") == "local_administrator"
            and details.get("authorization") == "not_approved"
        ):
            has_unauthorized_escalation = True

        if (
            details.get("action_target") == "security_configuration"
            and details.get("authorization") == "not_approved"
        ):
            has_privileged_action = True

    return (
        has_standard_user
        and has_unauthorized_escalation
        and has_privileged_action
    )


def has_potential_credential_compromise(events: list) -> bool:
    """Detect suspicious authentication with insufficient post-auth telemetry."""

    suspicious_auth = False
    telemetry_gap = False

    for event in events:
        details = event.details

        if (
            event.event_type.value == "authentication"
            and event.status == "success"
            and details.get("device_known") is False
            and details.get("location_known") is False
            and (
                details.get("risk_signal") == "high"
                or details.get("impossible_travel") is True
            )
        ):
            suspicious_auth = True

        if (
            event.action == "telemetry_gap"
            and details.get("reason") == "agent_offline"
        ):
            telemetry_gap = True

    return suspicious_auth and telemetry_gap


def has_unresolved_authentication_anomaly(events: list) -> bool:
    """Detect authentication with a legitimate explanation plus unresolved network activity."""

    has_vpn_explanation = False
    has_known_authentication = False
    has_unresolved_outbound = False

    for event in events:
        details = event.details

        # Legitimate explanation for unusual authentication location
        if (
            details.get("corporate_vpn") is True
            or details.get("corporate_vpn_egress") is True
            or details.get("location_explanation")
        ):
            has_vpn_explanation = True

        # Separate legitimate authentication from known environment
        if (
            event.event_type.value == "authentication"
            and event.status == "success"
            and details.get("device_known") is True
            and details.get("location_known") is True
        ):
            has_known_authentication = True

        # Unknown outbound destination without a determination
        if (
            event.action == "outbound_connection"
            and details.get("destination_known") is False
            and details.get("reputation") == "unknown"
            and details.get("approved") is None
            and details.get("business_justification") is None
        ):
            has_unresolved_outbound = True

    return (
        has_vpn_explanation
        and has_known_authentication
        and has_unresolved_outbound
    )


def has_benign_vpn_activity(events: list) -> bool:
    """Detect authentication explained by approved corporate VPN activity."""

    has_vpn_authentication = False
    has_active_vpn_session = False

    for event in events:
        details = event.details

        if (
            event.event_type.value == "authentication"
            and details.get("vpn_connection") is True
        ):
            has_vpn_authentication = True

        if (
            details.get("corporate_vpn") is True
            and details.get("approved_gateway") is True
        ):
            has_active_vpn_session = True

    return has_vpn_authentication and has_active_vpn_session


def has_malicious_powershell_execution(events: list) -> bool:
    """Detect malicious PowerShell execution corroborated by network activity."""

    has_encoded_powershell = False
    has_suspicious_parent = False
    has_malicious_network = False
    has_process_network_link = False

    for event in events:
        details = event.details

        # PowerShell with encoded command and suspicious document parent
        if (
            event.process_name == "powershell.exe"
            and details.get("encoded_command") is True
            and details.get("parent_process_suspicious") is True
        ):
            has_encoded_powershell = True
            has_suspicious_parent = True

        # Malicious outbound destination
        if (
            event.event_type.value == "network"
            and event.action == "outbound_connection"
            and details.get("reputation") == "malicious"
            and details.get("new_destination") is True
        ):
            has_malicious_network = True

        # Explicit process → network relationship
        if details.get("process_network_link") is True:
            has_process_network_link = True

    return (
        has_encoded_powershell
        and has_suspicious_parent
        and has_malicious_network
        and has_process_network_link
    )


def has_lateral_movement_pattern(cluster, events) -> bool:
    """Detect sequential remote access across hosts followed by unauthorized privilege activity."""

    cluster_event_ids = set(cluster.event_ids)

    event_by_id = {
        event.event_id: event
        for event in events
        if event.event_id in cluster_event_ids
    }

    remote_auth_events = [
        event
        for event in event_by_id.values()
        if (
            event.event_type.value == "authentication"
            and event.details.get("logon_type") == "remote"
            and event.details.get("source_host")
            and event.details.get("destination_host")
        )
    ]

    remote_network_events = [
        event
        for event in event_by_id.values()
        if (
            event.action == "remote_connection"
            and event.details.get("remote_access") is True
            and event.details.get("destination_host")
        )
    ]

    unauthorized_privilege = any(
        event.event_type.value == "privilege"
        and event.details.get("authorization") == "not_approved"
        for event in event_by_id.values()
    )

    return (
        len(remote_auth_events) >= 2
        and len(remote_network_events) >= 1
        and unauthorized_privilege
    )


def has_phishing_account_takeover_pattern(cluster, events) -> bool:
    """Detect a phishing-driven account takeover sequence."""

    cluster_event_ids = set(cluster.event_ids)

    event_by_id = {
        event.event_id: event
        for event in events
        if event.event_id in cluster_event_ids
    }

    has_phishing_delivery = any(
        event.action == "phishing_email_delivered"
        and event.details.get("url_reputation") == "malicious"
        for event in event_by_id.values()
    )

    has_user_interaction = any(
        event.action == "user_link_interaction"
        and event.details.get("phishing_event_id")
        for event in event_by_id.values()
    )

    has_phishing_credential_use = any(
        event.action == "credential_use"
        and event.details.get("credential_source") == "recent_phishing_event"
        and event.details.get("device_known") is False
        for event in event_by_id.values()
    )

    has_unauthorized_takeover = any(
        event.action == "account_takeover"
        and event.details.get("authorization") == "not_approved"
        for event in event_by_id.values()
    )

    return (
        has_phishing_delivery
        and has_user_interaction
        and has_phishing_credential_use
        and has_unauthorized_takeover
    )


def derive_signals(
    cluster: EvidenceCluster,
    events: list,
) -> ClusterSignals:
    """Derive investigation signals from an evidence cluster."""

    return ClusterSignals(
        multi_host=len(cluster.hosts) > 1,
        multi_stage=len(cluster.event_types) >= 3,
        rapid_sequence=cluster.duration_seconds <= 15 * 60,
        privilege_activity="privilege" in cluster.event_types,
        authentication_activity="authentication" in cluster.event_types,
        network_activity="network" in cluster.event_types,
        unauthorized_activity=has_unauthorized_activity(
            cluster,
            events,
        ),
        malicious_execution=has_malicious_execution(
            cluster,
            events,
        ),
        persistence_activity=has_persistence_activity(
            cluster,
            events,
        ),
        known_context=has_known_context(events),
        authorized_activity=has_authorized_activity(events),
        suspicious_context=has_suspicious_context(events),
        telemetry_gap=has_telemetry_gap(events),
        contradictory_context=has_contradictory_context(events),
        benign_context=has_benign_context(events),
        legitimate_explanation=has_legitimate_explanation(events),
        authentication_anomaly=has_authentication_anomaly(events),
        incomplete_process_context=has_incomplete_process_context(events),
        authorized_security_scanning=has_authorized_security_scanning(events),
        credential_compromise_pattern=has_credential_compromise_pattern(
            events
        ),
        privilege_escalation_pattern=has_privilege_escalation_pattern(
            events
        ),
        potential_credential_compromise=has_potential_credential_compromise(
            events
        ),
        unresolved_authentication_anomaly=has_unresolved_authentication_anomaly(
            events
        ),
        benign_vpn_activity=has_benign_vpn_activity(events),
        malicious_powershell_execution=has_malicious_powershell_execution(
            events
        ),
        lateral_movement_pattern=has_lateral_movement_pattern(
            cluster,
            events
        ),
        phishing_account_takeover_pattern=has_phishing_account_takeover_pattern(
            cluster,
            events
        ),
    )