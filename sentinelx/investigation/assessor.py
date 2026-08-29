from dataclasses import dataclass

from sentinelx.correlation.signals import ClusterSignals


@dataclass
class ClusterAssessment:
    outcome: str
    classification: str
    confidence: str
    next_step: str
    rationale: str


def assess_cluster(
    signals: ClusterSignals,
) -> ClusterAssessment:
    """Assess an evidence cluster using deterministic signals."""

    # 1. Lateral movement - sequential remote access with unauthorized privilege
    if signals.lateral_movement_pattern:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="lateral_movement",
            confidence="high",
            next_step="contain",
            rationale=(
                "The evidence cluster contains sequential remote access "
                "across multiple internal hosts followed by unauthorized "
                "privileged activity."
            ),
        )

    # 2. Phishing account takeover
    if signals.phishing_account_takeover_pattern:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="phishing_account_takeover",
            confidence="high",
            next_step="contain",
            rationale=(
                "The evidence cluster shows malicious phishing delivery "
                "followed by user interaction, credential use from an "
                "unrecognized source, and unauthorized account takeover."
            ),
        )

    # 3. Strong multi-stage attack
    if (
        signals.multi_host
        and signals.multi_stage
        and signals.rapid_sequence
        and signals.privilege_activity
    ):
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="multi_stage_attack",
            confidence="high",
            next_step="contain",
            rationale=(
                "The evidence cluster contains multi-host activity, "
                "multiple event types, rapid temporal progression, "
                "and privilege activity."
            ),
        )

    # 4. Unauthorized privilege escalation
    if signals.privilege_escalation_pattern:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="unauthorized_privilege_escalation",
            confidence="high",
            next_step="contain",
            rationale=(
                "A standard user account was escalated to local administrator "
                "without authorization and subsequently performed a privileged "
                "security-related action."
            ),
        )

    # 5. Malicious PowerShell execution
    if signals.malicious_powershell_execution:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="malicious_powershell_execution",
            confidence="high",
            next_step="contain",
            rationale=(
                "PowerShell execution with an encoded command and suspicious "
                "parent process is corroborated by malicious network activity "
                "and an explicit process-network relationship."
            ),
        )

    # 6. Explicit malicious execution
    if signals.malicious_execution:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="malicious_execution",
            confidence="high",
            next_step="contain",
            rationale=(
                "The evidence cluster contains explicit indicators "
                "of malicious execution."
            ),
        )

    # 7. Confirmed credential compromise - suspicious auth + legitimate session correlated
    if signals.credential_compromise_pattern:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="credential_compromise",
            confidence="high",
            next_step="contain",
            rationale=(
                "A successful authentication from an unrecognized high-risk "
                "source is correlated with a separate legitimate session "
                "from the user's known workstation."
            ),
        )

    # 8. Potential credential compromise - high-risk auth with telemetry gap
    if signals.potential_credential_compromise:
        return ClusterAssessment(
            outcome="insufficient_evidence",
            classification="potential_credential_compromise",
            confidence="low",
            next_step="collect_telemetry",
            rationale=(
                "High-risk authentication activity suggests potential "
                "credential compromise, but critical endpoint telemetry "
                "is unavailable to confirm post-authentication activity."
            ),
        )

    # 9. Incomplete telemetry takes priority over suspicious indicators.
    if signals.telemetry_gap:
        return ClusterAssessment(
            outcome="insufficient_evidence",
            classification="insufficient_telemetry",
            confidence="medium",
            next_step="collect_telemetry",
            rationale=(
                "Suspicious activity is present, but required telemetry "
                "is unavailable, preventing confirmation."
            ),
        )

    # 10. Unresolved authentication anomaly - VPN explains auth but outbound remains unresolved
    if signals.unresolved_authentication_anomaly:
        return ClusterAssessment(
            outcome="insufficient_evidence",
            classification="unresolved_authentication_anomaly",
            confidence="low",
            next_step="collect_telemetry",
            rationale=(
                "The authentication anomaly is partially explained by "
                "legitimate corporate VPN activity, but a separate outbound "
                "connection to an unknown destination remains unresolved."
            ),
        )

    # 11. Contradictory evidence requires additional investigation rather
    # than immediate classification as malicious.
    if signals.contradictory_context:
        return ClusterAssessment(
            outcome="insufficient_evidence",
            classification="contradictory_activity",
            confidence="medium",
            next_step="investigate",
            rationale=(
                "The evidence contains both legitimate explanations "
                "and unresolved suspicious indicators."
            ),
        )

    # 12. Authentication anomaly - repeated failures without compromise evidence
    if signals.authentication_anomaly:
        return ClusterAssessment(
            outcome="suspicious",
            classification="authentication_anomaly",
            confidence="medium",
            next_step="investigate",
            rationale=(
                "Repeated authentication failures were observed, "
                "but the available evidence does not establish "
                "account compromise."
            ),
        )

    # 13. Authorized security scanning - threat intel match explained by approved scanner
    if signals.authorized_security_scanning:
        return ClusterAssessment(
            outcome="benign",
            classification="authorized_security_scanning",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "The threat-intelligence match is associated with an "
                "approved internal security scanner performing an "
                "authorized vulnerability scan."
            ),
        )

    # 14. Incomplete process context - suspicious execution with limited telemetry
    if signals.incomplete_process_context:
        return ClusterAssessment(
            outcome="suspicious",
            classification="suspicious_process_execution",
            confidence="medium",
            next_step="investigate",
            rationale=(
                "Suspicious process execution was observed, but the "
                "available telemetry is insufficient to confirm malicious activity."
            ),
        )

    # 15. Benign VPN activity - authentication explained by approved corporate VPN
    if signals.benign_vpn_activity:
        return ClusterAssessment(
            outcome="benign",
            classification="benign_vpn_activity",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "The apparent authentication anomaly is explained by "
                "approved corporate VPN infrastructure and a corresponding "
                "active VPN session."
            ),
        )

    # 16. Authorized administrative activity (but not VPN activity)
    if signals.authorized_activity and not signals.benign_vpn_activity:
        return ClusterAssessment(
            outcome="benign",
            classification="authorized_administrative_activity",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "The administrative activity occurred within an authorized "
                "maintenance window and is associated with approved change activity."
            ),
        )

    # 17. Legitimate explanation - explicit explanation for apparent anomaly
    if signals.legitimate_explanation:
        return ClusterAssessment(
            outcome="benign",
            classification="legitimate_activity",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "The apparent anomaly is explained by legitimate "
                "corporate infrastructure or authorized activity."
            ),
        )

    # 18. Suspicious context - contextual indicators of suspicious activity
    if signals.suspicious_context:
        return ClusterAssessment(
            outcome="suspicious",
            classification="suspicious_activity",
            confidence="high",
            next_step="investigate",
            rationale=(
                "The evidence cluster contains contextual indicators "
                "associated with suspicious activity."
            ),
        )

    # 19. Confirmed scheduled-task persistence
    if signals.persistence_activity:
        return ClusterAssessment(
            outcome="confirmed_incident",
            classification="scheduled_task_persistence",
            confidence="high",
            next_step="contain",
            rationale=(
                "The evidence cluster contains an unauthorized scheduled "
                "task configured to execute a PowerShell script at user "
                "logon, with endpoint telemetry confirming execution."
            ),
        )

    # 20. Generic unauthorized activity
    if signals.unauthorized_activity:
        return ClusterAssessment(
            outcome="suspicious",
            classification="unauthorized_activity",
            confidence="high",
            next_step="investigate",
            rationale=(
                "The evidence cluster contains activity that is "
                "explicitly marked as unauthorized."
            ),
        )

    # 21. Benign authentication - authentication context with trusted indicators
    if signals.benign_context and signals.authentication_activity:
        return ClusterAssessment(
            outcome="benign",
            classification="benign_authentication",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "Multiple trusted contextual indicators support legitimate activity."
            ),
        )

    # 22. Generic benign context
    if signals.benign_context:
        return ClusterAssessment(
            outcome="benign",
            classification="benign_activity",
            confidence="high",
            next_step="continue_monitoring",
            rationale=(
                "Multiple trusted contextual indicators support legitimate activity."
            ),
        )

    # 23. Fallback
    return ClusterAssessment(
        outcome="insufficient_evidence",
        classification="unresolved_activity",
        confidence="low",
        next_step="collect_telemetry",
        rationale=(
            "The available cluster signals do not establish "
            "a specific attack pattern."
        ),
    )