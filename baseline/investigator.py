from sentinelx.models import (
    Confidence,
    InvestigationCase,
    InvestigationResult,
    NextStep,
    Outcome,
)


SUSPICIOUS_ACTIONS = {
    "failed_login",
    "account_locked",
    "privilege_escalation",
    "process_execution",
    "suspicious_process",
    "malware_detected",
    "lateral_movement",
    "scheduled_task_created",
    "credential_use",
}


SUSPICIOUS_PROCESS_TERMS = {
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "mshta",
}


def investigate(case: InvestigationCase) -> InvestigationResult:
    """
    Baseline security investigator.

    The baseline evaluates individual events using simple heuristics.
    It intentionally does not perform sophisticated cross-event correlation.
    """

    suspicious_events = []

    for event in case.events:
        action = event.action.lower()

        process_name = (event.process_name or "").lower()
        command_line = (event.command_line or "").lower()

        suspicious = (
            event.severity.value in {"high", "critical"}
            or action in SUSPICIOUS_ACTIONS
            or any(
                term in process_name
                for term in SUSPICIOUS_PROCESS_TERMS
            )
            or any(
                term in command_line
                for term in SUSPICIOUS_PROCESS_TERMS
            )
        )

        if suspicious:
            suspicious_events.append(event)

    if not suspicious_events:
        return InvestigationResult(
            case_id=case.case_id,
            outcome=Outcome.BENIGN,
            category="benign_activity",
            confidence=Confidence.HIGH,
            evidence_event_ids=[
                event.event_id for event in case.events
            ],
            reasoning=(
                "No individual event contained a strong suspicious "
                "indicator. The available telemetry is consistent "
                "with routine activity."
            ),
            next_step=NextStep.CONTINUE_MONITORING,
        )

    evidence_ids = [
        event.event_id for event in suspicious_events
    ]

    confidence = (
        Confidence.MEDIUM
        if len(suspicious_events) == 1
        else Confidence.HIGH
    )

    return InvestigationResult(
        case_id=case.case_id,
        outcome=Outcome.SUSPICIOUS,
        category="suspicious_activity",
        confidence=confidence,
        evidence_event_ids=evidence_ids,
        reasoning=(
            f"The case contains {len(suspicious_events)} event(s) "
            "with individually suspicious characteristics. "
            "Additional investigation is recommended."
        ),
        next_step=NextStep.INVESTIGATE,
    )