# SentinelX Evaluation Plan

## 1. Problem

Security incident investigation often requires an analyst to correlate events across
authentication, network, endpoint, process, and privilege telemetry.

The goal of SentinelX is to investigate these events and produce an evidence-backed
assessment that helps a security analyst determine:

- whether an incident is occurring;
- what type of incident it may be;
- which observations support the conclusion;
- what uncertainty remains; and
- what should be investigated next.

SentinelX does not autonomously execute consequential security actions.

---

## 2. Intended User

The intended user is a SOC/security analyst investigating a security alert or
collection of related security events.

---

## 3. Core Bottleneck

The primary bottleneck is cross-event reasoning.

Individual security events can be ambiguous or benign in isolation. A useful
investigation system must distinguish isolated anomalies from meaningful patterns
while avoiding unsupported conclusions.

---

## 4. Baseline

The baseline will be a single general-purpose language-model agent.

The baseline receives the same incident case presented to SentinelX and is asked to:

1. determine whether the case represents a security incident;
2. identify the incident category;
3. identify supporting evidence;
4. state its confidence; and
5. recommend the next investigation step.

The baseline will not have the specialized investigation workflow used by SentinelX.

---

## 5. SentinelX

SentinelX will use an agentic investigation workflow designed around observed
baseline failure modes.

Potential capabilities include:

- incident triage;
- event/context analysis;
- cross-event correlation;
- evidence verification;
- structured investigation reporting.

Components will only be added when an evaluation demonstrates a specific limitation
that the component is intended to address.

---

## 6. Evaluation Dataset

The initial evaluation set will contain 15 fixed incident cases.

The dataset will contain a mixture of:

- benign activity;
- suspicious but inconclusive activity;
- confirmed incidents;
- ambiguous cases;
- multi-stage incidents; and
- adversarial or misleading cases.

The ground truth for every case will be established before running the baseline
or SentinelX.

The same cases will be used for both systems.

---

## 7. Case Design Principles

Cases should test reasoning rather than simple keyword matching.

Cases should include situations where:

- a single event appears malicious but is benign in context;
- several individually weak signals combine into a meaningful incident;
- telemetry sources disagree;
- important evidence is missing;
- legitimate administrative activity resembles an attack;
- multiple stages of an attack must be correlated;
- the correct conclusion is uncertainty rather than a definitive classification.

Each case should have a documented failure mode that it is capable of exposing.

---

## 8. Ground Truth

Each case will define:

- expected incident determination;
- expected incident category;
- required supporting evidence;
- evidence that should not be treated as sufficient by itself;
- expected confidence/uncertainty;
- appropriate next investigation step.

Ground truth will be created independently of model outputs.

---

## 9. Primary Metric

Primary metric:

**Evidence-Supported Investigation Accuracy**

Each case will receive a predefined score based on whether the system:

1. correctly determines the incident status;
2. correctly identifies the incident category;
3. identifies the key supporting evidence; and
4. avoids unsupported conclusions.

The scoring criteria will be fixed before model evaluation.

---

## 10. Secondary Metrics

Additional measurements will include:

- false-positive rate;
- unsupported-claim rate;
- evidence completeness;
- investigation runtime;
- approximate cost per investigation.

---

## 11. Evaluation Protocol

For every case:

1. Present the case to the baseline.
2. Record the complete baseline output.
3. Score the baseline using the predefined rubric.
4. Present the identical case to SentinelX.
5. Record the complete SentinelX output and agent trajectory.
6. Score SentinelX using the same rubric.
7. Compare results.

No evaluation case will be removed because a system performs poorly on it.

---

## 12. Improvement Strategy

SentinelX will be developed iteratively.

Each meaningful iteration must document:

1. observed baseline or system failure;
2. hypothesis about the cause;
3. engineering change;
4. evaluation result;
5. decision to keep, modify, or remove the change.

The final system should demonstrate a measurable improvement over the baseline.

---

## 13. Success Criterion

SentinelX should demonstrate a meaningful improvement in evidence-supported
investigation accuracy over the baseline while maintaining acceptable runtime,
cost, and reliability.

Success must be demonstrated using recorded evaluation results rather than
subjective claims.

---

## 14. Safety Boundary

SentinelX is an investigation and decision-support system.

It will not autonomously:

- disable accounts;
- terminate processes;
- isolate endpoints;
- modify firewall rules;
- delete data; or
- perform other consequential security actions.

Recommended actions remain subject to human analyst review.

---

## 15. Reproducibility

A clean environment should be able to:

1. install the required dependencies;
2. load the evaluation cases;
3. execute the baseline;
4. execute SentinelX;
5. run the scoring process; and
6. reproduce the reported comparison.

All important dependencies, commands, configurations, and evaluation assumptions
are be documented.