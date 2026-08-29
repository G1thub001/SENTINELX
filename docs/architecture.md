\# SentinelX Architecture



\## 1. Overview



SentinelX is an evidence-driven security investigation system that combines

deterministic security analysis with an LLM-powered investigation agent.



The system is designed for SOC and security analysts who need to interpret

related authentication, network, endpoint, process, and privilege telemetry.



The central design principle is:



> The language model may orchestrate investigation, but the evidence and

> deterministic SentinelX assessment remain authoritative.



This prevents the LLM from independently inventing security conclusions.



\---



\## 2. High-Level Architecture



```text

Security Case

&#x20;    |

&#x20;    v

+----------------------+

|    LLM Agent         |

| Investigation        |

| Orchestration        |

+----------+-----------+

&#x20;          |

&#x20;          v

+----------------------+

| Specialized Tools    |

+----------+-----------+

&#x20;          |

&#x20;          v

+----------------------+

| Evidence Graph       |

| \& Clustering         |

+----------+-----------+

&#x20;          |

&#x20;          v

+----------------------+

| Security Signals     |

+----------+-----------+

&#x20;          |

&#x20;          v

+----------------------+

| Deterministic        |

| Assessment           |

+----------+-----------+

&#x20;          |

&#x20;          v

+----------------------+

| Independent          |

| Verification         |

+----------+-----------+

&#x20;          |

&#x20;          v

&#x20;    Final Result

&#x20;          |

&#x20;          v

&#x20;     Trace JSON



3\. Core Components

3.1 Investigation Agent



The SentinelX agent is an LLM-powered security investigation agent.



The agent receives a security case and uses specialized tools to inspect and

analyze the available evidence.



The agent is instructed to:



inspect the available case evidence;

correlate related events;

derive security-relevant signals;

obtain the deterministic SentinelX assessment;

produce a structured investigation result; and

remain grounded in the available evidence.



The agent is not permitted to invent telemetry or treat missing telemetry as

proof that malicious activity did not occur.



3.2 Specialized Investigation Tools



The agent operates through purpose-built tools rather than arbitrary code

execution.



The current investigation tools are:



inspect\_case



Provides a structured view of the case, including event identifiers,

timestamps, event types, hosts, users, actions, severity, and relevant process

context.



correlate\_evidence



Builds the SentinelX evidence graph and identifies connected evidence clusters.



This allows related events to be analyzed as a sequence rather than as isolated

alerts.



derive\_case\_signals



Derives higher-level security signals from an evidence cluster.



Examples include:



multi-host activity;

multi-stage activity;

rapid temporal progression;

privilege activity;

authentication activity;

network activity;

suspicious context;

telemetry gaps;

legitimate explanations;

credential compromise patterns;

phishing account-takeover patterns;

malicious PowerShell execution; and

lateral movement patterns.

assess\_case\_cluster



Runs the deterministic SentinelX assessment against the selected evidence

cluster.



This produces the authoritative:



outcome;

classification;

confidence;

recommended next step; and

rationale.

4\. Evidence Correlation Layer



The correlation layer is the core analytical component of SentinelX.



Individual security events can be ambiguous when examined independently.



SentinelX therefore constructs relationships between events using available

context such as:



user identity;

host;

source and destination information;

event type;

temporal proximity;

process relationships;

network relationships; and

other event-specific context.



Related events are grouped into evidence clusters.



This allows the system to recognize sequences such as:



Phishing email

|

v

User interaction

|

v

Credential use

|

v

Account takeover



rather than treating each event as an unrelated alert.



5\. Signal Derivation



Once an evidence cluster has been identified, SentinelX derives structured

signals from the cluster.



These signals provide a deterministic representation of the evidence.



For example:



multi\_host = true

multi\_stage = true

rapid\_sequence = true

unauthorized\_activity = true

suspicious\_context = true



For legitimate activity, the same layer can identify contextual signals such as:



known\_context = true

authorized\_activity = true

legitimate\_explanation = true



For incomplete investigations:



telemetry\_gap = true



This separation allows the system to reason about evidence without requiring

the LLM to independently interpret raw telemetry.



6\. Deterministic Assessment Layer



The deterministic assessment layer converts derived signals into an

authoritative investigation assessment.



The assessment determines:



incident outcome;

incident classification;

confidence;

next investigation step; and

evidence-based rationale.



The deterministic layer is deliberately kept separate from the LLM.



The LLM does not get to override the authoritative SentinelX assessment.



This is particularly important for security use cases where unsupported

certainty can create operational risk.



7\. Verification Layer



Every LLM-generated investigation result is independently verified.



The verifier checks that:



required output fields are present;

the proposed outcome matches the authoritative assessment;

the proposed classification matches the authoritative assessment;

the proposed confidence matches the authoritative assessment;

the proposed next step matches the authoritative assessment; and

cited evidence event IDs belong to the authoritative evidence cluster.



If the proposal conflicts with the deterministic assessment, verification fails.



The verifier therefore acts as a safety boundary between LLM-generated reasoning

and the final structured investigation result.



8\. Uncertainty Handling



SentinelX explicitly supports uncertainty.



The system distinguishes between:



benign activity;

suspicious activity;

confirmed incidents; and

insufficient evidence.



A telemetry gap is not interpreted as evidence that an attack did not occur.



For example, C14 contains suspicious authentication activity but lacks the

endpoint telemetry required to determine what happened after authentication.



SentinelX therefore produces:



Outcome:        insufficient\_evidence

Classification: potential\_credential\_compromise

Confidence:     low

Next step:      collect\_telemetry



This behavior prevents the system from converting incomplete evidence into

unsupported certainty.



9\. Contradictory Evidence



SentinelX also handles cases where legitimate context explains part of an

observed anomaly while another observation remains unresolved.



For example, C15 contains a legitimate corporate VPN explanation for an unusual

authentication source, while a separate outbound connection remains

unexplained.



The correct behavior is therefore not to classify the entire case as benign.



SentinelX produces:



Outcome:        insufficient\_evidence

Classification: unresolved\_authentication\_anomaly

Confidence:     low

Next step:      collect\_telemetry



This demonstrates evidence reconciliation rather than simple alert matching.



10\. Agent Trajectories



Agent investigations generate JSON trajectory traces.



Each trajectory records observable investigation steps including:



case inspection;

evidence correlation;

signal derivation;

deterministic assessment;

final model output; and

verification.



Current representative traces include:



traces/

├── C09\_agent.json

├── C12\_agent.json

├── C14\_agent.json

└── C15\_agent.json



These traces provide reproducible evidence of the agent's tool-assisted

investigation workflow.



11\. Safety Boundary



SentinelX is an investigation and decision-support system.



It does not autonomously:



disable accounts;

terminate processes;

isolate endpoints;

modify firewall rules;

delete data; or

perform other consequential security actions.



Actions such as containment remain recommendations for analyst review.



For example, a confirmed incident may produce:



next\_step = contain



but SentinelX does not execute containment itself.



12\. Baseline and Improvement



A simple event-level heuristic baseline was implemented to establish a

pre-SentinelX comparison point.



The baseline evaluates events independently using characteristics such as:



event severity;

suspicious actions;

suspicious process names; and

suspicious command-line terms.



It deliberately does not perform the evidence correlation and structured

investigation performed by SentinelX.



The fixed 15-case evaluation produced:



System	Average Score

Simple heuristic baseline	48.3/100

SentinelX	100.0/100



SentinelX therefore improved the measured score by:



+51.7 percentage points



The relative improvement over the baseline is approximately:



106.9%



The comparison uses the same fixed cases and scoring methodology.



13\. Validation



The current SentinelX implementation passes:



41/41 automated tests



The fixed investigation evaluation produces:



15/15 cases

Average: 100.0/100



Representative agent trajectories have also been successfully generated for

C09, C12, C14, and C15, with successful independent verification.



14\. Design Principles



SentinelX follows several core principles:



Evidence before conclusions



Security conclusions must be grounded in observable evidence.



Correlation over isolation



Related events should be analyzed as an evidence cluster rather than as

independent alerts.



Uncertainty over hallucination



Missing telemetry should result in appropriate uncertainty rather than

invented activity.



Deterministic verification



The LLM may assist with investigation and reporting, but the deterministic

SentinelX assessment remains authoritative.



Human-controlled actions



The system recommends investigative or response actions but does not autonomously

execute consequential security operations.



Reproducibility



Important investigation results are represented through structured outputs,

tests, evaluation results, and agent trajectory traces.

