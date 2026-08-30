\# SentinelX


## Solution Video

[Watch the SentinelX Solution Demo on Loom](https://www.loom.com/share/4a78f241d5d24dec968648dc0703a8b9)



\## Evidence-Driven Security Investigation Agent



SentinelX is an agentic security investigation system designed to help SOC and

security analysts investigate related security events across authentication,

network, endpoint, process, and privilege telemetry.



Instead of treating security alerts as isolated events, SentinelX correlates

related evidence, derives security signals, evaluates the resulting evidence

cluster, and produces a structured investigation assessment.



The LLM acts as the investigation and orchestration layer, while deterministic

SentinelX analysis and independent verification provide the authoritative

security decision.



\---



\## The Problem



Security telemetry is often fragmented across multiple sources.



A single event may look suspicious while being completely legitimate in context.

Conversely, several individually weak events can form a meaningful attack when

their relationships and timing are considered together.



Examples include:



\- impossible-travel alerts explained by corporate VPN infrastructure;

\- malicious PowerShell execution followed by suspicious network activity;

\- sequential remote authentication across multiple internal hosts;

\- phishing followed by credential use and account takeover; and

\- suspicious authentication where endpoint telemetry is unavailable.



The core challenge is therefore not simply detecting suspicious events.



It is \*\*reasoning across related evidence while preserving uncertainty\*\*.



\---



\## SentinelX Approach



SentinelX uses a layered investigation architecture:



```text

Security Case

&#x20;    |

&#x20;    v

+----------------------+

|      LLM Agent       |

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



The LLM does not receive unrestricted authority to make security decisions.



Instead, it uses specialized investigation tools to inspect and reason about

the evidence. The deterministic SentinelX assessment remains authoritative.



Agent Workflow



The SentinelX investigation agent follows a structured workflow:



Inspect the case

Correlate related evidence

Derive security signals

Obtain the deterministic assessment

Generate structured reasoning

Verify the proposed result

Record the investigation trajectory



The specialized tools include:



inspect\_case

correlate\_evidence

derive\_case\_signals

assess\_case\_cluster



This creates an observable agent trajectory rather than a single opaque

LLM response.



Evidence Correlation



SentinelX builds relationships between events using available context such as:



user identity;

host relationships;

source and destination information;

event type;

temporal proximity;

process relationships;

network relationships; and

event-specific security context.



Related events are grouped into evidence clusters.



For example:



Phishing Email

&#x20;     |

&#x20;     v

User Interaction

&#x20;     |

&#x20;     v

Credential Use

&#x20;     |

&#x20;     v

Account Takeover



The system can therefore reason about an attack sequence rather than evaluating

each event independently.



Deterministic Security Analysis



After evidence is correlated, SentinelX derives structured security signals.



Examples include:



multi\_host

multi\_stage

rapid\_sequence

privilege\_activity

authentication\_activity

network\_activity

unauthorized\_activity

telemetry\_gap

legitimate\_explanation

credential\_compromise\_pattern

phishing\_account\_takeover\_pattern

malicious\_powershell\_execution

lateral\_movement\_pattern



The deterministic assessment converts these signals into an authoritative

investigation result.



Possible outcomes include:



benign

suspicious

confirmed\_incident

insufficient\_evidence

Evidence-Grounded Uncertainty



SentinelX does not force a definitive classification when the available

telemetry is insufficient.



For example, a suspicious authentication sequence followed by a telemetry gap

may result in:



Outcome: insufficient\_evidence

Confidence: low

Next step: collect\_telemetry



This is intentional.



The absence of telemetry is not treated as proof that malicious activity did

not occur.



LLM Verification



The LLM proposes a structured investigation result, but the result is checked

against the authoritative SentinelX assessment.



Verification checks:



outcome;

classification;

confidence;

next step; and

cited evidence event IDs.



A proposal that conflicts with the authoritative assessment is not accepted as

a verified result.



This provides a safety boundary between model-generated reasoning and the

security decision.



Agent Trajectories



Each agent investigation can produce a JSON trajectory containing observable

steps such as:



tool calls;

tool results;

evidence correlation;

derived signals;

deterministic assessment;

final model output; and

verification.



Representative validated traces are included under:



traces/

├── C09\_agent.json

├── C12\_agent.json

├── C14\_agent.json

└── C15\_agent.json



These traces provide evidence of the agent's tool-assisted investigation

process.



Evaluation



SentinelX was evaluated against a fixed set of 15 security investigation cases.



The evaluation uses the same cases and scoring methodology across systems.



Baseline



A simple event-level heuristic baseline evaluates individual events using

characteristics such as:



event severity;

suspicious actions;

suspicious process names; and

suspicious command-line terms.



The baseline does not perform the specialized SentinelX evidence correlation

workflow.



Results

System	Average Score

Simple heuristic baseline	48.3/100

SentinelX	100.0/100



Measured improvement:



+51.7 percentage points



Relative improvement:



approximately 106.9%



SentinelX achieved:



15/15 evaluation cases

100.0/100 average score



The automated test suite also passes:



41/41 tests

Representative Investigation Cases

C09 — Malicious PowerShell Execution



SentinelX correlates:



Encoded PowerShell

&#x20;     +

Document-spawned process

&#x20;     +

Malicious network destination

&#x20;     +

Explicit process-network relationship



Result:



Outcome: confirmed\_incident

Classification: malicious\_powershell\_execution

Confidence: high

Next step: contain

C10 — Lateral Movement



SentinelX correlates remote authentication and network activity across

multiple internal hosts and connects the sequence to unauthorized privileged

activity.



Result:



Outcome: confirmed\_incident

Classification: lateral\_movement

Confidence: high

Next step: contain

C12 — Phishing Account Takeover



SentinelX correlates:



Phishing delivery

&#x20;     |

&#x20;     v

User interaction

&#x20;     |

&#x20;     v

Credential use from unknown source

&#x20;     |

&#x20;     v

Unauthorized account takeover



Result:



Outcome: confirmed\_incident

Classification: phishing\_account\_takeover

Confidence: high

Next step: contain

C14 — Incomplete Evidence



SentinelX recognizes suspicious authentication activity but also recognizes

that endpoint telemetry is unavailable.



Result:



Outcome: insufficient\_evidence

Classification: potential\_credential\_compromise

Confidence: low

Next step: collect\_telemetry

C15 — Legitimate Context With Unresolved Activity



SentinelX recognizes legitimate VPN context while refusing to dismiss a

separate unresolved outbound connection.



Result:



Outcome: insufficient\_evidence

Classification: unresolved\_authentication\_anomaly

Confidence: low

Next step: collect\_telemetry

Safety Boundary



SentinelX is an investigation and decision-support system.



It does not autonomously:



disable accounts;

terminate processes;

isolate endpoints;

modify firewall rules;

delete data; or

execute other consequential security actions.



Recommendations such as contain remain subject to human analyst review.



Project Structure

SentinelX/

├── baseline/

│   ├── investigator.py

│   ├── run\_baseline.py

│   └── scorer.py

│

├── data/

│   ├── cases/

│   ├── ground\_truth/

│   └── case\_matrix.json

│

├── docs/

│   ├── architecture.md

│   ├── EVALUATION\_PLAN.md

│   ├── improvement\_changelog.md

│   └── reproduction.md

│

├── evaluation/

│   ├── loader.py

│   ├── run\_baseline.py

│   ├── run\_sentinelx.py

│   ├── run\_agent.py

│   └── scorer.py

│

├── sentinelx/

│   ├── agent/

│   ├── correlation/

│   ├── investigation/

│   └── models.py

│

├── tests/

│

└── traces/

Reproduction

1\. Install dependencies

pip install -r requirements.txt

2\. Run the tests

python -m pytest



Expected:



41 passed

3\. Run the baseline

python -m baseline.run\_baseline



Expected average:



48.3/100

4\. Run SentinelX

python -m evaluation.run\_sentinelx



Expected:



Average: 100.0

5\. Configure the LLM agent



Set:



OPENAI\_API\_KEY



Do not commit API keys to the repository.



6\. Run the agent

python -m evaluation.run\_agent



The agent generates an investigation result and trajectory trace.



Documentation



Additional documentation:



docs/architecture.md — system architecture and design principles

docs/EVALUATION\_PLAN.md — evaluation methodology and measured results

docs/reproduction.md — reproduction instructions

docs/improvement\_changelog.md — development and improvement history

Design Philosophy



SentinelX is built around a simple principle:



Correlate evidence before making conclusions.



The system combines:



agentic investigation;

deterministic security analysis;

evidence correlation;

explicit uncertainty;

independent verification;

reproducible evaluation; and

human-controlled response.



The objective is not to replace a security analyst.



The objective is to give the analyst a more evidence-grounded investigation

starting point.

## Improvement Changelog

SentinelX was developed iteratively by identifying specific investigation
failure modes and adding targeted engineering improvements.

| Baseline Failure | Engineering Change | Evaluation Evidence | Result |
|---|---|---|---|
| Events were evaluated largely in isolation | Added evidence graph and event clustering | 15-case evaluation | Cross-event relationships became available to the investigation workflow |
| Suspicious activity could be misinterpreted without context | Added contextual and uncertainty-aware security signals | C01-C08 evaluation cases | Improved contextual classification |
| Process and network evidence could be analyzed independently | Added process-network correlation | C09 | Correctly identified malicious PowerShell execution |
| Multi-host activity could be treated as isolated authentication events | Added host-sequence and multi-host correlation | C10 | Correctly identified lateral movement |
| Phishing, credential use, and takeover activity could be treated independently | Added temporal phishing/account-takeover correlation | C12 | Correctly identified phishing-driven account takeover |
| Missing endpoint telemetry could encourage unsupported conclusions | Added telemetry-gap and insufficient-evidence handling | C14 | Preserved uncertainty and requested additional telemetry |
| Legitimate VPN context could be confused with malicious authentication | Added contextual interpretation of legitimate activity | C15 | Preserved legitimate context while keeping unresolved activity visible |
| An LLM could produce an unsupported security decision | Added specialized investigation tools, deterministic assessment, and independent verification | Agent trajectories C09/C12/C14/C15 | Agent proposals are checked against authoritative SentinelX assessments |

### Measured Progress

The final evaluation uses the same fixed 15 cases and scoring methodology as the
baseline comparison.

```text
Baseline:  48.3/100
SentinelX: 100.0/100
Improvement: +51.7 percentage points

The deterministic SentinelX system achieved 100.0/100 across all 15 evaluation
cases, while the simple event-level baseline achieved 48.3/100.

Main Failure Mode

The dominant failure mode was treating security events as isolated observations
instead of reasoning over their relationships, sequence, context, and missing
telemetry.

The improvement came from making those relationships explicit through evidence
correlation, clustering, specialized signals, deterministic assessment, and
verification.

Hot Take

LLMs are most useful in security investigation when they are constrained by
deterministic tools, structured evidence, schema enforcement, and independent
verification. The model should help reason over evidence—not invent the
security decision.







