\# SentinelX Evaluation Plan



\## 1. Problem



Security incident investigation often requires an analyst to correlate events

across authentication, network, endpoint, process, and privilege telemetry.



The goal of SentinelX is to investigate these events and produce an

evidence-backed assessment that helps a security analyst determine:



\- whether an incident is occurring;

\- what type of incident it may be;

\- which observations support the conclusion;

\- what uncertainty remains; and

\- what should be investigated next.



SentinelX does not autonomously execute consequential security actions.



\---



\## 2. Intended User



The intended user is a SOC or security analyst investigating a security alert

or collection of related security events.



\---



\## 3. Core Bottleneck



The primary bottleneck is cross-event reasoning.



Individual security events can be ambiguous or benign in isolation. A useful

investigation system must distinguish isolated anomalies from meaningful

patterns while avoiding unsupported conclusions.



SentinelX addresses this bottleneck by constructing evidence relationships,

grouping related events into clusters, deriving higher-level signals, and

performing structured assessment.



\---



\## 4. Baseline



A simple event-level heuristic baseline was implemented.



The baseline evaluates individual events using:



\- event severity;

\- suspicious actions;

\- suspicious process names; and

\- suspicious command-line terms.



The baseline intentionally does not perform the specialized cross-event

correlation used by SentinelX.



The baseline therefore provides a reproducible comparison point for measuring

the effect of the SentinelX investigation workflow.



\---



\## 5. SentinelX



SentinelX uses an agentic investigation workflow built around specialized

security investigation tools.



The workflow consists of:



1\. case inspection;

2\. evidence correlation;

3\. evidence clustering;

4\. signal derivation;

5\. deterministic assessment;

6\. LLM-assisted investigation and structured reasoning; and

7\. independent verification.



The LLM is used as an investigation and reasoning layer.



The deterministic SentinelX assessment remains authoritative and prevents the

LLM from overriding the evidence-based classification.



\---



\## 6. Evaluation Dataset



The evaluation set contains 15 fixed security investigation cases.



The cases include:



\- benign activity;

\- suspicious but inconclusive activity;

\- confirmed incidents;

\- ambiguous cases;

\- multi-stage incidents; and

\- cases containing misleading or incomplete context.



The same fixed cases are evaluated using the baseline and SentinelX.



Ground truth is stored independently in:



```text

data/ground\_truth/



The corresponding investigation cases are stored in:



data/cases/

7\. Case Design Principles



Cases are designed to test reasoning rather than simple keyword matching.



The dataset includes situations where:



a single event appears suspicious but is benign in context;

several individually weak signals combine into a meaningful incident;

telemetry is incomplete;

legitimate administrative or VPN activity resembles an attack;

multiple stages of an attack must be correlated;

authentication activity requires contextual interpretation;

process and network telemetry must be connected; and

the correct conclusion is uncertainty rather than unsupported certainty.



Each case contains a documented failure mode.



8\. Ground Truth



Each ground-truth case defines:



expected incident determination;

expected incident category;

required supporting evidence;

required evidence event IDs;

forbidden conclusions;

expected confidence;

expected next investigation step; and

the failure mode being evaluated.



Ground truth is created independently of model outputs.



9\. Primary Metric



The primary metric is:



Evidence-Supported Investigation Accuracy



Each case receives a predefined score based on whether the system:



correctly determines the incident status;

correctly identifies the incident category;

identifies the required supporting evidence;

reports the expected confidence;

recommends the expected next step; and

avoids unsupported conclusions.



The scoring rubric awards a maximum of 100 points per case.



10\. Secondary Metrics



Additional measurements include:



false-positive behavior;

unsupported-claim behavior;

evidence completeness;

investigation runtime;

agent verification status; and

approximate LLM cost.



These measurements provide additional context beyond the primary accuracy

score.



11\. Evaluation Protocol



For the deterministic comparison:



Present each fixed case to the baseline.

Record the baseline result.

Score the baseline using the predefined rubric.

Present the identical case to SentinelX.

Record the SentinelX result.

Score SentinelX using the same rubric.

Compare the results.



For agent investigations:



The agent receives the case.

The agent invokes specialized investigation tools.

Tool results are recorded in the trajectory.

The agent produces a structured proposal.

The proposal is compared with the authoritative deterministic assessment.

Verification status is recorded in the trajectory.



No evaluation case is removed because a system performs poorly on it.



12\. Baseline Results



The simple event-level baseline produced the following scores:



Case	Score

C01	85.0

C02	25.0

C03	85.0

C04	65.0

C05	85.0

C06	20.0

C07	40.0

C08	40.0

C09	50.0

C10	50.0

C11	50.0

C12	50.0

C13	50.0

C14	40.0

C15	40.0



The baseline average was:



48.3/100



13\. SentinelX Results



The final deterministic SentinelX evaluation produced:



C01=100.0

C02=100.0

C03=100.0

C04=100.0

C05=100.0

C06=100.0

C07=100.0

C08=100.0

C09=100.0

C10=100.0

C11=100.0

C12=100.0

C13=100.0

C14=100.0

C15=100.0



Average: 100.0



The complete automated test suite also passes:



41 passed

14\. Measured Improvement



The SentinelX score improved from:



Baseline:  48.3/100

SentinelX: 100.0/100



Absolute improvement:



+51.7 percentage points



Relative improvement over the baseline:



approximately 106.9%



The improvement demonstrates the value of moving from independent

event-level heuristics toward evidence correlation and structured investigation.



15\. Agent Trajectory Evidence



The LLM-powered investigation agent records observable investigation

trajectories.



Validated representative trajectories currently include:



traces/C09\_agent.json

traces/C12\_agent.json

traces/C14\_agent.json

traces/C15\_agent.json



The traces record:



tool calls;

tool results;

evidence correlation;

derived signals;

deterministic assessment;

final model output; and

verification.



The trajectories provide evidence that the agent uses the SentinelX

investigation workflow rather than relying solely on a direct model response.



16\. Verification Strategy



The LLM is not treated as the authoritative source of the security decision.



The deterministic SentinelX assessment provides the authoritative:



outcome;

classification;

confidence;

next step; and

evidence cluster.



The verification layer checks the LLM proposal against this assessment.



A proposal that disagrees with the authoritative assessment is not accepted

as a verified result.



This design reduces the risk of unsupported or hallucinated security

conclusions.



17\. Iterative Improvement



SentinelX was developed iteratively around observed failure modes.



Examples include:



Context blindness



A VPN-related impossible-travel signal required correlation with approved VPN

context.



Process and network correlation failure



Malicious PowerShell activity required connecting the encoded PowerShell

execution with its suspicious parent process and subsequent malicious network

activity.



Multi-host correlation failure



Lateral movement required connecting authentication and network activity across

multiple hosts and linking it to unauthorized privileged activity.



Temporal correlation failure



Phishing-driven account takeover required connecting phishing delivery, user

interaction, credential use, and subsequent takeover activity.



These failure modes informed the specialized signals and investigation logic.



18\. Uncertainty



SentinelX explicitly supports insufficient evidence.



Where telemetry is missing or contradictory, the system does not force a

definitive benign or malicious classification.



For example, C14 results in:



Outcome: insufficient\_evidence

Classification: potential\_credential\_compromise

Confidence: low

Next step: collect\_telemetry



Similarly, C15 remains unresolved because legitimate VPN context explains part

of the authentication sequence while subsequent activity remains unexplained.



19\. Safety Boundary



SentinelX is an investigation and decision-support system.



It does not autonomously:



disable accounts;

terminate processes;

isolate endpoints;

modify firewall rules;

delete data; or

execute other consequential security actions.



Recommended actions such as contain remain subject to human analyst review.



20\. Reproducibility



The deterministic evaluation can be reproduced with:



python -m pytest

python -m baseline.run\_baseline

python -m evaluation.run\_sentinelx



The LLM-powered agent can be demonstrated with:



python -m evaluation.run\_agent



An OpenAI API key is required only for the LLM-powered agent.



The project includes the evaluation cases, ground truth, scoring logic,

automated tests, source code, and representative agent trajectories required

to reproduce the reported results.

