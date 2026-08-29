# SentinelX Reproduction Guide

## 1. Requirements

SentinelX requires:

- Python 3.13+
- Git
- An OpenAI API key for the LLM-powered agent
- Windows, Linux, or macOS

The deterministic SentinelX investigation pipeline does not require an external LLM API. The API is required only for the agent layer.

## 2. Clone the Repository

Clone the SentinelX repository and enter the project directory.

```bash
git clone <REPOSITORY_URL>
cd SentinelX

Replace <REPOSITORY_URL> with the repository URL used for the final submission.

3. Create a Virtual Environment

Create a Python virtual environment:

python -m venv .venv

Activate it on Windows PowerShell:

.\.venv\Scripts\Activate.ps1

On Linux or macOS:

source .venv/bin/activate
4. Install Dependencies

Install the required Python packages:

pip install -r requirements.txt

The deterministic investigation pipeline uses Pydantic for structured data validation.

The agent layer additionally requires the OpenAI Python SDK.

5. Configure the LLM API

The SentinelX agent uses an environment variable for the API key.

Windows PowerShell:

$env:OPENAI_API_KEY="YOUR_API_KEY"

Linux/macOS:

export OPENAI_API_KEY="YOUR_API_KEY"

The API key must not be committed to the repository.

6. Verify the Deterministic System

Run the complete automated test suite:

python -m pytest

The current implementation passes:

41 passed
7. Run the SentinelX Evaluation

Run the fixed 15-case evaluation:

python -m evaluation.run_sentinelx

The current validated result is:

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

The evaluation uses the fixed cases in:

data/cases/

and the corresponding ground truth in:

data/ground_truth/
8. Run the Baseline

The simple heuristic baseline can be reproduced with:

python -m baseline.run_baseline

The baseline evaluates individual events using simple suspicious-event heuristics rather than the SentinelX correlation and investigation workflow.

The current baseline scores are:

C01: 85.0/100
C02: 25.0/100
C03: 85.0/100
C04: 65.0/100
C05: 85.0/100
C06: 20.0/100
C07: 40.0/100
C08: 40.0/100
C09: 50.0/100
C10: 50.0/100
C11: 50.0/100
C12: 50.0/100
C13: 50.0/100
C14: 40.0/100
C15: 40.0/100

Average: 48.3/100
9. Run the LLM-Powered Agent

After configuring OPENAI_API_KEY, run:

python -m evaluation.run_agent

The agent performs an investigation using specialized SentinelX tools.

The current workflow includes:

case inspection;
evidence correlation;
signal derivation;
deterministic assessment;
LLM-generated structured reasoning; and
independent verification.
10. Agent Trajectories

Agent investigations produce JSON traces in:

traces/

Representative validated traces include:

traces/
├── C09_agent.json
├── C12_agent.json
├── C14_agent.json
└── C15_agent.json

Each trajectory records the observable tool-assisted investigation process, including tool calls, tool results, the final model output, and verification.

These traces are part of the reproducibility and evaluation evidence.

11. Example Agent Execution

A representative investigation can be executed with:

python -c "from sentinelx.agent.investigator import investigate_with_agent; print(investigate_with_agent('C12'))"

A successful verified result contains:

Outcome: confirmed_incident
Classification: phishing_account_takeover
Confidence: high
Next step: contain
Agent verified: True

The corresponding trajectory is written to:

traces/C12_agent.json
12. Verification

The SentinelX agent does not independently determine the authoritative security classification.

The LLM proposes a structured result based on the evidence it receives.

The deterministic SentinelX assessment is then used as the authoritative reference.

The verification layer checks the proposed result against that authoritative assessment.

This prevents the language model from overriding deterministic security logic.

13. Reproducing the Evaluation

A complete reproduction should run:

python -m pytest
python -m baseline.run_baseline
python -m evaluation.run_sentinelx
python -m evaluation.run_agent

The first three commands reproduce the deterministic tests, baseline comparison, and fixed SentinelX evaluation.

The final command demonstrates the LLM-powered investigation agent and generates an agent trajectory trace.

14. Expected Results

The current validated results are:

Measurement	Result
Automated tests	41/41
Evaluation cases	15/15
SentinelX average	100.0/100
Baseline average	48.3/100
Improvement	+51.7 points

The agent layer additionally produces independently verified investigation trajectories.

15. Security and Safety

Never commit API keys or other credentials to the repository.

SentinelX is a decision-support and investigation system.

It does not autonomously:

disable accounts;
terminate processes;
isolate endpoints;
modify firewall rules;
delete data; or
execute other consequential security actions.

Recommended actions such as contain remain recommendations for human analyst review.

16. Project Structure

The primary project components are:

SentinelX/
├── baseline/
├── data/
│   ├── cases/
│   └── ground_truth/
├── docs/
├── evaluation/
├── sentinelx/
│   ├── agent/
│   ├── correlation/
│   └── investigation/
├── tests/
└── traces/

The architecture, evaluation methodology, source code, tests, and agent trajectories are maintained as separate reproducible project artifacts.