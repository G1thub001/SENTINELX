import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openai import OpenAI

from sentinelx.agent.prompts import SYSTEM_PROMPT
from sentinelx.agent.tools import (
    assess_case_cluster,
    correlate_evidence,
    derive_case_signals,
    inspect_case,
    load_case,
)
from sentinelx.agent.verifier import verify_result


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRACE_DIR = PROJECT_ROOT / "traces"

MODEL_NAME = os.getenv("MODEL_NAME", "gpt-5.6-luna")

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
)


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "name": "inspect_case",
        "description": (
            "Inspect a security investigation case and return a compact "
            "inventory of its telemetry events."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "correlate_evidence",
        "description": (
            "Build the SentinelX evidence graph and identify correlated "
            "evidence clusters."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "derive_case_signals",
        "description": (
            "Derive security signals from a correlated evidence cluster. "
            "Use cluster_index to select the cluster."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cluster_index": {
                    "type": "integer",
                    "description": "Zero-based evidence cluster index.",
                }
            },
            "required": ["cluster_index"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "assess_case_cluster",
        "description": (
            "Run the authoritative deterministic SentinelX assessment "
            "for a correlated evidence cluster."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cluster_index": {
                    "type": "integer",
                    "description": "Zero-based evidence cluster index.",
                }
            },
            "required": ["cluster_index"],
            "additionalProperties": False,
        },
    },
]


def _tool_call(
    name: str,
    arguments: dict[str, Any],
    case: Any,
) -> dict[str, Any]:
    """Execute one approved SentinelX agent tool."""

    if name == "inspect_case":
        return inspect_case(case)

    if name == "correlate_evidence":
        return correlate_evidence(case)

    if name == "derive_case_signals":
        return derive_case_signals(
            case,
            cluster_index=arguments["cluster_index"],
        )

    if name == "assess_case_cluster":
        return assess_case_cluster(
            case,
            cluster_index=arguments["cluster_index"],
        )

    raise ValueError(f"Unknown tool requested: {name}")


def _save_trace(case_id: str, trace: dict[str, Any]) -> Path:
    """Persist an agent trajectory for hackathon evaluation."""

    TRACE_DIR.mkdir(parents=True, exist_ok=True)

    path = TRACE_DIR / f"{case_id}_agent.json"

    path.write_text(
        json.dumps(trace, indent=2, default=str),
        encoding="utf-8",
    )

    return path


def investigate_with_agent(
    case_id: str,
    max_steps: int = 8,
) -> dict[str, Any]:
    """
    Run the SentinelX LLM investigation agent.

    The LLM orchestrates investigation tools, while the deterministic
    SentinelX assessment remains authoritative.
    """

    case = load_case(case_id)

    trace: dict[str, Any] = {
        "case_id": case_id,
        "agent": "SentinelX Security Investigation Agent",
        "model": MODEL_NAME,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "steps": [],
    }

    initial_prompt = f"""
Investigate security case {case_id}.

Use the SentinelX tools to inspect the evidence, correlate the
events, derive signals, and obtain the authoritative assessment.

Do not skip evidence gathering.

After obtaining the authoritative assessment, return a JSON object
with exactly these fields:

outcome
classification
confidence
evidence_event_ids
reasoning
next_step
"""

    response = client.responses.create(
        model=MODEL_NAME,
        instructions=SYSTEM_PROMPT,
        input=initial_prompt,
        tools=TOOL_DEFINITIONS,
    )

    for step_number in range(max_steps):
        function_calls = [
            item
            for item in response.output
            if item.type == "function_call"
        ]

        if not function_calls:
            break

        tool_outputs = []

        for call in function_calls:
            arguments = json.loads(call.arguments)

            trace["steps"].append(
                {
                    "step": step_number,
                    "type": "tool_call",
                    "tool": call.name,
                    "arguments": arguments,
                }
            )

            result = _tool_call(
                call.name,
                arguments,
                case,
            )

            trace["steps"].append(
                {
                    "step": step_number,
                    "type": "tool_result",
                    "tool": call.name,
                    "result": result,
                }
            )

            tool_outputs.append(
                {
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": json.dumps(
                        result,
                        default=str,
                    ),
                }
            )

        response = client.responses.create(
            model=MODEL_NAME,
            instructions=SYSTEM_PROMPT,
            previous_response_id=response.id,
            input=tool_outputs,
            tools=TOOL_DEFINITIONS,
        )

    final_text = response.output_text

    trace["steps"].append(
        {
            "type": "final_model_output",
            "output": final_text,
        }
    )

    try:
        proposed = json.loads(final_text)
    except json.JSONDecodeError:
        proposed = {}

    # Always obtain the deterministic assessment independently.
    authoritative = assess_case_cluster(case, cluster_index=0)

    verification = verify_result(
        proposed=proposed,
        authoritative=authoritative,
    )

    trace["verification"] = verification
    trace["finished_at"] = datetime.now(timezone.utc).isoformat()

    trace_path = _save_trace(case_id, trace)

    if verification["verified"]:
        final_result = proposed
    else:
        assessment = authoritative["assessment"]

        final_result = {
            "outcome": assessment["outcome"],
            "classification": assessment["classification"],
            "confidence": assessment["confidence"],
            "evidence_event_ids": authoritative["event_ids"],
            "reasoning": assessment["rationale"],
            "next_step": assessment["next_step"],
        }

    final_result["case_id"] = case_id
    final_result["agent_verified"] = verification["verified"]
    final_result["trace_path"] = str(trace_path)

    return final_result