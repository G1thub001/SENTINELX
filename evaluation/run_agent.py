import sys

from sentinelx.agent.investigator import investigate_with_agent


def main() -> None:
    case_id = sys.argv[1] if len(sys.argv) > 1 else "C12"

    result = investigate_with_agent(case_id)

    print()
    print("=== SentinelX Agent Result ===")
    print(f"Case:           {result['case_id']}")
    print(f"Outcome:        {result['outcome']}")
    print(f"Classification: {result['classification']}")
    print(f"Confidence:     {result['confidence']}")
    print(f"Evidence:       {result['evidence_event_ids']}")
    print(f"Next step:      {result['next_step']}")
    print(f"Verified:       {result['agent_verified']}")
    print(f"Trace:          {result['trace_path']}")
    print(f"Reasoning:      {result['reasoning']}")


if __name__ == "__main__":
    main()