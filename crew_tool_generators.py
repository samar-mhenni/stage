import argparse

import agents.tool_generators  # noqa: F401 - registers standalone generator agents
from agents.execution import run_agent_task
from crewai import Task


TOOL_GENERATOR_AGENTS = {
    "red-team-search": {
        "agent": "red_team_search_tool_generator_agent",
        "capability": (
            "Generate a CrewAI BaseTool named RedTeamSearchTool. It must call "
            "red_team_database_search(query) and must not run target commands."
        ),
    },
    "threat-intel-search": {
        "agent": "threat_intel_search_tool_generator_agent",
        "capability": (
            "Generate a CrewAI BaseTool named ThreatIntelSearchTool. It must call "
            "threat_intel_database_search(query) and return source-aware enrichment."
        ),
    },
    "hash-cracking": {
        "agent": "hash_cracking_tool_generator_agent",
        "capability": (
            "Generate a CrewAI BaseTool named JohnTheRipperHashCrackTool. It must run "
            "local john only, accept format/wordlist/timeout options, and use temporary files."
        ),
    },
}


def build_generation_task(kind: str, extra_requirements: str) -> Task:
    spec = TOOL_GENERATOR_AGENTS[kind]
    return Task(
        description=(
            "Generate reviewable Python code for this tool capability. Return only one "
            "compact JSON object with keys: agent, tool_name, purpose, safety, code.\n\n"
            f"Capability:\n{spec['capability']}\n\n"
            f"Extra requirements:\n{extra_requirements or 'None.'}\n\n"
            "The code must be self-contained except for existing project imports from tools.py "
            "and generated_tool_runtime.py. "
            "Do not modify pipelines, do not execute the generated code, and do not include markdown."
        ),
        expected_output="A compact JSON object containing generated CrewAI BaseTool code.",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run standalone agents that generate CrewAI tool code.")
    parser.add_argument("kind", choices=sorted(TOOL_GENERATOR_AGENTS))
    parser.add_argument("--requirements", default="", help="Optional extra requirements for the generated tool.")
    args = parser.parse_args()

    task = build_generation_task(args.kind, args.requirements)
    print(run_agent_task(TOOL_GENERATOR_AGENTS[args.kind]["agent"], task))


if __name__ == "__main__":
    main()
