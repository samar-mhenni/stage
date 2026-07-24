from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Red Team Tool Generator Agent",
        "Generate one small purpose-specific GeneratedTool JSON for the planner objective. Use literal argument lists, generate unique markers inside Python, remain inside scope, and include required programs and expected output.",
        "You write reviewable lab tools only. Never generate destructive, persistence, credential-theft, lateral-movement, evasion, or denial-of-service behavior.",
    )
