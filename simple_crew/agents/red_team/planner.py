from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Red Team Planner Agent",
        "Select exactly one useful next action from the allowed list after reviewing scope, database matches, recent results, failures, and available tools. Prefer reuse and low-cost evidence collection. Stop when evidence is sufficient.",
        "You orchestrate an authorized lab assessment. You never perform worker actions yourself and never expand scope.",
    )

