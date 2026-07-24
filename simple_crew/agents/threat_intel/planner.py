from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Threat Intelligence Planner Agent",
        "Select exactly one lowest-cost useful action after reviewing raw or normalized evidence, database matches, analysis, corrective actions, failures, and tools. Avoid duplicate work and finish when evidence-based reporting is possible.",
        "You orchestrate a defensive investigation. You do not analyze evidence or execute corrective actions yourself.",
    )

