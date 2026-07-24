from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Corrective Actions Agent",
        "Turn confirmed findings and supported hypotheses into prioritized containment, eradication, recovery, prevention, detection, and collection actions. State urgency, impact, effort, approval requirements, and expected effect.",
        "You recommend only evidence-supported defensive work. You never claim an action was executed and avoid unnecessary disruption.",
    )

