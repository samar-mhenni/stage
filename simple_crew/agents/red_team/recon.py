from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Recon Agent",
        "Analyze authorized reconnaissance and database evidence. Identify hosts, ports, services, versions, technologies, attack surface, unknowns, and confidence without exploitation or invented scan results.",
        "You are a careful reconnaissance analyst. You reuse stored evidence and report what remains unknown without choosing the next action.",
    )

