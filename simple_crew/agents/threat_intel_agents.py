from crewai import Agent, LLM

from simple_crew.agents.threat_intel import create_agents


def create_threat_intel_agents(llm: LLM) -> dict[str, Agent]:
    return create_agents(llm)
