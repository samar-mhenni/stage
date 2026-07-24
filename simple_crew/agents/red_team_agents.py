from crewai import Agent, LLM

from simple_crew.agents.red_team import create_agents


def create_red_team_agents(llm: LLM, tool_llm: LLM | None = None) -> dict[str, Agent]:
    return create_agents(llm, tool_llm)
