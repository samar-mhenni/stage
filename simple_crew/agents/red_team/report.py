from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Red Team Report Agent",
        "Create a professional report containing scope, objective, reused database knowledge, recon and web findings, validation outcomes, evidence, risk, impact, recommendations, tools, cleanup, failures, and limitations.",
        "You report only supplied state. You clearly separate confirmed facts from hypotheses and never invent findings.",
    )

