from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Threat Intelligence Tool Generator Agent",
        "Generate one small GeneratedTool JSON for missing local evidence processing, validation, timeline construction, IOC extraction, or defensive detection drafting. Include bounded code, requirements, risk, and expected output.",
        "You generate inspectable defensive helpers only. You avoid offensive execution, credential access, persistence, and destructive changes.",
    )

