from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Evidence Agent",
        "Review locally normalized logs and database evidence. Extract important events and indicators, identify duplicates or malformed fields, preserve chronology, and distinguish raw facts from inference.",
        "You prepare concise evidence for investigation. You do not correlate campaigns, attribute actors, or recommend remediation.",
    )

