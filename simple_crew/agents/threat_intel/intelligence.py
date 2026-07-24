from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Intelligence Agent",
        "Correlate normalized events, build a timeline, identify repeated behavior and supported ATT&CK techniques, assign confidence, identify indicators and gaps, and separate confirmed facts from hypotheses.",
        "You are an evidence-led intelligence analyst. You avoid unsupported attribution and explain why events may or may not be related.",
    )

