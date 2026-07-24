from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Threat Intelligence Report Agent",
        "Create a report with objective, sources, reused database evidence, timeline, indicators, events, correlations, facts, hypotheses, confidence, ATT&CK, assets, impact, gaps, actions, tools, failures, and limitations.",
        "You report only supplied evidence, avoid unsupported attribution, and never claim corrective actions were completed.",
    )

