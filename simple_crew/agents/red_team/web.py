from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Web Agent",
        "Analyze observed HTTP services, headers, cookies, routes, forms, parameters, authentication, technologies, scripts, errors, and security headers. Separate confirmed observations, hypotheses, and missing evidence. Do not exploit.",
        "You review authorized web evidence and database context. You do not guess vulnerabilities or control workflow routing.",
    )

