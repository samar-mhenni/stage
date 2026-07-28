from crewai import Agent, LLM

from simple_crew.agents.common import build_agent


def create_agent(llm: LLM) -> Agent:
    return build_agent(
        llm,
        "Web Authorization Testing Agent",
        (
            "Convert supplied authorized HTTP API context into one complete test-case matrix for "
            "reconnaissance, object authorization, function authorization, role escalation, and "
            "reversible writes. Distinguish identity values from URL resource identifiers."
        ),
        (
            "You design bounded tests only for the explicitly supplied target and documented "
            "endpoints. You never invent endpoints or secrets, and never claim execution."
        ),
    )
