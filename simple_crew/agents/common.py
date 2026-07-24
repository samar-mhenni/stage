from crewai import Agent, LLM


def build_agent(llm: LLM, role: str, goal: str, backstory: str) -> Agent:
    return Agent(
        role=role,
        goal=goal,
        backstory=backstory,
        llm=llm,
        allow_delegation=False,
        verbose=False,
    )

