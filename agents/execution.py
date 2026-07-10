from crewai import Crew, Process

from agents.registry import AgentRegistry


def run_agent_task(agent_name: str, task) -> str:
    agent = AgentRegistry.get_agent(agent_name)
    task.agent = agent
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)
    last_error: Exception | None = None
    for _ in range(2):
        try:
            output = str(crew.kickoff() or "").strip()
            if output:
                return output
            last_error = ValueError("empty agent output")
        except ValueError as exc:
            last_error = exc
            if "Invalid response from LLM call" not in str(exc) and "empty" not in str(exc).lower():
                raise
    raise ValueError(f"{agent_name} returned no usable output after retry: {last_error}")


def run_agent_task_or_fallback(agent_name: str, task, fallback: str) -> str:
    try:
        return run_agent_task(agent_name, task)
    except ValueError as exc:
        if "no usable output" not in str(exc) and "Invalid response from LLM call" not in str(exc):
            raise
        return fallback
