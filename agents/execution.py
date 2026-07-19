from crewai import Crew, Process

from agents.base_agent import get_default_llm
from agents.registry import AgentRegistry
from config.settings import settings


def _is_quota_failure(exc: Exception) -> bool:
    message = str(exc).lower()
    return "error code: 402" in message or "insufficient_quota" in message or "insufficient_funds" in message


def _retry_with_groq(agent, last_error: Exception) -> bool:
    if settings.LLM_PROVIDER.lower() == "groq" or not settings.GROQ_API_KEY:
        return False
    if not _is_quota_failure(last_error):
        return False
    agent.llm = get_default_llm(provider_override="groq")
    return True


def run_bound_agent_task(agent, task) -> str:
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)
    last_error: Exception | None = None
    used_groq_fallback = False
    for _ in range(3):
        try:
            output = str(crew.kickoff() or "").strip()
            if output:
                return output
            last_error = ValueError("empty agent output")
        except ValueError as exc:
            last_error = exc
            if "Invalid response from LLM call" not in str(exc) and "empty" not in str(exc).lower():
                raise
        except Exception as exc:
            last_error = exc
            if not used_groq_fallback and _retry_with_groq(agent, exc):
                used_groq_fallback = True
                continue
            raise
    raise ValueError(f"{agent.role} returned no usable output after retry: {last_error}")


def run_agent_task(agent_name: str, task) -> str:
    agent = AgentRegistry.get_agent(agent_name)
    task.agent = agent
    return run_bound_agent_task(agent, task)


def run_agent_task_or_fallback(agent_name: str, task, fallback: str) -> str:
    try:
        return run_agent_task(agent_name, task)
    except ValueError as exc:
        message = str(exc).lower()
        fallback_markers = (
            "no usable output",
            "invalid response from llm call",
            "llm call failed",
            "model ",
            "not found",
            "insufficient credits",
            "api call failed",
            "error code: 402",
            "error code: 404",
        )
        if not any(marker in message for marker in fallback_markers):
            raise
        return fallback
