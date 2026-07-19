import os

from crewai import Agent, LLM
from crewai.agents.crew_agent_executor import CrewAgentExecutor

from config.settings import settings


def get_default_llm(max_tokens: int | None = None, provider_override: str | None = None):
    """Return the configured LLM for all agents using standard CrewAI patterns."""
    provider = (provider_override or settings.LLM_PROVIDER).lower()
    max_tokens = max_tokens or settings.LLM_MAX_TOKENS
    if provider == "groq":
        if os.getenv("OPENAI_API_KEY", "").startswith(("sk-or-v1", "gsk_")):
            os.environ.pop("OPENAI_API_KEY", None)
        os.environ["GROQ_API_KEY"] = settings.GROQ_API_KEY
        return LLM(
            model=settings.GROQ_MODEL,
            provider="openai",
            api_key=settings.GROQ_API_KEY,
            base_url=settings.GROQ_BASE_URL,
            temperature=0.1,
            max_tokens=max_tokens,
        )

    if os.getenv("OPENAI_API_KEY", "").startswith("sk-or-v1"):
        os.environ.pop("OPENAI_API_KEY", None)
    os.environ["OPENROUTER_API_KEY"] = settings.OPENROUTER_API_KEY
    
    if "gpt-oss" in settings.QWEN_MODEL and max_tokens < 1200:
        max_tokens = 1200

    return LLM(
        model=f"openrouter/{settings.QWEN_MODEL}",
        api_key=settings.OPENROUTER_API_KEY,
        base_url=settings.OPENROUTER_BASE_URL,
        temperature=0.1,
        max_tokens=max_tokens,
    )


class BaseAgentFactory:
    """Base factory to ensure all agents are built consistently."""

    @classmethod
    def create(cls, **kwargs) -> Agent:
        """Create an agent with default configurations (LLM, verbosity)."""
        llm_max_tokens = kwargs.pop("llm_max_tokens", settings.LLM_MAX_TOKENS)
        llm = kwargs.pop("llm", get_default_llm(llm_max_tokens))
        verbose = kwargs.pop("verbose", settings.DEBUG_MODE)

        return Agent(
            llm=llm,
            verbose=verbose,
            executor_class=CrewAgentExecutor,
            **kwargs,
        )
