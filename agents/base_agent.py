from crewai import Agent, LLM
from crewai.agents.crew_agent_executor import CrewAgentExecutor
from config.settings import settings
import os

def get_default_llm():
    """Return the configured LLM for all agents using standard CrewAI patterns."""
    # Since LiteLLM doesn't like generic OpenAI keys for OpenRouter sometimes, we ensure it uses the specific one.
    if os.getenv("OPENAI_API_KEY", "").startswith("sk-or-v1"):
        os.environ.pop("OPENAI_API_KEY", None)
    os.environ["OPENROUTER_API_KEY"] = settings.OPENROUTER_API_KEY
    
    return LLM(
        model=f"openrouter/{settings.QWEN_MODEL}",
        api_key=settings.OPENROUTER_API_KEY,
        base_url=settings.OPENROUTER_BASE_URL,
        temperature=0.1,
        max_tokens=3000
    )

class BaseAgentFactory:
    """Base factory to ensure all agents are built consistently."""
    
    @classmethod
    def create(cls, **kwargs) -> Agent:
        """Create an agent with default configurations (LLM, verbosity)."""
        llm = kwargs.pop('llm', get_default_llm())
        verbose = kwargs.pop('verbose', settings.DEBUG_MODE)
        
        return Agent(
            llm=llm,
            verbose=verbose,
            executor_class=CrewAgentExecutor,
            **kwargs
        )
