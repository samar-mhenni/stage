from typing import Dict, Callable
from crewai import Agent
from config.logging import logger

class AgentRegistry:
    """Central registry to manage and instantiate agents dynamically."""
    
    _registry: Dict[str, Callable[[], Agent]] = {}

    @classmethod
    def register(cls, name: str):
        """Decorator to register an agent creation function."""
        def wrapper(func: Callable[[], Agent]):
            if name in cls._registry:
                logger.warning(f"Overwriting registered agent: {name}")
            cls._registry[name] = func
            logger.debug(f"Registered agent: {name}")
            return func
        return wrapper

    @classmethod
    def get_agent(cls, name: str) -> Agent:
        """Retrieve and instantiate an agent by name."""
        if name not in cls._registry:
            raise ValueError(f"Agent '{name}' not found in registry.")
        
        logger.info(f"Instantiating agent: {name}")
        return cls._registry[name]()

    @classmethod
    def get_all_agent_names(cls) -> list[str]:
        return list(cls._registry.keys())

# Example registration for future agents:
# @AgentRegistry.register("campaign_orchestrator")
# def create_orchestrator():
#     return BaseAgentFactory.create(role="Orchestrator", goal="...", backstory="...")
