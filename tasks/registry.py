from typing import Dict, Callable
from crewai import Task
from config.logging import logger

class TaskRegistry:
    """Central registry to manage and instantiate tasks dynamically."""
    
    _registry: Dict[str, Callable[..., Task]] = {}

    @classmethod
    def register(cls, name: str):
        """Decorator to register a task creation function."""
        def wrapper(func: Callable[..., Task]):
            if name in cls._registry:
                logger.warning(f"Overwriting registered task: {name}")
            cls._registry[name] = func
            logger.debug(f"Registered task: {name}")
            return func
        return wrapper

    @classmethod
    def get_task(cls, name: str, **kwargs) -> Task:
        """Retrieve and instantiate a task by name, injecting any runtime context kwargs."""
        if name not in cls._registry:
            raise ValueError(f"Task '{name}' not found in registry.")
        
        logger.info(f"Instantiating task: {name}")
        return cls._registry[name](**kwargs)
