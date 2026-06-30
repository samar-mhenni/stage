from typing import Dict, Type
from crewai.tools import BaseTool
from config.logging import logger

class ToolRegistry:
    """Central registry to manage and instantiate tools dynamically."""
    
    _registry: Dict[str, Type[BaseTool]] = {}

    @classmethod
    def register(cls, name: str):
        """Decorator to register a tool class."""
        def wrapper(tool_cls: Type[BaseTool]):
            if name in cls._registry:
                logger.warning(f"Overwriting registered tool: {name}")
            cls._registry[name] = tool_cls
            logger.debug(f"Registered tool: {name}")
            return tool_cls
        return wrapper

    @classmethod
    def get_tool(cls, name: str, **kwargs) -> BaseTool:
        """Retrieve and instantiate a tool by name."""
        if name not in cls._registry:
            raise ValueError(f"Tool '{name}' not found in registry.")
        
        logger.info(f"Instantiating tool: {name}")
        return cls._registry[name](**kwargs)
