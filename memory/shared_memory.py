import json
from typing import Any, Dict
from config.logging import logger

class SharedStateMemory:
    """
    A lightweight shared memory interface.
    This acts as a shared whiteboard for agents to read/write context 
    (like orchestrator plans) across the CrewAI workflow.
    """
    
    _state: Dict[str, Any] = {}

    @classmethod
    def set(cls, key: str, value: Any):
        """Set a value in the shared memory."""
        cls._state[key] = value
        logger.debug(f"Memory update: {key} set.")

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Retrieve a value from the shared memory."""
        return cls._state.get(key, default)

    @classmethod
    def append_to_list(cls, key: str, value: Any):
        """Append an item to a list in memory (creates the list if it doesn't exist)."""
        if key not in cls._state:
            cls._state[key] = []
        if isinstance(cls._state[key], list):
            cls._state[key].append(value)
            logger.debug(f"Memory update: Appended to {key}.")
        else:
            raise ValueError(f"Memory key {key} is not a list.")

    @classmethod
    def dump(cls) -> str:
        """Dump the current memory state as a JSON string for debugging."""
        return json.dumps(cls._state, indent=2, default=str)
    
    @classmethod
    def clear(cls):
        """Clear the shared memory state."""
        cls._state.clear()
        logger.info("Shared memory cleared.")
