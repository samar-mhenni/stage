import importlib
from pathlib import Path
from typing import Any

from agents.tool_config import load_agent_config


def red_team_config() -> dict[str, Any]:
    return dict(load_agent_config().get("red_team", {}))


def red_team_artifact_config() -> dict[str, str]:
    artifacts = red_team_config().get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("Missing red_team.artifacts config.")
    return {str(key): str(value) for key, value in artifacts.items()}


def red_team_artifact_path(key: str) -> Path:
    artifacts = red_team_artifact_config()
    if key not in artifacts:
        raise ValueError(f"Missing red_team.artifacts.{key} config.")
    return Path(artifacts[key])


def red_team_artifact_name(key: str) -> str:
    return red_team_artifact_path(key).name


def red_team_pipeline_agents() -> list[str]:
    agents = red_team_config().get("pipeline_agents")
    if not isinstance(agents, list) or not agents:
        raise ValueError("Missing red_team.pipeline_agents config.")
    return [str(agent) for agent in agents]


def red_team_generated_tool_active_args() -> list[str]:
    generated_tools = red_team_config().get("generated_tools", {})
    if not isinstance(generated_tools, dict):
        return []
    active_args = generated_tools.get("active_args", [])
    return [str(arg) for arg in active_args] if isinstance(active_args, list) else []


def red_team_specialist_config() -> dict[str, dict[str, str]]:
    specialists = red_team_config().get("specialists")
    if not isinstance(specialists, dict) or not specialists:
        raise ValueError("Missing red_team.specialists config.")
    normalized: dict[str, dict[str, str]] = {}
    for domain, spec in specialists.items():
        if not isinstance(spec, dict) or not spec.get("agent") or not spec.get("planning_task"):
            raise ValueError(f"Invalid red_team.specialists.{domain} config.")
        normalized[str(domain)] = {
            "agent": str(spec["agent"]),
            "planning_task": str(spec["planning_task"]),
            "agent_module": str(spec.get("agent_module", "")),
            "task_module": str(spec.get("task_module", "")),
        }
    return normalized


def load_red_team_modules() -> None:
    agent_modules = red_team_config().get("agent_modules", {})
    if isinstance(agent_modules, dict):
        for module_name in agent_modules.values():
            if module_name:
                importlib.import_module(str(module_name))
    for spec in red_team_specialist_config().values():
        for module_key in ("agent_module", "task_module"):
            module_name = spec.get(module_key)
            if module_name:
                importlib.import_module(module_name)


load_red_team_modules()
RED_TEAM_SPECIALISTS = {domain: spec["agent"] for domain, spec in red_team_specialist_config().items()}
