import json
import os
from pathlib import Path

from tools import RedTeamSearchTool, ThreatIntelSearchTool


DEFAULT_AGENT_CONFIG_PATH = Path("config/threat_intel_agents.json")


def load_agent_config() -> dict:
    config_path = Path(os.getenv("THREAT_INTEL_AGENT_CONFIG", str(DEFAULT_AGENT_CONFIG_PATH)))
    if not config_path.is_file():
        return {}
    return json.loads(config_path.read_text(encoding="utf-8"))


def configured_tool_names(agent_name: str) -> list[str]:
    config = load_agent_config()
    agents = config.get("agents", {})
    default_tools = config.get("default_tools", ["threat_intel_database_search"])
    return list(agents.get(agent_name, {}).get("tools", default_tools))


def load_registered_tool(tool_name: str):
    if tool_name in {"knowledge_base_tool", "threat_intel_database_search"}:
        return ThreatIntelSearchTool()
    if tool_name == "red_team_database_search":
        return RedTeamSearchTool()
    raise ValueError(f"Unknown configured database tool: {tool_name}")


def configured_agent_tools(agent_name: str):
    return [load_registered_tool(tool_name) for tool_name in configured_tool_names(agent_name)]
