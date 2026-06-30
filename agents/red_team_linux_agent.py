from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.registry import ToolRegistry


import tools.exploitdb_tool  # noqa: F401 - registers exploitdb_tool
import tools.knowledge_base_tool  # noqa: F401 - registers knowledge_base_tool
import tools.vulnerability_scan_tool  # noqa: F401 - registers vulnerability_scan_tool


@AgentRegistry.register("red_team_linux_attack_agent")
def create_red_team_linux_attack_agent():
    return BaseAgentFactory.create(
        role="Red Team Linux Attack Agent",
        goal="Analyze Linux and Unix network services for authorized remote validation paths.",
        backstory=(
            "You are a Linux exploitation specialist in a contained training range. You focus on "
            "legacy daemons, exposed RPC/RMI services, and known lab-safe command validation while "
            "avoiding persistence or destructive actions."
        ),
        tools=[
            ToolRegistry.get_tool("vulnerability_scan_tool"),
            ToolRegistry.get_tool("exploitdb_tool"),
            ToolRegistry.get_tool("knowledge_base_tool"),
        ],
        allow_delegation=False,
    )
