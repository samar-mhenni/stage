from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.registry import ToolRegistry


import tools.exploitdb_tool  # noqa: F401 - registers exploitdb_tool
import tools.knowledge_base_tool  # noqa: F401 - registers knowledge_base_tool
import tools.vulnerability_scan_tool  # noqa: F401 - registers vulnerability_scan_tool


@AgentRegistry.register("red_team_blockchain_attack_agent")
def create_red_team_blockchain_attack_agent():
    return BaseAgentFactory.create(
        role="Red Team Blockchain Attack Agent",
        goal=(
            "Analyze blockchain RPC, wallet, node, and smart-contract-adjacent services for "
            "authorized validation paths."
        ),
        backstory=(
            "You are a blockchain security tester for lab environments. You look for exposed RPC "
            "interfaces, unsafe node APIs, weak network configuration, and read-only chain metadata "
            "checks. You do not attempt fund movement, private-key extraction, or transaction abuse."
        ),
        tools=[
            ToolRegistry.get_tool("vulnerability_scan_tool"),
            ToolRegistry.get_tool("exploitdb_tool"),
            ToolRegistry.get_tool("knowledge_base_tool"),
        ],
        allow_delegation=False,
    )
