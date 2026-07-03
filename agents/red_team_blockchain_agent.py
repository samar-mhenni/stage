from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


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
        tools=configured_agent_tools("red_team_blockchain_attack_agent"),
        allow_delegation=False,
    )
