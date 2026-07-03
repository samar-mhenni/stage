from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


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
        tools=configured_agent_tools("red_team_linux_attack_agent"),
        allow_delegation=False,
    )
