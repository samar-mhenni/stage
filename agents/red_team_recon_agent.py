from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


@AgentRegistry.register("red_team_recon_agent")
def create_red_team_recon_agent():
    return BaseAgentFactory.create(
        role="Red Team Recon Agent",
        goal=(
            "Run authorized lab enumeration and preserve service evidence for controlled "
            "exploitability validation."
        ),
        backstory=(
            "You are a red-team reconnaissance operator working in an approved lab. You gather "
            "only the evidence needed to choose safe validation paths and avoid broad, noisy scans."
        ),
        tools=configured_agent_tools("red_team_recon_agent"),
        llm_max_tokens=1800,
        allow_delegation=False,
    )
