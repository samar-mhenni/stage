from agents.red_team.factory import create_red_team_agent
from agents.registry import AgentRegistry


@AgentRegistry.register("red_team_recon_agent")
def create_red_team_recon_agent():
    return create_red_team_agent(
        agent_key="red_team_recon_agent",
        agent_role="Red Team Recon Agent",
        goal=(
            "Run authorized target enumeration and preserve service evidence for controlled "
            "exploitability validation."
        ),
        backstory=(
            "You are a red-team reconnaissance operator working in an approved environment. You gather "
            "only the evidence needed to choose safe validation paths and avoid broad, noisy scans."
        ),
        llm_max_tokens=1800,
    )
