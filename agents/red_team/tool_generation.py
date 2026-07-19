from agents.red_team.factory import create_red_team_agent
from agents.registry import AgentRegistry


@AgentRegistry.register("red_team_tool_generation_agent")
def create_red_team_tool_generation_agent():
    return create_red_team_agent(
        agent_key="red_team_tool_generation_agent",
        agent_role="Red Team Tool Generation Agent",
        goal=(
            "Generate reviewable validation tools for the exploit plan. Tools must default to "
            "planning mode and require explicit execution flags for active checks."
        ),
        backstory=(
            "You are a red-team automation engineer. You produce small auditable scripts for "
            "authorized environments, record all commands, and keep exploit validation bounded to the "
            "provided target and ports."
        ),
        llm_max_tokens=1600,
    )
