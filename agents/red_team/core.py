from agents.red_team.factory import create_red_team_agent
from agents.registry import AgentRegistry


@AgentRegistry.register("red_team_exploit_planner_agent")
def create_red_team_exploit_planner_agent():
    return create_red_team_agent(
        agent_key="red_team_exploit_planner_agent",
        agent_role="Red Team Exploit Planner Agent",
        goal=(
            "Map enumerated services to likely exploit validation opportunities, required "
            "tools, and safety constraints."
        ),
        backstory=(
            "You are a red-team planner for a contained training range. You translate scan "
            "findings into reproducible validation steps while minimizing impact and avoiding "
            "persistence, credential theft, or destructive actions."
        ),
        llm_max_tokens=700,
    )
