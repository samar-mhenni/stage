from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


@AgentRegistry.register("red_team_exploit_planner_agent")
def create_red_team_exploit_planner_agent():
    return BaseAgentFactory.create(
        role="Red Team Exploit Planner Agent",
        goal=(
            "Map enumerated services to likely exploit validation opportunities, required "
            "tools, and safety constraints."
        ),
        backstory=(
            "You are a red-team planner for a contained training range. You translate scan "
            "findings into reproducible validation steps while minimizing impact and avoiding "
            "persistence, credential theft, or destructive actions."
        ),
        tools=configured_agent_tools("red_team_exploit_planner_agent"),
        llm_max_tokens=700,
        allow_delegation=False,
    )


@AgentRegistry.register("red_team_reporting_agent")
def create_red_team_reporting_agent():
    return BaseAgentFactory.create(
        role="Red Team Reporting Agent",
        goal="Summarize exploitability validation results, evidence, and follow-up actions.",
        backstory=(
            "You write concise red-team validation reports for defenders. You distinguish "
            "confirmed evidence, likely exploitability, skipped checks, and tooling gaps."
        ),
        tools=configured_agent_tools("red_team_reporting_agent"),
        llm_max_tokens=900,
        allow_delegation=False,
    )
