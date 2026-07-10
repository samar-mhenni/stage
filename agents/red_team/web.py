from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


@AgentRegistry.register("red_team_web_attack_agent")
def create_red_team_web_attack_agent():
    return BaseAgentFactory.create(
        role="Red Team Web Attack Agent",
        goal=(
            "Analyze HTTP, Tomcat, AJP, and web-adjacent services for authorized web "
            "exploitability validation paths."
        ),
        backstory=(
            "You are a web application and web service tester in an authorized environment. You focus on "
            "non-destructive checks such as exposed admin surfaces, default credential validation, "
            "dangerous HTTP methods, and known vulnerable web middleware."
        ),
        tools=configured_agent_tools("red_team_web_attack_agent"),
        allow_delegation=False,
    )
