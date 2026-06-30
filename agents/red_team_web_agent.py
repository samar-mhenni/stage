from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.registry import ToolRegistry


import tools.exploitdb_tool  # noqa: F401 - registers exploitdb_tool
import tools.knowledge_base_tool  # noqa: F401 - registers knowledge_base_tool
import tools.vulnerability_scan_tool  # noqa: F401 - registers vulnerability_scan_tool


@AgentRegistry.register("red_team_web_attack_agent")
def create_red_team_web_attack_agent():
    return BaseAgentFactory.create(
        role="Red Team Web Attack Agent",
        goal=(
            "Analyze HTTP, Tomcat, AJP, and web-adjacent services for authorized web "
            "exploitability validation paths."
        ),
        backstory=(
            "You are a web application and web service tester in an approved lab. You focus on "
            "non-destructive checks such as exposed admin surfaces, default credential validation, "
            "dangerous HTTP methods, and known vulnerable web middleware."
        ),
        tools=[
            ToolRegistry.get_tool("vulnerability_scan_tool"),
            ToolRegistry.get_tool("exploitdb_tool"),
            ToolRegistry.get_tool("knowledge_base_tool"),
        ],
        allow_delegation=False,
    )
