from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.registry import ToolRegistry


import tools.exploitdb_tool  # noqa: F401 - registers exploitdb_tool
import tools.knowledge_base_tool  # noqa: F401 - registers knowledge_base_tool
import tools.vulnerability_scan_tool  # noqa: F401 - registers vulnerability_scan_tool


@AgentRegistry.register("red_team_windows_attack_agent")
def create_red_team_windows_attack_agent():
    return BaseAgentFactory.create(
        role="Red Team Windows and AD Attack Agent",
        goal=(
            "Analyze SMB, NetBIOS, RDP, WinRM, LDAP, Kerberos, and AD-adjacent services for "
            "authorized validation paths."
        ),
        backstory=(
            "You are a Windows and Active Directory tester. You identify safe checks for exposed "
            "Windows management and file-sharing surfaces without password spraying, credential "
            "theft, persistence, or lateral movement outside the approved target."
        ),
        tools=[
            ToolRegistry.get_tool("vulnerability_scan_tool"),
            ToolRegistry.get_tool("exploitdb_tool"),
            ToolRegistry.get_tool("knowledge_base_tool"),
        ],
        allow_delegation=False,
    )
