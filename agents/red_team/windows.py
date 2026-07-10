from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


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
        tools=configured_agent_tools("red_team_windows_attack_agent"),
        allow_delegation=False,
    )
