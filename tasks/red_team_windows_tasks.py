from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_windows_planning_task")
def create_red_team_windows_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a controlled Windows/AD red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            "Focus only on SMB, NetBIOS, RDP, WinRM, LDAP, Kerberos, and AD-adjacent checks. "
            "Do not include password spraying, credential theft, persistence, lateral movement, "
            "or targets outside this lab."
        ),
        expected_output="A focused Windows/AD exploitability validation plan.",
        agent=agent,
    )
