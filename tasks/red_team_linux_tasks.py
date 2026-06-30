from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_linux_planning_task")
def create_red_team_linux_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a controlled Linux/Unix red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            "Focus only on Linux/Unix network services, legacy daemons, RPC/RMI, FTP, IRC, "
            "distccd, and bounded command validation. Avoid persistence, credential theft, "
            "destructive commands, or targets outside this lab."
        ),
        expected_output="A focused Linux/Unix exploitability validation plan.",
        agent=agent,
    )
