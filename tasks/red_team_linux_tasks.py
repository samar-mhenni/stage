from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_linux_planning_task")
def create_red_team_linux_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Use provided local context and configured database tools first. Only infer what is missing. "
            "Be brief and avoid repeating raw scan data.\n\n"
            "Create a controlled Linux/Unix red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability/local evidence:\n{vulnerability_context}\n\n"
            "Focus only on Linux/Unix network services, legacy daemons, RPC/RMI, FTP, IRC, distccd, and bounded command validation. "
            "Return at most 4 bullets: service, reason, safe validation idea, prerequisite. "
            "Avoid credential theft, persistence, destructive actions, or targets outside this lab."
        ),
        expected_output="At most 4 concise validation bullets.",
        agent=agent,
    )
