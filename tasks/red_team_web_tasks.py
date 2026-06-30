from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_web_planning_task")
def create_red_team_web_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a controlled web red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            "Focus only on HTTP, HTTPS, AJP, Tomcat, web middleware, exposed admin surfaces, "
            "dangerous HTTP methods, and non-destructive web validation checks. Avoid credential "
            "theft, destructive requests, persistence, or targets outside this lab."
        ),
        expected_output="A focused web exploitability validation plan.",
        agent=agent,
    )
