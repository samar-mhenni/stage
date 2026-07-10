from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_web_planning_task")
def create_red_team_web_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Use provided local context and configured database tools first. Only infer what is missing. "
            "Be brief and avoid repeating raw scan data.\n\n"
            "Create a controlled web red-team validation plan for an authorized target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability/local evidence:\n{vulnerability_context}\n\n"
            "Prioritize product-specific CVEs only when fresh recon, live HTTP fingerprinting, or database context supports them. "
            "Focus on HTTP, HTTPS, AJP, Tomcat/Jetty/web middleware, exposed admin surfaces, dangerous HTTP "
            "methods, version disclosure, and product-specific proof-of-vulnerability checks. "
            "Return at most 4 bullets: service, reason, safe validation idea, prerequisite. "
            "Do not treat 404/403/000 responses as confirmed findings. Avoid persistence, credential theft, destructive actions, "
            "or targets outside the authorized target."
        ),
        expected_output="At most 4 concise validation bullets.",
        agent=agent,
    )
