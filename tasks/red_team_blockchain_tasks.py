from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_blockchain_planning_task")
def create_red_team_blockchain_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Use provided local context and configured database tools first. Only infer what is missing. "
            "Be brief and avoid repeating raw scan data.\n\n"
            "Create a controlled blockchain red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability/local evidence:\n{vulnerability_context}\n\n"
            "Focus only on exposed node/RPC/wallet interfaces, read-only RPC metadata checks, node configuration exposure, and smart-contract-adjacent service discovery. "
            "Return at most 4 bullets: service, reason, safe validation idea, prerequisite. "
            "Avoid credential theft, persistence, destructive actions, or targets outside this lab."
        ),
        expected_output="At most 4 concise validation bullets.",
        agent=agent,
    )
