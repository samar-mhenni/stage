from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_blockchain_planning_task")
def create_red_team_blockchain_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a controlled blockchain red-team validation plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            "Focus only on exposed node/RPC/wallet interfaces, read-only RPC metadata checks, "
            "node configuration exposure, and smart-contract-adjacent service discovery. Do not "
            "attempt fund movement, private-key extraction, transaction abuse, or targets outside this lab."
        ),
        expected_output="A focused blockchain exploitability validation plan.",
        agent=agent,
    )
