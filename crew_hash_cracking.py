import argparse

import agents.hash_cracking  # noqa: F401 - registers standalone hash-cracking agent
import tasks.hash_cracking  # noqa: F401 - registers standalone hash-cracking task
from agents.execution import run_bound_agent_task
from agents.registry import AgentRegistry
from tasks.registry import TaskRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the standalone hash-cracking agent.")
    parser.add_argument("hashes", help="Hash string, or multiple hashes separated by literal newlines.")
    parser.add_argument("--format", default="raw-md5", help="John format, e.g. raw-md5, raw-sha1, nt, bcrypt.")
    parser.add_argument("--wordlist", help="Optional John wordlist path.")
    parser.add_argument("--timeout", type=int, default=300, help="Maximum John runtime in seconds.")
    args = parser.parse_args()

    agent = AgentRegistry.get_agent("hash_cracking_agent")
    task = TaskRegistry.get_task(
        "hash_cracking_task",
        agent=agent,
        hashes=args.hashes.replace("\\n", "\n"),
        hash_format=args.format,
        wordlist=args.wordlist,
        timeout=args.timeout,
    )
    print(run_bound_agent_task(agent, task))


if __name__ == "__main__":
    main()
