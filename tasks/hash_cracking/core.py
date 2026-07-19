from crewai import Task

from tasks.registry import TaskRegistry


@TaskRegistry.register("hash_cracking_task")
def create_hash_cracking_task(
    agent,
    hashes: str,
    hash_format: str = "raw-md5",
    wordlist: str | None = None,
    timeout: int = 300,
) -> Task:
    tool_input = [f"format={hash_format}", f"timeout={timeout}", hashes.strip()]
    if wordlist:
        tool_input.insert(1, f"wordlist={wordlist}")

    return Task(
        description=(
            "Crack the following authorized hash material using the "
            "john_the_ripper_hash_crack tool. Use this exact tool input:\n\n"
            + "\n".join(tool_input)
            + "\n\nSummarize whether any hashes were cracked. If cracked, return each "
            "original hash mapped to its plaintext."
        ),
        expected_output=(
            "A concise cracking result listing cracked hashes when found, or a clear "
            "statement that no hash was cracked."
        ),
        agent=agent,
    )
