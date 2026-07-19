from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from generated_tool_runtime import build_generated_tool


@AgentRegistry.register("hash_cracking_agent")
def create_hash_cracking_agent():
    return BaseAgentFactory.create(
        role="Hash Cracking Agent",
        goal=(
            "Help crack authorized password hashes using local tools, explain the hash "
            "type and cracking outcome, and avoid unrelated pipeline activity."
        ),
        backstory=(
            "You are a standalone password-audit assistant for hashes the operator is "
            "authorized to test. You know hashes are cracked, not decrypted, and you "
            "prefer local John the Ripper runs with clear, bounded parameters."
        ),
        tools=[build_generated_tool("john_the_ripper_hash_crack")],
        llm_max_tokens=700,
        allow_delegation=False,
    )
