from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


@AgentRegistry.register("red_team_search_tool_generator_agent")
def create_red_team_search_tool_generator_agent():
    return BaseAgentFactory.create(
        role="Red Team Search Tool Generator Agent",
        goal=(
            "Generate reviewable CrewAI BaseTool code for red-team database search, "
            "using the local red_team_database_search helper as the execution boundary."
        ),
        backstory=(
            "You are a toolsmith for authorized security workflows. You convert a requested "
            "red-team search capability into small Python tool code that only queries local "
            "knowledge stores and does not execute target actions."
        ),
        tools=configured_agent_tools("red_team_search_tool_generator_agent"),
        llm_max_tokens=1200,
        allow_delegation=False,
    )


@AgentRegistry.register("threat_intel_search_tool_generator_agent")
def create_threat_intel_search_tool_generator_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Search Tool Generator Agent",
        goal=(
            "Generate reviewable CrewAI BaseTool code for threat-intelligence database search, "
            "using the local threat_intel_database_search helper as the execution boundary."
        ),
        backstory=(
            "You are a SOC automation toolsmith. You create compact Python tools that enrich "
            "defensive analysis from local knowledge stores and keep results grounded in "
            "source collection metadata."
        ),
        tools=configured_agent_tools("threat_intel_search_tool_generator_agent"),
        llm_max_tokens=1200,
        allow_delegation=False,
    )


@AgentRegistry.register("hash_cracking_tool_generator_agent")
def create_hash_cracking_tool_generator_agent():
    return BaseAgentFactory.create(
        role="Hash Cracking Tool Generator Agent",
        goal=(
            "Generate reviewable CrewAI BaseTool code for authorized hash cracking with "
            "local John the Ripper, including bounded runtime and explicit hash-format inputs."
        ),
        backstory=(
            "You are a password-audit toolsmith. You know hashes are cracked rather than "
            "decrypted, and you only generate local, bounded tooling for hashes the operator "
            "is authorized to test."
        ),
        tools=configured_agent_tools("hash_cracking_tool_generator_agent"),
        llm_max_tokens=1400,
        allow_delegation=False,
    )
