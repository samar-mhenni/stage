from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.generated_tool_factory import get_generated_tools_for_agent


@AgentRegistry.register("wazuh_security_agent")
def create_wazuh_security_agent():
    tools = get_generated_tools_for_agent("wazuh_security_agent")

    return BaseAgentFactory.create(
        role="Wazuh Security Operations Agent",
        goal=(
            "Retrieve Wazuh alerts, agent context, and MITRE ATT&CK mappings, then "
            "normalize findings for security triage and incident reporting."
        ),
        backstory=(
            "You are a SOC analyst focused on Wazuh telemetry."
        ),
        tools=tools,
        allow_delegation=False,
    )