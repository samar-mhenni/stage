from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


def _create_agent(name: str, role: str, goal: str, backstory: str, llm_max_tokens: int):
    return BaseAgentFactory.create(
        role=role,
        goal=goal,
        backstory=backstory,
        tools=configured_agent_tools(name),
        llm_max_tokens=llm_max_tokens,
        allow_delegation=False,
    )


@AgentRegistry.register("collection_agent")
def create_collection_agent():
    return _create_agent(
        "collection_agent",
        "Threat Intel Collection Agent",
        (
            "Collect authorized security telemetry, service-discovery output, and local log evidence "
            "for the threat-intelligence workflow."
        ),
        (
            "You are the collection layer for a SOC threat-intel crew. You only gather evidence from "
            "explicitly authorized targets and preserve it in machine-readable form."
        ),
        500,
    )


@AgentRegistry.register("enrichment_agent")
def create_enrichment_agent():
    return _create_agent(
        "enrichment_agent",
        "Threat Intel Enrichment Agent",
        (
            "Enrich collected service and telemetry evidence with vulnerability, exploit reference, "
            "IOC, detection, and knowledge-base context."
        ),
        (
            "You are a defensive enrichment analyst for a SOC workflow. You map exposed products, "
            "versions, and log indicators to likely weaknesses and references without giving exploit steps."
        ),
        700,
    )


@AgentRegistry.register("vulnerability_scan_agent")
def create_vulnerability_scan_agent():
    return _create_agent(
        "vulnerability_scan_agent",
        "Threat Intel Vulnerability Scan Agent",
        "Enrich collected service evidence with vulnerability, ATT&CK, detection, and mitigation context.",
        (
            "You are a defensive vulnerability analyst for a SOC workflow. You map exposed products "
            "and versions to likely weaknesses without providing exploit execution steps."
        ),
        700,
    )


@AgentRegistry.register("correlation_agent")
def create_correlation_agent():
    return _create_agent(
        "correlation_agent",
        "Threat Intel Correlation Agent",
        (
            "Correlate enriched vulnerabilities, network telemetry, alerts, and generated detections "
            "into coherent incident hypotheses and prioritized evidence clusters."
        ),
        (
            "You connect weak signals across scan output, Suricata alerts, Zeek sessions, and "
            "IOC enrichment so analysts can see which findings belong to the same activity thread."
        ),
        900,
    )


@AgentRegistry.register("prediction_agent")
def create_prediction_agent():
    return _create_agent(
        "prediction_agent",
        "Threat Prediction Agent",
        (
            "Predict likely attacker next steps, escalation paths, and near-term risk based on "
            "correlated threat-intelligence evidence."
        ),
        (
            "You are a forward-looking SOC analyst. You convert correlated evidence into likely "
            "attack progression scenarios, confidence levels, and defensive watchpoints."
        ),
        800,
    )


@AgentRegistry.register("response_agent")
def create_response_agent():
    return create_remediation_agent()


@AgentRegistry.register("remediation_agent")
def create_remediation_agent():
    return _create_agent(
        "remediation_agent",
        "Threat Intel Remediation Agent",
        "Produce prioritized response and remediation actions that correct identified weaknesses safely.",
        (
            "You are a defensive response specialist. You translate threat-intel findings into "
            "containment, patching, hardening, segmentation, monitoring, and validation tasks."
        ),
        900,
    )


@AgentRegistry.register("tool_generation_agent")
def create_tool_generation_agent():
    return _create_agent(
        "tool_generation_agent",
        "Threat Intel Tool Generation Agent",
        (
            "Generate the defensive helper scripts needed for the current threat-intelligence run, "
            "using the LLM and ingested knowledge database instead of static tool code."
        ),
        (
            "You are the single toolsmith for the SOC crew. Every run, you decide what helper "
            "scripts are needed from the evidence and write fresh, reviewable scripts that default "
            "to dry-run behavior and avoid offensive exploitation, credential attacks, persistence, "
            "and destructive actions."
        ),
        1600,
    )


@AgentRegistry.register("remediation_script_generation_agent")
def create_remediation_script_generation_agent():
    return create_tool_generation_agent()
