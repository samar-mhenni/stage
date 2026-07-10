from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from agents.tool_config import configured_agent_tools


@AgentRegistry.register("collection_agent")
def create_collection_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Collection Agent",
        goal=(
            "Collect authorized security telemetry, service-discovery output, and local log evidence "
            "for the threat-intelligence workflow."
        ),
        backstory=(
            "You are the collection layer for a SOC threat-intel crew. You only gather evidence from "
            "explicitly authorized targets and preserve it in machine-readable form."
        ),
        tools=configured_agent_tools("collection_agent"),
        llm_max_tokens=500,
        allow_delegation=False,
    )


@AgentRegistry.register("enrichment_agent")
def create_enrichment_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Enrichment Agent",
        goal=(
            "Enrich collected service and telemetry evidence with vulnerability, exploit reference, "
            "IOC, detection, and knowledge-base context."
        ),
        backstory=(
            "You are a defensive enrichment analyst for a SOC workflow. You map exposed products, "
            "versions, and log indicators to likely weaknesses and references without giving exploit steps."
        ),
        tools=configured_agent_tools("enrichment_agent"),
        llm_max_tokens=700,
        allow_delegation=False,
    )


@AgentRegistry.register("vulnerability_scan_agent")
def create_vulnerability_scan_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Vulnerability Scan Agent",
        goal="Enrich collected service evidence with vulnerability, ATT&CK, detection, and mitigation context.",
        backstory=(
            "You are a defensive vulnerability analyst for a SOC workflow. You map exposed products "
            "and versions to likely weaknesses without providing exploit execution steps."
        ),
        tools=configured_agent_tools("vulnerability_scan_agent"),
        llm_max_tokens=700,
        allow_delegation=False,
    )


@AgentRegistry.register("correlation_agent")
def create_correlation_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Correlation Agent",
        goal=(
            "Correlate enriched vulnerabilities, network telemetry, alerts, and generated detections "
            "into coherent incident hypotheses and prioritized evidence clusters."
        ),
        backstory=(
            "You connect weak signals across scan output, Suricata alerts, Zeek sessions, and "
            "IOC enrichment so analysts can see which findings belong to the same activity thread."
        ),
        tools=configured_agent_tools("correlation_agent"),
        llm_max_tokens=900,
        allow_delegation=False,
    )


@AgentRegistry.register("prediction_agent")
def create_prediction_agent():
    return BaseAgentFactory.create(
        role="Threat Prediction Agent",
        goal=(
            "Predict likely attacker next steps, escalation paths, and near-term risk based on "
            "correlated threat-intelligence evidence."
        ),
        backstory=(
            "You are a forward-looking SOC analyst. You convert correlated evidence into likely "
            "attack progression scenarios, confidence levels, and defensive watchpoints."
        ),
        tools=configured_agent_tools("prediction_agent"),
        llm_max_tokens=800,
        allow_delegation=False,
    )


@AgentRegistry.register("reporting_agent")
def create_reporting_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Reporting Agent",
        goal="Write a clear SOC report from collection, enrichment, correlation, and prediction evidence.",
        backstory=(
            "You write concise, evidence-grounded SOC reports that separate confirmed log/tool "
            "facts, enriched intelligence, correlated hypotheses, predictions, and uncertainty."
        ),
        tools=configured_agent_tools("reporting_agent"),
        llm_max_tokens=1100,
        allow_delegation=False,
    )


@AgentRegistry.register("response_agent")
def create_response_agent():
    return create_remediation_agent()


@AgentRegistry.register("remediation_agent")
def create_remediation_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Remediation Agent",
        goal="Produce prioritized response and remediation actions that correct identified weaknesses safely.",
        backstory=(
            "You are a defensive response specialist. You translate threat-intel findings into "
            "containment, patching, hardening, segmentation, monitoring, and validation tasks."
        ),
        tools=configured_agent_tools("remediation_agent"),
        llm_max_tokens=900,
        allow_delegation=False,
    )


@AgentRegistry.register("tool_generation_agent")
def create_tool_generation_agent():
    return BaseAgentFactory.create(
        role="Threat Intel Tool Generation Agent",
        goal=(
            "Generate the defensive helper scripts needed for the current threat-intelligence run, "
            "using the LLM and ingested knowledge database instead of static tool code."
        ),
        backstory=(
            "You are the single toolsmith for the SOC crew. Every run, you decide what helper "
            "scripts are needed from the evidence and write fresh, reviewable scripts that default "
            "to dry-run behavior and avoid offensive exploitation, credential attacks, persistence, "
            "and destructive actions."
        ),
        tools=configured_agent_tools("tool_generation_agent"),
        llm_max_tokens=1600,
        allow_delegation=False,
    )


@AgentRegistry.register("remediation_script_generation_agent")
def create_remediation_script_generation_agent():
    return create_tool_generation_agent()
