from crewai import Task

from tasks.common import CONCISE_LOCAL_FIRST
from tasks.registry import TaskRegistry


@TaskRegistry.register("nmap_scan_task")
def create_nmap_scan_task(agent, target: str, ports: str, timeout: int, local_context: str = "") -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Collect or summarize authorized service-discovery evidence for this lab target using "
            "your configured tools and available context.\n\n"
            f"Target: {target}\n"
            f"Evidence focus: services and exposed ports\n"
            f"Ports: {ports}\n"
            f"Timeout seconds: {timeout}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return only compact JSON if available, otherwise 3 bullets maximum."
        ),
        expected_output="Compact structured collection evidence or at most 3 concise bullets.",
        agent=agent,
    )


@TaskRegistry.register("collection_task")
def create_collection_task(agent, target: str, ports: str, timeout: int, local_context: str = "") -> Task:
    return create_nmap_scan_task(agent, target, ports, timeout, local_context)


@TaskRegistry.register("vulnerability_scan_task")
def create_vulnerability_scan_task(agent, scan_json: str, local_context: str = "") -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Use your available knowledge-base/database access to enrich this collected evidence. "
            "Search the database only for missing product/version, ATT&CK, detection, or mitigation context.\n\n"
            f"Nmap JSON:\n{scan_json}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return at most 6 findings. For each: host:port, risk, why, ATT&CK/detection if known, mitigation. "
            "One line per finding. Do not provide exploit execution steps."
        ),
        expected_output="At most 6 concise defensive enrichment findings grounded in local/database evidence.",
        agent=agent,
    )


@TaskRegistry.register("enrichment_task")
def create_enrichment_task(agent, scan_json: str, local_context: str = "") -> Task:
    return create_vulnerability_scan_task(agent, scan_json, local_context)


@TaskRegistry.register("correlation_task")
def create_correlation_task(
    agent,
    target: str,
    collection_context: str,
    enrichment_context: str,
    telemetry_context: str,
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Correlate this threat-intelligence evidence into related activity clusters.\n\n"
            f"Target: {target}\n\n"
            f"Collection evidence:\n{collection_context}\n\n"
            f"Enrichment evidence:\n{enrichment_context}\n\n"
            f"Telemetry and detection evidence:\n{telemetry_context}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return at most 4 clusters. Each cluster must be 2 lines: evidence, confidence/gap. Keep defensive."
        ),
        expected_output="At most 4 concise correlated clusters with confidence and evidence references.",
        agent=agent,
    )


@TaskRegistry.register("prediction_task")
def create_prediction_task(
    agent,
    target: str,
    correlation_context: str,
    enrichment_context: str,
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Predict likely attacker next steps and near-term risk from the correlated evidence.\n\n"
            f"Target: {target}\n\n"
            f"Correlation evidence:\n{correlation_context}\n\n"
            f"Enrichment evidence:\n{enrichment_context}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return exactly 5 bullets: next step, risk horizon, confidence, watchpoint, preventive control. "
            "Do not include offensive exploitation instructions."
        ),
        expected_output="Exactly 5 concise defensive prediction bullets.",
        agent=agent,
    )


@TaskRegistry.register("reporting_task")
def create_reporting_task(
    agent,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    correlation_context: str = "",
    prediction_context: str = "",
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Create a SOC threat-intelligence report from the evidence below.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability scan evidence:\n{vulnerability_context}\n\n"
            f"Correlation evidence:\n{correlation_context or 'Not provided.'}\n\n"
            f"Prediction evidence:\n{prediction_context or 'Not provided.'}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return a terse report under 450 words with sections: Summary, Top Risks, Correlation, Prediction, Gaps. "
            "No repeated raw scan data."
        ),
        expected_output="A concise SOC threat-intelligence report under 450 words.",
        agent=agent,
    )


@TaskRegistry.register("remediation_task")
def create_remediation_task(
    agent,
    target: str,
    report_context: str,
    vulnerability_context: str,
    correlation_context: str = "",
    prediction_context: str = "",
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Create a remediation plan to correct the weaknesses identified in this SOC report.\n\n"
            f"Target: {target}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            f"Correlation evidence:\n{correlation_context or 'Not provided.'}\n\n"
            f"Prediction evidence:\n{prediction_context or 'Not provided.'}\n\n"
            f"SOC report:\n{report_context}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return at most 8 ordered actions. Each action: priority, action, validation. No exploit instructions."
        ),
        expected_output="At most 8 concise remediation actions with validation checks.",
        agent=agent,
    )


@TaskRegistry.register("tool_generation_task")
def create_tool_generation_task(
    agent,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    correlation_context: str,
    prediction_context: str,
    report_context: str,
    remediation_context: str,
) -> Task:
    return Task(
        description=(
            "Generate the defensive helper scripts needed for this run. Use your configured "
            "knowledge-base/database access to decide what scripts are useful; do not rely on a "
            "static tool list. The scripts may validate exposure, collect local evidence, check "
            "configuration, prepare SIEM queries, or support safe remediation review.\n\n"
            f"Target: {target}\n\n"
            f"Collection evidence:\n{scan_context}\n\n"
            f"Enrichment evidence:\n{vulnerability_context}\n\n"
            f"Correlation evidence:\n{correlation_context}\n\n"
            f"Prediction evidence:\n{prediction_context}\n\n"
            f"SOC report:\n{report_context}\n\n"
            f"Remediation plan:\n{remediation_context}\n\n"
            "Return only one compact JSON object. Generate at most 2 scripts. Keep each script body under "
            "120 lines and avoid long comments or repeated report text. Do not wrap the JSON in markdown.\n\n"
            "Use this shape:\n"
            "{\n"
            "  \"agent\": \"tool_generation_agent\",\n"
            "  \"mode\": \"llm_generated_each_run\",\n"
            "  \"safety\": \"Scripts default to dry-run and require --apply for changes.\",\n"
            "  \"scripts\": [\n"
            "    {\n"
            "      \"name\": \"short_snake_case_name\",\n"
            "      \"filename\": \"NN_short_snake_case_name.sh\",\n"
            "      \"purpose\": \"what this script safely helps validate or collect\",\n"
            "      \"interpreter\": \"bash\",\n"
            "      \"body\": \"full script text\"\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Every script must be defensive, bounded to the target/evidence, reviewable, and safe by default. "
            "Scripts must default to dry-run mode, require an explicit --apply flag before making changes, "
            "and avoid exploit code, credential attacks, persistence, privilege abuse, or destructive data deletion."
        ),
        expected_output="JSON manifest describing fresh LLM-generated defensive helper scripts for this run.",
        agent=agent,
    )


@TaskRegistry.register("remediation_script_generation_task")
def create_remediation_script_generation_task(
    agent,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    remediation_context: str,
) -> Task:
    return create_tool_generation_task(
        agent,
        target,
        scan_context,
        vulnerability_context,
        "",
        "",
        "",
        remediation_context,
    )
