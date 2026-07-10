from crewai import Task

from tasks.common import CONCISE_LOCAL_FIRST
from tasks.registry import TaskRegistry


@TaskRegistry.register("collection_task")
def create_collection_task(agent, target: str, evidence_context: str, local_context: str = "") -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Review the provided tool logs/evidence for this threat-intelligence run. "
            "Do not generate or run collection commands; use only the supplied evidence.\n\n"
            f"Target/evidence label: {target}\n\n"
            f"Evidence:\n{evidence_context}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return a compact evidence summary with key hosts, users, alerts, IOCs, vulnerable products, "
            "suspicious behaviors, timestamps, and gaps."
        ),
        expected_output="Concise summary of the supplied tool logs/evidence.",
        agent=agent,
    )


@TaskRegistry.register("vulnerability_scan_task")
def create_vulnerability_scan_task(agent, evidence_json: str, local_context: str = "") -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Use the supplied local database enrichment first, then your available knowledge-base/database access only for gaps. "
            "Keep findings tied to explicit evidence: observed service, CVE, IOC, alert, hash, user, host, or timestamp.\n\n"
            f"Evidence JSON/logs:\n{evidence_json}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return at most 6 findings. For each: host:port or evidence id, risk, why, ATT&CK/detection if known, mitigation. "
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
            "Correlate this threat-intelligence evidence into related activity clusters. Use local database enrichment "
            "as supporting context, but keep each cluster grounded in the provided logs/evidence.\n\n"
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
            "Create a SOC threat-intelligence report from the evidence below. Separate direct evidence from database enrichment and inference.\n\n"
            f"Target: {target}\n\n"
            f"Tool/log evidence:\n{scan_context}\n\n"
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
            "Create a remediation plan to correct the weaknesses identified in this SOC report. Prefer actions that are directly supported by supplied evidence and generated enrichment.\n\n"
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
            "Generate the defensive helper scripts needed for this run. Use the supplied evidence, local database enrichment, and target access context to decide what scripts are useful; do not rely on a "
            "static tool list. The scripts may validate exposure, collect local evidence, check "
            "configuration, prepare SIEM queries, or support safe remediation review.\n\n"
            f"Target: {target}\n\n"
            f"Collection evidence:\n{scan_context}\n\n"
            f"Enrichment evidence:\n{vulnerability_context}\n\n"
            f"Correlation evidence:\n{correlation_context}\n\n"
            f"Prediction evidence:\n{prediction_context}\n\n"
            f"SOC report:\n{report_context}\n\n"
            f"Remediation plan:\n{remediation_context}\n\n"
            "Return only one compact JSON object. Generate up to 3 scripts for the highest-value safe "
            "corrective actions. Keep each script body under 55 lines and avoid long comments or repeated "
            "report text. Do not wrap the JSON in markdown.\n\n"
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
            "and avoid exploit code, credential attacks, persistence, privilege abuse, or destructive data deletion. "
            "If target access context includes TARGET_CONTAINER, make changes inside that container with docker exec. "
            "When TARGET_CONTAINER is present, service probes and changes must use docker exec; do not run target-specific probes or file edits on the API host. "
            "If no direct execution context is available, the script must perform validation only or exit 20 with a clear reason. "
            "When package upgrades are not appropriate for the authorized environment, prefer disabling or restricting unnecessary vulnerable services. "
            "Never pin exact package versions unless the target context explicitly proves that version exists; use unpinned package-manager upgrades only when appropriate. "
            "Use the detected listener process, service manager, and configuration facts from the target context; do not assume a specific init system exists. "
            "When editing service configuration, use only detected snippets and preserve detected file/service names. "
            "Validate changes with approved follow-up tool logs; do not rely only on config grep or process checks. "
            "For endpoint-exposure findings, validate the exact observed endpoint, HTTP status, and product-specific response markers from the supplied evidence; "
            "do not declare remediation success or non-vulnerability from a missing version file, empty version string, or guessed local path. "
            "Do not exit early as 'already disabled' if evidence still shows exposure; restart the detected owning listener service and revalidate. "
            "Use if statements for probes and version checks; do not let a missing process "
            "or closed port abort the script accidentally. After --apply, exit 0 only when validation shows the "
            "corrective action succeeded or was already satisfied."
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
