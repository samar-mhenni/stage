from crewai import Task

from tasks.registry import TaskRegistry

@TaskRegistry.register("nmap_scan_task")
def create_nmap_scan_task(agent, target: str, ports: str, timeout: int) -> Task:
    return Task(
        description=(
            "Use NmapTool to run authorized service discovery against this lab target.\n\n"
            f"Target: {target}\n"
            f"Scan type: service\n"
            f"Ports: {ports}\n"
            f"Timeout seconds: {timeout}\n\n"
            "Return only the structured JSON produced by NmapTool. Do not add markdown."
        ),
        expected_output="Valid Nmap JSON with scanner, args, summary, hosts, ports, services, products, and versions.",
        agent=agent,
    )


@TaskRegistry.register("vulnerability_scan_task")
def create_vulnerability_scan_task(agent, scan_json: str) -> Task:
    return Task(
        description=(
            "Use VulnerabilityScanTool on this Nmap JSON. Then, if useful, enrich the highest-risk "
            "findings with ExploitDBTool and Universal Knowledge Base Search.\n\n"
            f"Nmap JSON:\n{scan_json}\n\n"
            "Return defensive vulnerability findings as structured text or JSON. Include risk, "
            "affected host/port, product/version, exploit references, ATT&CK or detection context, "
            "and uncertainty. Do not provide exploit execution steps."
        ),
        expected_output="Prioritized defensive vulnerability findings based on the Nmap scan.",
        agent=agent,
    )


@TaskRegistry.register("reporting_task")
def create_reporting_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a SOC threat-intelligence report from the evidence below.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability scan evidence:\n{vulnerability_context}\n\n"
            "Include executive summary, attack surface, prioritized vulnerabilities, likely ATT&CK "
            "mappings, detection notes, and analytic gaps. Keep the report defensive."
        ),
        expected_output="A complete SOC threat-intelligence report.",
        agent=agent,
    )


@TaskRegistry.register("remediation_task")
def create_remediation_task(agent, target: str, report_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a remediation plan to correct the weaknesses identified in this SOC report.\n\n"
            f"Target: {target}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            f"SOC report:\n{report_context}\n\n"
            "Prioritize actions by urgency and blast-radius reduction. Include patching, service "
            "disablement, configuration hardening, network segmentation, monitoring, and validation "
            "checks. Do not include offensive exploitation instructions."
        ),
        expected_output="A prioritized remediation plan with concrete defensive actions and validation checks.",
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
    return Task(
        description=(
            "Generate a set of safe remediation and validation scripts for this authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            f"Remediation plan:\n{remediation_context}\n\n"
            "Return a JSON manifest of script names, purpose, required interpreter, and script body. "
            "Scripts must default to dry-run mode, require an explicit --apply flag before making changes, "
            "and avoid exploit code, credential attacks, or destructive data deletion."
        ),
        expected_output="JSON manifest describing generated defensive scripts.",
        agent=agent,
    )
