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


@TaskRegistry.register("red_team_recon_task")
def create_red_team_recon_task(agent, target: str, ports: str, timeout: int) -> Task:
    return Task(
        description=(
            "Run authorized red-team reconnaissance against this lab target.\n\n"
            f"Target: {target}\n"
            f"Ports: {ports}\n"
            f"Timeout seconds: {timeout}\n\n"
            "Return structured Nmap JSON only. Keep enumeration bounded to the supplied target."
        ),
        expected_output="Valid Nmap JSON with host, port, service, product, and version evidence.",
        agent=agent,
    )


@TaskRegistry.register("red_team_exploit_planning_task")
def create_red_team_exploit_planning_task(agent, target: str, scan_context: str, vulnerability_context: str) -> Task:
    return Task(
        description=(
            "Create a controlled red-team exploitability plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            "Prioritize likely exploitable services, identify validation tooling, define safety "
            "constraints, and note prerequisites. Do not include persistence, credential theft, "
            "destructive actions, or instructions for targets outside this lab."
        ),
        expected_output="A prioritized exploitability validation plan with tools, commands, and safety notes.",
        agent=agent,
    )


@TaskRegistry.register("red_team_tool_generation_task")
def create_red_team_tool_generation_task(agent, target: str, scan_context: str, exploit_plan: str) -> Task:
    return Task(
        description=(
            "Generate a JSON manifest of reviewable red-team validation scripts for this authorized lab.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Exploitability plan:\n{exploit_plan}\n\n"
            "Scripts must be bounded to the target, log every command, and default to plan-only or "
            "safe-check mode. Active validation must require an explicit operator flag."
        ),
        expected_output="JSON manifest describing generated red-team validation scripts.",
        agent=agent,
    )


@TaskRegistry.register("red_team_reporting_task")
def create_red_team_reporting_task(
    agent,
    target: str,
    scan_context: str,
    exploit_plan: str,
    execution_context: str,
) -> Task:
    return Task(
        description=(
            "Write a red-team validation report for the authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Exploitability plan:\n{exploit_plan}\n\n"
            f"Generated-tool execution evidence:\n{execution_context}\n\n"
            "Separate confirmed observations from likely exploitability and skipped checks. Include "
            "a list of tools used and recommended next validation steps."
        ),
        expected_output="A concise red-team validation report.",
        agent=agent,
    )
