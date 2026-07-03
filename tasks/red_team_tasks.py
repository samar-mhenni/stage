from crewai import Task

from tasks.common import CONCISE_LOCAL_FIRST
from tasks.registry import TaskRegistry


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


@TaskRegistry.register("red_team_recon_tool_generation_task")
def create_red_team_recon_tool_generation_task(
    agent,
    target: str,
    ports: str,
    timeout: int,
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Generate the fresh reconnaissance command manifest for this authorized lab run. The recon agent must "
            "decide the exact bounded Nmap arguments from the target, ports, timeout, local context, and "
            "database/tool knowledge. Do not output a script body.\n\n"
            f"Target: {target}\n"
            f"Ports: {ports}\n"
            f"Timeout seconds: {timeout}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return only one minified JSON object with no markdown. Keep it under 900 characters. "
            "Do not wrap JSON in markdown.\n\n"
            "Rules: command must be nmap only; include service/version detection; bounded to supplied target and ports; "
            "avoid brute force, exploit NSE scripts, credential attacks, persistence, or destructive actions; "
            "do not include output flags because the runner adds XML/GNMAP output paths; do not include shell operators.\n\n"
            "Use this shape:\n"
            "{\n"
            "  \"agent\": \"red_team_recon_agent\",\n"
            "  \"mode\": \"llm_generated_each_run\",\n"
            "  \"safety\": \"Authorized bounded recon only.\",\n"
            "  \"tool\": \"nmap\",\n"
            "  \"target\": \"target ip or host\",\n"
            "  \"ports\": \"port expression\",\n"
            "  \"args\": [\"-sV\", \"--version-light\", \"-Pn\", \"--open\", \"-T4\"],\n"
            "  \"timeout_seconds\": 180\n"
            "}"
        ),
        expected_output="Tiny JSON manifest describing the fresh bounded Nmap recon command for this run.",
        agent=agent,
    )


@TaskRegistry.register("red_team_exploit_planning_task")
def create_red_team_exploit_planning_task(
    agent,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    local_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Create a controlled red-team exploitability plan for an authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            f"Previous/local context:\n{local_context or 'None.'}\n\n"
            "Return at most 5 validation candidates. Each: service, reason, safe validation idea, prerequisite. "
            "No persistence, credential theft, destructive actions, or out-of-scope instructions."
        ),
        expected_output="At most 5 concise red-team validation candidates with safety notes.",
        agent=agent,
    )


@TaskRegistry.register("red_team_tool_generation_task")
def create_red_team_tool_generation_task(agent, target: str, scan_context: str, exploit_plan: str) -> Task:
    return Task(
        description=(
            "Generate a compact JSON manifest of reviewable red-team validation scripts for this authorized lab. "
            "Use your configured knowledge-base/database access and the exploitability plan; do not rely on a "
            "static tool list.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Exploitability plan:\n{exploit_plan}\n\n"
            "Return only one minified JSON object. Generate up to 3 scripts when needed to cover distinct candidates. "
            "Keep each script body under 80 lines and avoid long comments or repeated report text. Do not wrap "
            "the JSON in markdown.\n\n"
            "Use this shape:\n"
            "{\n"
            "  \"agent\": \"red_team_tool_generation_agent\",\n"
            "  \"mode\": \"llm_generated_each_run\",\n"
            "  \"safety\": \"Scripts default to dry-run and require --execute for active validation.\",\n"
            "  \"scripts\": [\n"
            "    {\n"
            "      \"name\": \"short_snake_case_name\",\n"
            "      \"filename\": \"NN_short_snake_case_name.sh\",\n"
            "      \"domain\": \"web|linux|windows|blockchain|coordinator\",\n"
            "      \"purpose\": \"what this script safely validates\",\n"
            "      \"interpreter\": \"bash\",\n"
            "      \"body\": \"full script text\"\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Scripts must be bounded to the target, log every command, default to dry-run mode when --execute is absent, "
            "and perform active non-destructive validation only when --execute is present. Avoid persistence, credential theft, "
            "destructive actions, privilege abuse, or targeting anything outside the authorized lab."
        ),
        expected_output="JSON manifest describing fresh LLM-generated red-team validation scripts.",
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
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Write a red-team validation report for the authorized lab target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Exploitability plan:\n{exploit_plan}\n\n"
            f"Generated-tool execution evidence:\n{execution_context}\n\n"
            "Return under 350 words. Separate confirmed observations from likely exploitability and skipped checks. "
            "Include only essential tools used and next validation steps."
        ),
        expected_output="A concise red-team validation report under 350 words.",
        agent=agent,
    )
