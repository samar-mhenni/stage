from crewai import Task

from tasks.common import CONCISE_LOCAL_FIRST
from tasks.registry import TaskRegistry


@TaskRegistry.register("red_team_recon_task")
def create_red_team_recon_task(agent, target: str, ports: str, timeout: int) -> Task:
    return Task(
        description=(
            "Run authorized red-team reconnaissance against this target.\n\n"
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
            "Generate fresh reconnaissance tooling for this authorized run. The recon agent must always "
            "include a bounded Nmap command manifest, and may include additional safe enumeration helper scripts "
            "when useful for the detected surface. The runner writes and executes only the Nmap script by default; "
            "the pipeline then adds safe post-recon enumeration for observed services. Extra helper scripts are generated "
            "as reviewable artifacts when they add clear evidence value.\n\n"
            f"Target: {target}\n"
            f"Ports: {ports}\n"
            f"Timeout seconds: {timeout}\n\n"
            f"Current live context:\n{local_context or 'None.'}\n\n"
            "Return only one minified JSON object with no markdown. Keep it compact. "
            "Do not wrap JSON in markdown.\n\n"
            "Rules: the primary command must be nmap; include service/version detection and open-port filtering; bounded to supplied target and ports; "
            "avoid brute force, exploit NSE scripts, credential attacks, persistence, or destructive actions; "
            "do not include output flags because the runner adds XML/GNMAP output paths; do not include shell operators. "
            "Additional enumeration scripts must be passive or low-impact, bounded to TARGET/PORTS, and focused on evidence such as banners, headers, titles, protocol options, and version fingerprints.\n\n"
            "Use this shape:\n"
            "{\n"
            "  \"agent\": \"red_team_recon_agent\",\n"
            "  \"mode\": \"llm_generated_each_run\",\n"
            "  \"safety\": \"Authorized bounded recon only.\",\n"
            "  \"tool\": \"nmap\",\n"
            "  \"target\": \"target ip or host\",\n"
            "  \"ports\": \"port expression\",\n"
            "  \"args\": [\"-sV\", \"--version-light\", \"-Pn\", \"--open\", \"-T4\"],\n"
            "  \"timeout_seconds\": 180,\n"
            "  \"enumeration_tools\": [\n"
            "    {\n"
            "      \"name\": \"short_snake_case_name\",\n"
            "      \"filename\": \"NN_short_snake_case_name.sh\",\n"
            "      \"purpose\": \"what this helper safely enumerates\",\n"
            "      \"interpreter\": \"bash\",\n"
            "      \"body\": \"full script text\"\n"
            "    }\n"
            "  ]\n"
            "}"
        ),
        expected_output="JSON manifest describing the fresh bounded Nmap recon command and optional enumeration helpers.",
        agent=agent,
    )


@TaskRegistry.register("red_team_exploit_planning_task")
def create_red_team_exploit_planning_task(
    agent,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    local_context: str = "",
    database_context: str = "",
) -> Task:
    return Task(
        description=(
            f"{CONCISE_LOCAL_FIRST}\n\n"
            "Create a controlled red-team exploitability plan for an authorized target.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Vulnerability evidence:\n{vulnerability_context}\n\n"
            f"Ingested database exploit context:\n{database_context or 'No database exploit context provided.'}\n\n"
            f"Current live context:\n{local_context or 'None.'}\n\n"
            "First use the ingested database exploit context. If it contains relevant candidates, base the plan on "
            "those records and cite the source/name. Only if the database context explicitly says no strong candidates "
            "were found may you infer conservative candidates from the fresh scan and live fingerprint only. In that fallback mode, "
            "do not claim the service is known-vulnerable, do not name CVEs, and do not suggest sensitive-file paths or traversal to system directories. "
            "Use post-recon enumeration artifacts as supporting evidence when they are present in the scan context. "
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
            "Generate a compact JSON manifest of reviewable red-team validation scripts for this authorized target. "
            "Use the fresh recon evidence, live HTTP fingerprint, configured database context, and exploitability plan; do not rely on a "
            "static tool list or external solution material.\n\n"
            f"Target: {target}\n\n"
            f"Nmap scan evidence:\n{scan_context}\n\n"
            f"Exploitability plan:\n{exploit_plan}\n\n"
            "Use the plan's ingested-database candidates first. If the plan marks LLM fallback, keep checks conservative "
            "and evidence-gathering focused. Do not include a CVE ID, exploit name, or product-specific exploit path unless "
            "that exact CVE/product appears in the ingested database context and also matches the observed product or live fingerprint. "
            "Return only one minified JSON object. If the plan identifies a strong product-specific CVE, "
            "generate exactly 1 script for that focused validation and skip generic checks. Otherwise generate up to 2 scripts "
            "when needed to cover distinct candidates. Keep each script body under 45 lines and avoid comments or repeated report text. Do not wrap "
            "the JSON in markdown.\n\n"
            "Never generate denial-of-service, stress, flooding, resource-exhaustion, crash, persistence, credential theft, "
            "or destructive validation scripts, even if such candidates appear in database context.\n\n"
            "For disclosure-style CVEs, write raw responses only inside OUT_DIR, write redacted evidence artifacts when "
            "sensitive fields may be present, and confirm only when product-specific evidence from recon and database "
            "records is present. Capture HTTP status separately, for example HTTP_STATUS=$(curl -ksS -o \"$RAW\" "
            "-w \"%{http_code}\" \"$URL\"), then parse the raw body file. Use single-quoted grep patterns for JSON keys "
            "or a short Python JSON parser to avoid shell quote errors. Never print passwords, tokens, database users, "
            "database hosts, or secrets.\n\n"
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
            "For account-creation CVEs, prefer a compact bash script: set OUT_DIR, parse --execute, generate USER/PASS "
            "from date +%s only when the live product fingerprint and database record justify that check, use double quotes around shell variables so USER/PASS expand, write observations.txt, confirmed_exploits.txt, and "
            "created_credentials.txt. Scripts must be bounded to the target, log every command, default to dry-run mode when --execute is absent, "
            "and perform active validation only when --execute is present. Parse --execute from any argument, "
            "not only $1. Always write useful evidence to ${OUT_DIR:-.}/observations.txt. When a product-specific CVE "
            "requires creating a temporary proof account to validate exploitability, the script may create exactly one "
            "clearly named authorized-test proof account with a generated username/password, then write the login URL, username, "
            "password, and evidence to ${OUT_DIR:-.}/created_credentials.txt. Do not reuse real credentials or read secrets. "
            "Only write to "
            "${OUT_DIR:-.}/confirmed_exploits.txt when a positive exploitability signal is confirmed, such as an exposed "
            "admin endpoint with 2xx/3xx status, dangerous method explicitly allowed by an Allow/Public header, version disclosure, "
            "vulnerable protocol response, product-specific CVE response, or successful safe check. For authentication bypass/path traversal "
            "checks, compare a direct restricted URL against the bypass URL and confirm only when the direct URL redirects/denies access "
            "while the bypass URL reaches the restricted handler, returns a product-specific exception, sets expected app cookies, or exposes "
            "restricted page content. For account-creation CVEs, confirm only when the create request returns a known product success signal, "
            "the restricted handler is reached with expected cookies/content, a distinctive product-specific exception occurs after the create request, "
            "or a login check proves the generated account works. "
            "For generic cookie/deserialization/upload/traversal checks, never confirm from HTTP 200 alone; require a distinctive "
            "signal such as leaked file contents, a reflected marker, a changed behavior compared with baseline, an executed harmless marker, "
            "or a known product-specific error. Never request sensitive local files such as system password, key, token, or shadow files; "
            "use a harmless marker path or response-difference check instead. Never mark a generic base path, HTTP 200 alone, HTTP 404, 403, 000, empty output, or connection failure as confirmed. Avoid credential theft, "
            "destructive actions, uncontrolled persistence, or targeting anything outside the authorized target."
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
            "Write a red-team validation report for the authorized target.\n\n"
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
