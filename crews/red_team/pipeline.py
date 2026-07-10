import argparse
import json
from pathlib import Path
from typing import Any

import agents.red_team  # noqa: F401 - registers red-team agents
import agents.threat_intel  # noqa: F401 - registers shared threat-intel agents
from agents.execution import run_agent_task
from agents.registry import AgentRegistry
from agents.tool_config import configured_tool_names
from crews.common.generated_scripts import (
    execute_red_team_scripts,
    normalize_red_team_script_body,
    write_script_manifest,
)
from crews.red_team.config import (
    RED_TEAM_SPECIALISTS,
    red_team_artifact_name,
    red_team_artifact_path,
    red_team_generated_tool_active_args,
    red_team_pipeline_agents,
    red_team_specialist_config,
)
from crews.red_team.exploits import build_exploit_candidate_context
from crews.red_team.recon import local_http_context, run_dynamic_red_team_recon_stage
from crews.red_team.results import (
    build_human_execution_summary,
    extract_confirmed_exploits,
    extract_created_credentials,
    red_team_execution_status,
    render_human_execution_summary,
    target_only_context,
)
from crews.threat_intel.pipeline import (
    RUNS_DIR,
    extract_json_object,
    next_artifact_run_id,
    run_vulnerability_stage,
    salvage_generated_script_objects,
    truncate_context,
)
from tasks.registry import TaskRegistry
from tasks.red_team import (
    create_red_team_exploit_planning_task,
    create_red_team_reporting_task,
    create_red_team_tool_generation_task,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the authorized red-team validation pipeline.")
    parser.add_argument("target", help="Authorized target.")
    parser.add_argument("--domain", choices=sorted(RED_TEAM_SPECIALISTS), help="Run only one specialist domain.")
    parser.add_argument("--ports", default="1-10000", help="Nmap port expression.")
    parser.add_argument("--timeout", type=int, default=180, help="Nmap timeout in seconds.")
    parser.add_argument("--reuse-scan", default="", help="Deprecated; red-team recon is generated fresh every run.")
    parser.add_argument("--use-agents", action="store_true", help="Deprecated; red-team planning now uses agents.")
    parser.add_argument("--no-nmap-agent", action="store_true", help="Deprecated compatibility flag.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated validation scripts. Default only generates the scripts.",
    )
    parser.add_argument("--execution-timeout", type=int, default=180, help="Timeout per generated script.")
    parser.add_argument("--environment-context", default="", help="Optional notes about the authorized target environment.")
    parser.add_argument("--environment-file", default="", help="Optional file with authorized environment details.")
    return parser.parse_args()


def _load_environment_context(environment_context: str = "", environment_file: str = "") -> str:
    if environment_file:
        path = Path(environment_file)
        if not path.is_file():
            raise ValueError(f"Environment context file not found: {environment_file}")
        file_context = path.read_text(encoding="utf-8", errors="replace")
        return (environment_context + "\n\n" + file_context).strip()
    return environment_context.strip()


def _render_executive_summary(
    target: str,
    nmap_source: str,
    plan_text: str,
    scripts: list[dict[str, Any]],
    human_result_text: str,
    execution: dict[str, Any] | None,
    report: str = "",
    specialist: str = "",
) -> str:
    lines = [
        "# Executive Summary",
        "",
        f"Target: `{target}`",
    ]
    if specialist:
        lines.append(f"Specialist: `{specialist}`")
    lines.extend(
        [
            f"Enumeration source: `{nmap_source}`",
            "",
        ]
    )
    if report:
        lines.extend(["## Report", "", report, ""])
    lines.extend(["## Exploit Plan" if not specialist else "## Specialist Plan", "", plan_text, "", "## Validation Scripts", ""])
    if scripts:
        for script in scripts:
            lines.append(f"- `{script['filename']}`: {script.get('purpose', 'Generated validation script')}")
    else:
        lines.append("- No scripts were generated.")
    lines.extend(["", "## Execution", "", human_result_text, "", "## Raw Execution JSON", ""])
    lines.append(json.dumps(execution or {"status": "not_executed"}, indent=2))
    return "\n".join(lines).rstrip() + "\n"


def _scan_service_terms(scan: dict[str, Any]) -> set[str]:
    terms = set()
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            terms.add(str(port.get("port") or "").lower())
            for key in ("service", "product", "version", "extra_info"):
                for token in str(port.get(key) or "").lower().replace("/", " ").replace("(", " ").replace(")", " ").split():
                    if len(token) >= 3:
                        terms.add(token)
    return terms


def _plan_references_observed_surface(plan: str, scan: dict[str, Any]) -> bool:
    scan_terms = _scan_service_terms(scan)
    if not scan_terms:
        return False
    plan_lower = str(plan or "").lower()
    return any(term and term in plan_lower for term in scan_terms)


def _scan_bound_plan(scan: dict[str, Any], exploit_context: dict[str, Any]) -> str:
    lines = []
    records = exploit_context.get("records") or []
    for host in scan.get("hosts", []):
        host_id = host.get("host") or scan.get("target")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = " ".join(
                str(port.get(key) or "")
                for key in ("service", "product", "version", "extra_info")
                if port.get(key)
            ).strip() or f"port {port.get('port')}"
            matching = []
            service_text = service.lower()
            for record in records:
                record_text = " ".join(str(record.get(key) or "") for key in ("name", "text")).lower()
                if any(token in record_text for token in service_text.split() if len(token) >= 4):
                    matching.append(record)
                if len(matching) >= 3:
                    break
            candidate_names = ", ".join(str(item.get("name") or item.get("type")) for item in matching) or "no strong database CVE match"
            lines.append(
                "\n".join(
                    [
                        f"{len(lines) + 1}. **Service**: {host_id}:{port.get('port')}/TCP - {service}",
                        f"   **Reason**: Open service from Nmap; database-first candidates: {candidate_names}.",
                        "   **Safe Validation Idea**: Generate bounded evidence checks only for this observed service; do not test unavailable ports or services.",
                        "   **Prerequisite**: Validate only against the observed open port and require distinctive evidence before confirming exploitability.",
                    ]
                )
            )
    return "\n\n".join(lines) or "No open services were available for exploit planning."


def _no_surface_plan(exploit_context: dict[str, Any]) -> str:
    if exploit_context.get("source_mode") == "no_recon_surface":
        return (
            "No exploit plan was generated because fresh recon found no open services "
            "and no live HTTP fingerprint for the target."
        )
    return ""


def _enforce_scan_bound_plan(plan: str, scan: dict[str, Any], exploit_context: dict[str, Any]) -> str:
    plan_lower = str(plan or "").lower()
    if exploit_context.get("source_mode") == "llm_fallback" and _contains_unsupported_fallback_specifics(plan_lower):
        return _scan_bound_plan(scan, exploit_context)
    if not _plan_references_observed_surface(plan, scan):
        return _scan_bound_plan(scan, exploit_context)
    return plan


def _contains_unsupported_fallback_specifics(text: str) -> bool:
    text_lower = str(text or "").lower()
    unsupported_fallback_markers = (
        "cve-",
        "known to be vulnerable",
        "known vulnerabilities",
        "/etc",
        "../",
        "passwd",
        "shadow",
        "/proc",
        "/var/www",
    )
    return any(marker in text_lower for marker in unsupported_fallback_markers)


def _manifest_uses_unsupported_fallback_specifics(manifest: dict[str, Any], exploit_context: dict[str, Any] | None) -> bool:
    if not exploit_context or exploit_context.get("source_mode") != "llm_fallback":
        return False
    return _contains_unsupported_fallback_specifics(json.dumps(manifest, sort_keys=True))


def run_red_team_tool_generation_stage(
    artifact_run_id: int,
    target: str,
    scan_context: str,
    plan_context: str,
    exploit_context: dict[str, Any] | None = None,
    http_context: str = "",
) -> dict[str, Any]:
    if exploit_context and exploit_context.get("source_mode") == "no_recon_surface":
        return write_script_manifest(
            run_dir=(RUNS_DIR / f"run_{artifact_run_id:04d}" / red_team_artifact_name("tools_subdir")).resolve(),
            current_dir=red_team_artifact_path("current_tools_dir").resolve(),
            target=target,
            manifest={
                "agent": "red_team_tool_generation_agent",
                "mode": "fresh_recon_no_surface",
                "safety": "No validation scripts generated because fresh recon found no open services.",
                "target": target,
                "scripts": [],
            },
            default_agent="red_team_tool_generation_agent",
            default_mode="fresh_recon_no_surface",
            safety="No validation scripts generated because fresh recon found no open services.",
            normalizer=normalize_red_team_script_body,
        )
    tool_agent = AgentRegistry.get_agent("red_team_tool_generation_agent")
    retry_plan_context = truncate_context(plan_context, 6000)
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    for attempt in range(2):
        tool_task = create_red_team_tool_generation_task(
            tool_agent,
            target,
            truncate_context(scan_context, 4500),
            retry_plan_context,
        )
        raw_manifest = run_agent_task("red_team_tool_generation_agent", tool_task)
        try:
            manifest = extract_json_object(raw_manifest)
        except Exception:
            repaired_manifest = raw_manifest.replace("\\$", "$")
            try:
                manifest = extract_json_object(repaired_manifest)
            except Exception:
                manifest = {
                    "agent": "red_team_tool_generation_agent",
                    "mode": "llm_generated_each_run",
                    "safety": "Tool generation output could not be parsed as JSON.",
                    "scripts": salvage_generated_script_objects(repaired_manifest),
                    "raw_output": raw_manifest,
                }
        if _manifest_uses_unsupported_fallback_specifics(manifest, exploit_context):
            manifest["scripts"] = []
            raw_manifest = json.dumps(manifest)
        if manifest.get("scripts"):
            break
        retry_plan_context = (
            "Previous tool manifest was invalid, empty, or had no scripts. "
            "Return only complete valid minified JSON. Do not escape dollar signs. "
            "Generate exactly one compact bash script for the strongest fresh-recon validation candidate. "
            "If exploit source mode is llm_fallback, do not include CVE IDs, known-vulnerable claims, traversal payloads, "
            "or sensitive filesystem paths; use only conservative banner, header, method, and response-difference evidence checks. "
            "If this is an account-creation CVE, include the generated username/password and login URL in "
            "created_credentials.txt. Keep script body under 45 lines.\n\n"
            f"Original plan:\n{truncate_context(plan_context, 3500)}\n\n"
            f"Previous output excerpt:\n{truncate_context(raw_manifest, 1200)}"
        )
    return write_script_manifest(
        run_dir=(RUNS_DIR / f"run_{artifact_run_id:04d}" / red_team_artifact_name("tools_subdir")).resolve(),
        current_dir=red_team_artifact_path("current_tools_dir").resolve(),
        target=target,
        manifest=manifest,
        default_agent="red_team_tool_generation_agent",
        default_mode="llm_generated_each_run",
        safety="Scripts default to dry-run and require --execute for active validation.",
        normalizer=normalize_red_team_script_body,
    )


def run_red_team_specialist_pipeline(
    domain: str,
    target: str,
    ports: str = "1-10000",
    timeout: int = 180,
    reuse_scan: str = "",
    use_nmap_agent: bool = True,
    use_llm_agent: bool = False,
    execute: bool = False,
    execution_timeout: int = 180,
    environment_context: str = "",
) -> dict[str, Any]:
    if domain not in RED_TEAM_SPECIALISTS:
        raise ValueError(f"Unsupported red-team domain: {domain}")

    artifact_run_id = next_artifact_run_id()
    scan, _nmap_output, recon_artifacts, recon_execution = run_dynamic_red_team_recon_stage(
        artifact_run_id,
        target,
        ports,
        timeout,
    )
    nmap_source = "red_team_recon_agent_dynamic_command"

    vulnerability_scan, vulnerability_context = run_vulnerability_stage(scan, include_previous_context=False)
    vulnerability_context = target_only_context(vulnerability_context, target)
    scan_context = json.dumps(scan, indent=2)
    live_context = local_http_context(scan)
    exploit_context = build_exploit_candidate_context(scan, http_context=live_context)
    exploit_context_text = exploit_context["summary"]

    specialist_spec = red_team_specialist_config()[domain]
    agent_name = specialist_spec["agent"]
    agent = AgentRegistry.get_agent(agent_name)
    task = TaskRegistry.get_task(
        specialist_spec["planning_task"],
        agent=agent,
        target=target,
        scan_context=truncate_context(scan_context, 2200),
        vulnerability_context=(
            truncate_context(vulnerability_context, 1800)
            + "\n\nDatabase-first exploit context:\n"
            + truncate_context(exploit_context_text, 2600)
            + "\n\nLive HTTP fingerprint:\n"
            + truncate_context(live_context or "No HTTP fingerprint was collected. Infer only from fresh recon, database, and authorized environment context.", 4200)
            + "\n\nAuthorized environment context:\n"
            + truncate_context(environment_context or "No extra environment context provided.", 1200)
        ),
    )
    agent_output = run_agent_task(agent_name, task)
    agent_output = _no_surface_plan(exploit_context) or agent_output
    agent_output = _enforce_scan_bound_plan(agent_output, scan, exploit_context)
    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        truncate_context(scan_context, 2200),
        (
            f"Specialist domain: {domain}\n\n"
            f"Exploit source mode: {exploit_context['source_mode']}\n\n"
            f"Database-first exploit context:\n{truncate_context(exploit_context_text, 2600)}\n\n"
            f"Authorized environment context:\n{truncate_context(environment_context or 'No extra environment context provided.', 1200)}\n\n"
            f"Live HTTP fingerprint:\n{truncate_context(live_context or 'No HTTP fingerprint was collected. Infer only from fresh recon, database, and authorized environment context.', 4200)}\n\n"
            f"Specialist plan:\n{agent_output}"
        ),
        exploit_context=exploit_context,
        http_context=live_context,
    )
    execution = (
        execute_red_team_scripts(tool_artifacts, execution_timeout, red_team_generated_tool_active_args())
        if execute
        else None
    )
    working_exploits = extract_confirmed_exploits(execution)
    created_credentials = extract_created_credentials(execution)
    human_summary = build_human_execution_summary(execution)
    human_result_text = render_human_execution_summary(human_summary)
    summary = _render_executive_summary(
        target=target,
        nmap_source=nmap_source,
        plan_text=agent_output,
        scripts=tool_artifacts["manifest"].get("scripts", []),
        human_result_text=human_result_text,
        execution=execution,
        specialist=domain,
    )

    run_dir = Path(tool_artifacts["tools_dir"])
    result_path = run_dir / "result.json"
    scan_path = run_dir / "nmap_scan.json"
    summary_path = run_dir / "executive_summary.md"
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    summary_path.write_text(summary, encoding="utf-8")

    result = {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "domain": domain,
        "agent": agent_name,
        "target": target,
        "nmap_source": nmap_source,
        "candidate_count": None,
        "candidates": [],
        "execute": execute,
        "context_policy": "fresh_recon_only_no_docs_no_previous_outputs",
        "execution": execution,
        "execution_status": red_team_execution_status(execution),
        "human_summary": human_summary,
        "working_exploits": working_exploits,
        "created_credentials": created_credentials,
        "executive_summary": summary,
        "agent_output": agent_output,
        "exploit_source_mode": exploit_context["source_mode"],
        "database_exploit_candidates": exploit_context["records"],
        "generated_scripts": tool_artifacts["manifest"],
        "artifacts": {
            "run_dir": str(run_dir),
            "result": str(result_path),
            "tool_manifest": str(tool_artifacts["manifest_path"]),
            "nmap_scan": str(scan_path),
            "executive_summary": str(summary_path),
        },
    }
    if recon_artifacts:
        result["artifacts"]["red_team_recon_manifest"] = str(recon_artifacts["manifest_path"])
    if recon_execution:
        result["artifacts"]["red_team_recon_execution_results"] = recon_execution["results_path"]
    if execution:
        result["artifacts"]["execution_results"] = execution["results_path"]
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def run_red_team_pipeline(
    target: str,
    ports: str = "1-10000",
    timeout: int = 180,
    reuse_scan: str = "",
    use_agents: bool = False,
    execute: bool = False,
    execution_timeout: int = 180,
    environment_context: str = "",
) -> dict[str, Any]:
    artifact_run_id = next_artifact_run_id()
    scan, _nmap_output, recon_artifacts, recon_execution = run_dynamic_red_team_recon_stage(
        artifact_run_id,
        target,
        ports,
        timeout,
    )
    nmap_source = "red_team_recon_agent_dynamic_command"
    vulnerability_scan, vulnerability_output = run_vulnerability_stage(scan, include_previous_context=False)
    vulnerability_output = target_only_context(vulnerability_output, target)

    scan_context = json.dumps(scan, indent=2)
    live_context = local_http_context(scan)
    live_context_text = live_context or "No HTTP fingerprint was collected. Infer only from fresh recon, database, and authorized environment context."
    environment_context_text = environment_context or "No extra environment context provided."
    exploit_context = build_exploit_candidate_context(scan, http_context=live_context)
    exploit_context_text = exploit_context["summary"]

    agents_used = red_team_pipeline_agents()
    tools_used = sorted(
        {tool for agent_name in agents_used for tool in configured_tool_names(agent_name)}
        | {"llm_generated_red_team_tools"}
    )

    planner = AgentRegistry.get_agent("red_team_exploit_planner_agent")
    planning_task = create_red_team_exploit_planning_task(
        planner,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(vulnerability_output, 2000),
        truncate_context(
            "Authorized environment context:\n"
            + environment_context_text
            + "\n\nLive HTTP fingerprint:\n"
            + live_context_text,
            3200,
        ),
        truncate_context(exploit_context_text, 3200),
    )
    plan_text = run_agent_task("red_team_exploit_planner_agent", planning_task)
    plan_text = _no_surface_plan(exploit_context) or plan_text
    plan_text = _enforce_scan_bound_plan(plan_text, scan, exploit_context)
    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(
            f"Exploit source mode: {exploit_context['source_mode']}\n\n"
            f"Database-first exploit context:\n{exploit_context_text}\n\n"
            f"Authorized environment context:\n{environment_context_text}\n\n"
            f"Live HTTP fingerprint:\n{live_context_text}\n\n"
            f"Plan:\n{plan_text}",
            6200,
        ),
        exploit_context=exploit_context,
        http_context=live_context,
    )
    execution = (
        execute_red_team_scripts(tool_artifacts, execution_timeout, red_team_generated_tool_active_args())
        if execute
        else None
    )
    human_summary = build_human_execution_summary(execution)
    human_result_text = render_human_execution_summary(human_summary)
    execution_context = human_result_text
    reporter = AgentRegistry.get_agent("red_team_reporting_agent")
    report_task = create_red_team_reporting_task(
        reporter,
        target,
        truncate_context(scan_context, 1800),
        truncate_context(plan_text, 2500),
        truncate_context(execution_context, 1200),
    )
    report = run_agent_task("red_team_reporting_agent", report_task)

    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    used_path = run_dir / "red_team_used.json"
    summary = _render_executive_summary(
        target=target,
        nmap_source=nmap_source,
        plan_text=plan_text,
        scripts=tool_artifacts["manifest"].get("scripts", []),
        human_result_text=human_result_text,
        execution=execution,
        report=report,
    )
    summary_path = Path(tool_artifacts["tools_dir"]) / "executive_summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    used = {
        "agents": agents_used,
        "tools": tools_used,
        "report": report,
        "executive_summary": summary,
        "plan": plan_text,
        "exploit_source_mode": exploit_context["source_mode"],
        "database_exploit_candidates": exploit_context["records"],
        "human_summary": human_summary,
        "scripts": tool_artifacts["manifest"]["scripts"],
        "nmap_source": nmap_source,
        "context_policy": "fresh_recon_only_no_docs_no_previous_outputs",
        "artifacts": {
            "run_dir": str(run_dir),
            "red_team_tools_manifest": str(tool_artifacts["manifest_path"]),
            "current_red_team_tools": str(tool_artifacts["current_tools_dir"]),
            "executive_summary": str(summary_path),
        },
    }
    if recon_artifacts:
        used["artifacts"]["red_team_recon_manifest"] = str(recon_artifacts["manifest_path"])
        used["artifacts"]["current_red_team_recon"] = str(recon_artifacts["current_tools_dir"])
    if recon_execution:
        used["artifacts"]["red_team_recon_execution_results"] = recon_execution["results_path"]
    if execution:
        used["artifacts"]["execution_results"] = execution["results_path"]
    used_path.write_text(json.dumps(used, indent=2), encoding="utf-8")

    return {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "target": target,
        "ports": ports,
        "nmap_source": nmap_source,
        "candidate_count": None,
        "execute": execute,
        "context_policy": "fresh_recon_only_no_docs_no_previous_outputs",
        "agents_used": agents_used,
        "tools_used": tools_used,
        "artifacts": used["artifacts"],
        "recon_execution": recon_execution,
        "execution": execution,
        "execution_status": red_team_execution_status(execution),
        "human_summary": human_summary,
        "plan": plan_text,
        "exploit_source_mode": exploit_context["source_mode"],
        "database_exploit_candidates": exploit_context["records"],
        "generated_scripts": tool_artifacts["manifest"],
    }


def main() -> None:
    args = parse_args()
    environment_context = _load_environment_context(args.environment_context, args.environment_file)
    if args.domain:
        result = run_red_team_specialist_pipeline(
            domain=args.domain,
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_nmap_agent=not args.no_nmap_agent,
            use_llm_agent=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
            environment_context=environment_context,
        )
    else:
        result = run_red_team_pipeline(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_agents=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
            environment_context=environment_context,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
