import json
from pathlib import Path
from typing import Any

import agents.red_team  # noqa: F401 - registers red-team agents
import agents.threat_intel  # noqa: F401 - registers shared threat-intel agents
from agents.execution import run_agent_task
from agents.registry import AgentRegistry
from agents.tool_config import configured_tool_names
from crews.common.generated_scripts import execute_red_team_scripts
from crews.red_team.config import (
    RED_TEAM_SPECIALISTS,
    red_team_generated_tool_active_args,
    red_team_pipeline_agents,
    red_team_specialist_config,
)
from crews.red_team.exploits import build_exploit_candidate_context
from crews.red_team.planning import (
    _lab_scoped_tomcat_put_plan,
    _database_ranked_plan,
    _enforce_scan_bound_plan,
    _no_surface_plan,
    _render_executive_summary,
)
from crews.red_team.recon import local_http_context, run_dynamic_red_team_recon_stage
from crews.red_team.results import (
    build_human_execution_summary,
    extract_confirmed_exploits,
    extract_created_credentials,
    red_team_execution_status,
    render_red_team_evidence_report,
    render_human_execution_summary,
    target_only_context,
)
from crews.red_team.tool_generation_stage import run_red_team_tool_generation_stage
from crews.threat_intel.pipeline import (
    RUNS_DIR,
    next_artifact_run_id,
    run_vulnerability_stage,
    truncate_context,
)
from tasks.registry import TaskRegistry
from tasks.red_team import create_red_team_exploit_planning_task



def prepare_red_team_run_context(
    artifact_run_id: int,
    target: str,
    ports: str,
    timeout: int,
    skip_vulnerability_stage: bool = False,
    skip_exploit_context: bool = False,
) -> dict[str, Any]:
    scan, _nmap_output, recon_artifacts, recon_execution = run_dynamic_red_team_recon_stage(
        artifact_run_id,
        target,
        ports,
        timeout,
    )
    if skip_vulnerability_stage:
        vulnerability_scan = {
            "scanner": "skipped_for_lab_scoped_validation",
            "finding_count": 0,
            "findings": [],
        }
        vulnerability_context = "Vulnerability stage skipped for lab-scoped validation run."
    else:
        vulnerability_scan, vulnerability_context = run_vulnerability_stage(scan, include_previous_context=False)
        vulnerability_context = target_only_context(vulnerability_context, target)
    scan_context = json.dumps(scan, indent=2)
    live_context = local_http_context(scan)
    if skip_exploit_context:
        exploit_context = {
            "source_mode": "lab_scoped_validation",
            "summary": "Lab-scoped Tomcat CVE-2017-12615 validation only.",
            "records": [],
        }
    else:
        exploit_context = build_exploit_candidate_context(scan, http_context=live_context)
    return {
        "scan": scan,
        "recon_artifacts": recon_artifacts,
        "recon_execution": recon_execution,
        "nmap_source": "red_team_recon_agent_dynamic_command",
        "vulnerability_scan": vulnerability_scan,
        "vulnerability_context": vulnerability_context,
        "scan_context": scan_context,
        "live_context": live_context,
        "live_context_text": live_context
        or "No HTTP fingerprint was collected. Infer only from fresh recon, database, and authorized environment context.",
        "exploit_context": exploit_context,
        "exploit_context_text": exploit_context["summary"],
    }


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
    use_lab_notes: bool = False,
    environment_context: str = "",
) -> dict[str, Any]:
    if domain not in RED_TEAM_SPECIALISTS:
        raise ValueError(f"Unsupported red-team domain: {domain}")

    artifact_run_id = next_artifact_run_id()
    context = prepare_red_team_run_context(artifact_run_id, target, ports, timeout)
    scan = context["scan"]
    recon_artifacts = context["recon_artifacts"]
    recon_execution = context["recon_execution"]
    nmap_source = context["nmap_source"]
    vulnerability_context = context["vulnerability_context"]
    scan_context = context["scan_context"]
    live_context = context["live_context"]
    exploit_context = context["exploit_context"]
    exploit_context_text = context["exploit_context_text"]

    specialist_spec = red_team_specialist_config()[domain]
    agent_name = specialist_spec["agent"]
    agent_output = _no_surface_plan(exploit_context)
    if not agent_output:
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
    agent_output = _enforce_scan_bound_plan(agent_output, scan, exploit_context)
    agent_output = _database_ranked_plan(scan, exploit_context) or agent_output
    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        scan_context,
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
    report = render_red_team_evidence_report(
        target,
        scan,
        tool_artifacts["manifest"].get("scripts", []),
        human_summary,
    )
    summary = _render_executive_summary(
        target=target,
        nmap_source=nmap_source,
        plan_text=agent_output,
        scripts=tool_artifacts["manifest"].get("scripts", []),
        human_result_text=human_result_text,
        execution=execution,
        report=report,
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
        "report": report,
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
    use_lab_notes: bool = False,
    environment_context: str = "",
) -> dict[str, Any]:
    artifact_run_id = next_artifact_run_id()
    environment_context_text = environment_context or "No extra environment context provided."
    lab_scoped_tomcat = "Vulhub Engagement Letter: Tomcat CVE-2017-12615 Lab" in environment_context_text
    if lab_scoped_tomcat:
        context = prepare_red_team_run_context(
            artifact_run_id,
            target,
            ports,
            timeout,
            skip_vulnerability_stage=True,
            skip_exploit_context=True,
        )
    else:
        context = prepare_red_team_run_context(artifact_run_id, target, ports, timeout)
    scan = context["scan"]
    recon_artifacts = context["recon_artifacts"]
    recon_execution = context["recon_execution"]
    nmap_source = context["nmap_source"]
    vulnerability_output = context["vulnerability_context"]
    scan_context = context["scan_context"]
    live_context = context["live_context"]
    live_context_text = context["live_context_text"]
    exploit_context = context["exploit_context"]
    exploit_context_text = context["exploit_context_text"]

    agents_used = red_team_pipeline_agents()
    tools_used = sorted(
        {tool for agent_name in agents_used for tool in configured_tool_names(agent_name)}
        | {"llm_generated_red_team_tools"}
    )

    plan_text = _no_surface_plan(exploit_context)
    if not plan_text:
        if lab_scoped_tomcat:
            plan_text = _lab_scoped_tomcat_put_plan(target, ports)
            exploit_context = {
                "source_mode": "lab_scoped_validation",
                "summary": "Lab-scoped Tomcat CVE-2017-12615 validation only.",
                "records": [],
            }
            exploit_context_text = exploit_context["summary"]
        else:
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
    plan_text = _enforce_scan_bound_plan(plan_text, scan, exploit_context)
    if not lab_scoped_tomcat:
        plan_text = _database_ranked_plan(scan, exploit_context) or plan_text
    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        scan_context,
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
    report = render_red_team_evidence_report(
        target,
        scan,
        tool_artifacts["manifest"].get("scripts", []),
        human_summary,
    )

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
    from crews.red_team.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
