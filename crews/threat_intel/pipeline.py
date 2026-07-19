import json
from pathlib import Path
from typing import Any

import agents.threat_intel  # noqa: F401 - registers threat-intel agents
from agents.execution import run_agent_task_or_fallback
from agents.registry import AgentRegistry
from crews.common.generated_scripts import execute_remediation_scripts
from crews.common.json_output import extract_json_object
from crews.threat_intel.fallbacks import (
    local_correlation_fallback,
    local_prediction_fallback,
    local_remediation_fallback,
    local_vulnerability_fallback,
)
from crews.threat_intel.evidence import (
    _apply_red_team_evidence_guard,
    build_local_threat_context,
    load_evidence,
    render_soc_evidence_report,
    summarize_evidence_sources,
    summarize_services,
    truncate_context,
)
from crews.threat_intel.storage import (
    build_run_artifacts,
    remediation_execution_overview,
    remediation_execution_status,
    save_run,
)
from crews.threat_intel.tool_generation_stage import run_tool_generation_stage
from tasks.threat_intel import (
    create_correlation_task,
    create_prediction_task,
    create_remediation_task,
    create_vulnerability_scan_task,
)


OUTPUT_DIR = Path("outputs")
RUNS_DIR = OUTPUT_DIR / "runs"
CURRENT_GENERATED_TOOLS_DIR = OUTPUT_DIR / "generated_tools"
DEFAULT_DB_PATH = OUTPUT_DIR / "threat_intel_results.db"


def next_artifact_run_id(preferred_id: int | None = None) -> int:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    existing_ids = []
    for path in RUNS_DIR.glob("run_[0-9][0-9][0-9][0-9]"):
        if not path.is_dir():
            continue
        try:
            existing_ids.append(int(path.name.removeprefix("run_")))
        except ValueError:
            continue
    if preferred_id is not None and preferred_id not in existing_ids:
        return preferred_id
    return (max(existing_ids) + 1) if existing_ids else (preferred_id or 1)


def run_vulnerability_stage(
    scan: dict[str, Any],
    include_previous_context: bool = True,
    local_context: str = "",
) -> tuple[dict[str, Any], str]:
    scan_json = json.dumps(scan, indent=2)
    agent = AgentRegistry.get_agent("vulnerability_scan_agent")
    task = create_vulnerability_scan_task(
        agent,
        truncate_context(scan_json, 2500),
        truncate_context(local_context, 1800),
    )
    raw_output = run_agent_task_or_fallback("vulnerability_scan_agent", task, local_vulnerability_fallback(scan))
    try:
        return extract_json_object(raw_output), raw_output
    except Exception:
        return {
            "scanner": "llm_database_enrichment",
            "finding_count": 0,
            "findings": [],
            "raw_enrichment": raw_output,
        }, raw_output


def run_guarded_text_stage(
    agent_name: str,
    task_factory,
    fallback: str,
    scan: dict[str, Any],
    *task_args,
) -> str:
    agent = AgentRegistry.get_agent(agent_name)
    task = task_factory(agent, *task_args)
    output = run_agent_task_or_fallback(agent_name, task, fallback)
    return _apply_red_team_evidence_guard(output, scan)


def run_correlation_stage(
    target: str,
    scan: dict[str, Any],
    scan_context: str,
    vulnerability_context: str,
    telemetry_context: str,
    local_threat_context: str,
) -> str:
    return run_guarded_text_stage(
        "correlation_agent",
        create_correlation_task,
        local_correlation_fallback(target, vulnerability_context),
        scan,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(vulnerability_context, 2200),
        telemetry_context,
        truncate_context(local_threat_context, 1600),
    )


def run_prediction_stage(
    target: str,
    scan: dict[str, Any],
    correlation_report: str,
    vulnerability_context: str,
    local_threat_context: str,
) -> str:
    return run_guarded_text_stage(
        "prediction_agent",
        create_prediction_task,
        local_prediction_fallback(target, vulnerability_context),
        scan,
        target,
        truncate_context(correlation_report, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(local_threat_context, 1400),
    )


def run_remediation_stage(
    target: str,
    scan: dict[str, Any],
    soc_report: str,
    vulnerability_context: str,
    correlation_report: str,
    prediction_report: str,
    local_threat_context: str,
) -> str:
    return run_guarded_text_stage(
        "remediation_agent",
        create_remediation_task,
        local_remediation_fallback(target, vulnerability_context),
        scan,
        target,
        truncate_context(soc_report, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(correlation_report, 1300),
        truncate_context(prediction_report, 1000),
        truncate_context(local_threat_context, 1400),
    )


def run_threat_intel_pipeline(
    target: str = "172.17.0.2",
    db_path: str | Path = DEFAULT_DB_PATH,
    evidence_path: str = "",
    reuse_scan: str = "",
    include_remediation_plan: bool = True,
    auto_execute_remediation: bool = True,
    auto_apply_remediation: bool = False,
    remediation_timeout: int = 120,
) -> dict[str, Any]:
    artifact_run_id = next_artifact_run_id()
    evidence_file = evidence_path or reuse_scan
    scan, raw_evidence = load_evidence(evidence_file, target)
    service_summary = summarize_services(scan)
    evidence_summary = summarize_evidence_sources(scan)
    local_threat_context = build_local_threat_context(scan, raw_evidence)

    vulnerability_json, vulnerability_report = run_vulnerability_stage(scan, local_context=local_threat_context)
    scan_context = json.dumps(scan, indent=2)
    vulnerability_context = (
        vulnerability_report
        if vulnerability_report.strip()
        else json.dumps(vulnerability_json, indent=2)
    )

    telemetry_context = (
        "Use the provided tool logs/evidence as the collection source for this run.\n\n"
        + truncate_context(evidence_summary, 1800)
        + "\n\n"
        + truncate_context(local_threat_context, 1800)
    )
    correlation_report = run_correlation_stage(
        target,
        scan,
        scan_context,
        vulnerability_context,
        telemetry_context,
        local_threat_context,
    )

    prediction_report = run_prediction_stage(
        target,
        scan,
        correlation_report,
        vulnerability_context,
        local_threat_context,
    )

    soc_report = render_soc_evidence_report(target, scan)
    soc_report = _apply_red_team_evidence_guard(soc_report, scan)

    script_artifacts = None
    if include_remediation_plan:
        remediation_plan = run_remediation_stage(
            target,
            scan,
            soc_report,
            vulnerability_context,
            correlation_report,
            prediction_report,
            local_threat_context,
        )

        script_artifacts = run_tool_generation_stage(
            artifact_run_id,
            target,
            scan_context,
            vulnerability_context + "\n\n" + truncate_context(local_threat_context, 1800),
            correlation_report,
            prediction_report,
            soc_report,
            remediation_plan,
        )
    else:
        remediation_plan = "Remediation plan intentionally excluded for this run."

    run_id = save_run(
        Path(db_path),
        target,
        "provided-evidence",
        scan,
        service_summary,
        vulnerability_context,
        soc_report,
        remediation_plan,
    )
    remediation_execution = None
    if auto_execute_remediation and script_artifacts:
        remediation_execution = execute_remediation_scripts(
            script_artifacts,
            apply_changes=auto_apply_remediation,
            timeout=remediation_timeout,
        )
    artifacts = build_run_artifacts(
        run_id,
        artifact_run_id,
        target,
        "provided-evidence",
        "complete" if include_remediation_plan else "complete_without_remediation",
        scan,
        service_summary,
        evidence_summary,
        vulnerability_context,
        correlation_report,
        prediction_report,
        soc_report,
        remediation_plan,
        raw_evidence,
        script_artifacts,
        remediation_execution,
    )
    return {
        "run_id": run_id,
        "artifact_run_id": artifact_run_id,
        "status": "complete" if include_remediation_plan else "complete_without_remediation",
        "target": target,
        "evidence_path": evidence_file,
        "scan": scan,
        "service_summary": service_summary,
        "evidence_summary": evidence_summary,
        "vulnerability_scan": vulnerability_json,
        "vulnerability_report": vulnerability_context,
        "local_threat_context": local_threat_context,
        "correlation_report": correlation_report,
        "prediction_report": prediction_report,
        "soc_report": soc_report,
        "remediation_plan": remediation_plan,
        "remediation_plan_excluded": not include_remediation_plan,
        "db_path": str(db_path),
        "artifacts": artifacts,
        "generated_scripts": script_artifacts["manifest"] if script_artifacts else None,
        "remediation_execution_status": remediation_execution_status(remediation_execution),
        "remediation_summary": remediation_execution_overview(remediation_execution),
        "remediation_execution": remediation_execution,
    }


def main() -> None:
    from crews.threat_intel.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
