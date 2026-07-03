import argparse
import json
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crewai import Crew, Process

import agents.intel_agents  # noqa: F401 - registers threat-intel agents
from agents.registry import AgentRegistry
from tasks.intel_tasks import (
    create_correlation_task,
    create_nmap_scan_task,
    create_prediction_task,
    create_remediation_task,
    create_reporting_task,
    create_tool_generation_task,
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CrewAI SOC threat-intel pipeline.")
    parser.add_argument("target", nargs="?", default="172.17.0.2", help="Authorized lab target.")
    parser.add_argument("--ports", default="1-10000", help="Nmap port expression.")
    parser.add_argument("--timeout", type=int, default=180, help="Nmap timeout in seconds.")
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="SQLite output path.")
    parser.add_argument("--reuse-scan", default="", help="Optional existing Nmap JSON file.")
    parser.add_argument(
        "--no-auto-remediation",
        action="store_true",
        help="Generate tool scripts without automatically executing them.",
    )
    parser.add_argument(
        "--skip-remediation-plan",
        action="store_true",
        help="Skip response/remediation planning and generated remediation scripts for this run.",
    )
    parser.add_argument(
        "--auto-apply-remediation",
        action="store_true",
        help="Execute generated remediation scripts with --apply instead of dry-run mode.",
    )
    parser.add_argument(
        "--remediation-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for each generated remediation script.",
    )
    return parser.parse_args()


def run_agent_task(agent_name: str, task) -> str:
    agent = AgentRegistry.get_agent(agent_name)
    task.agent = agent
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)
    return str(crew.kickoff())


def extract_json_object(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in agent output.")
    return json.loads(match.group(0))


def salvage_generated_script_objects(text: str, max_scripts: int = 2) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    script_start = text.find('"scripts"')
    if script_start == -1:
        return scripts

    scan_position = script_start
    while len(scripts) < max_scripts:
        object_start = text.find("{", scan_position)
        if object_start == -1:
            break
        try:
            candidate, object_end = decoder.raw_decode(text[object_start:])
        except json.JSONDecodeError:
            scan_position = object_start + 1
            continue

        scan_position = object_start + object_end
        if not isinstance(candidate, dict):
            continue
        if not candidate.get("body"):
            continue
        candidate.setdefault("name", f"generated_tool_{len(scripts) + 1}")
        candidate.setdefault("filename", f"{len(scripts) + 1:02d}_{candidate['name']}.sh")
        candidate.setdefault("interpreter", "bash")
        scripts.append(candidate)
    return scripts


def truncate_context(text: str, limit: int = 5000) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n\n[truncated for tool generation]"


def previous_output_context(
    filenames: tuple[str, ...],
    max_runs: int = 3,
    chars_per_file: int = 700,
) -> str:
    snippets = []
    for run_dir in sorted(RUNS_DIR.glob("run_[0-9][0-9][0-9][0-9]"), reverse=True):
        if len(snippets) >= max_runs * len(filenames):
            break
        for filename in filenames:
            path = run_dir / filename
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            if not text:
                continue
            snippets.append(f"[{run_dir.name}/{filename}]\n{truncate_context(text, chars_per_file)}")
            if len(snippets) >= max_runs * len(filenames):
                break
    return "\n\n---\n\n".join(snippets)


def summarize_services(scan: dict[str, Any]) -> str:
    lines = []
    for host in scan.get("hosts", []):
        host_id = host.get("host") or "unknown-host"
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service_bits = [
                str(port.get("service") or "unknown"),
                str(port.get("product") or "").strip(),
                str(port.get("version") or "").strip(),
                str(port.get("extra_info") or "").strip(),
            ]
            service = " ".join(bit for bit in service_bits if bit).strip()
            lines.append(f"{host_id}:{port.get('port')}/{port.get('protocol')} open {service}")
    return "\n".join(lines) if lines else "No open services were identified."


def run_nmap_stage(target: str, ports: str, timeout: int, reuse_scan: str = "") -> tuple[dict[str, Any], str]:
    if reuse_scan:
        scan = json.loads(Path(reuse_scan).read_text(encoding="utf-8"))
        return scan, json.dumps(scan, indent=2)

    agent = AgentRegistry.get_agent("collection_agent")
    task = create_nmap_scan_task(agent, target, ports, timeout)
    raw_output = run_agent_task("collection_agent", task)
    try:
        return extract_json_object(raw_output), raw_output
    except Exception:
        return {"scanner": "llm_database_collection", "hosts": []}, raw_output


def run_vulnerability_stage(scan: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scan_json = json.dumps(scan, indent=2)
    agent = AgentRegistry.get_agent("enrichment_agent")
    local_context = previous_output_context(("vulnerability_report.md", "service_summary.txt"), max_runs=2)
    task = create_vulnerability_scan_task(
        agent,
        truncate_context(scan_json, 2500),
        truncate_context(local_context, 1800),
    )
    raw_output = run_agent_task("enrichment_agent", task)
    try:
        return extract_json_object(raw_output), raw_output
    except Exception:
        return {
            "scanner": "llm_database_enrichment",
            "finding_count": 0,
            "findings": [],
            "raw_enrichment": raw_output,
        }, raw_output


def run_tool_generation_stage(
    artifact_run_id: int,
    target: str,
    scan_context: str,
    vulnerability_context: str,
    correlation_report: str,
    prediction_report: str,
    soc_report: str,
    remediation_plan: str,
) -> dict[str, Any]:
    tool_agent = AgentRegistry.get_agent("tool_generation_agent")
    tool_task = create_tool_generation_task(
        tool_agent,
        target,
        truncate_context(scan_context, 3500),
        truncate_context(vulnerability_context, 5000),
        truncate_context(correlation_report, 3500),
        truncate_context(prediction_report, 3500),
        truncate_context(soc_report, 3500),
        truncate_context(remediation_plan, 5000),
    )
    raw_manifest = run_agent_task("tool_generation_agent", tool_task)
    try:
        manifest = extract_json_object(raw_manifest)
    except Exception:
        salvaged_scripts = salvage_generated_script_objects(raw_manifest)
        manifest = {
            "agent": "tool_generation_agent",
            "mode": "llm_generated_each_run",
            "safety": "Tool generation output could not be parsed as JSON.",
            "scripts": salvaged_scripts,
            "raw_output": raw_manifest,
        }
    return write_generated_tool_scripts(artifact_run_id, target, manifest)


def has_live_host(scan: dict[str, Any]) -> bool:
    return any(host.get("status") == "up" for host in scan.get("hosts", []))


def build_unreachable_text(target: str, ports: str, scan: dict[str, Any]) -> str:
    raw_scan = json.dumps(scan, indent=2)
    return (
        "# SOC Threat Intelligence Diagnostic\n\n"
        f"Target `{target}` did not return any live hosts for ports `{ports}`.\n\n"
        "No vulnerability, reporting, or remediation agents were run because there is no reachable "
        "service evidence to analyze. Confirm the Metasploitable VM/container is running and rerun "
        "against its current IP address.\n\n"
        f"Raw Nmap summary: {scan.get('summary', 'No Nmap summary available.')}\n\n"
        "Raw Nmap JSON:\n\n"
        f"```json\n{raw_scan}\n```"
    )


def build_run_artifacts(
    run_id: int,
    artifact_run_id: int,
    target: str,
    ports: str,
    status: str,
    scan: dict[str, Any],
    service_summary: str,
    vulnerability_report: str,
    correlation_report: str,
    prediction_report: str,
    soc_report: str,
    remediation_plan: str,
    nmap_agent_output: str,
    script_artifacts: dict[str, Any] | None = None,
    remediation_execution: dict[str, Any] | None = None,
) -> dict[str, str]:
    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    scan_path = run_dir / "nmap_scan.json"
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")

    summary_path = run_dir / "service_summary.txt"
    summary_path.write_text(service_summary + "\n", encoding="utf-8")

    vulnerability_path = run_dir / "vulnerability_report.md"
    vulnerability_path.write_text(vulnerability_report.rstrip() + "\n", encoding="utf-8")

    correlation_path = run_dir / "correlation_report.md"
    correlation_path.write_text(correlation_report.rstrip() + "\n", encoding="utf-8")

    prediction_path = run_dir / "prediction_report.md"
    prediction_path.write_text(prediction_report.rstrip() + "\n", encoding="utf-8")

    report_path = run_dir / "soc_report.md"
    report_path.write_text(soc_report.rstrip() + "\n", encoding="utf-8")

    raw_nmap_path = run_dir / "nmap_agent_output.txt"
    raw_nmap_path.write_text(nmap_agent_output.rstrip() + "\n", encoding="utf-8")

    execution_summary = build_remediation_execution_summary(remediation_execution)
    if execution_summary:
        remediation_plan = remediation_plan.rstrip() + "\n\n" + execution_summary
        execution_summary_path = run_dir / "remediation_execution_summary.md"
        execution_summary_path.write_text(execution_summary.rstrip() + "\n", encoding="utf-8")
    else:
        execution_summary_path = None
    remediation_path = run_dir / "remediation_plan.md"
    remediation_path.write_text(remediation_plan.rstrip() + "\n", encoding="utf-8")

    combined_path = run_dir / "threat_intel_output.md"
    combined_path.write_text(
        "\n\n".join(
            [
                "# SOC Threat Intelligence Output",
                f"- Run ID: {run_id}",
                f"- Artifact Run ID: {artifact_run_id}",
                f"- Status: {status}",
                f"- Target: {target}",
                f"- Ports: {ports}",
                "## Service Summary",
                service_summary,
                "## Vulnerability Findings",
                vulnerability_report,
                "## Correlation",
                correlation_report,
                "## Prediction",
                prediction_report,
                "## SOC Report",
                soc_report,
                "## Remediation Plan",
                remediation_plan,
                "## Remediation Execution",
                execution_summary or "Remediation scripts were not executed for this run.",
            ]
        ).rstrip()
        + "\n",
        encoding="utf-8",
    )

    artifacts = {
        "run_dir": str(run_dir),
        "artifact_run_id": str(artifact_run_id),
        "combined_markdown": str(combined_path),
        "nmap_scan_json": str(scan_path),
        "service_summary": str(summary_path),
        "vulnerability_report": str(vulnerability_path),
        "correlation_report": str(correlation_path),
        "prediction_report": str(prediction_path),
        "soc_report": str(report_path),
        "remediation_plan": str(remediation_path),
        "nmap_agent_output": str(raw_nmap_path),
    }
    if script_artifacts:
        artifacts["generated_scripts_dir"] = str(script_artifacts["scripts_dir"])
        artifacts["generated_scripts_manifest"] = str(script_artifacts["manifest_path"])
        artifacts["current_generated_tools_dir"] = str(script_artifacts["current_scripts_dir"])
        artifacts["current_generated_tools_manifest"] = str(script_artifacts["current_manifest_path"])
    if remediation_execution:
        artifacts["remediation_execution_dir"] = str(remediation_execution["execution_dir"])
        artifacts["remediation_execution_results"] = str(remediation_execution["results_path"])
    if execution_summary_path:
        artifacts["remediation_execution_summary"] = str(execution_summary_path)
    return artifacts


def remediation_execution_status(remediation_execution: dict[str, Any] | None) -> str:
    if not remediation_execution:
        return "not_executed"
    statuses = {item.get("status") for item in remediation_execution.get("results", [])}
    if statuses == {"ok"}:
        return "success"
    if statuses <= {"ok", "skipped"} and "skipped" in statuses:
        return "partial_skipped"
    if "timeout" in statuses:
        return "timeout"
    if "failed" in statuses and "ok" in statuses:
        return "partial_failure"
    if "failed" in statuses:
        return "failed"
    return "unknown"


def remediation_execution_overview(remediation_execution: dict[str, Any] | None) -> dict[str, Any]:
    status = remediation_execution_status(remediation_execution)
    overview: dict[str, Any] = {
        "status": status,
        "mode": "not_executed",
        "total_steps": 0,
        "successful_steps": [],
        "failed_steps": [],
        "skipped_steps": [],
        "timeout_steps": [],
        "results_path": "",
    }
    if not remediation_execution:
        return overview

    overview["mode"] = remediation_execution.get("mode", "unknown")
    overview["results_path"] = remediation_execution.get("results_path", "")
    for item in remediation_execution.get("results", []):
        step = {
            "script": item.get("script", ""),
            "returncode": item.get("returncode"),
            "stdout_path": item.get("stdout_path", ""),
            "stderr_path": item.get("stderr_path", ""),
            "adapted": item.get("adapted", False),
            "adapted_from": item.get("adapted_from", ""),
            "adaptation_reason": item.get("adaptation_reason", ""),
        }
        overview["total_steps"] += 1
        if item.get("status") == "ok":
            overview["successful_steps"].append(step)
        elif item.get("status") == "skipped":
            step["reason"] = _short_file_text(str(item.get("stderr_path") or ""))
            overview["skipped_steps"].append(step)
        elif item.get("status") == "timeout":
            step["reason"] = _short_file_text(str(item.get("stderr_path") or ""))
            overview["timeout_steps"].append(step)
        else:
            step["reason"] = _short_file_text(str(item.get("stderr_path") or ""))
            overview["failed_steps"].append(step)

    overview["successful_count"] = len(overview["successful_steps"])
    overview["failed_count"] = len(overview["failed_steps"])
    overview["skipped_count"] = len(overview["skipped_steps"])
    overview["timeout_count"] = len(overview["timeout_steps"])
    return overview


def _short_file_text(path: str, limit: int = 300) -> str:
    try:
        text = Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return ""
    if len(text) > limit:
        return text[:limit].rstrip() + "..."
    return text


def build_remediation_execution_summary(remediation_execution: dict[str, Any] | None) -> str:
    if not remediation_execution:
        return ""
    overview = remediation_execution_overview(remediation_execution)

    lines = [
        "# Remediation Execution Summary",
        "",
        f"Overall status: `{overview['status']}`",
        f"Execution mode: `{remediation_execution.get('mode', 'unknown')}`",
        f"Successful steps: `{overview.get('successful_count', 0)}`",
        f"Failed steps: `{overview.get('failed_count', 0)}`",
        f"Skipped steps: `{overview.get('skipped_count', 0)}`",
        f"Timed out steps: `{overview.get('timeout_count', 0)}`",
        f"Results file: `{remediation_execution.get('results_path', '')}`",
        "",
        "| Script | Status | Return code | Adapted | Notes |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in remediation_execution.get("results", []):
        notes = ""
        if item.get("adapted"):
            notes = str(item.get("adaptation_reason") or "")
        if item.get("status") != "ok":
            stderr_note = _short_file_text(str(item.get("stderr_path") or ""))
            notes = f"{notes} {stderr_note}".strip()
        lines.append(
            "| {script} | {status} | {returncode} | {adapted} | {notes} |".format(
                script=item.get("script", ""),
                status=item.get("status", ""),
                returncode=item.get("returncode", ""),
                adapted="yes" if item.get("adapted") else "no",
                notes=notes.replace("|", "\\|"),
            )
        )
    return "\n".join(lines)


def _write_script(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o750)


def _open_services(scan: dict[str, Any]) -> list[dict[str, Any]]:
    services = []
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                services.append({"host": host.get("host"), **port})
    return services


def write_generated_tool_scripts(
    artifact_run_id: int,
    target: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    scripts_dir = RUNS_DIR / f"run_{artifact_run_id:04d}" / "generated_scripts"
    if scripts_dir.exists():
        shutil.rmtree(scripts_dir)
    scripts_dir.mkdir(parents=True, exist_ok=True)

    if CURRENT_GENERATED_TOOLS_DIR.exists():
        shutil.rmtree(CURRENT_GENERATED_TOOLS_DIR)
    CURRENT_GENERATED_TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    manifest = dict(manifest)
    manifest.setdefault("agent", "tool_generation_agent")
    manifest.setdefault("target", target)
    manifest.setdefault("mode", "llm_generated_each_run")
    manifest.setdefault("safety", "Scripts default to dry-run and require --apply for changes.")

    written_scripts = []
    for index, script in enumerate(manifest.get("scripts", []), start=1):
        filename = str(script.get("filename") or f"{index:02d}_{script.get('name', 'generated_tool')}.sh")
        filename = Path(filename).name
        body = str(script.get("body") or "").strip()
        if not body:
            continue

        script_path = scripts_dir / filename
        current_script_path = CURRENT_GENERATED_TOOLS_DIR / filename
        _write_script(script_path, body + "\n")
        shutil.copy2(script_path, current_script_path)
        written_scripts.append(
            {
                **{key: value for key, value in script.items() if key != "body"},
                "filename": filename,
                "path": str(script_path),
                "current_path": str(current_script_path),
            }
        )
    manifest["scripts"] = written_scripts

    manifest_path = scripts_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path = CURRENT_GENERATED_TOOLS_DIR / "manifest.json"
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "scripts_dir": scripts_dir,
        "manifest_path": manifest_path,
        "current_scripts_dir": CURRENT_GENERATED_TOOLS_DIR,
        "current_manifest_path": current_manifest_path,
        "manifest": manifest,
    }


def _run_generated_script(
    script_path: Path,
    execution_dir: Path,
    mode: str,
    apply_changes: bool,
    timeout: int,
    attempt_label: str = "",
) -> dict[str, Any]:
    command = [str(script_path)]
    if apply_changes:
        command.append("--apply")

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
        if returncode == 0:
            status = "ok"
        elif returncode == 20:
            status = "skipped"
        else:
            status = "failed"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        returncode = 124
        status = "timeout"

    stem = script_path.stem + (f".{attempt_label}" if attempt_label else "")
    stdout_path = execution_dir / f"{stem}.stdout.txt"
    stderr_path = execution_dir / f"{stem}.stderr.txt"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    return {
        "path": str(script_path),
        "mode": mode,
        "status": status,
        "returncode": returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stderr": stderr,
    }


def execute_generated_remediation_scripts(
    script_artifacts: dict[str, Any],
    apply_changes: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    scripts_dir = Path(script_artifacts["scripts_dir"])
    execution_dir = scripts_dir / "execution"
    if execution_dir.exists():
        shutil.rmtree(execution_dir)
    execution_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "mode": "apply" if apply_changes else "dry_run",
        "scripts_dir": str(scripts_dir),
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "results": [],
    }

    for script in script_artifacts["manifest"].get("scripts", []):
        script_path = Path(script["path"])
        attempt = _run_generated_script(
            script_path,
            execution_dir,
            results["mode"],
            apply_changes,
            timeout,
        )
        result = {
            "script": script["filename"],
            "path": str(script_path),
            "mode": results["mode"],
            "status": attempt["status"],
            "returncode": attempt["returncode"],
            "stdout_path": attempt["stdout_path"],
            "stderr_path": attempt["stderr_path"],
            "adapted": False,
            "attempts": [
                {
                    "script": script["filename"],
                    "status": attempt["status"],
                    "returncode": attempt["returncode"],
                    "stdout_path": attempt["stdout_path"],
                    "stderr_path": attempt["stderr_path"],
                }
            ],
        }

        results["results"].append(result)

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def update_saved_remediation_plan(db_path: Path, run_id: int, remediation_plan: str) -> None:
    with sqlite3.connect(db_path) as connection:
        ensure_schema(connection)
        connection.execute(
            "UPDATE threat_intel_runs SET remediation_plan = ? WHERE id = ?",
            (remediation_plan, run_id),
        )
        connection.commit()


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            target TEXT NOT NULL,
            ports TEXT NOT NULL,
            scan_json TEXT NOT NULL,
            service_summary TEXT NOT NULL,
            vulnerability_report TEXT NOT NULL,
            soc_report TEXT NOT NULL,
            remediation_plan TEXT NOT NULL
        )
        """
    )
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(threat_intel_runs)").fetchall()
    }
    if "vulnerability_report" not in columns:
        connection.execute(
            "ALTER TABLE threat_intel_runs ADD COLUMN vulnerability_report TEXT NOT NULL DEFAULT ''"
        )
    if "remediation_plan" not in columns:
        connection.execute(
            "ALTER TABLE threat_intel_runs ADD COLUMN remediation_plan TEXT NOT NULL DEFAULT ''"
        )
    connection.commit()


def save_run(
    db_path: Path,
    target: str,
    ports: str,
    scan: dict[str, Any],
    service_summary: str,
    vulnerability_report: str,
    soc_report: str,
    remediation_plan: str,
) -> int:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        ensure_schema(connection)
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(threat_intel_runs)").fetchall()
        }
        values = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "ports": ports,
            "scan_json": json.dumps(scan, indent=2),
            "service_summary": service_summary,
            "vulnerability_report": vulnerability_report,
            "threat_intel_report": vulnerability_report,
            "soc_report": soc_report,
            "remediation_plan": remediation_plan,
        }
        insert_columns = [column for column in values if column in columns]
        placeholders = ", ".join("?" for _ in insert_columns)
        cursor = connection.execute(
            f"INSERT INTO threat_intel_runs ({', '.join(insert_columns)}) VALUES ({placeholders})",
            tuple(values[column] for column in insert_columns),
        )
        connection.commit()
        return int(cursor.lastrowid)


def run_threat_intel_pipeline(
    target: str = "172.17.0.2",
    ports: str = "1-10000",
    timeout: int = 180,
    db_path: str | Path = DEFAULT_DB_PATH,
    reuse_scan: str = "",
    include_remediation_plan: bool = True,
    auto_execute_remediation: bool = True,
    auto_apply_remediation: bool = False,
    remediation_timeout: int = 120,
) -> dict[str, Any]:
    if not reuse_scan:
        raise ValueError(
            "Threat-intel runs require collected evidence via --reuse-scan. "
            "The hard-coded local scanner/tool-only path has been removed; provide evidence for the LLM/database agents."
        )
    scan, nmap_agent_output = run_nmap_stage(target, ports, timeout, reuse_scan)
    service_summary = summarize_services(scan)

    if not has_live_host(scan):
        diagnostic = build_unreachable_text(target, ports, scan)
        run_id = save_run(
            Path(db_path),
            target,
            ports,
            scan,
            service_summary,
            diagnostic,
            diagnostic,
            diagnostic,
        )
        artifact_run_id = next_artifact_run_id(run_id)
        artifacts = build_run_artifacts(
            run_id,
            artifact_run_id,
            target,
            ports,
            "unreachable",
            scan,
            service_summary,
            diagnostic,
            diagnostic,
            diagnostic,
            diagnostic,
            diagnostic,
            nmap_agent_output,
        )
        return {
            "run_id": run_id,
            "artifact_run_id": artifact_run_id,
            "status": "unreachable",
            "target": target,
            "ports": ports,
            "scan": scan,
            "service_summary": service_summary,
            "vulnerability_report": diagnostic,
            "correlation_report": diagnostic,
            "prediction_report": diagnostic,
            "soc_report": diagnostic,
            "remediation_plan": diagnostic,
            "db_path": str(db_path),
            "artifacts": artifacts,
            "nmap_agent_output": nmap_agent_output,
        }

    vulnerability_json, vulnerability_report = run_vulnerability_stage(scan)
    scan_context = json.dumps(scan, indent=2)
    vulnerability_context = (
        vulnerability_report
        if vulnerability_report.strip()
        else json.dumps(vulnerability_json, indent=2)
    )

    artifact_run_id = next_artifact_run_id()
    telemetry_context = (
        "No hard-coded telemetry tools were auto-run. Use the ingested knowledge database "
        "through your configured tools to correlate this evidence."
    )
    local_context = previous_output_context(
        (
            "correlation_report.md",
            "prediction_report.md",
            "soc_report.md",
            "remediation_plan.md",
        ),
        max_runs=2,
        chars_per_file=650,
    )
    correlation_agent = AgentRegistry.get_agent("correlation_agent")
    correlation_task = create_correlation_task(
        correlation_agent,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(vulnerability_context, 2200),
        telemetry_context,
        truncate_context(local_context, 1800),
    )
    correlation_report = run_agent_task("correlation_agent", correlation_task)

    prediction_agent = AgentRegistry.get_agent("prediction_agent")
    prediction_task = create_prediction_task(
        prediction_agent,
        target,
        truncate_context(correlation_report, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(local_context, 1500),
    )
    prediction_report = run_agent_task("prediction_agent", prediction_task)

    reporting_agent = AgentRegistry.get_agent("reporting_agent")
    report_task = create_reporting_task(
        reporting_agent,
        target,
        truncate_context(scan_context, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(correlation_report, 1500),
        truncate_context(prediction_report, 1200),
        truncate_context(local_context, 1600),
    )
    soc_report = run_agent_task("reporting_agent", report_task)

    script_artifacts = None
    if include_remediation_plan:
        remediation_agent = AgentRegistry.get_agent("response_agent")
        remediation_task = create_remediation_task(
            remediation_agent,
            target,
            truncate_context(soc_report, 1800),
            truncate_context(vulnerability_context, 1800),
            truncate_context(correlation_report, 1300),
            truncate_context(prediction_report, 1000),
            truncate_context(local_context, 1600),
        )
        remediation_plan = run_agent_task("response_agent", remediation_task)

        script_artifacts = run_tool_generation_stage(
            artifact_run_id,
            target,
            scan_context,
            vulnerability_context,
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
        ports,
        scan,
        service_summary,
        vulnerability_context,
        soc_report,
        remediation_plan,
    )
    remediation_execution = None
    if auto_execute_remediation and script_artifacts:
        remediation_execution = execute_generated_remediation_scripts(
            script_artifacts,
            apply_changes=auto_apply_remediation,
            timeout=remediation_timeout,
        )
    artifacts = build_run_artifacts(
        run_id,
        artifact_run_id,
        target,
        ports,
        "complete" if include_remediation_plan else "complete_without_remediation",
        scan,
        service_summary,
        vulnerability_context,
        correlation_report,
        prediction_report,
        soc_report,
        remediation_plan,
        nmap_agent_output,
        script_artifacts,
        remediation_execution,
    )
    return {
        "run_id": run_id,
        "artifact_run_id": artifact_run_id,
        "status": "complete" if include_remediation_plan else "complete_without_remediation",
        "target": target,
        "ports": ports,
        "scan": scan,
        "service_summary": service_summary,
        "vulnerability_scan": vulnerability_json,
        "vulnerability_report": vulnerability_context,
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
        "nmap_agent_output": nmap_agent_output,
    }


def main() -> None:
    args = parse_args()
    result = run_threat_intel_pipeline(
        target=args.target,
        ports=args.ports,
        timeout=args.timeout,
        db_path=args.db_path,
        reuse_scan=args.reuse_scan,
        auto_execute_remediation=not args.no_auto_remediation,
        include_remediation_plan=not args.skip_remediation_plan,
        auto_apply_remediation=args.auto_apply_remediation,
        remediation_timeout=args.remediation_timeout,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "scan"}, indent=2))


if __name__ == "__main__":
    main()
