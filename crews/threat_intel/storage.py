import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUNS_DIR = Path("outputs") / "runs"


def build_run_artifacts(
    run_id: int,
    artifact_run_id: int,
    target: str,
    evidence_label: str,
    status: str,
    evidence: dict[str, Any],
    service_summary: str,
    vulnerability_report: str,
    correlation_report: str,
    prediction_report: str,
    soc_report: str,
    remediation_plan: str,
    raw_evidence: str,
    script_artifacts: dict[str, Any] | None = None,
    remediation_execution: dict[str, Any] | None = None,
) -> dict[str, str]:
    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = run_dir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    execution_summary = build_remediation_execution_summary(remediation_execution)
    if execution_summary:
        remediation_plan = remediation_plan.rstrip() + "\n\n" + execution_summary

    combined_path = run_dir / "threat_intel_output.md"
    combined_path.write_text(
        "\n\n".join(
            [
                "# SOC Threat Intelligence Output",
                f"- Run ID: {run_id}",
                f"- Artifact Run ID: {artifact_run_id}",
                f"- Status: {status}",
                f"- Target: {target}",
                f"- Evidence: {evidence_label}",
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
        "evidence_json": str(evidence_path),
    }
    if script_artifacts:
        artifacts["generated_scripts_dir"] = str(script_artifacts["scripts_dir"])
        artifacts["generated_scripts_manifest"] = str(script_artifacts["manifest_path"])
        artifacts["current_generated_tools_dir"] = str(script_artifacts["current_scripts_dir"])
        artifacts["current_generated_tools_manifest"] = str(script_artifacts["current_manifest_path"])
    if remediation_execution:
        artifacts["remediation_execution_dir"] = str(remediation_execution["execution_dir"])
        artifacts["remediation_execution_results"] = str(remediation_execution["results_path"])
    return artifacts


def remediation_execution_status(remediation_execution: dict[str, Any] | None) -> str:
    if not remediation_execution:
        return "not_executed"
    if not remediation_execution.get("results"):
        return "no_scripts_generated"
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
    return text[:limit].rstrip() + "..." if len(text) > limit else text


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
    ]
    return "\n".join(lines)


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
    columns = {row[1] for row in connection.execute("PRAGMA table_info(threat_intel_runs)").fetchall()}
    if "vulnerability_report" not in columns:
        connection.execute("ALTER TABLE threat_intel_runs ADD COLUMN vulnerability_report TEXT NOT NULL DEFAULT ''")
    if "remediation_plan" not in columns:
        connection.execute("ALTER TABLE threat_intel_runs ADD COLUMN remediation_plan TEXT NOT NULL DEFAULT ''")
    connection.commit()


def save_run(
    db_path: Path,
    target: str,
    evidence_label: str,
    evidence: dict[str, Any],
    service_summary: str,
    vulnerability_report: str,
    soc_report: str,
    remediation_plan: str,
) -> int:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        ensure_schema(connection)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(threat_intel_runs)").fetchall()}
        values = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "ports": evidence_label,
            "scan_json": json.dumps(evidence, indent=2),
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
