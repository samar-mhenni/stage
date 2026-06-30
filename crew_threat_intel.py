import argparse
import json
import os
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
    create_nmap_scan_task,
    create_remediation_task,
    create_reporting_task,
    create_vulnerability_scan_task,
)
from tools.nmap_tool import run_nmap_scan
from tools.vulnerability_scan_tool import vulnerability_scan_from_nmap
import tools.misp_tool  # noqa: F401 - registers misp_tool
import tools.sigma_tool  # noqa: F401 - registers sigma_tool
import tools.suricata_tool  # noqa: F401 - registers suricata_tool
import tools.virustotal_tool  # noqa: F401 - registers virustotal_tool
import tools.zeek_tool  # noqa: F401 - registers zeek_tool
from tools.registry import ToolRegistry


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
        "--tool-only",
        action="store_true",
        help="Skip LLM agents and generate deterministic reports from scan/tool evidence.",
    )
    parser.add_argument(
        "--no-auto-remediation",
        action="store_true",
        help="Generate remediation scripts without automatically executing them.",
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

    agent = AgentRegistry.get_agent("nmap_scan_agent")
    task = create_nmap_scan_task(agent, target, ports, timeout)
    raw_output = run_agent_task("nmap_scan_agent", task)
    try:
        return extract_json_object(raw_output), raw_output
    except Exception:
        fallback = json.loads(run_nmap_scan(target, "service", ports, timeout, True))
        return fallback, json.dumps(fallback, indent=2)


def run_nmap_tool_stage(
    target: str,
    ports: str,
    timeout: int,
    reuse_scan: str = "",
) -> tuple[dict[str, Any], str]:
    if reuse_scan:
        scan = json.loads(Path(reuse_scan).read_text(encoding="utf-8"))
        return scan, json.dumps(scan, indent=2)

    raw_output = run_nmap_scan(target, "service", ports, timeout, True)
    return json.loads(raw_output), raw_output


def run_vulnerability_stage(scan: dict[str, Any]) -> tuple[dict[str, Any], str]:
    scan_json = json.dumps(scan, indent=2)
    agent = AgentRegistry.get_agent("vulnerability_scan_agent")
    task = create_vulnerability_scan_task(agent, scan_json)
    raw_output = run_agent_task("vulnerability_scan_agent", task)
    try:
        return extract_json_object(raw_output), raw_output
    except Exception:
        fallback = vulnerability_scan_from_nmap(scan)
        return fallback, json.dumps(fallback, indent=2)


def run_vulnerability_tool_stage(scan: dict[str, Any]) -> tuple[dict[str, Any], str]:
    result = vulnerability_scan_from_nmap(scan)
    return result, json.dumps(result, indent=2)


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
    soc_report: str,
    remediation_plan: str,
    nmap_agent_output: str,
    script_artifacts: dict[str, Any] | None = None,
    remediation_execution: dict[str, Any] | None = None,
    integrated_tool_results: dict[str, Any] | None = None,
) -> dict[str, str]:
    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    scan_path = run_dir / "nmap_scan.json"
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")

    summary_path = run_dir / "service_summary.txt"
    summary_path.write_text(service_summary + "\n", encoding="utf-8")

    vulnerability_path = run_dir / "vulnerability_report.md"
    vulnerability_path.write_text(vulnerability_report.rstrip() + "\n", encoding="utf-8")

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
    tool_summary = build_integrated_tool_summary(integrated_tool_results)
    if tool_summary:
        tool_summary_path = run_dir / "integrated_tool_summary.md"
        tool_summary_path.write_text(tool_summary.rstrip() + "\n", encoding="utf-8")
    else:
        tool_summary_path = None

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
                "## SOC Report",
                soc_report,
                "## Remediation Plan",
                remediation_plan,
                "## Remediation Execution",
                execution_summary or "Remediation scripts were not executed for this run.",
                "## Integrated Tool Evidence",
                tool_summary or "No additional tool stage was run.",
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
    if integrated_tool_results:
        artifacts["tool_evidence_json"] = str(integrated_tool_results.get("artifacts", {}).get("tool_evidence_json", ""))
        artifacts["sigma_rules_dir"] = str(integrated_tool_results.get("artifacts", {}).get("sigma_rules_dir", ""))
    if tool_summary_path:
        artifacts["integrated_tool_summary"] = str(tool_summary_path)
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


def build_integrated_tool_summary(integrated_tool_results: dict[str, Any] | None) -> str:
    if not integrated_tool_results:
        return ""
    used = integrated_tool_results.get("used_tools", [])
    skipped = integrated_tool_results.get("skipped_tools", [])
    sigma = integrated_tool_results.get("results", {}).get("sigma_tool", {})
    lines = [
        "# Integrated Tool Summary",
        "",
        f"Used tools: `{', '.join(used) if used else 'none'}`",
        f"Skipped tools: `{len(skipped)}`",
        f"Generated Sigma rules: `{sigma.get('generated_rule_count', 0)}`",
        f"Evidence file: `{integrated_tool_results.get('artifacts', {}).get('tool_evidence_json', '')}`",
        "",
        "| Tool | Status | Notes |",
        "| :--- | :--- | :--- |",
    ]
    for tool_name in used:
        if tool_name == "sigma_tool":
            notes = f"generated {sigma.get('generated_rule_count', 0)} detection rules"
        else:
            result = integrated_tool_results.get("results", {}).get(tool_name, {})
            notes = str(result.get("error") or "completed")
        lines.append(f"| {tool_name} | used | {notes} |")
    for skipped_item in skipped:
        lines.append(
            "| {tool} | skipped | {reason} |".format(
                tool=skipped_item.get("tool", ""),
                reason=str(skipped_item.get("reason", "")).replace("|", "\\|"),
            )
        )
    return "\n".join(lines)


def _script_header(name: str, target: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n\n"
        f"# Generated by the remediation script generation agent for {target}.\n"
        f"# Script: {name}\n"
        "# Default mode is dry-run. Pass --apply to perform changes.\n\n"
        "APPLY=0\n"
        "if [[ \"${1:-}\" == \"--apply\" ]]; then\n"
        "  APPLY=1\n"
        "fi\n\n"
        "run_cmd() {\n"
        "  if [[ \"$APPLY\" -eq 1 ]]; then\n"
        "    echo \"+ $*\"\n"
        "    \"$@\"\n"
        "  else\n"
        "    printf '[dry-run] '\n"
        "    printf '%q ' \"$@\"\n"
        "    printf '\\n'\n"
        "  fi\n"
        "}\n\n"
    )


def _adaptive_script_header(name: str, target: str) -> str:
    return _script_header(name, target) + "# Adapted after execution feedback from the target host.\n\n"


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


def _safe_json_loads(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception as exc:
        return {"error": "invalid_tool_json", "message": str(exc), "raw": value}


def _configured_env_value(name: str) -> str:
    value = os.getenv(name, "").strip()
    placeholders = {
        "",
        "replace_with_your_virustotal_api_key",
        "replace_with_your_openrouter_api_key",
        "replace_with_your_neo4j_password",
        "replace_with_your_wazuh_password",
    }
    return "" if value.lower() in placeholders else value


def _first_existing_file(paths: list[str]) -> str:
    for path in paths:
        candidate = Path(path)
        if candidate.is_file():
            return str(candidate)
    return ""


def _finding_detection_requirement(finding: dict[str, Any]) -> str:
    service = finding.get("service") or "unknown service"
    product = finding.get("product") or service
    port = finding.get("port")
    risk = str(finding.get("risk") or "low").upper()
    return (
        f"Detect suspicious activity against {product} {service} on port {port}. "
        f"Risk level from scan evidence: {risk}."
    )


def _sigma_context_for_finding(finding: dict[str, Any]) -> tuple[str, str, str]:
    service = str(finding.get("service") or "").lower()
    if service in {"ftp", "telnet", "ssh", "netbios-ssn", "mysql", "postgresql", "irc"}:
        return "linux", "network_connection", "high"
    if service in {"http", "ajp13"}:
        return "webserver", "webserver", "medium"
    return "linux", "process_creation", str(finding.get("risk") or "medium")


def run_integrated_tool_stage(
    artifact_run_id: int,
    target: str,
    scan: dict[str, Any],
    vulnerability_scan: dict[str, Any],
) -> dict[str, Any]:
    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    tool_dir = run_dir / "tool_evidence"
    if tool_dir.exists():
        shutil.rmtree(tool_dir)
    tool_dir.mkdir(parents=True, exist_ok=True)

    evidence: dict[str, Any] = {
        "used_tools": [],
        "skipped_tools": [],
        "artifacts": {},
        "results": {},
    }

    sigma_tool = ToolRegistry.get_tool("sigma_tool")
    sigma_dir = tool_dir / "sigma_rules"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    sigma_results = []
    high_findings = [
        finding
        for finding in vulnerability_scan.get("findings", [])
        if str(finding.get("risk") or "").lower() in {"critical", "high"}
    ][:8]
    for index, finding in enumerate(high_findings, start=1):
        product, category, level = _sigma_context_for_finding(finding)
        result = _safe_json_loads(
            sigma_tool._run(
                action="generate",
                attack_technique="T1046 Network Service Discovery",
                detection_requirement=_finding_detection_requirement(finding),
                logsource_product=product,
                logsource_category=category,
                level=level,
            )
        )
        rule_text = result.get("sigma_rule", "")
        rule_path = ""
        if rule_text:
            rule_path = str(sigma_dir / f"{index:02d}_{finding.get('service')}_{finding.get('port')}.yml")
            Path(rule_path).write_text(rule_text, encoding="utf-8")
        sigma_results.append(
            {
                "host": finding.get("host"),
                "port": finding.get("port"),
                "service": finding.get("service"),
                "risk": finding.get("risk"),
                "rule_path": rule_path,
                "result": result,
            }
        )
    evidence["used_tools"].append("sigma_tool")
    evidence["results"]["sigma_tool"] = {
        "generated_rule_count": len([item for item in sigma_results if item.get("rule_path")]),
        "rules": sigma_results,
    }
    evidence["artifacts"]["sigma_rules_dir"] = str(sigma_dir)

    suricata_path = _first_existing_file(
        [
            "data/eve.json",
            "data/suricata/eve.json",
            "outputs/eve.json",
        ]
    )
    if suricata_path:
        suricata_tool = ToolRegistry.get_tool("suricata_tool")
        evidence["used_tools"].append("suricata_tool")
        evidence["results"]["suricata_tool"] = _safe_json_loads(
            suricata_tool._run(eve_path=suricata_path, event_type="alert", limit=200)
        )
    else:
        evidence["skipped_tools"].append(
            {"tool": "suricata_tool", "reason": "No Suricata eve.json file found."}
        )

    zeek_path = _first_existing_file(
        [
            "data/conn.log",
            "data/zeek/conn.log",
            "outputs/conn.log",
        ]
    )
    if zeek_path:
        zeek_tool = ToolRegistry.get_tool("zeek_tool")
        evidence["used_tools"].append("zeek_tool")
        evidence["results"]["zeek_tool"] = _safe_json_loads(
            zeek_tool._run(log_path=zeek_path, log_type="auto", limit=200)
        )
    else:
        evidence["skipped_tools"].append({"tool": "zeek_tool", "reason": "No Zeek log file found."})

    if _configured_env_value("VIRUSTOTAL_API_KEY"):
        vt_tool = ToolRegistry.get_tool("virustotal_tool")
        evidence["used_tools"].append("virustotal_tool")
        evidence["results"]["virustotal_tool"] = _safe_json_loads(
            vt_tool._run(ip=target, include_relationships=False, relationship_limit=5)
        )
    else:
        evidence["skipped_tools"].append(
            {"tool": "virustotal_tool", "reason": "VIRUSTOTAL_API_KEY is not configured."}
        )

    if os.getenv("MISP_URL") and os.getenv("MISP_API_KEY"):
        misp_tool = ToolRegistry.get_tool("misp_tool")
        evidence["used_tools"].append("misp_tool")
        evidence["results"]["misp_tool"] = _safe_json_loads(misp_tool._run(action="ioc_lookup", ip=target, limit=10))
    else:
        evidence["skipped_tools"].append(
            {"tool": "misp_tool", "reason": "MISP_URL and MISP_API_KEY are not configured."}
        )

    evidence_path = tool_dir / "tool_evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    evidence["artifacts"]["tool_evidence_json"] = str(evidence_path)
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    return evidence


def _needed_tool_specs(scan: dict[str, Any], vulnerability_scan: dict[str, Any]) -> list[dict[str, Any]]:
    services = _open_services(scan)
    service_names = {str(item.get("service") or "").lower() for item in services}
    ports = {int(item.get("port")) for item in services if item.get("port")}

    specs = [
        {
            "name": "validate_exposure",
            "filename": "01_validate_exposure.sh",
            "purpose": "Re-run service validation against the target and capture before/after evidence.",
            "interpreter": "bash",
        }
    ]

    if {"telnet", "ftp", "exec", "login"} & service_names or ports & {21, 23, 512, 513, 514, 2121}:
        specs.append(
            {
                "name": "disable_legacy_remote_services",
                "filename": "02_disable_legacy_remote_services.sh",
                "purpose": "Stop and disable legacy cleartext or remote shell services.",
                "interpreter": "bash",
            }
        )

    if {"netbios-ssn", "microsoft-ds"} & service_names or ports & {139, 445}:
        specs.append(
            {
                "name": "harden_samba",
                "filename": "03_harden_samba.sh",
                "purpose": "Back up Samba configuration and apply SMB hardening settings.",
                "interpreter": "bash",
            }
        )

    if {"mysql", "postgresql"} & service_names or ports & {3306, 5432}:
        specs.append(
            {
                "name": "restrict_databases",
                "filename": "04_restrict_databases.sh",
                "purpose": "Restrict database listeners and restart database services.",
                "interpreter": "bash",
            }
        )

    if {"http", "ajp13"} & service_names or ports & {80, 8009, 8180}:
        specs.append(
            {
                "name": "web_service_review",
                "filename": "05_web_service_review.sh",
                "purpose": "Collect web-service package and listener evidence for patch planning.",
                "interpreter": "bash",
            }
        )

    high_risk = any(
        str(item.get("risk") or "").lower() in {"critical", "high"}
        for item in vulnerability_scan.get("findings", [])
    )
    if high_risk:
        specs.append(
            {
                "name": "host_firewall_baseline",
                "filename": "06_host_firewall_baseline.sh",
                "purpose": "Apply a restrictive host firewall baseline for the identified exposed services.",
                "interpreter": "bash",
            }
        )

    return specs


def _script_body(spec_name: str, target: str, ports: str) -> str:
    if spec_name == "validate_exposure":
        return (
            _script_header("validate_exposure", target)
            + f"TARGET=${{TARGET:-{target}}}\n"
            + f"PORTS=${{PORTS:-{ports}}}\n"
            + "OUT_DIR=${OUT_DIR:-./validation-output}\n\n"
            + "mkdir -p \"$OUT_DIR\"\n"
            + "echo \"Writing validation evidence to $OUT_DIR\"\n"
            + "nmap -sV --version-light -Pn -p \"$PORTS\" -oA \"$OUT_DIR/nmap_validation\" \"$TARGET\"\n"
        )

    if spec_name == "disable_legacy_remote_services":
        return (
            _script_header("disable_legacy_remote_services", target)
            + "for svc in telnet telnetd inetd openbsd-inetd xinetd vsftpd proftpd rsh rsh-server rlogin rexec; do\n"
            + "  if systemctl list-unit-files \"$svc.service\" >/dev/null 2>&1; then\n"
            + "    run_cmd systemctl stop \"$svc.service\"\n"
            + "    run_cmd systemctl disable \"$svc.service\"\n"
            + "  fi\n"
            + "done\n"
            + "echo \"Review /etc/inetd.conf and /etc/xinetd.d/ for legacy shell services.\"\n"
        )

    if spec_name == "harden_samba":
        return (
            _script_header("harden_samba", target)
            + "SMB_CONF=${SMB_CONF:-/etc/samba/smb.conf}\n"
            + "if [[ -f \"$SMB_CONF\" ]]; then\n"
            + "  run_cmd cp \"$SMB_CONF\" \"$SMB_CONF.generated-backup\"\n"
            + "  if [[ \"$APPLY\" -eq 1 ]]; then\n"
            + "    grep -q '^\\s*server min protocol' \"$SMB_CONF\" || printf '\\nserver min protocol = SMB2\\nmin protocol = SMB2\\n' >> \"$SMB_CONF\"\n"
            + "    systemctl restart smbd || true\n"
            + "  else\n"
            + "    echo '[dry-run] would ensure SMB2 minimum protocol and restart smbd'\n"
            + "  fi\n"
            + "else\n"
            + "  echo \"Samba config not found at $SMB_CONF\"\n"
            + "fi\n"
        )

    if spec_name == "restrict_databases":
        return (
            _script_header("restrict_databases", target)
            + "echo \"Review database bind addresses before applying.\"\n"
            + "for svc in mysql mariadb postgresql; do\n"
            + "  if systemctl list-unit-files \"$svc.service\" >/dev/null 2>&1; then\n"
            + "    run_cmd systemctl restart \"$svc.service\"\n"
            + "  fi\n"
            + "done\n"
            + "echo \"Set MySQL/PostgreSQL bind-address/listen_addresses to localhost or approved app subnets.\"\n"
        )

    if spec_name == "web_service_review":
        return (
            _script_header("web_service_review", target)
            + "echo 'Collecting web stack evidence for patch planning.'\n"
            + "apache2 -v 2>/dev/null || httpd -v 2>/dev/null || true\n"
            + "dpkg -l 2>/dev/null | grep -Ei 'apache|tomcat|php|openssl' || true\n"
            + "ss -ltnp | grep -E ':80|:443|:8009|:8180' || true\n"
        )

    if spec_name == "host_firewall_baseline":
        return (
            _script_header("host_firewall_baseline", target)
            + "MGMT_CIDR=${MGMT_CIDR:-127.0.0.1/32}\n"
            + "echo \"Using management CIDR: $MGMT_CIDR\"\n"
            + "run_cmd ufw default deny incoming\n"
            + "run_cmd ufw allow from \"$MGMT_CIDR\" to any port 22 proto tcp\n"
            + "run_cmd ufw deny 21/tcp\n"
            + "run_cmd ufw deny 23/tcp\n"
            + "run_cmd ufw deny 139/tcp\n"
            + "run_cmd ufw deny 445/tcp\n"
            + "run_cmd ufw deny 3306/tcp\n"
            + "run_cmd ufw deny 5432/tcp\n"
            + "run_cmd ufw deny 6667/tcp\n"
            + "run_cmd ufw deny 6697/tcp\n"
            + "run_cmd ufw enable\n"
        )

    raise ValueError(f"Unknown script spec: {spec_name}")


def _adaptive_firewall_script_body(target: str) -> str:
    return (
        _adaptive_script_header("host_firewall_baseline_adapted", target)
        + "MGMT_CIDR=${MGMT_CIDR:-127.0.0.1/32}\n"
        + "echo \"Using management CIDR: $MGMT_CIDR\"\n"
        + "SUDO=()\n"
        + "if [[ \"${EUID:-$(id -u)}\" -eq 0 ]]; then\n"
        + "  SUDO=()\n"
        + "elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then\n"
        + "  SUDO=(sudo -n)\n"
        + "else\n"
        + "  SUDO=()\n"
        + "fi\n"
        + "run_privileged() {\n"
        + "  if [[ \"${#SUDO[@]}\" -gt 0 ]]; then\n"
        + "    run_cmd \"${SUDO[@]}\" \"$@\"\n"
        + "  else\n"
        + "    run_cmd \"$@\"\n"
        + "  fi\n"
        + "}\n"
        + "can_install_or_apply() {\n"
        + "  [[ \"${EUID:-$(id -u)}\" -eq 0 || \"${#SUDO[@]}\" -gt 0 ]]\n"
        + "}\n"
        + "install_ufw_if_possible() {\n"
        + "  if command -v ufw >/dev/null 2>&1; then\n"
        + "    return 0\n"
        + "  fi\n"
        + "  if [[ \"$APPLY\" -ne 1 ]]; then\n"
        + "    echo '[dry-run] would install ufw if package manager and privileges are available'\n"
        + "    return 1\n"
        + "  fi\n"
        + "  if ! can_install_or_apply; then\n"
        + "    echo 'Cannot install ufw automatically: root or passwordless sudo is required.' >&2\n"
        + "    return 1\n"
        + "  fi\n"
        + "  if command -v apt-get >/dev/null 2>&1; then\n"
        + "    run_privileged apt-get update\n"
        + "    run_privileged apt-get install -y ufw\n"
        + "  elif command -v dnf >/dev/null 2>&1; then\n"
        + "    run_privileged dnf install -y ufw\n"
        + "  elif command -v yum >/dev/null 2>&1; then\n"
        + "    run_privileged yum install -y ufw\n"
        + "  elif command -v pacman >/dev/null 2>&1; then\n"
        + "    run_privileged pacman -Sy --noconfirm ufw\n"
        + "  elif command -v zypper >/dev/null 2>&1; then\n"
        + "    run_privileged zypper --non-interactive install ufw\n"
        + "  else\n"
        + "    echo 'Cannot install ufw automatically: no supported package manager found.' >&2\n"
        + "    return 1\n"
        + "  fi\n"
        + "}\n"
        + "install_ufw_if_possible || true\n"
        + "if command -v ufw >/dev/null 2>&1; then\n"
        + "  FIREWALL_BACKEND=ufw\n"
        + "elif command -v nft >/dev/null 2>&1; then\n"
        + "  FIREWALL_BACKEND=nftables\n"
        + "elif command -v iptables >/dev/null 2>&1; then\n"
        + "  FIREWALL_BACKEND=iptables\n"
        + "else\n"
        + "  FIREWALL_BACKEND=none\n"
        + "fi\n"
        + "echo \"Selected firewall backend: $FIREWALL_BACKEND\"\n\n"
        + "if [[ \"$APPLY\" -eq 1 && \"$FIREWALL_BACKEND\" != \"none\" ]] && ! can_install_or_apply; then\n"
        + "  echo 'SKIPPED: firewall changes require root privileges or passwordless sudo.' >&2\n"
        + "  exit 20\n"
        + "fi\n"
        + "if [[ \"$FIREWALL_BACKEND\" == \"ufw\" ]]; then\n"
        + "  run_privileged ufw default deny incoming\n"
        + "  run_privileged ufw allow from \"$MGMT_CIDR\" to any port 22 proto tcp\n"
        + "  for port in 21 23 139 445 3306 5432 6667 6697; do run_privileged ufw deny \"$port/tcp\"; done\n"
        + "  run_privileged ufw enable\n"
        + "elif [[ \"$FIREWALL_BACKEND\" == \"nftables\" ]]; then\n"
        + "  if [[ \"$APPLY\" -eq 1 ]]; then\n"
        + "    run_privileged nft list ruleset >/dev/null\n"
        + "  else\n"
        + "    echo '[dry-run] would validate nftables and create deny rules for exposed legacy ports'\n"
        + "  fi\n"
        + "  echo 'nftables backend detected. Review policy before applying persistent production rules.'\n"
        + "elif [[ \"$FIREWALL_BACKEND\" == \"iptables\" ]]; then\n"
        + "  for port in 21 23 139 445 3306 5432 6667 6697; do\n"
        + "    run_privileged iptables -A INPUT -p tcp --dport \"$port\" -j DROP\n"
        + "  done\n"
        + "else\n"
        + "  echo 'No supported firewall tool found and automatic install was not possible.' >&2\n"
        + "  exit 20\n"
        + "fi\n"
    )


def generate_remediation_scripts(
    artifact_run_id: int,
    target: str,
    ports: str,
    scan: dict[str, Any],
    vulnerability_scan: dict[str, Any],
) -> dict[str, Any]:
    scripts_dir = RUNS_DIR / f"run_{artifact_run_id:04d}" / "generated_scripts"
    if scripts_dir.exists():
        shutil.rmtree(scripts_dir)
    scripts_dir.mkdir(parents=True, exist_ok=True)

    if CURRENT_GENERATED_TOOLS_DIR.exists():
        shutil.rmtree(CURRENT_GENERATED_TOOLS_DIR)
    CURRENT_GENERATED_TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    specs = _needed_tool_specs(scan, vulnerability_scan)
    manifest = {
        "agent": "remediation_script_generation_agent",
        "target": target,
        "mode": "generated_each_run",
        "safety": "Scripts default to dry-run and require --apply for changes.",
        "scripts": [],
    }
    for spec in specs:
        script_path = scripts_dir / spec["filename"]
        current_script_path = CURRENT_GENERATED_TOOLS_DIR / spec["filename"]
        _write_script(script_path, _script_body(spec["name"], target, ports))
        shutil.copy2(script_path, current_script_path)
        manifest["scripts"].append(
            {
                **spec,
                "path": str(script_path),
                "current_path": str(current_script_path),
            }
        )

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


def _adapt_failed_script(
    script: dict[str, Any],
    failed_attempt: dict[str, Any],
    script_artifacts: dict[str, Any],
) -> dict[str, Any] | None:
    stderr = str(failed_attempt.get("stderr") or "")
    if script.get("name") == "host_firewall_baseline" and "ufw: command not found" in stderr:
        adapted_name = "06_host_firewall_baseline_adapted.sh"
        scripts_dir = Path(script_artifacts["scripts_dir"])
        current_dir = Path(script_artifacts["current_scripts_dir"])
        adapted_path = scripts_dir / adapted_name
        current_adapted_path = current_dir / adapted_name
        target = str(script_artifacts["manifest"].get("target", "target"))

        _write_script(adapted_path, _adaptive_firewall_script_body(target))
        shutil.copy2(adapted_path, current_adapted_path)
        adapted_script = {
            **script,
            "script": adapted_name,
            "filename": adapted_name,
            "name": "host_firewall_baseline_adapted",
            "path": str(adapted_path),
            "current_path": str(current_adapted_path),
            "adapted_from": script.get("filename"),
            "adaptation_reason": "ufw was not installed; generated backend-detecting firewall script.",
        }
        script_artifacts["manifest"].setdefault("adaptations", []).append(adapted_script)
        Path(script_artifacts["manifest_path"]).write_text(
            json.dumps(script_artifacts["manifest"], indent=2),
            encoding="utf-8",
        )
        Path(script_artifacts["current_manifest_path"]).write_text(
            json.dumps(script_artifacts["manifest"], indent=2),
            encoding="utf-8",
        )
        return adapted_script
    return None


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

        if attempt["status"] != "ok":
            adapted_script = _adapt_failed_script(script, attempt, script_artifacts)
            if adapted_script:
                retry = _run_generated_script(
                    Path(adapted_script["path"]),
                    execution_dir,
                    results["mode"],
                    apply_changes,
                    timeout,
                    "adapted",
                )
                result.update(
                    {
                        "script": adapted_script["filename"],
                        "path": adapted_script["path"],
                        "status": retry["status"],
                        "returncode": retry["returncode"],
                        "stdout_path": retry["stdout_path"],
                        "stderr_path": retry["stderr_path"],
                        "adapted": True,
                        "adapted_from": adapted_script["adapted_from"],
                        "adaptation_reason": adapted_script["adaptation_reason"],
                    }
                )
                result["attempts"].append(
                    {
                        "script": adapted_script["filename"],
                        "status": retry["status"],
                        "returncode": retry["returncode"],
                        "stdout_path": retry["stdout_path"],
                        "stderr_path": retry["stderr_path"],
                        "adaptation_reason": adapted_script["adaptation_reason"],
                    }
                )

        results["results"].append(result)

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def _risk_counts(vulnerability_scan: dict[str, Any]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in vulnerability_scan.get("findings", []):
        risk = str(finding.get("risk") or "low").lower()
        counts[risk] = counts.get(risk, 0) + 1
    return counts


def build_tool_soc_report(
    target: str,
    scan: dict[str, Any],
    service_summary: str,
    vulnerability_scan: dict[str, Any],
) -> str:
    counts = _risk_counts(vulnerability_scan)
    top_findings = sorted(
        vulnerability_scan.get("findings", []),
        key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            str(item.get("risk") or "low").lower(),
            4,
        ),
    )[:12]
    finding_lines = []
    for finding in top_findings:
        refs = finding.get("exploit_references") or []
        ref_text = ", ".join(
            str(ref.get("cve") or ref.get("exploit_id") or "reference") for ref in refs[:3]
        )
        finding_lines.append(
            "- {risk}: {host}:{port}/{protocol} {service} {product} {version}{refs}".format(
                risk=str(finding.get("risk") or "low").upper(),
                host=finding.get("host"),
                port=finding.get("port"),
                protocol=finding.get("protocol"),
                service=finding.get("service") or "unknown",
                product=finding.get("product") or "",
                version=finding.get("version") or "",
                refs=f" | refs: {ref_text}" if ref_text else "",
            ).strip()
        )

    return (
        "# SOC Threat Intelligence Report\n\n"
        f"Target: `{target}`\n\n"
        "## Executive Summary\n\n"
        f"Nmap identified {len(vulnerability_scan.get('findings', []))} open service findings. "
        f"Risk distribution: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low.\n\n"
        "## Attack Surface\n\n"
        f"{service_summary}\n\n"
        "## Prioritized Findings\n\n"
        + ("\n".join(finding_lines) if finding_lines else "No open-service findings were generated.")
        + "\n\n## Detection Notes\n\n"
        "- Monitor inbound access to Telnet, FTP, SMB, database, IRC, and remote shell services.\n"
        "- Alert on repeated authentication failures and cleartext management protocols.\n"
        "- Treat exposed legacy services on Metasploitable as intentionally vulnerable lab evidence.\n\n"
        "## Analytic Gaps\n\n"
        "- This report is generated from service discovery and local vulnerability references.\n"
        "- Confirm exact package patch levels before applying production remediation decisions.\n"
    )


def build_tool_remediation_plan(target: str, vulnerability_scan: dict[str, Any]) -> str:
    risky_services = {
        str(finding.get("service") or "").lower()
        for finding in vulnerability_scan.get("findings", [])
        if str(finding.get("risk") or "").lower() in {"critical", "high"}
    }
    service_actions = []
    if {"telnet", "ftp", "netbios-ssn", "mysql", "postgresql"} & risky_services:
        service_actions.extend(
            [
                "- Disable Telnet and replace it with hardened SSH.",
                "- Disable anonymous or legacy FTP; use SFTP/SSH for file transfer.",
                "- Restrict SMB/Samba to trusted internal hosts and disable SMBv1.",
                "- Bind MySQL/PostgreSQL to localhost or application subnets only.",
            ]
        )
    service_actions.extend(
        [
            "- Patch or remove end-of-life services identified in the Nmap scan.",
            "- Apply host firewall rules allowing only required management and application ports.",
            "- Re-run Nmap after remediation and compare open ports against the expected baseline.",
        ]
    )
    return (
        "# Remediation Plan\n\n"
        f"Target: `{target}`\n\n"
        "## Priority Actions\n\n"
        + "\n".join(service_actions)
        + "\n\n## Validation\n\n"
        "- Confirm closed services with `nmap -sV` from the same network segment.\n"
        "- Review authentication logs for prior access attempts.\n"
        "- Keep the Metasploitable host isolated from production networks.\n"
    )


def append_integrated_tool_remediation_actions(
    remediation_plan: str,
    integrated_tool_results: dict[str, Any] | None,
) -> str:
    if not integrated_tool_results:
        return remediation_plan

    sigma = integrated_tool_results.get("results", {}).get("sigma_tool", {})
    skipped = integrated_tool_results.get("skipped_tools", [])
    used = integrated_tool_results.get("used_tools", [])
    actions = []

    sigma_count = int(sigma.get("generated_rule_count") or 0)
    sigma_dir = integrated_tool_results.get("artifacts", {}).get("sigma_rules_dir", "")
    if sigma_count:
        actions.append(
            f"- Review and deploy the {sigma_count} generated Sigma detection rules from `{sigma_dir}` "
            "to the SIEM after tuning field mappings and log sources."
        )

    if "suricata_tool" in used:
        actions.append("- Review parsed Suricata alerts and add network blocks or signatures for confirmed malicious traffic.")
    if "zeek_tool" in used:
        actions.append("- Review Zeek connection/DNS/HTTP telemetry and add network containment for suspicious sessions.")
    if "virustotal_tool" in used:
        vt = integrated_tool_results.get("results", {}).get("virustotal_tool", {})
        detections = vt.get("detections", {}) if isinstance(vt, dict) else {}
        malicious = detections.get("malicious") if isinstance(detections, dict) else None
        if malicious:
            actions.append("- VirusTotal reported malicious detections for the target IOC; prioritize isolation and IOC blocking.")
        else:
            actions.append("- VirusTotal enrichment completed; keep reputation evidence attached to the case for analyst review.")
    if "misp_tool" in used:
        actions.append("- MISP enrichment completed; sync matching attributes/tags into the case and detection backlog.")

    if skipped:
        skipped_text = ", ".join(f"{item.get('tool')} ({item.get('reason')})" for item in skipped)
        actions.append(f"- Complete missing telemetry/enrichment setup so skipped tools can run next time: {skipped_text}.")

    if not actions:
        return remediation_plan

    return (
        remediation_plan.rstrip()
        + "\n\n## Integrated Tool Actions\n\n"
        + "\n".join(actions)
        + "\n"
    )


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
    use_agents: bool = True,
    auto_execute_remediation: bool = True,
    auto_apply_remediation: bool = False,
    remediation_timeout: int = 120,
) -> dict[str, Any]:
    if use_agents:
        scan, nmap_agent_output = run_nmap_stage(target, ports, timeout, reuse_scan)
    else:
        scan, nmap_agent_output = run_nmap_tool_stage(target, ports, timeout, reuse_scan)
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
            "soc_report": diagnostic,
            "remediation_plan": diagnostic,
            "db_path": str(db_path),
            "artifacts": artifacts,
            "nmap_agent_output": nmap_agent_output,
        }

    if use_agents:
        vulnerability_json, vulnerability_report = run_vulnerability_stage(scan)
    else:
        vulnerability_json, vulnerability_report = run_vulnerability_tool_stage(scan)
    scan_context = json.dumps(scan, indent=2)
    vulnerability_context = (
        vulnerability_report
        if vulnerability_report.strip()
        else json.dumps(vulnerability_json, indent=2)
    )

    if use_agents:
        reporting_agent = AgentRegistry.get_agent("reporting_agent")
        report_task = create_reporting_task(reporting_agent, target, scan_context, vulnerability_context)
        soc_report = run_agent_task("reporting_agent", report_task)

        remediation_agent = AgentRegistry.get_agent("remediation_agent")
        remediation_task = create_remediation_task(
            remediation_agent,
            target,
            soc_report,
            vulnerability_context,
        )
        remediation_plan = run_agent_task("remediation_agent", remediation_task)
    else:
        soc_report = build_tool_soc_report(target, scan, service_summary, vulnerability_json)
        remediation_plan = build_tool_remediation_plan(target, vulnerability_json)

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
    artifact_run_id = next_artifact_run_id(run_id)
    integrated_tool_results = run_integrated_tool_stage(
        artifact_run_id,
        target,
        scan,
        vulnerability_json,
    )
    remediation_plan = append_integrated_tool_remediation_actions(
        remediation_plan,
        integrated_tool_results,
    )
    update_saved_remediation_plan(Path(db_path), run_id, remediation_plan)
    script_artifacts = generate_remediation_scripts(
        artifact_run_id,
        target,
        ports,
        scan,
        vulnerability_json,
    )
    remediation_execution = None
    if auto_execute_remediation:
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
        "complete",
        scan,
        service_summary,
        vulnerability_context,
        soc_report,
        remediation_plan,
        nmap_agent_output,
        script_artifacts,
        remediation_execution,
        integrated_tool_results,
    )
    return {
        "run_id": run_id,
        "artifact_run_id": artifact_run_id,
        "status": "complete",
        "target": target,
        "ports": ports,
        "scan": scan,
        "service_summary": service_summary,
        "vulnerability_scan": vulnerability_json,
        "vulnerability_report": vulnerability_context,
        "soc_report": soc_report,
        "remediation_plan": remediation_plan,
        "db_path": str(db_path),
        "artifacts": artifacts,
        "generated_scripts": script_artifacts["manifest"],
        "integrated_tools": integrated_tool_results,
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
        use_agents=not args.tool_only,
        auto_execute_remediation=not args.no_auto_remediation,
        auto_apply_remediation=args.auto_apply_remediation,
        remediation_timeout=args.remediation_timeout,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "scan"}, indent=2))


if __name__ == "__main__":
    main()
