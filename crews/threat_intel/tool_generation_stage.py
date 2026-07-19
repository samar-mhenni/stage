import json
from pathlib import Path
from typing import Any

from agents.execution import run_agent_task_or_fallback
from agents.registry import AgentRegistry
from crews.common.generated_scripts import (
    generated_script_quality_error,
    normalize_remediation_script_body,
    write_script_manifest,
)
from crews.common.json_output import extract_json_object
from crews.threat_intel.evidence import truncate_context
from crews.threat_intel.fallbacks import local_tool_manifest_fallback
from crews.threat_intel.target_access import discover_target_access, format_target_access_context
from tasks.threat_intel import create_tool_generation_task

OUTPUT_DIR = Path("outputs")
RUNS_DIR = OUTPUT_DIR / "runs"
CURRENT_GENERATED_TOOLS_DIR = OUTPUT_DIR / "generated_tools"

def _remediation_manifest_quality_issues(manifest: dict[str, Any], target_access: dict[str, Any]) -> list[str]:
    issues = []
    scripts = manifest.get("scripts")
    if not isinstance(scripts, list):
        return ["manifest scripts field is missing or not a list"]
    network_only = target_access.get("ACCESS_MODE") == "network_only"
    local_only_markers = (
        "/var/log/",
        "iptables",
        "ufw ",
        "firewall-cmd",
        "systemctl",
        "service ",
        "apt ",
        "apt-get",
        "yum ",
        "dnf ",
        "sed -i",
        "/etc/",
    )
    for script in scripts:
        if not isinstance(script, dict):
            issues.append("script entry is not an object")
            continue
        filename = str(script.get("filename") or script.get("name") or "generated_script")
        body = normalize_remediation_script_body(str(script.get("body") or ""))
        quality_error = generated_script_quality_error(body, script.get("interpreter", "bash"))
        if quality_error:
            issues.append(f"{filename}: {quality_error}")
        body_lower = body.lower()
        if network_only and any(marker in body_lower for marker in local_only_markers):
            issues.append(
                f"{filename}: target access is network_only, but script uses API-host local logs, firewall, packages, or service commands"
            )
        if network_only and "--apply" in body_lower and "exit 20" not in body_lower and any(
            marker in body_lower for marker in ("iptables", "systemctl", "service ", "apt", "yum", "dnf", "sed -i")
        ):
            issues.append(f"{filename}: network_only apply path must skip with exit 20 instead of changing the API host")
    return issues


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
    target_access = discover_target_access(target)
    target_access_context = format_target_access_context(target, target_access)
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    manifest_parse_failed = False
    retry_suffix = ""
    quality_issues: list[str] = []
    for attempt in range(3):
        tool_task = create_tool_generation_task(
            tool_agent,
            target,
            truncate_context(scan_context, 1800),
            truncate_context(vulnerability_context, 2200),
            truncate_context(correlation_report, 1200),
            truncate_context(prediction_report, 1000),
            truncate_context(soc_report, 1200),
            truncate_context(
                "Target access context for generated scripts:\n"
                + target_access_context
                + "\n\nRemediation plan:\n"
                + remediation_plan
                + retry_suffix,
                2200,
            ),
        )
        raw_manifest = run_agent_task_or_fallback(
            "tool_generation_agent",
            tool_task,
            json.dumps(
                {
                    "agent": "tool_generation_agent",
                    "mode": "local_fallback_no_llm_output",
                    "safety": "LLM returned no output; no remediation script was generated.",
                    "scripts": [],
                }
            ),
        )
        parsed_manifest = True
        try:
            manifest = extract_json_object(raw_manifest)
        except Exception:
            parsed_manifest = False
            manifest_parse_failed = True
            manifest = {
                "agent": "tool_generation_agent",
                "mode": "llm_generated_each_run",
                "safety": "Tool generation output could not be parsed as JSON.",
                "scripts": [],
                "raw_output": raw_manifest,
            }
        quality_issues = _remediation_manifest_quality_issues(manifest, target_access)
        if quality_issues:
            manifest["scripts"] = []
        if parsed_manifest and manifest.get("scripts"):
            break
        retry_suffix = (
            "\n\nThe previous tool manifest was invalid, truncated, or contained no runnable scripts. "
            "Return exactly one complete minified JSON object with up to 2 short bash scripts. "
            "Keep each body under 45 lines. Use if statements for probes; do not let grep/process checks "
            "abort under set -e. In apply mode, validate the service state and exit nonzero only when the "
            "corrective action truly failed. If target access mode is network_only, do not read local log files, "
            "do not use iptables/ufw/firewall-cmd, do not use systemctl/service, do not edit /etc, and do not "
            "run package managers on the API host. In network_only mode, generate remote HTTP validation only, "
            "or exit 20 with a clear skip reason for changes that require host/container access. "
            f"Quality issues: {truncate_context('; '.join(quality_issues) or 'None.', 900)}. "
            "Do not include markdown."
        )
    if manifest_parse_failed or not manifest.get("scripts"):
        fallback_manifest = local_tool_manifest_fallback(target, scan_context)
        fallback_manifest["generation_error"] = (
            "The LLM tool manifest was invalid/truncated after retry."
            if manifest_parse_failed
            else "No runnable LLM scripts were generated after retry."
        )
        fallback_manifest["raw_tool_generation_output"] = raw_manifest
        manifest = fallback_manifest
    manifest["target_access"] = target_access
    script_artifacts = write_script_manifest(
        run_dir=RUNS_DIR / f"run_{artifact_run_id:04d}" / "generated_scripts",
        current_dir=CURRENT_GENERATED_TOOLS_DIR,
        target=target,
        manifest=manifest,
        default_agent="tool_generation_agent",
        default_mode="llm_generated_each_run",
        safety="Scripts default to dry-run and require --apply for changes.",
        normalizer=normalize_remediation_script_body,
    )
    if not script_artifacts["manifest"].get("scripts") and manifest.get("scripts"):
        fallback_manifest = local_tool_manifest_fallback(target, scan_context)
        fallback_manifest["generation_error"] = "All generated scripts failed local syntax validation."
        fallback_manifest["skipped_generated_scripts"] = script_artifacts["manifest"].get("skipped_scripts", [])
        fallback_manifest["target_access"] = target_access
        script_artifacts = write_script_manifest(
            run_dir=RUNS_DIR / f"run_{artifact_run_id:04d}" / "generated_scripts",
            current_dir=CURRENT_GENERATED_TOOLS_DIR,
            target=target,
            manifest=fallback_manifest,
            default_agent="tool_generation_agent",
            default_mode="local_fallback_from_scan_evidence",
            safety="Generated scripts failed syntax validation; fallback validation script created from evidence.",
            normalizer=normalize_remediation_script_body,
        )
    return script_artifacts

