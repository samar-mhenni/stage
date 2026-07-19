import json
from typing import Any

from agents.execution import run_agent_task
from agents.registry import AgentRegistry
from crews.common.generated_scripts import normalize_red_team_script_body, write_script_manifest
from crews.red_team.config import red_team_artifact_name, red_team_artifact_path
from crews.red_team.planning import (
    _database_guided_validation_manifest,
    _manifest_generation_quality_issues,
    _manifest_has_weak_rce_validation,
    _manifest_uses_unsupported_fallback_specifics,
)
from crews.common.json_output import extract_json_object, salvage_generated_script_objects
from crews.threat_intel.pipeline import RUNS_DIR, truncate_context
from tasks.red_team import create_red_team_tool_generation_task


def _lab_scoped_tomcat_put_manifest(target: str, plan_context: str) -> dict[str, Any]:
    context = str(plan_context or "")
    if "CVE-2017-12615" not in context or "readonly=false" not in context:
        return {}
    body = """#!/usr/bin/env bash
set -uo pipefail
OUT_DIR="${OUT_DIR:-.}"
EXECUTE=0
for arg in "$@"; do
  [[ "$arg" == "--execute" ]] && EXECUTE=1
done
mkdir -p "$OUT_DIR"
OBS="$OUT_DIR/observations.txt"
MARKER="validation-put-$(date +%s)"
URL="http://127.0.0.1:18080/validation_marker.txt"
RAW="$OUT_DIR/validation_marker_body.txt"
HDR="$OUT_DIR/validation_marker_headers.txt"
echo "[plan] Lab-scoped CVE-2017-12615 harmless text PUT validation." > "$OBS"
echo "URL: $URL" >> "$OBS"
echo "Marker: $MARKER" >> "$OBS"
if [[ "$EXECUTE" -ne 1 ]]; then
  echo "[dry-run] Would PUT a plain-text marker file, GET it back, and optionally DELETE it." >> "$OBS"
  exit 0
fi
PUT_STATUS="$(printf "%s" "$MARKER" | curl -ksS -X PUT --data-binary @- -D "$HDR" -o /dev/null -w "%{http_code}" "$URL" 2>>"$OBS" || true)"
echo "PUT Status: $PUT_STATUS" >> "$OBS"
GET_STATUS="$(curl -ksS -D "$HDR" -o "$RAW" -w "%{http_code}" "$URL" 2>>"$OBS" || true)"
echo "GET Status: $GET_STATUS" >> "$OBS"
if grep -Fq "$MARKER" "$RAW"; then
  echo "Confirmed CVE-2017-12615-style writable PUT behavior: harmless marker file was written and retrieved." >> "$OUT_DIR/confirmed_exploits.txt"
  echo "[confirmed] Marker retrieved successfully from harmless text proof artifact." >> "$OBS"
else
  echo "[not-confirmed] Marker was not retrieved from the harmless text proof artifact." >> "$OBS"
fi
DELETE_STATUS="$(curl -ksS -X DELETE -o /dev/null -w "%{http_code}" "$URL" 2>>"$OBS" || true)"
echo "DELETE Status: $DELETE_STATUS" >> "$OBS"
"""
    return {
        "agent": "red_team_tool_generation_agent",
        "mode": "lab_scoped_validation",
        "safety": "Lab-scoped harmless PUT validation for the Vulhub Tomcat CVE-2017-12615 environment.",
        "target": target,
        "fallback_reason": "Environment context explicitly scoped the run to Vulhub Tomcat CVE-2017-12615.",
        "scripts": [
            {
                "name": "cve_2017_12615_put_check",
                "filename": "01_cve_2017_12615_put_check.sh",
                "domain": "web",
                "purpose": "Validate harmless writable PUT behavior for the scoped Vulhub Tomcat CVE-2017-12615 lab.",
                "interpreter": "bash",
                "body": body,
            }
        ],
    }


def run_red_team_tool_generation_stage(
    artifact_run_id: int,
    target: str,
    scan_context: str,
    plan_context: str,
    exploit_context: dict[str, Any] | None = None,
    http_context: str = "",
) -> dict[str, Any]:
    lab_scoped_manifest = _lab_scoped_tomcat_put_manifest(target, plan_context)
    if lab_scoped_manifest:
        return write_script_manifest(
            run_dir=(RUNS_DIR / f"run_{artifact_run_id:04d}" / red_team_artifact_name("tools_subdir")).resolve(),
            current_dir=red_team_artifact_path("current_tools_dir").resolve(),
            target=target,
            manifest=lab_scoped_manifest,
            default_agent="red_team_tool_generation_agent",
            default_mode="lab_scoped_validation",
            safety="Scripts default to dry-run and require --execute for active validation.",
            normalizer=normalize_red_team_script_body,
        )

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

    database_guided_manifest = _database_guided_validation_manifest(
        target=target,
        scan_context=scan_context,
        plan_context=(plan_context + "\n\n" + http_context).strip(),
        exploit_context=exploit_context,
        reason="Structured validation guidance was available in the ingested database.",
    )
    if database_guided_manifest:
        return write_script_manifest(
            run_dir=(RUNS_DIR / f"run_{artifact_run_id:04d}" / red_team_artifact_name("tools_subdir")).resolve(),
            current_dir=red_team_artifact_path("current_tools_dir").resolve(),
            target=target,
            manifest=database_guided_manifest,
            default_agent="red_team_tool_generation_agent",
            default_mode="database_guided_validation",
            safety="Scripts are generated from structured database validation guidance and require --execute.",
            normalizer=normalize_red_team_script_body,
        )

    tool_agent = AgentRegistry.get_agent("red_team_tool_generation_agent")
    retry_plan_context = truncate_context(plan_context, 6000)
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    quality_issues: list[str] = []
    for attempt in range(3):
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
        if _manifest_has_weak_rce_validation(manifest, plan_context):
            manifest["scripts"] = []
            raw_manifest = json.dumps(manifest)
        quality_issues = _manifest_generation_quality_issues(manifest, plan_context)
        if quality_issues:
            manifest["scripts"] = []
            raw_manifest = json.dumps({"quality_issues": quality_issues, "manifest": manifest})
        if manifest.get("scripts"):
            break
        retry_plan_context = (
            "Previous tool manifest was invalid, empty, or had no scripts. "
            "Return only complete valid minified JSON. Do not escape dollar signs. "
            "Generate exactly one compact bash script for the strongest fresh-recon validation candidate. "
            "If the strongest candidate is RCE, command injection, OGNL, or template injection, do not check only "
            "version, setup endpoint reachability, or HTTP 200. Generate a harmless unique-marker validation that "
            "writes observations.txt and confirms only when the marker is returned in the response/header or a "
            "distinctive product-specific injection-path signal appears. "
            "The generated marker must be included in the actual validation request URL, header, or body. "
            "Assign any raw response artifact path once, for example RAW=\"$OUT_DIR/response.raw\" or "
            "RUN_ID=$(date +%s); RAW=\"$OUT_DIR/${RUN_ID}.raw\", then reuse that same RAW variable for curl, grep, "
            "parsing, and observations. Never generate separate timestamped filenames for curl output and marker checks. "
            "Never write negative evidence such as 'not found' or 'not confirmed' to confirmed_exploits.txt; "
            "write that only to observations.txt. "
            "If the database guidance says to use a URL path segment and not a query parameter, preserve that exactly: "
            "do not use ?param=, setup pages, or setup-step paths for the validation request. "
            "If a URL needs a literal ${...} sequence, single-quote or percent-encode it so Bash never treats it as "
            "parameter expansion. "
            "If exploit source mode is llm_fallback, do not include CVE IDs, known-vulnerable claims, traversal payloads, "
            "or sensitive filesystem paths; use only conservative banner, header, method, and response-difference evidence checks. "
            "If this is an account-creation CVE, include the generated username/password and login URL in "
            "created_credentials.txt. Keep script body under 45 lines.\n\n"
            f"Original plan:\n{truncate_context(plan_context, 3500)}\n\n"
            f"Quality issues:\n{truncate_context(chr(10).join(quality_issues) or 'None.', 1200)}\n\n"
            f"Previous output excerpt:\n{truncate_context(raw_manifest, 1200)}"
        )
    if not manifest.get("scripts"):
        fallback_reason = "LLM tool manifest was empty, invalid, or failed generated-script quality checks."
        fallback_manifest = _database_guided_validation_manifest(
            target=target,
            scan_context=scan_context,
            plan_context=(plan_context + "\n\n" + http_context).strip(),
            exploit_context=exploit_context,
            reason=fallback_reason,
        )
        if fallback_manifest:
            fallback_manifest["raw_tool_generation_output"] = raw_manifest
            if quality_issues:
                fallback_manifest["quality_issues"] = quality_issues
            manifest = fallback_manifest
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
