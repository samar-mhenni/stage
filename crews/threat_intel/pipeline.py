import argparse
import json
import re
from pathlib import Path
from typing import Any

import agents.threat_intel  # noqa: F401 - registers threat-intel agents
from agents.execution import run_agent_task, run_agent_task_or_fallback
from agents.registry import AgentRegistry
from crews.common.generated_scripts import (
    execute_remediation_scripts,
    normalize_remediation_script_body,
    write_script_manifest,
)
from crews.threat_intel.fallbacks import (
    local_correlation_fallback,
    local_prediction_fallback,
    local_remediation_fallback,
    local_soc_report_fallback,
    local_tool_manifest_fallback,
    local_vulnerability_fallback,
)
from crews.threat_intel.storage import (
    build_run_artifacts,
    remediation_execution_overview,
    remediation_execution_status,
    save_run,
)
from crews.threat_intel.target_access import discover_target_access, format_target_access_context
from tasks.threat_intel import (
    create_correlation_task,
    create_prediction_task,
    create_remediation_task,
    create_reporting_task,
    create_tool_generation_task,
    create_vulnerability_scan_task,
)
from tools import get_records_by_metadata, search_records


OUTPUT_DIR = Path("outputs")
RUNS_DIR = OUTPUT_DIR / "runs"
CURRENT_GENERATED_TOOLS_DIR = OUTPUT_DIR / "generated_tools"
DEFAULT_DB_PATH = OUTPUT_DIR / "threat_intel_results.db"
GENERIC_EVIDENCE_TERMS = {
    "http",
    "https",
    "service",
    "status",
    "event",
    "events",
    "source",
    "target",
    "generated",
    "redacted",
    "evidence",
    "tool",
    "logs",
    "alert",
    "host",
    "port",
    "risk",
    "medium",
    "high",
    "low",
}


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
    parser.add_argument("target", nargs="?", default="provided-evidence", help="Evidence label or target name.")
    parser.add_argument("--evidence-path", default="", help="Required JSON/text logs or tool-output evidence file.")
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="SQLite output path.")
    parser.add_argument("--reuse-scan", default="", help="Deprecated alias for --evidence-path.")
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


def _flatten_evidence_text(value: Any, limit: int = 24000) -> str:
    if isinstance(value, str):
        return value[:limit]
    try:
        return json.dumps(value, indent=2)[:limit]
    except TypeError:
        return str(value)[:limit]


def _tokens(value: Any) -> set[str]:
    text = str(value or "").lower()
    return {
        token
        for token in "".join(char if char.isalnum() else " " for char in text).split()
        if len(token) >= 4 and not token.isdigit() and token not in GENERIC_EVIDENCE_TERMS
    }


def _evidence_cves(text: str) -> set[str]:
    return {match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)}


def _evidence_attack_ids(text: str) -> set[str]:
    return {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)}


def _evidence_queries(scan: dict[str, Any], raw_evidence: str = "", limit: int = 8) -> list[str]:
    text = _flatten_evidence_text(scan) + "\n" + str(raw_evidence or "")[:12000]
    queries: list[str] = []
    if "hosts" in scan:
        for host in scan.get("hosts", []):
            for port in host.get("ports", []):
                if port.get("state") and port.get("state") != "open":
                    continue
                parts = [
                    str(port.get("service") or ""),
                    str(port.get("product") or ""),
                    str(port.get("version") or ""),
                    str(port.get("extra_info") or ""),
                    "vulnerability detection mitigation",
                ]
                query = " ".join(part for part in parts if part).strip()
                if query and query not in queries:
                    queries.append(query)
    patterns = [
        r"CVE-\d{4}-\d{4,7}",
        r"\bT\d{4}(?:\.\d{3})?\b",
        r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\b[a-fA-F0-9]{32,64}\b",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            query = f"{match} threat intelligence detection mitigation"
            if query not in queries:
                queries.append(query)
            if len(queries) >= limit:
                return queries[:limit]
    if not queries:
        for line in str(raw_evidence or "").splitlines():
            cleaned = re.sub(r"\s+", " ", line).strip()
            if len(cleaned) >= 30:
                queries.append(cleaned[:220] + " threat intelligence")
            if len(queries) >= limit:
                break
    return queries[:limit]


def build_local_threat_context(scan: dict[str, Any], raw_evidence: str = "", top_k: int = 3) -> str:
    records = []
    seen = set()
    evidence_text = _flatten_evidence_text(scan) + "\n" + str(raw_evidence or "")
    observed_cves = _evidence_cves(evidence_text)
    observed_attack_ids = _evidence_attack_ids(evidence_text)
    observed_terms = _tokens(evidence_text)

    def add_record(record: dict[str, Any]) -> None:
        key = (record.get("source"), record.get("type"), record.get("name"), record.get("text"))
        if key in seen:
            return
        seen.add(key)
        record_text = " ".join(str(record.get(key) or "") for key in ("name", "type", "text", "cve_str", "mitre_id"))
        record_cves = _evidence_cves(record_text)
        record_attack_ids = _evidence_attack_ids(record_text)
        record_terms = _tokens(record_text)
        record["_exact_cve_overlap"] = len(observed_cves & record_cves)
        record["_exact_attack_overlap"] = len(observed_attack_ids & record_attack_ids)
        record["_term_overlap"] = len(observed_terms & record_terms)
        records.append(record)

    for record in get_records_by_metadata("threat_intel_db", "name", observed_cves):
        add_record(record)
    for record in get_records_by_metadata("attack_db", "mitre_id", observed_attack_ids):
        add_record(record)

    for query in _evidence_queries(scan, raw_evidence):
        for record in search_records(
            query,
            ["threat_intel_db", "detection_db", "attack_db", "actor_db"],
            top_k=top_k,
            type_filters={"attack_db": {"attack-pattern"}},
        ):
            add_record(record)
    if not records:
        return "No local database enrichment records matched the supplied evidence."
    records = sorted(
        records,
        key=lambda item: (
            item.get("_exact_cve_overlap", 0),
            item.get("_exact_attack_overlap", 0),
            item.get("_term_overlap", 0),
            item.get("match", 0),
        ),
        reverse=True,
    )[:10]
    lines = ["Local database enrichment from supplied evidence:"]
    for record in records:
        record.pop("_exact_cve_overlap", None)
        record.pop("_exact_attack_overlap", None)
        record.pop("_term_overlap", None)
        lines.append(
            "\n".join(
                [
                    f"- Source: {record.get('source')}",
                    f"  Type: {record.get('type')}",
                    f"  Name: {record.get('name')}",
                    f"  Match: {record.get('match'):.4f}",
                    f"  Evidence: {record.get('text')}",
                ]
            )
        )
    return "\n".join(lines)


def summarize_services(scan: dict[str, Any]) -> str:
    if "hosts" not in scan:
        source = scan.get("source") or scan.get("evidence_path") or "provided evidence"
        kind = scan.get("evidence_type", "logs")
        env = scan.get("environment") if isinstance(scan.get("environment"), dict) else {}
        events = scan.get("events") if isinstance(scan.get("events"), list) else []
        lines = [f"Evidence source: {source} ({kind})."]
        host = env.get("host_ip") or scan.get("target")
        service = env.get("service")
        port = env.get("port")
        if host and service:
            endpoint = f"{host}:{port}" if port else str(host)
            lines.append(f"Observed asset: {endpoint} {service}.")
        products = []
        for key in ("server_header", "x_powered_by", "application_fingerprint"):
            if env.get(key):
                products.append(str(env[key]))
        for event in events:
            if not isinstance(event, dict):
                continue
            product = " ".join(str(event.get(key) or "") for key in ("product", "service", "version")).strip()
            if product:
                products.append(product)
        if products:
            unique_products = list(dict.fromkeys(products))
            lines.append("Observed products/signals: " + "; ".join(unique_products[:6]) + ".")
        return " ".join(lines)
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


def load_evidence(evidence_path: str | Path, target: str = "provided-evidence") -> tuple[dict[str, Any], str]:
    path = Path(evidence_path)
    if not path.is_file():
        raise ValueError(f"Evidence file is required and was not found: {path}")
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "target": target,
            "source": str(path),
            "evidence_type": "text_logs",
            "logs": raw_text.splitlines(),
        }
    if isinstance(parsed, dict):
        evidence = parsed
    else:
        evidence = {
            "target": target,
            "source": str(path),
            "evidence_type": "json_logs",
            "events": parsed,
        }
    evidence.setdefault("target", target)
    evidence.setdefault("source", str(path))
    evidence.setdefault("evidence_type", "provided_logs")
    return evidence, raw_text


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
    for attempt in range(2):
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
        if parsed_manifest and manifest.get("scripts"):
            break
        retry_suffix = (
            "\n\nThe previous tool manifest was invalid, truncated, or contained no runnable scripts. "
            "Return exactly one complete minified JSON object with up to 2 short bash scripts. "
            "Keep each body under 45 lines. Use if statements for probes; do not let grep/process checks "
            "abort under set -e. In apply mode, validate the service state and exit nonzero only when the "
            "corrective action truly failed. Do not include markdown."
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
        + truncate_context(local_threat_context, 1800)
    )
    correlation_agent = AgentRegistry.get_agent("correlation_agent")
    correlation_task = create_correlation_task(
        correlation_agent,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(vulnerability_context, 2200),
        telemetry_context,
        truncate_context(local_threat_context, 1600),
    )
    correlation_report = run_agent_task_or_fallback(
        "correlation_agent",
        correlation_task,
        local_correlation_fallback(target, vulnerability_context),
    )

    prediction_agent = AgentRegistry.get_agent("prediction_agent")
    prediction_task = create_prediction_task(
        prediction_agent,
        target,
        truncate_context(correlation_report, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(local_threat_context, 1400),
    )
    prediction_report = run_agent_task_or_fallback(
        "prediction_agent",
        prediction_task,
        local_prediction_fallback(target, vulnerability_context),
    )

    reporting_agent = AgentRegistry.get_agent("reporting_agent")
    report_task = create_reporting_task(
        reporting_agent,
        target,
        truncate_context(scan_context, 1800),
        truncate_context(vulnerability_context, 1800),
        truncate_context(correlation_report, 1500),
        truncate_context(prediction_report, 1200),
        truncate_context(local_threat_context, 1400),
    )
    soc_report = run_agent_task_or_fallback(
        "reporting_agent",
        report_task,
        local_soc_report_fallback(
            target,
            service_summary,
            vulnerability_context,
            correlation_report,
            prediction_report,
        ),
    )

    script_artifacts = None
    if include_remediation_plan:
        remediation_agent = AgentRegistry.get_agent("remediation_agent")
        remediation_task = create_remediation_task(
            remediation_agent,
            target,
            truncate_context(soc_report, 1800),
            truncate_context(vulnerability_context, 1800),
            truncate_context(correlation_report, 1300),
            truncate_context(prediction_report, 1000),
            truncate_context(local_threat_context, 1400),
        )
        remediation_plan = run_agent_task_or_fallback(
            "remediation_agent",
            remediation_task,
            local_remediation_fallback(target, vulnerability_context),
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
    args = parse_args()
    result = run_threat_intel_pipeline(
        target=args.target,
        db_path=args.db_path,
        evidence_path=args.evidence_path,
        reuse_scan=args.reuse_scan,
        auto_execute_remediation=not args.no_auto_remediation,
        include_remediation_plan=not args.skip_remediation_plan,
        auto_apply_remediation=args.auto_apply_remediation,
        remediation_timeout=args.remediation_timeout,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "scan"}, indent=2))


if __name__ == "__main__":
    main()
