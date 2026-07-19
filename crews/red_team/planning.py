import json
import re
import shlex
from typing import Any

from crews.common.generated_scripts import generated_script_quality_error, normalize_red_team_script_body
from crews.common.json_output import extract_json_object, salvage_generated_script_objects
from crews.threat_intel.pipeline import truncate_context
from tools import get_records_by_metadata

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
        "# Red-Team Run Summary",
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
        lines.extend(["## Evidence Report", "", report, ""])
        lines.extend(
            [
                "## Candidate Plan",
                "",
                "Candidate planning output is stored in `red_team_used.json`. It is not treated as confirmation.",
                "",
                "## Artifacts",
                "",
            ]
        )
        if execution and execution.get("results_path"):
            lines.append(f"- Raw execution JSON: `{execution['results_path']}`")
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(["## Candidate Plan", "", str(plan_text or "No candidate plan was generated."), "", "## Validation Scripts", ""])
    if scripts:
        for script in scripts:
            lines.append(f"- `{script['filename']}`: {script.get('purpose', 'Generated validation script')}")
    else:
        lines.append("- No scripts were generated.")
    lines.extend(["", "## Execution", "", human_result_text])
    if execution and execution.get("results_path"):
        lines.extend(["", f"Raw execution JSON: `{execution['results_path']}`"])
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


def _tokens(value: Any) -> set[str]:
    text = str(value or "").lower()
    return {
        token
        for token in "".join(char if char.isalnum() else " " for char in text).split()
        if len(token) >= 4 and not token.isdigit()
    }


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


def _record_field(record: dict[str, Any], field_name: str) -> str:
    text = str(record.get("text") or "")
    match = re.search(
        rf"(?ims)^{re.escape(field_name)}:\s*(.*?)(?=\n[A-Za-z][A-Za-z0-9_ ]*:\s*|\Z)",
        text,
    )
    return match.group(1).strip() if match else ""


def _http_base_url_from_context(target: str, scan_context: str, plan_context: str) -> str:
    def from_host_port(host: str, port: str, scheme: str = "http") -> str:
        host = host.strip().rstrip("/")
        port = port.strip()
        if host.startswith(("http://", "https://")):
            base_match = re.match(r"^(https?://[^/]+)", host)
            if not base_match:
                return host
            base = base_match.group(1)
            if re.search(r":\d+$", base) or port in {"80", "443"}:
                return base
            return f"{base}:{port}"
        if port in {"80", "443"}:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    service_match = re.search(r"\b([A-Za-z0-9_.-]+):(\d+)/TCP\b", plan_context, flags=re.IGNORECASE)
    if service_match:
        host, port = service_match.groups()
        return from_host_port(host, port)

    try:
        scan = json.loads(scan_context)
    except Exception:
        scan = {}
    for host in scan.get("hosts", []):
        host_id = host.get("host") or target
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = str(port.get("service") or "").lower()
            scheme = "https" if "https" in service or "ssl" in str(port.get("extra_info") or "").lower() else "http"
            port_value = str(port.get("port") or "").strip()
            if port_value in {"80", "443"}:
                return f"{scheme}://{host_id}"
            if port_value:
                return f"{scheme}://{host_id}:{port_value}"

    scan_text = str(scan_context or "")
    host_match = re.search(r'"(?:target|host)"\s*:\s*"([^"]+)"', scan_text)
    host = host_match.group(1) if host_match else target
    ports_match = re.search(r'"ports"\s*:\s*"(\d{2,5})"', scan_text)
    if ports_match:
        return from_host_port(host, ports_match.group(1))
    open_port_match = re.search(r'"port"\s*:\s*(\d{2,5}).{0,250}"state"\s*:\s*"open"', scan_text, flags=re.DOTALL)
    if open_port_match:
        return from_host_port(host, open_port_match.group(1))

    url_match = re.search(r"https?://[^\s`\"')]+", plan_context)
    if url_match and target in url_match.group(0):
        url = url_match.group(0).rstrip("/")
        return re.sub(r"^(https?://[^/]+).*$", r"\1", url)
    port_context_match = re.search(r"\b(?:port|ports|on)\s+(\d{2,5})\b", plan_context, flags=re.IGNORECASE)
    if port_context_match:
        return from_host_port(target, port_context_match.group(1))
    return target.rstrip("/") if target.startswith(("http://", "https://")) else f"http://{target}"


def _database_guided_validation_manifest(
    target: str,
    scan_context: str,
    plan_context: str,
    exploit_context: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    observed_terms = _scan_context_terms(scan_context)
    records = (exploit_context or {}).get("records") or []
    for record in records:
        if not isinstance(record, dict) or str(record.get("type") or "") != "validation_guidance":
            continue
        product_terms = _record_product_terms(record)
        if observed_terms and product_terms and not (observed_terms & product_terms):
            continue
        record_terms = _tokens(" ".join(str(record.get(key) or "") for key in ("name", "type", "text")))
        if observed_terms and not (observed_terms & record_terms):
            continue
        record = _full_validation_guidance_record(record)
        path_template = _record_field(record, "validationPathTemplate")
        validation_type = _record_field(record, "validationType")
        if not path_template or validation_type not in {
            "http_path_ognl_header_marker",
            "http_content_type_ognl_header_marker",
        }:
            continue

        cve_id = _record_field(record, "cveID") or str(record.get("name") or "database_guided_validation")
        header_name = _record_field(record, "confirmationHeader") or "X-Codex-Marker"
        method = (_record_field(record, "httpMethod") or "GET").upper()
        base_url = _http_base_url_from_context(target, scan_context, plan_context)
        script_name = re.sub(r"[^a-z0-9]+", "_", cve_id.lower()).strip("_") or "database_guided_validation"
        if validation_type == "http_path_ognl_header_marker":
            body = f"""#!/usr/bin/env bash
set -uo pipefail
OUT_DIR="${{OUT_DIR:-.}}"
EXECUTE=0
for arg in "$@"; do [[ "$arg" == "--execute" ]] && EXECUTE=1; done
mkdir -p "$OUT_DIR"
OBS="$OUT_DIR/observations.txt"
RUN_ID="$(date +%s)"
MARKER="codex${{RUN_ID}}"
BASE_URL={shlex.quote(base_url)}
PATH_TEMPLATE={shlex.quote(path_template)}
HEADER_NAME={shlex.quote(header_name)}
RAW="$OUT_DIR/{script_name}_body.raw"
HDR="$OUT_DIR/{script_name}_headers.txt"
URL="$(python3 - "$BASE_URL" "$PATH_TEMPLATE" "$MARKER" <<'PY'
import sys
from urllib.parse import quote
base, template, marker = sys.argv[1:]
path = template.replace("{{marker}}", marker)
print(base.rstrip("/") + "/" + quote(path.lstrip("/"), safe="/"))
PY
)"
echo "[plan] Database-guided {cve_id} validation using harmless marker response evidence." > "$OBS"
echo "URL: $URL" >> "$OBS"
echo "Marker: $MARKER" >> "$OBS"
if [[ "$EXECUTE" -ne 1 ]]; then
  echo "[dry-run] Would send bounded {method} request and confirm only if $HEADER_NAME or body contains marker." >> "$OBS"
  exit 0
fi
HTTP_STATUS="$(curl -ksS --path-as-is --max-time 15 -X {method} \\
  -H "Accept-Encoding: gzip, deflate" \\
  -H "Accept: */*" \\
  -H "Accept-Language: en" \\
  -H "User-Agent: Mozilla/5.0" \\
  -H "Connection: close" \\
  -D "$HDR" -o "$RAW" -w "%{{http_code}}" "$URL" 2>>"$OBS" || true)"
touch "$HDR" "$RAW"
echo "HTTP Status: $HTTP_STATUS" >> "$OBS"
if grep -Fqi "$HEADER_NAME: $MARKER" "$HDR" || grep -Fq "$MARKER" "$RAW"; then
  echo "Confirmed {cve_id}: marker returned by database-guided validation request." >> "$OUT_DIR/confirmed_exploits.txt"
  echo "[confirmed] Marker found in response evidence." >> "$OBS"
elif grep -Eqi "^Location: .*/(bootstrap|setup)/" "$HDR"; then
  echo "[not-confirmed] Confluence redirected the crafted request to setup/bootstrap before marker execution." >> "$OBS"
  echo "[diagnosis] The lab is reachable but appears not fully initialized; initialize Confluence setup before validating this CVE." >> "$OBS"
else
  echo "[not-confirmed] Marker was not found in response headers or body." >> "$OBS"
fi
"""
        else:
            body = f"""#!/usr/bin/env bash
set -uo pipefail
OUT_DIR="${{OUT_DIR:-.}}"
EXECUTE=0
for arg in "$@"; do [[ "$arg" == "--execute" ]] && EXECUTE=1; done
mkdir -p "$OUT_DIR"
OBS="$OUT_DIR/observations.txt"
RUN_ID="$(date +%s)"
MARKER="codex${{RUN_ID}}"
BASE_URL={shlex.quote(base_url)}
HEADER_TEMPLATE={shlex.quote(path_template)}
HEADER_NAME={shlex.quote(header_name)}
RAW="$OUT_DIR/{script_name}_body.raw"
HDR="$OUT_DIR/{script_name}_headers.txt"
CONTENT_TYPE="${{HEADER_TEMPLATE//\\{{marker\\}}/$MARKER}}"
echo "[plan] Database-guided {cve_id} validation using harmless Content-Type marker evidence." > "$OBS"
echo "URL: $BASE_URL" >> "$OBS"
echo "Marker: $MARKER" >> "$OBS"
if [[ "$EXECUTE" -ne 1 ]]; then
  echo "[dry-run] Would send bounded {method} request and confirm only if $HEADER_NAME contains marker." >> "$OBS"
  exit 0
fi
HTTP_STATUS="$(curl -ksS --path-as-is --max-time 15 -X {method} \\
  -H "Content-Type: $CONTENT_TYPE" \\
  -D "$HDR" -o "$RAW" -w "%{{http_code}}" "$BASE_URL" 2>>"$OBS" || true)"
touch "$HDR" "$RAW"
echo "HTTP Status: $HTTP_STATUS" >> "$OBS"
if grep -Fqi "$HEADER_NAME: $MARKER" "$HDR"; then
  echo "Confirmed {cve_id}: marker returned by database-guided validation request." >> "$OUT_DIR/confirmed_exploits.txt"
  echo "[confirmed] Marker found in response header evidence." >> "$OBS"
else
  echo "[not-confirmed] Marker was not found in response headers." >> "$OBS"
fi
"""
        return {
            "agent": "red_team_tool_generation_agent",
            "mode": "database_guided_fallback",
            "safety": "Generated from structured validation guidance in the ingested database after LLM tool output failed validation.",
            "target": target,
            "fallback_reason": reason,
            "scripts": [
                {
                    "name": f"{script_name}_check",
                    "filename": f"01_{script_name}_check.sh",
                    "domain": "web",
                    "purpose": f"Validate {cve_id} using structured database guidance and harmless marker evidence.",
                    "interpreter": "bash",
                    "body": body,
                }
            ],
        }
    return {}


def _full_validation_guidance_record(record: dict[str, Any]) -> dict[str, Any]:
    if _record_field(record, "validationType") and _record_field(record, "validationPathTemplate"):
        return record
    cve_id = _record_field(record, "cveID") or str(record.get("name") or "")
    if not cve_id:
        return record
    for candidate in get_records_by_metadata("threat_intel_db", "name", {cve_id}):
        if candidate.get("type") == "validation_guidance":
            return candidate
    return record


def _observed_service_label(scan: dict[str, Any]) -> str:
    fingerprints = [
        item
        for item in scan.get("web_fingerprints", [])
        if isinstance(item, dict) and item.get("application")
    ]
    app_label = ""
    if fingerprints:
        first = fingerprints[0]
        versions = ", ".join(str(version) for version in first.get("versions", []) if version)
        app_label = str(first.get("application"))
        if versions:
            app_label = f"{app_label} {versions}"
    for host in scan.get("hosts", []):
        host_id = host.get("host") or scan.get("target")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = app_label or " ".join(
                str(port.get(key) or "")
                for key in ("service", "product", "version", "extra_info")
                if port.get(key)
            ).strip()
            return f"{host_id}:{port.get('port')}/TCP - {service or 'observed open service'}"
    return str(scan.get("target") or "observed target")


def _scan_context_terms(scan_context: str) -> set[str]:
    try:
        scan = json.loads(scan_context)
    except Exception:
        return set()
    return _scan_service_terms(scan)


def _record_product_terms(record: dict[str, Any]) -> set[str]:
    return _tokens(
        " ".join(
            _record_field(record, field_name)
            for field_name in ("product", "vulnerabilityName")
        )
    )


def _database_ranked_plan(scan: dict[str, Any], exploit_context: dict[str, Any]) -> str:
    if exploit_context.get("source_mode") != "database_first":
        return ""
    records = [record for record in exploit_context.get("records", []) if isinstance(record, dict)]
    if not records:
        return ""

    service_label = _observed_service_label(scan)
    observed_terms = _scan_service_terms(scan)
    lines = []
    for record in records[:5]:
        if str(record.get("type") or "") == "validation_guidance":
            product_terms = _record_product_terms(record)
            if observed_terms and product_terms and not (observed_terms & product_terms):
                continue
        record_terms = _tokens(" ".join(str(record.get(key) or "") for key in ("name", "type", "text")))
        if observed_terms and not (observed_terms & record_terms):
            continue
        name = str(record.get("name") or record.get("type") or "database candidate")
        source = str(record.get("source") or "database")
        record_type = str(record.get("type") or "candidate")
        validation_hint = _record_field(record, "validationHint")
        short_description = _record_field(record, "shortDescription")
        safe_idea = validation_hint or (
            "Generate a bounded, non-destructive validation from the database record and confirm only with "
            "distinctive product-specific evidence."
        )
        reason_parts = [
            f"Ranked database candidate `{name}` from `{source}` / `{record_type}`",
            f"match score {float(record.get('match', 0)):.4f}",
        ]
        if short_description:
            reason_parts.append(short_description)
        lines.append(
            "\n".join(
                [
                    f"{len(lines) + 1}. **Service**: {service_label}",
                    f"   **Candidate**: {name}",
                    f"   **Reason**: {'; '.join(reason_parts)}.",
                    f"   **Safe Validation Idea**: {safe_idea}",
                    "   **Prerequisite**: Use only the fresh observed host, port, and live fingerprint; require a distinctive positive signal before writing confirmed_exploits.txt.",
                ]
            )
        )
    return "\n\n".join(lines)


def _no_surface_plan(exploit_context: dict[str, Any]) -> str:
    if exploit_context.get("source_mode") == "no_recon_surface":
        return (
            "No exploit plan was generated because fresh recon found no open services "
            "and no live HTTP fingerprint for the target."
        )
    return ""


def _lab_scoped_tomcat_put_plan(target: str, port: str = "18080") -> str:
    return "\n\n".join(
        [
            f"1. **Service**: {target}:{port}/TCP - http Apache Tomcat 8.5.19",
            "   **Candidate**: CVE-2017-12615",
            "   **Reason**: The Vulhub lab notes explicitly describe Tomcat 8.5.19 with `readonly=false` on the default servlet, enabling a bounded PUT-method write-file validation scenario.",
            "   **Safe Validation Idea**: If active validation is explicitly enabled, send one harmless HTTP PUT for a plain-text marker file such as `/validation_marker.txt`, retrieve it with a GET request, confirm only if the same marker is returned, and attempt cleanup with DELETE if supported. Do not upload JSP or executable content.",
            "   **Prerequisite**: Stay strictly on the authorized target and port, keep the proof artifact non-executable, and treat the result as unconfirmed unless the marker is written and read back successfully.",
        ]
    )


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


def _manifest_has_weak_rce_validation(manifest: dict[str, Any], plan_context: str) -> bool:
    plan_lower = str(plan_context or "").lower()
    if not any(marker in plan_lower for marker in ("remote code execution", " rce", "ognl", "template-injection", "template injection")):
        return False
    scripts = manifest.get("scripts")
    if not isinstance(scripts, list) or not scripts:
        return False
    manifest_text = json.dumps(scripts, sort_keys=True).lower()
    weak_status_check = any(
        marker in manifest_text
        for marker in (
            "http_status -eq 200",
            "http_status == 200",
            "setup endpoint accessible",
            "version confirms exploitability",
            "vulnerable version detected",
        )
    )
    has_marker_validation = any(marker in manifest_text for marker in ("marker", "unique"))
    return weak_status_check or not has_marker_validation


def _manifest_generation_quality_issues(manifest: dict[str, Any], plan_context: str) -> list[str]:
    issues = []
    scripts = manifest.get("scripts")
    if not isinstance(scripts, list):
        return ["manifest scripts field is missing or not a list"]

    plan_lower = str(plan_context or "").lower()
    requires_path_expression = "url path segment" in plan_lower and "not in a query parameter" in plan_lower
    for script in scripts:
        if not isinstance(script, dict):
            issues.append("script entry is not an object")
            continue
        filename = str(script.get("filename") or script.get("name") or "generated_script")
        body = normalize_red_team_script_body(str(script.get("body") or ""))
        quality_error = generated_script_quality_error(body, script.get("interpreter", "bash"))
        if quality_error:
            issues.append(f"{filename}: {quality_error}")
        body_lower = body.lower()
        if "marker" in plan_lower and "marker" in body_lower:
            request_lines = "\n".join(
                line
                for line in body.splitlines()
                if any(token in line.lower() for token in ("url=", "curl ", "payload", "data=", "-h "))
            )
            if "marker" not in request_lines.lower():
                issues.append(f"{filename}: marker is generated or checked but not included in the validation request")
            if re.search(r"'[^'\n]*\$MARKER[^'\n]*'", request_lines):
                issues.append(f"{filename}: marker is inside a single-quoted shell string and will not expand in the request")
            if "sed 's/ /%20/g'" in body_lower or 'sed "s/ /%20/g"' in body_lower:
                issues.append(f"{filename}: URL encoding only replaces spaces; use a real URL encoder for payload paths")
            if re.search(r"curl [^\n]*-o\s+\"?\$OUT_DIR/[^\"\n]*\$\(", body) and re.search(
                r"grep [^\n]+\"?\$OUT_DIR/[^\"\n]*\$\(",
                body,
            ):
                issues.append(
                    f"{filename}: curl output and grep use separately evaluated command substitutions; assign RAW once and reuse it"
                )
            if "java.lang.runtime@getruntime" in body_lower and ".exec" not in body_lower:
                issues.append(f"{filename}: OGNL marker validation references Runtime without executing a harmless marker command")
        if "--execute" in body and "curl " in body_lower:
            first_curl = body_lower.find("curl ")
            gate_positions = [
                pos
                for pos in (
                    body_lower.find("if $execute"),
                    body_lower.find('if [[ "$execute"'),
                    body_lower.find("if [[ $execute"),
                    body_lower.find('if [ "$execute"'),
                    body_lower.find('if [[ "$execute" -eq 1'),
                )
                if pos >= 0
            ]
            if gate_positions and first_curl >= 0 and first_curl < min(gate_positions):
                issues.append(f"{filename}: active curl request runs before the --execute gate")
        if "x-validation-marker" in body_lower and "header" in body_lower:
            captures_headers = re.search(r"curl [^\n]*(\s-D\s|--dump-header|\s-i(\s|$)|--include)", body, flags=re.IGNORECASE)
            if not captures_headers:
                issues.append(f"{filename}: header marker validation must capture response headers with curl -D/--dump-header or --include")
        if requires_path_expression:
            if re.search(r"https?://[^\s\"']+\?[A-Za-z0-9_.-]+=", body) or re.search(r"\?[A-Za-z0-9_.-]+=", body):
                issues.append(f"{filename}: plan requires URL path validation, but script uses a query parameter")
            if "setup-step" in body_lower or "setup/setup" in body_lower:
                issues.append(f"{filename}: plan forbids setup-page validation for this injection check")
    return issues
