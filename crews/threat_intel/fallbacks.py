import json
from typing import Any


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n\n[truncated]"


def open_services(scan: dict[str, Any]) -> list[dict[str, Any]]:
    services = []
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                services.append({"host": host.get("host"), **port})
    return services


def local_vulnerability_fallback(scan: dict[str, Any]) -> str:
    lines = []
    for item in open_services(scan):
        service = item.get("service") or "unknown"
        product = item.get("product") or service
        version = item.get("version") or "unknown version"
        risk = "REVIEW"
        mitigation = (
            "Validate whether the service is expected, restrict exposure to approved sources, "
            "and update or harden the detected product when vendor guidance or local policy requires it."
        )
        lines.append(
            f"- {item['host']}:{item['port']}/{item['protocol']} {service} {product} {version} | "
            f"Risk: {risk} | Mitigation: {mitigation}"
        )
    return "\n".join(lines) if lines else "- No open services were available for enrichment."


def local_correlation_fallback(target: str, vulnerability_context: str) -> str:
    return (
        f"Local correlation fallback for {target}:\n"
        "- Public-facing services were grouped by exposed network surface.\n"
        "- Prioritize services that are externally reachable, unexpected, outdated, or repeatedly referenced in the supplied evidence.\n"
        "- Use collected evidence and configured database context for final vulnerability confirmation.\n\n"
        f"Evidence summary:\n{_truncate(vulnerability_context, 1200)}"
    )


def local_prediction_fallback(target: str, vulnerability_context: str) -> str:
    return (
        f"Local prediction fallback for {target}:\n"
        "- Most likely next attacker step: probe reachable exposed services identified in the supplied evidence.\n"
        "- Risk horizon: immediate for reachable services with weak exposure controls or unresolved vulnerabilities.\n"
        "- Watchpoints: unusual requests, authentication attempts, repeated failures, and service instability.\n\n"
        f"Evidence summary:\n{_truncate(vulnerability_context, 900)}"
    )


def local_soc_report_fallback(
    target: str,
    service_summary: str,
    vulnerability_context: str,
    correlation_report: str,
    prediction_report: str,
) -> str:
    return (
        "# SOC Threat Intelligence Report\n\n"
        f"Target: {target}\n\n"
        "## Summary\n"
        "This report was generated from local scan evidence because an LLM stage returned no output.\n\n"
        "## Services\n"
        f"{service_summary}\n\n"
        "## Top Risks\n"
        f"{_truncate(vulnerability_context, 1200)}\n\n"
        "## Correlation\n"
        f"{_truncate(correlation_report, 900)}\n\n"
        "## Prediction\n"
        f"{_truncate(prediction_report, 700)}\n"
    )


def local_remediation_fallback(target: str, vulnerability_context: str) -> str:
    return (
        f"Local remediation fallback for {target}:\n"
        "1. Restrict exposed services to trusted networks where possible. Validate with the available tool logs.\n"
        "2. Patch or upgrade outdated service products identified in the scan. Validate versions after change.\n"
        "3. Disable or reconfigure services that are not required for the approved environment. Validate with follow-up logs from your approved tools.\n"
        "4. Add monitoring for suspicious requests and authentication attempts against exposed services.\n\n"
        f"Evidence summary:\n{_truncate(vulnerability_context, 1200)}"
    )


def local_tool_manifest_fallback(target: str, scan_context: str) -> dict[str, Any]:
    try:
        scan = json.loads(scan_context)
    except json.JSONDecodeError:
        scan = {"hosts": []}
    services = open_services(scan)
    endpoints = []
    if isinstance(scan.get("iocs"), dict):
        endpoints.extend(str(url) for url in scan["iocs"].get("urls", []) if url)
    for event in scan.get("events", []) if isinstance(scan.get("events"), list) else []:
        if not isinstance(event, dict):
            continue
        path = str(event.get("url_path") or "").strip()
        host = str(event.get("dest_ip") or scan.get("target") or target).strip()
        port = str(event.get("dest_port") or "").strip()
        if path.startswith("/"):
            scheme = "https" if port == "443" else "http"
            port_suffix = "" if port in {"", "80", "443"} else f":{port}"
            endpoints.append(f"{scheme}://{host}{port_suffix}{path}")
    endpoints = list(dict.fromkeys(endpoints))[:5]
    service_lines = [
        f"{item.get('host', target)}:{item.get('port')}/{item.get('protocol', 'tcp')} "
        f"{item.get('service') or 'unknown'} {item.get('product') or ''} {item.get('version') or ''}".strip()
        for item in services
    ]
    if not service_lines and scan.get("environment"):
        env = scan.get("environment") if isinstance(scan.get("environment"), dict) else {}
        service_lines.append(
            f"{env.get('host_ip', scan.get('target', target))}:{env.get('port', '')} "
            f"{env.get('service', 'unknown')} {env.get('server_header', '')} {env.get('x_powered_by', '')}".strip()
        )
    evidence = "\\n".join(service_lines) if service_lines else "No service details were available."
    endpoint_block = "\n".join(f'  "{endpoint}"' for endpoint in endpoints)
    body = f"""#!/usr/bin/env bash
set -uo pipefail

TARGET="${{TARGET:-{target}}}"
OUT_DIR="${{OUT_DIR:-.}}"
OBS="$OUT_DIR/observations.txt"

mkdir -p "$OUT_DIR"
echo "Local fallback validation generated from collected evidence." > "$OBS"
printf '%b\\n' "{evidence}" >> "$OBS"
ENDPOINTS=(
{endpoint_block}
)
if [ "${{#ENDPOINTS[@]}}" -gt 0 ]; then
  for url in "${{ENDPOINTS[@]}}"; do
    status=$(curl -ksS --max-time 10 -o /dev/null -w "%{{http_code}}" "$url" 2>/dev/null || true)
    echo "$url status=$status" >> "$OBS"
  done
else
  echo "No URL endpoints were present in the supplied evidence." >> "$OBS"
fi
echo "Automatic corrective action was not attempted because the LLM tool manifest was empty or truncated."
echo "Apply the remediation plan manually or rerun after the model/provider returns a complete tool manifest." >> "$OBS"
cat "$OBS"
"""
    return {
        "agent": "tool_generation_agent",
        "mode": "local_fallback_from_scan_evidence",
        "safety": "LLM tool manifest was empty/truncated; generated a bounded validation script from scan evidence.",
        "scripts": [
            {
                "name": "validate_current_exposure",
                "filename": "01_validate_current_exposure.sh",
                "purpose": "Validate current exposed services after remediation planning when LLM script generation fails.",
                "interpreter": "bash",
                "body": body,
            }
        ],
    }
