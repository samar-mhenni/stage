import json
import re
from pathlib import Path
from typing import Any

from tools import get_records_by_metadata, search_records

GENERIC_EVIDENCE_TERMS = {
    "http", "https", "service", "status", "event", "events", "source", "target",
    "generated", "redacted", "evidence", "tool", "logs", "alert", "host", "port",
    "risk", "medium", "high", "low",
}

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


def _short_value(value: Any, limit: int = 120) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _count_label(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _red_team_human_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    summary = evidence.get("human_summary")
    return summary if isinstance(summary, dict) else {}


def _red_team_has_no_confirmed_exploit(evidence: dict[str, Any]) -> bool:
    summary = _red_team_human_summary(evidence)
    if not summary:
        return False
    confirmed = summary.get("confirmed_findings")
    return isinstance(confirmed, list) and not confirmed


def _red_team_evidence_guard(evidence: dict[str, Any]) -> str:
    if not _red_team_has_no_confirmed_exploit(evidence):
        return ""
    summary = _red_team_human_summary(evidence)
    observations = _short_value(summary.get("observations"), 220)
    return (
        "Evidence guard: the supplied red-team execution has zero confirmed findings. "
        "Treat CVEs as database-ranked candidates or exposure risks only; do not describe exploitability, "
        "RCE, marker reflection, or partial success as confirmed. "
        f"Execution headline: {_short_value(summary.get('headline'), 160)}"
        + (f" Observations: {observations}" if observations else "")
    )


def _apply_red_team_evidence_guard(text: str, evidence: dict[str, Any]) -> str:
    guard = _red_team_evidence_guard(evidence)
    if not guard:
        return text
    corrected = str(text or "")
    replacements = {
        "confirmed partial success": "unconfirmed validation attempt",
        "confirmed exploit success": "unconfirmed validation attempt",
        "confirmed exploitable vulnerability": "unconfirmed database-ranked vulnerability candidate",
        "confirmed exploitable": "unconfirmed candidate",
        "confirmed vulnerable": "identified as a candidate, not confirmed vulnerable",
        "is confirmed vulnerable to": "is a database-ranked candidate for",
        "already confirmed partial success": "unconfirmed validation attempt",
        "has a confirmed exploitable vulnerability": "has an unconfirmed database-ranked vulnerability candidate",
    }
    for before, after in replacements.items():
        corrected = re.sub(re.escape(before), after, corrected, flags=re.IGNORECASE)
    if guard.lower() not in corrected.lower():
        corrected = guard + "\n\n" + corrected
    return corrected


def summarize_evidence_sources(evidence: dict[str, Any]) -> str:
    """Build a deterministic evidence summary so rich tool logs are visible in reports."""
    lines: list[str] = []
    source = evidence.get("source") or evidence.get("evidence_path") or "provided evidence"
    evidence_type = evidence.get("evidence_type", "logs")
    lines.append(f"- Source file: `{source}`")
    lines.append(f"- Evidence type: `{evidence_type}`")
    if evidence.get("case_id"):
        lines.append(f"- Case ID: `{evidence['case_id']}`")
    if evidence.get("generated_at"):
        lines.append(f"- Generated at: `{evidence['generated_at']}`")
    tools = evidence.get("tools")
    if isinstance(tools, list) and tools:
        lines.append("- Tool sources: " + ", ".join(f"`{tool}`" for tool in tools))

    red_team_summary = _red_team_human_summary(evidence)
    if red_team_summary:
        confirmed = red_team_summary.get("confirmed_findings")
        confirmed_count = len(confirmed) if isinstance(confirmed, list) else 0
        lines.append(f"- Red-team validation headline: {_short_value(red_team_summary.get('headline'), 160)}")
        lines.append(f"- Red-team confirmed findings: `{confirmed_count}`")
        observations = _short_value(red_team_summary.get("observations"), 220)
        if observations:
            lines.append(f"- Red-team observations: {observations}")
    candidates = evidence.get("database_exploit_candidates")
    if isinstance(candidates, list) and candidates:
        candidate_bits = []
        for candidate in candidates[:3]:
            if isinstance(candidate, dict):
                name = candidate.get("name") or candidate.get("type") or "candidate"
                score = candidate.get("match")
                score_text = f" ({score:.4f})" if isinstance(score, (int, float)) else ""
                candidate_bits.append(f"`{name}`{score_text}")
        if candidate_bits:
            lines.append("- Top database candidates: " + ", ".join(candidate_bits))
    guard = _red_team_evidence_guard(evidence)
    if guard:
        lines.append(f"- {guard}")

    env = evidence.get("environment") if isinstance(evidence.get("environment"), dict) else {}
    if env:
        asset = env.get("host_ip") or evidence.get("target") or "unknown"
        service = env.get("service") or env.get("application") or "unknown-service"
        port = f":{env['port']}" if env.get("port") else ""
        product_bits = [
            env.get("application"),
            env.get("observed_version"),
            env.get("server_header"),
            env.get("x_powered_by"),
        ]
        products = "; ".join(_short_value(bit) for bit in product_bits if bit)
        lines.append(f"- Observed asset: `{asset}{port}` `{service}`" + (f" ({products})" if products else ""))

    wazuh_alerts = evidence.get("wazuh_alerts")
    if isinstance(wazuh_alerts, list) and wazuh_alerts:
        lines.append(f"- Wazuh alerts: {_count_label(len(wazuh_alerts), 'alert')}")
        for alert in wazuh_alerts[:3]:
            if not isinstance(alert, dict):
                continue
            rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
            data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
            rule_id = rule.get("id", "unknown-rule")
            level = rule.get("level", "unknown")
            desc = _short_value(rule.get("description"), 110)
            src = data.get("srcip") or data.get("source_ip") or "-"
            dst = data.get("dstip") or data.get("dest_ip") or data.get("dstport") or "-"
            vulnerability = data.get("vulnerability")
            cve = data.get("cve")
            if not cve and isinstance(vulnerability, dict):
                cve = vulnerability.get("cve")
            suffix = f", CVE `{cve}`" if cve else ""
            lines.append(f"  - Rule `{rule_id}` level `{level}`: {desc} (`{src}` -> `{dst}`{suffix})")

    thehive_case = evidence.get("thehive_case")
    if isinstance(thehive_case, dict):
        observables = thehive_case.get("observables") if isinstance(thehive_case.get("observables"), list) else []
        tasks = thehive_case.get("tasks") if isinstance(thehive_case.get("tasks"), list) else []
        title = _short_value(thehive_case.get("title"), 130)
        lines.append(
            f"- TheHive case: {title} "
            f"(status `{thehive_case.get('status', 'unknown')}`, severity `{thehive_case.get('severity', 'unknown')}`, "
            f"{_count_label(len(observables), 'observable')}, {_count_label(len(tasks), 'task')})"
        )
        for obs in observables[:4]:
            if isinstance(obs, dict):
                lines.append(f"  - Observable `{obs.get('dataType', 'unknown')}`: `{_short_value(obs.get('data'), 100)}`")

    misp_event = evidence.get("misp_event")
    if isinstance(misp_event, dict):
        attrs = misp_event.get("attributes") or misp_event.get("Attribute") or []
        tags = misp_event.get("tags") or misp_event.get("Tag") or []
        if isinstance(attrs, list):
            lines.append(
                f"- MISP event: {_short_value(misp_event.get('info'), 130)} "
                f"({_count_label(len(attrs), 'attribute')}, {_count_label(len(tags) if isinstance(tags, list) else 0, 'tag')})"
            )
            for attr in attrs[:4]:
                if isinstance(attr, dict):
                    lines.append(f"  - `{attr.get('type', 'unknown')}`: `{_short_value(attr.get('value'), 100)}`")

    cortex_results = evidence.get("cortex_analyzer_results")
    if isinstance(cortex_results, list) and cortex_results:
        lines.append(f"- Cortex analyzer results: {_count_label(len(cortex_results), 'result')}")
        for result in cortex_results[:3]:
            if isinstance(result, dict):
                analyzer = result.get("analyzer", "unknown-analyzer")
                observable = result.get("observable", result.get("data", ""))
                verdict = result.get("verdict") or result.get("status") or "unknown"
                lines.append(f"  - `{analyzer}` verdict `{verdict}` for `{_short_value(observable, 100)}`")

    events = evidence.get("events")
    if isinstance(events, list) and events:
        source_counts: dict[str, int] = {}
        for event in events:
            if isinstance(event, dict):
                source_tool = str(event.get("source_tool") or event.get("event_type") or "unknown")
                source_counts[source_tool] = source_counts.get(source_tool, 0) + 1
        counts = ", ".join(f"`{tool}`={count}" for tool, count in sorted(source_counts.items())[:8])
        lines.append(f"- Generic event records: {_count_label(len(events), 'event')} ({counts})")

    iocs = evidence.get("iocs") if isinstance(evidence.get("iocs"), dict) else {}
    if iocs:
        ioc_parts = []
        for key in ("ips", "domains", "urls", "cves", "attack_techniques"):
            values = iocs.get(key)
            if isinstance(values, list) and values:
                ioc_parts.append(f"{key}={len(values)}")
        if ioc_parts:
            lines.append("- IOC totals: " + ", ".join(ioc_parts))

    if len(lines) <= 2:
        lines.append("- No structured SOC tool fields were found; see the saved `evidence.json` artifact for raw evidence.")
    return "\n".join(lines)


def render_soc_evidence_report(target: str, evidence: dict[str, Any]) -> str:
    """Render the final SOC report from structured evidence only."""
    lines = [
        "This SOC report is generated locally from `evidence.json`; it does not add new claims beyond saved evidence.",
        "",
        "## Direct Evidence",
        "",
        f"- Target: `{target}`",
        f"- Source file: `{evidence.get('source') or evidence.get('evidence_path') or 'provided evidence'}`",
        f"- Evidence type: `{evidence.get('evidence_type', 'logs')}`",
    ]
    if evidence.get("case_id"):
        lines.append(f"- Case ID: `{evidence['case_id']}`")
    tools = evidence.get("tools")
    if isinstance(tools, list) and tools:
        lines.append("- Tool sources: " + ", ".join(f"`{tool}`" for tool in tools))

    env = evidence.get("environment") if isinstance(evidence.get("environment"), dict) else {}
    if env:
        host = env.get("host_ip") or evidence.get("target") or target
        port = f":{env['port']}" if env.get("port") else ""
        service = env.get("service") or env.get("application") or "unknown-service"
        product = "; ".join(
            _short_value(value)
            for value in (env.get("application"), env.get("observed_version"), env.get("server_header"), env.get("x_powered_by"))
            if value
        )
        lines.append(f"- Observed asset: `{host}{port}` `{service}`" + (f" ({product})" if product else ""))

    wazuh_alerts = evidence.get("wazuh_alerts")
    if isinstance(wazuh_alerts, list) and wazuh_alerts:
        lines.append(f"- Wazuh alerts: `{len(wazuh_alerts)}`")
        for alert in wazuh_alerts[:3]:
            if not isinstance(alert, dict):
                continue
            rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
            data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
            cve = data.get("cve")
            vulnerability = data.get("vulnerability")
            if not cve and isinstance(vulnerability, dict):
                cve = vulnerability.get("cve")
            cve_text = f", CVE `{cve}`" if cve else ""
            lines.append(
                f"  - Rule `{rule.get('id', 'unknown')}` level `{rule.get('level', 'unknown')}`: "
                f"{_short_value(rule.get('description'), 120)}{cve_text}"
            )

    thehive_case = evidence.get("thehive_case")
    if isinstance(thehive_case, dict):
        lines.append(
            f"- TheHive case: `{_short_value(thehive_case.get('title'), 120)}` "
            f"status `{thehive_case.get('status', 'unknown')}`, severity `{thehive_case.get('severity', 'unknown')}`"
        )

    cortex_results = evidence.get("cortex_analyzer_results")
    if isinstance(cortex_results, list) and cortex_results:
        verdicts = ", ".join(
            f"`{_short_value(item.get('analyzer'), 50)}`={item.get('verdict') or item.get('status') or 'unknown'}"
            for item in cortex_results[:4]
            if isinstance(item, dict)
        )
        if verdicts:
            lines.append(f"- Cortex verdicts: {verdicts}")

    iocs = evidence.get("iocs") if isinstance(evidence.get("iocs"), dict) else {}
    cves = sorted(_evidence_cves(_flatten_evidence_text(evidence)))
    attack_ids = sorted(_evidence_attack_ids(_flatten_evidence_text(evidence)))
    if iocs or cves or attack_ids:
        lines.extend(["", "## Observables", ""])
        for key in ("ips", "domains", "urls", "hashes", "cves", "attack_techniques"):
            values = iocs.get(key) if isinstance(iocs, dict) else None
            if isinstance(values, list) and values:
                preview = ", ".join(f"`{_short_value(value, 80)}`" for value in values[:5])
                lines.append(f"- {key}: `{len(values)}`" + (f" ({preview})" if preview else ""))
        if cves:
            lines.append("- CVEs in direct evidence: " + ", ".join(f"`{cve}`" for cve in cves[:8]))
        if attack_ids:
            lines.append("- ATT&CK IDs in direct evidence: " + ", ".join(f"`{attack_id}`" for attack_id in attack_ids[:8]))

    red_team_summary = _red_team_human_summary(evidence)
    if red_team_summary:
        confirmed = red_team_summary.get("confirmed_findings")
        confirmed_count = len(confirmed) if isinstance(confirmed, list) else 0
        lines.extend(
            [
                "",
                "## Red-Team Evidence",
                "",
                f"- Headline: {_short_value(red_team_summary.get('headline'), 160)}",
                f"- Confirmed findings: `{confirmed_count}`",
            ]
        )
        observations = _short_value(red_team_summary.get("observations"), 220)
        if observations:
            lines.append(f"- Observations: {observations}")

    lines.extend(
        [
            "",
            "## Gaps And Boundaries",
            "",
            "- Database and model enrichment are treated as supporting context, not confirmation.",
            "- Vulnerability or exploitability is confirmed only when the direct evidence records the positive signal.",
            "- Raw details remain in `evidence.json` and generated script execution artifacts.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


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

