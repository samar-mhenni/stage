import logging
from pathlib import Path
import re
from typing import Any

from simple_crew.config import PROJECT_ROOT


logger = logging.getLogger(__name__)

COLLECTIONS = {
    "red_team": ["redteam_db", "exploit_db", "attack_db", "actor_db"],
    "threat_intel": ["threat_intel_db", "detection_db", "attack_db", "actor_db"],
}


def search_relevant_context(
    query: str,
    workflow_type: str,
    target: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    try:
        from tools import search_records

        text = " ".join(part for part in (target, query) if part).strip()
        records = search_records(text, COLLECTIONS.get(workflow_type, []), top_k=max(10, limit * 5))
        records.sort(key=lambda item: float(item.get("match", 0)), reverse=True)
        requested_cves = {item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)}
        if requested_cves:
            exact, neutral = [], []
            for record in records:
                record_text = " ".join(str(record.get(key, "")) for key in ("cve_str", "text", "name"))
                record_cves = {item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,7}", record_text, re.IGNORECASE)}
                if requested_cves & record_cves:
                    exact.append(record)
                elif not record_cves:
                    neutral.append(record)
            if not exact:
                warning = {
                    "source": "retrieval",
                    "type": "warning",
                    "name": "No exact CVE record found",
                    "match": 1.0,
                    "text": f"No database record matched the exact identifier(s): {', '.join(sorted(requested_cves))}. Similar CVEs were excluded.",
                }
                return [warning, *neutral[: max(0, limit - 1)]]
            records = [*exact, *neutral]
        return records[:limit]
    except Exception as exc:
        logger.warning("Database search unavailable: %s", exc)
        return []


def get_previous_target_results(target: str, limit: int = 5) -> list[dict[str, Any]]:
    path = PROJECT_ROOT / "simple_crew" / "outputs" / "workflow_results.jsonl"
    if not path.is_file():
        return []
    matches = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if f'"target": "{target}"' in line:
            matches.append({"summary": line[:600]})
    return matches[-limit:]


def get_relevant_remediation_context(findings: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    query = " ".join(str(item.get("summary") or item.get("name") or item) for item in findings[:5])
    return search_relevant_context(query + " detection mitigation remediation", "threat_intel", limit=limit)


def save_workflow_result(workflow_id: str, agent_name: str, result: dict[str, Any]) -> None:
    import json

    path = PROJECT_ROOT / "simple_crew" / "outputs" / "workflow_results.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"workflow_id": workflow_id, "agent": agent_name, **result}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")
