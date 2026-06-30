import json
import re
from pathlib import Path
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry


MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")


class SuricataToolInput(BaseModel):
    eve_path: str | None = Field(default=None, description="Path to a Suricata eve.json JSONL file.")
    eve_json: str | None = Field(default=None, description="Raw Suricata eve.json JSONL or JSON array content.")
    event_type: str = Field(default="alert", description="Event type to normalize, usually alert.")
    limit: int = Field(default=100, description="Maximum number of events to parse.")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        cleaned = str(value or "").strip()
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def _read_events(eve_path: str | None, eve_json: str | None, limit: int) -> list[dict[str, Any]]:
    if eve_path:
        content = Path(eve_path).read_text(encoding="utf-8")
    elif eve_json:
        content = eve_json
    else:
        raise ValueError("Provide eve_path or eve_json.")

    stripped = content.strip()
    if not stripped:
        return []

    events = []
    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("eve_json array must contain event objects.")
        events = [item for item in parsed if isinstance(item, dict)]
    else:
        for line_number, line in enumerate(stripped.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on eve line {line_number}: {exc}") from exc
            if isinstance(item, dict):
                events.append(item)
            if len(events) >= limit:
                break
    return events[:limit]


def _extract_attack_mappings(event: dict[str, Any]) -> list[str]:
    alert = event.get("alert") or {}
    metadata = alert.get("metadata") or {}
    values = []
    for key, value in metadata.items():
        key_lower = str(key).lower()
        if "mitre" in key_lower or "attack" in key_lower:
            values.extend(str(item) for item in _as_list(value))
    values.append(str(alert.get("signature", "")))
    values.append(str(alert.get("category", "")))
    return _unique(match.upper() for value in values for match in MITRE_PATTERN.findall(value))


def _extract_iocs(event: dict[str, Any]) -> dict[str, list[str]]:
    http = event.get("http") or {}
    dns = event.get("dns") or {}
    tls = event.get("tls") or {}
    fileinfo = event.get("fileinfo") or {}
    payload_text = " ".join(str(event.get(key, "")) for key in ("payload_printable", "packet_info"))
    url = ""
    if http.get("hostname") and http.get("url"):
        scheme = "https" if event.get("dest_port") == 443 else "http"
        url = f"{scheme}://{http.get('hostname')}{http.get('url')}"

    domains = []
    domains.extend(str(item.get("rrname", "")) for item in _as_list(dns.get("answers")) if isinstance(item, dict))
    domains.extend([http.get("hostname", ""), tls.get("sni", "")])

    return {
        "ips": _unique([event.get("src_ip", ""), event.get("dest_ip", "")]),
        "domains": _unique(domains),
        "urls": _unique([url, *URL_PATTERN.findall(payload_text)]),
        "hashes": _unique(
            [
                fileinfo.get("md5", ""),
                fileinfo.get("sha1", ""),
                fileinfo.get("sha256", ""),
                *HASH_PATTERN.findall(payload_text),
            ]
        ),
    }


def normalize_suricata_event(event: dict[str, Any]) -> dict[str, Any]:
    alert = event.get("alert") or {}
    flow = event.get("flow") or {}
    normalized = {
        "source": "suricata",
        "event_type": event.get("event_type", ""),
        "timestamp": event.get("timestamp", ""),
        "alert_id": str(alert.get("signature_id", "") or event.get("flow_id", "")),
        "signature": alert.get("signature", ""),
        "category": alert.get("category", ""),
        "severity": alert.get("severity", ""),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "protocol": event.get("proto", ""),
        "app_proto": event.get("app_proto", ""),
        "flow_id": event.get("flow_id", ""),
        "flow": {
            "pkts_toserver": flow.get("pkts_toserver", ""),
            "pkts_toclient": flow.get("pkts_toclient", ""),
            "bytes_toserver": flow.get("bytes_toserver", ""),
            "bytes_toclient": flow.get("bytes_toclient", ""),
        },
        "mitre_attack": _extract_attack_mappings(event),
        "iocs": _extract_iocs(event),
        "metadata": alert.get("metadata", {}),
    }
    return normalized


@ToolRegistry.register("suricata_tool")
class SuricataTool(BaseTool):
    name: str = "SuricataTool"
    description: str = (
        "Parse Suricata eve.json events, normalize alert records, extract IOCs, and extract "
        "MITRE ATT&CK mappings from alert metadata or signatures."
    )
    args_schema: type[BaseModel] = SuricataToolInput

    def _run(
        self,
        eve_path: str | None = None,
        eve_json: str | None = None,
        event_type: str = "alert",
        limit: int = 100,
    ) -> str:
        try:
            safe_limit = max(1, min(int(limit), 10000))
            events = _read_events(eve_path=eve_path, eve_json=eve_json, limit=safe_limit)
            normalized = [
                normalize_suricata_event(event)
                for event in events
                if event_type == "all" or event.get("event_type") == event_type
            ]
            return json.dumps(
                {
                    "count": len(normalized),
                    "alerts": normalized,
                },
                indent=2,
            )
        except Exception as exc:
            logger.exception("SuricataTool failed.")
            return json.dumps({"error": "suricata_tool_error", "message": str(exc)}, indent=2)
