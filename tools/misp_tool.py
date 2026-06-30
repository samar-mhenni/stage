import json
import os
from typing import Any

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry


IOC_TYPES = {
    "ip": ["ip-src", "ip-dst"],
    "domain": ["domain", "hostname"],
    "hash": ["md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256"],
    "url": ["url", "uri"],
}


class MISPToolInput(BaseModel):
    action: str = Field(
        default="ioc_lookup",
        description="Action to run: ioc_lookup, threat_actor_lookup, malware_lookup, events, or enrich.",
    )
    ip: str | None = Field(default=None, description="IP address IOC to enrich.")
    domain: str | None = Field(default=None, description="Domain IOC to enrich.")
    hash: str | None = Field(default=None, description="File hash IOC to enrich.")
    url: str | None = Field(default=None, description="URL IOC to enrich.")
    threat_actor: str | None = Field(default=None, description="Threat actor name or tag to search.")
    malware: str | None = Field(default=None, description="Malware family name or tag to search.")
    event_id: str | None = Field(default=None, description="Optional MISP event ID to retrieve.")
    limit: int = Field(default=25, description="Maximum number of MISP results to process.")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        cleaned = value.strip()
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def _tag_name(tag: Any) -> str:
    if isinstance(tag, dict):
        return str(tag.get("name") or tag.get("Name") or "")
    return str(tag or "")


def _event_from_result(result: dict[str, Any]) -> dict[str, Any]:
    if "Event" in result and isinstance(result["Event"], dict):
        return result["Event"]
    return result


def _attributes_from_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    attributes = []
    for attribute in _as_list(event.get("Attribute")):
        if isinstance(attribute, dict):
            attributes.append(attribute)
    for obj in _as_list(event.get("Object")):
        if isinstance(obj, dict):
            for attribute in _as_list(obj.get("Attribute")):
                if isinstance(attribute, dict):
                    attributes.append(attribute)
    return attributes


def _all_tags(event: dict[str, Any]) -> list[str]:
    tags = [_tag_name(tag) for tag in _as_list(event.get("Tag"))]
    for attribute in _attributes_from_event(event):
        tags.extend(_tag_name(tag) for tag in _as_list(attribute.get("Tag")))
    for galaxy in _as_list(event.get("Galaxy")):
        if isinstance(galaxy, dict):
            tags.append(str(galaxy.get("name") or galaxy.get("type") or ""))
            for cluster in _as_list(galaxy.get("GalaxyCluster")):
                if isinstance(cluster, dict):
                    tags.append(str(cluster.get("value") or cluster.get("tag_name") or ""))
    for cluster in _as_list(event.get("GalaxyCluster")):
        if isinstance(cluster, dict):
            tags.append(str(cluster.get("value") or cluster.get("tag_name") or ""))
    return _unique(tags)


def _extract_by_keywords(tags: list[str], keywords: tuple[str, ...]) -> list[str]:
    values = []
    for tag in tags:
        tag_lower = _lower(tag)
        if any(keyword in tag_lower for keyword in keywords):
            if "=" in tag:
                values.append(tag.rsplit("=", 1)[-1].strip('"'))
            elif ":" in tag:
                values.append(tag.rsplit(":", 1)[-1].strip('"'))
            else:
                values.append(tag)
    return _unique(values)


def normalize_misp_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    malware: list[str] = []
    threat_actors: list[str] = []
    campaigns: list[str] = []
    related_events: list[dict[str, Any]] = []

    for raw_event in events:
        event = _event_from_result(raw_event)
        tags = _all_tags(event)
        malware.extend(_extract_by_keywords(tags, ("malware", "misp-galaxy:malware", "tool=")))
        threat_actors.extend(_extract_by_keywords(tags, ("threat-actor", "threat actor", "intrusion-set", "apt")))
        campaigns.extend(_extract_by_keywords(tags, ("campaign", "operation")))
        related_events.append(
            {
                "event_id": str(event.get("id") or event.get("uuid") or ""),
                "info": event.get("info", ""),
                "date": event.get("date", ""),
                "threat_level": event.get("threat_level_id", ""),
                "tags": tags,
            }
        )

    return {
        "associated_malware": _unique(malware),
        "associated_threat_actors": _unique(threat_actors),
        "related_campaigns": _unique(campaigns),
        "events": related_events,
    }


@ToolRegistry.register("misp_tool")
class MISPTool(BaseTool):
    name: str = "MISPTool"
    description: str = (
        "Connect to MISP for threat intelligence enrichment. Supports IOC lookup for IP, "
        "domain, hash, and URL values, threat actor lookup, malware lookup, event retrieval, "
        "and normalized output for associated malware, threat actors, and campaigns."
    )
    args_schema: type[BaseModel] = MISPToolInput

    def _run(
        self,
        action: str = "ioc_lookup",
        ip: str | None = None,
        domain: str | None = None,
        hash: str | None = None,
        url: str | None = None,
        threat_actor: str | None = None,
        malware: str | None = None,
        event_id: str | None = None,
        limit: int = 25,
    ) -> str:
        safe_limit = max(1, min(int(limit), 200))
        try:
            client = _MISPClient()
            if action == "ioc_lookup":
                events = client.search_iocs(ip=ip, domain=domain, hash_value=hash, url=url, limit=safe_limit)
                return json.dumps(normalize_misp_events(events), indent=2)

            if action == "threat_actor_lookup":
                if not threat_actor:
                    raise ValueError("threat_actor is required for threat_actor_lookup.")
                events = client.search_by_tag_or_value(threat_actor, limit=safe_limit)
                return json.dumps(normalize_misp_events(events), indent=2)

            if action == "malware_lookup":
                if not malware:
                    raise ValueError("malware is required for malware_lookup.")
                events = client.search_by_tag_or_value(malware, limit=safe_limit)
                return json.dumps(normalize_misp_events(events), indent=2)

            if action == "events":
                events = [client.get_event(event_id)] if event_id else client.search_events(limit=safe_limit)
                return json.dumps(normalize_misp_events(events), indent=2)

            if action == "enrich":
                events = client.search_iocs(ip=ip, domain=domain, hash_value=hash, url=url, limit=safe_limit)
                if threat_actor:
                    events.extend(client.search_by_tag_or_value(threat_actor, limit=safe_limit))
                if malware:
                    events.extend(client.search_by_tag_or_value(malware, limit=safe_limit))
                if event_id:
                    events.append(client.get_event(event_id))
                return json.dumps(normalize_misp_events(events), indent=2)

            raise ValueError("Unsupported action. Use ioc_lookup, threat_actor_lookup, malware_lookup, events, or enrich.")
        except Exception as exc:
            logger.exception("MISPTool failed.")
            return json.dumps({"error": "misp_tool_error", "message": str(exc)}, indent=2)


class _MISPClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("MISP_URL", "https://localhost").rstrip("/")
        self.api_key = os.getenv("MISP_API_KEY", "")
        self.verify_ssl = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
        self.timeout = int(os.getenv("MISP_TIMEOUT", "30"))
        if not self.api_key:
            raise ValueError("MISP_API_KEY is required.")
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update(
            {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def search_iocs(
        self,
        ip: str | None = None,
        domain: str | None = None,
        hash_value: str | None = None,
        url: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for ioc_type, value in (("ip", ip), ("domain", domain), ("hash", hash_value), ("url", url)):
            if not value:
                continue
            payload = {
                "returnFormat": "json",
                "value": value,
                "type": IOC_TYPES[ioc_type],
                "includeEventTags": True,
                "includeContext": True,
                "limit": limit,
            }
            events.extend(self._post_events_rest_search(payload))
        return events

    def search_by_tag_or_value(self, value: str, limit: int = 25) -> list[dict[str, Any]]:
        payload = {
            "returnFormat": "json",
            "tags": value,
            "includeEventTags": True,
            "includeContext": True,
            "limit": limit,
        }
        events = self._post_events_rest_search(payload)
        if events:
            return events
        payload.pop("tags", None)
        payload["value"] = value
        return self._post_attributes_rest_search(payload)

    def search_events(self, limit: int = 25) -> list[dict[str, Any]]:
        return self._post_events_rest_search(
            {
                "returnFormat": "json",
                "includeEventTags": True,
                "includeContext": True,
                "limit": limit,
            }
        )

    def get_event(self, event_id: str | None) -> dict[str, Any]:
        if not event_id:
            raise ValueError("event_id is required for event retrieval.")
        response = self.session.get(f"{self.base_url}/events/view/{event_id}.json", timeout=self.timeout)
        response.raise_for_status()
        return _event_from_result(response.json())

    def _post_events_rest_search(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        response = self.session.post(f"{self.base_url}/events/restSearch", json=payload, timeout=self.timeout)
        response.raise_for_status()
        return self._extract_response_events(response.json())

    def _post_attributes_rest_search(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        response = self.session.post(f"{self.base_url}/attributes/restSearch", json=payload, timeout=self.timeout)
        response.raise_for_status()
        return self._extract_response_events(response.json())

    @staticmethod
    def _extract_response_events(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        if isinstance(payload.get("response"), list):
            return [item for item in payload["response"] if isinstance(item, dict)]
        if isinstance(payload.get("Event"), list):
            return [{"Event": item} for item in payload["Event"] if isinstance(item, dict)]
        if isinstance(payload.get("Attribute"), list):
            return [{"Event": item.get("Event", {})} for item in payload["Attribute"] if isinstance(item, dict)]
        return []
