import base64
import json
import os
from typing import Any

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry


class VirusTotalToolInput(BaseModel):
    ip: str | None = Field(default=None, description="IP address to look up in VirusTotal.")
    hash: str | None = Field(default=None, description="File hash to look up in VirusTotal.")
    domain: str | None = Field(default=None, description="Domain to look up in VirusTotal.")
    url: str | None = Field(default=None, description="URL to look up in VirusTotal.")
    include_relationships: bool = Field(
        default=True,
        description="Retrieve related infrastructure relationships when supported.",
    )
    relationship_limit: int = Field(default=10, description="Maximum related infrastructure items per relationship.")


def _url_id(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


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


def _analysis_detections(attributes: dict[str, Any]) -> dict[str, Any]:
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    vendors = []
    for vendor, result in results.items():
        if isinstance(result, dict) and result.get("category") in {"malicious", "suspicious"}:
            vendors.append(
                {
                    "engine": vendor,
                    "category": result.get("category", ""),
                    "result": result.get("result", ""),
                }
            )
    return {
        "stats": stats,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "engines": vendors[:20],
    }


def _related_malware(attributes: dict[str, Any]) -> list[str]:
    values = []
    classification = attributes.get("popular_threat_classification") or {}
    values.append(classification.get("suggested_threat_label", ""))
    for item in classification.get("popular_threat_name") or []:
        if isinstance(item, dict):
            values.append(item.get("value", ""))
    for item in classification.get("popular_threat_category") or []:
        if isinstance(item, dict):
            values.append(item.get("value", ""))
    values.extend(attributes.get("names") or [])
    values.extend(attributes.get("tags") or [])
    return _unique(values)


def _relationship_items(payload: dict[str, Any]) -> list[str]:
    values = []
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id")
        attributes = item.get("attributes") or {}
        values.append(item_id or attributes.get("host_name") or attributes.get("url") or attributes.get("meaningful_name") or "")
    return _unique(values)


def _normalize_response(
    indicator_type: str,
    indicator: str,
    payload: dict[str, Any],
    related_infrastructure: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    detections = _analysis_detections(attributes)
    return {
        "indicator": indicator,
        "type": indicator_type,
        "reputation": attributes.get("reputation", 0),
        "detections": detections,
        "related_malware": _related_malware(attributes),
        "related_infrastructure": related_infrastructure or {},
    }


@ToolRegistry.register("virustotal_tool")
class VirusTotalTool(BaseTool):
    name: str = "VirusTotalTool"
    description: str = (
        "Enrich IOCs with VirusTotal. Supports IP, hash, domain, and URL lookups, returning "
        "reputation, detections, related malware labels, and related infrastructure."
    )
    args_schema: type[BaseModel] = VirusTotalToolInput

    def _run(
        self,
        ip: str | None = None,
        hash: str | None = None,
        domain: str | None = None,
        url: str | None = None,
        include_relationships: bool = True,
        relationship_limit: int = 10,
    ) -> str:
        try:
            client = _VirusTotalClient()
            results = []
            if ip:
                results.append(client.lookup("ip", ip, include_relationships, relationship_limit))
            if hash:
                results.append(client.lookup("hash", hash, include_relationships, relationship_limit))
            if domain:
                results.append(client.lookup("domain", domain, include_relationships, relationship_limit))
            if url:
                results.append(client.lookup("url", url, include_relationships, relationship_limit))
            if not results:
                raise ValueError("Provide at least one IOC: ip, hash, domain, or url.")
            return json.dumps(results[0] if len(results) == 1 else results, indent=2)
        except Exception as exc:
            logger.exception("VirusTotalTool failed.")
            return json.dumps({"error": "virustotal_tool_error", "message": str(exc)}, indent=2)


class _VirusTotalClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("VIRUSTOTAL_API_URL", "https://www.virustotal.com/api/v3").rstrip("/")
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.timeout = int(os.getenv("VIRUSTOTAL_TIMEOUT", "30"))
        if not self.api_key or self.api_key.lower() == "replace_with_your_virustotal_api_key":
            raise ValueError("A real VIRUSTOTAL_API_KEY is required.")
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key, "Accept": "application/json"})

    def lookup(
        self,
        indicator_type: str,
        indicator: str,
        include_relationships: bool,
        relationship_limit: int,
    ) -> dict[str, Any]:
        object_path, relationships = self._object_path_and_relationships(indicator_type, indicator)
        payload = self._get(object_path)
        related = {}
        if include_relationships:
            related = self._relationships(object_path, relationships, relationship_limit)
        return _normalize_response(indicator_type, indicator, payload, related)

    def _object_path_and_relationships(self, indicator_type: str, indicator: str) -> tuple[str, list[str]]:
        if indicator_type == "ip":
            return f"/ip_addresses/{indicator}", ["resolutions", "communicating_files", "downloaded_files", "urls"]
        if indicator_type == "hash":
            return f"/files/{indicator}", ["contacted_domains", "contacted_ips", "contacted_urls", "execution_parents"]
        if indicator_type == "domain":
            return f"/domains/{indicator}", ["resolutions", "communicating_files", "downloaded_files", "urls"]
        if indicator_type == "url":
            return f"/urls/{_url_id(indicator)}", ["communicating_files", "downloaded_files", "redirecting_urls"]
        raise ValueError(f"Unsupported indicator type: {indicator_type}")

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self.session.get(f"{self.base_url}{path}", params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def _relationships(self, object_path: str, relationships: list[str], limit: int) -> dict[str, list[str]]:
        safe_limit = max(1, min(int(limit), 40))
        related: dict[str, list[str]] = {}
        for relationship in relationships:
            try:
                payload = self._get(f"{object_path}/{relationship}", params={"limit": safe_limit})
                items = _relationship_items(payload)
                if items:
                    related[relationship] = items
            except requests.HTTPError as exc:
                logger.warning("VirusTotal relationship lookup failed: %s %s", relationship, exc)
            except Exception as exc:
                logger.warning("VirusTotal relationship lookup skipped: %s %s", relationship, exc)
        return related
