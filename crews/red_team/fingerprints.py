from __future__ import annotations

import json
import re
from typing import Any

import chromadb


_signature_cache: list[dict[str, Any]] | None = None


def _json_list(value: Any) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if str(item).strip()]


def _load_web_app_signatures() -> list[dict[str, Any]]:
    global _signature_cache
    if _signature_cache is not None:
        return _signature_cache

    signatures: list[dict[str, Any]] = []
    try:
        collection = chromadb.PersistentClient(path="./chroma_db").get_collection("redteam_db")
        results = collection.get(where={"type": "web_app_signature"}, include=["metadatas"])
    except Exception:
        _signature_cache = []
        return _signature_cache

    for meta in results.get("metadatas", []):
        signatures.append(
            {
                "name": meta.get("name", "Unknown web application"),
                "terms": _json_list(meta.get("terms_json")),
                "markers": _json_list(meta.get("markers_json")),
                "version_patterns": _json_list(meta.get("version_patterns_json")),
            }
        )

    _signature_cache = signatures
    return _signature_cache


def detect_web_app_fingerprints(text: str) -> list[dict[str, Any]]:
    content = str(text or "")
    lowered = content.lower()
    fingerprints: list[dict[str, Any]] = []
    for signature in _load_web_app_signatures():
        matched_markers = [marker for marker in signature["markers"] if marker.lower() in lowered]
        if not matched_markers:
            continue
        versions: list[str] = []
        for pattern in signature.get("version_patterns", []):
            for version in re.findall(pattern, content, flags=re.IGNORECASE):
                version_text = version[0] if isinstance(version, tuple) else version
                if version_text and version_text not in versions:
                    versions.append(version_text)
        confidence = "high" if len(matched_markers) >= 2 else "medium"
        fingerprints.append(
            {
                "application": signature["name"],
                "confidence": confidence,
                "matched_markers": matched_markers[:6],
                "versions": versions[:4],
                "terms": signature["terms"],
            }
        )
    return fingerprints


def application_hint_terms(fingerprints: list[dict[str, Any]]) -> set[str]:
    terms: set[str] = set()
    for fingerprint in fingerprints:
        for term in fingerprint.get("terms", []):
            normalized = str(term or "").lower().strip()
            if normalized:
                terms.add(normalized)
        for part in str(fingerprint.get("application") or "").lower().split():
            if len(part) >= 4:
                terms.add(part)
    return terms


def format_web_fingerprint_summary(fingerprints: list[dict[str, Any]]) -> str:
    if not fingerprints:
        return "Detected web applications: none."
    lines = ["Detected web applications:"]
    for fingerprint in fingerprints:
        versions = fingerprint.get("versions") or []
        version_text = f" versions={', '.join(versions)}" if versions else ""
        markers = ", ".join(fingerprint.get("matched_markers", [])[:4])
        lines.append(
            f"- {fingerprint.get('application')} "
            f"confidence={fingerprint.get('confidence')}{version_text}; markers: {markers}"
        )
    return "\n".join(lines)
