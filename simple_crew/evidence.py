import csv
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from simple_crew.config import settings


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def load_and_normalize(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_file():
        raise ValueError(f"evidence file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")[: settings.max_tool_output_chars * 4]
    events: list[Any]
    if path.suffix.lower() == ".csv":
        events = list(csv.DictReader(text.splitlines()))
    else:
        try:
            parsed = json.loads(text)
            events = parsed.get("events", [parsed]) if isinstance(parsed, dict) else parsed
        except json.JSONDecodeError:
            events = []
            for line in text.splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    if line.strip():
                        events.append({"message": line.strip()})
    unique: dict[str, Any] = {}
    for event in events:
        key = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()
        unique[key] = event
    compact_events = list(unique.values())[:100]
    flat = json.dumps(compact_events, default=str)
    return {
        "source": str(path),
        "event_count": len(compact_events),
        "events": compact_events[:20],
        "indicators": {
            "ips": sorted(set(IP_RE.findall(flat)))[:20],
            "urls": sorted(set(URL_RE.findall(flat)))[:20],
            "hashes": sorted(set(HASH_RE.findall(flat)))[:20],
        },
        "truncated": len(unique) > 100,
    }

