from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from threading import Lock
from typing import Any
from uuid import uuid4

from simple_crew.config import PROJECT_ROOT, settings


OUTPUTS = PROJECT_ROOT / "simple_crew" / "outputs"
LIVE_LOG = OUTPUTS / "wazuh_live_alerts.jsonl"
_lock = Lock()
_windows: dict[tuple[str, str, str], deque[tuple[float, dict[str, Any]]]] = defaultdict(deque)
_last_trigger: dict[tuple[str, str, str], float] = {}
_last_snapshot: dict[tuple[str, str, str], Path] = {}


def _first(alert: dict[str, Any], paths: tuple[str, ...], default: Any = "") -> Any:
    for path in paths:
        value: Any = alert
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, ""):
            return value
    return default


def _timestamp(alert: dict[str, Any]) -> float:
    raw = str(_first(alert, ("timestamp", "@timestamp", "data.timestamp"), ""))
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


def _groups(alert: dict[str, Any]) -> str:
    groups = _first(alert, ("rule.groups", "groups"), [])
    return " ".join(groups if isinstance(groups, list) else [str(groups)]).lower()


def _source(alert: dict[str, Any]) -> str:
    value = _first(alert, (
        "data.source_ip", "data.srcip", "data.src_ip", "src_ip", "srcip",
    ))
    if value:
        return str(value)
    description = str(_first(alert, ("rule.description", "message"), ""))
    match = re.search(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b", description)
    return match.group(1) if match else "unknown"


def _username(alert: dict[str, Any]) -> str:
    value = _first(alert, (
        "data.target_account_id", "data.srcuser", "data.dstuser", "data.username",
        "username", "user",
    ))
    if value:
        return str(value)
    description = str(_first(alert, ("rule.description", "message"), ""))
    match = re.search(r"\bfor\s+([A-Za-z0-9_.@-]+)", description)
    return match.group(1) if match else "unknown"


def _path(alert: dict[str, Any]) -> str:
    value = _first(alert, (
        "data.http.path", "data.path", "http.path", "path", "url.path",
    ))
    if value:
        return str(value)
    return "ssh" if "sshd" in _groups(alert) else "/login"


def _rule_level(alert: dict[str, Any]) -> int:
    try:
        return int(_first(alert, ("rule.level", "level"), 0))
    except (TypeError, ValueError):
        return 0


def _is_failed_login(alert: dict[str, Any]) -> bool:
    group_text = _groups(alert)
    status = str(_first(alert, (
        "data.http.status", "data.status", "status", "http.status", "response.status",
    ), ""))
    outcome = str(_first(alert, (
        "data.authentication.result", "data.authentication.reason",
        "data.outcome", "outcome", "event.outcome",
    ), "")).lower()
    description = str(_first(alert, ("rule.description", "message", "full_log"), "")).lower()
    return (
        any(marker in group_text for marker in ("authentication_fail", "invalid_login", "bruteforce"))
        or status in {"401", "403"}
        or any(marker in outcome + " " + description for marker in (
            "invalid_credentials", "invalid credentials", "authentication failed", "login failed",
        ))
    )


def _is_wazuh_bruteforce(alert: dict[str, Any]) -> bool:
    text = _groups(alert) + " " + str(_first(alert, ("rule.description",), "")).lower()
    return _rule_level(alert) >= 10 and any(
        marker in text for marker in ("brute_force", "brute force", "authentication_failures")
    )


def _append_snapshot(path: Path, alert: dict[str, Any]) -> None:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    events = content.setdefault("events", [])
    alert_id = alert.get("id")
    if not any(item.get("id") == alert_id for item in events if isinstance(item, dict)):
        events.append(alert)
    content.setdefault("detector", {})["wazuh_level10_observed"] = True
    content["detector"]["wazuh_rule_id"] = _first(alert, ("rule.id",), None)
    path.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")


def ingest_alert(alert: dict[str, Any]) -> dict[str, Any]:
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    now = _timestamp(alert)
    source = _source(alert)
    username = _username(alert)
    path = _path(alert)
    key = (source, username, path)
    with _lock:
        with LIVE_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert, ensure_ascii=False, separators=(",", ":")) + "\n")
        if not _is_failed_login(alert):
            return {"accepted": True, "failed_login": False, "triggered": False}
        level10 = _is_wazuh_bruteforce(alert)
        previous_snapshot = _last_snapshot.get(key)
        if level10 and previous_snapshot and previous_snapshot.is_file():
            _append_snapshot(previous_snapshot, alert)
            return {
                "accepted": True, "failed_login": True, "triggered": False,
                "enriched_existing_incident": True, "evidence_path": str(previous_snapshot),
                "source_ip": source, "username": username, "path": path,
                "wazuh_level": _rule_level(alert),
            }
        window = _windows[key]
        window.append((now, alert))
        cutoff = now - settings.wazuh_bruteforce_window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        count = len(window)
        last = _last_trigger.get(key, 0)
        triggered = (
            (count >= settings.wazuh_bruteforce_threshold or level10)
            and now - last >= settings.wazuh_alert_cooldown_seconds
        )
        snapshot = None
        if triggered:
            _last_trigger[key] = now
            snapshot = OUTPUTS / f"wazuh_bruteforce_{uuid4().hex[:12]}.json"
            _last_snapshot[key] = snapshot
            snapshot.write_text(json.dumps({
                "source": "Wazuh real-time webhook",
                "detector": {
                    "type": "failed_login_threshold",
                    "source_ip": source,
                    "username": username,
                    "path": path,
                    "count": count,
                    "window_seconds": settings.wazuh_bruteforce_window_seconds,
                    "wazuh_level10_observed": level10,
                    "wazuh_rule_id": _first(alert, ("rule.id",), None) if level10 else None,
                },
                "events": [item for _, item in window],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "accepted": True,
            "failed_login": True,
            "source_ip": source,
            "username": username,
            "path": path,
            "window_count": count,
            "threshold": settings.wazuh_bruteforce_threshold,
            "wazuh_level": _rule_level(alert),
            "wazuh_level10_observed": level10,
            "triggered": triggered,
            "evidence_path": str(snapshot) if snapshot else None,
        }
