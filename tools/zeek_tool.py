import json
from pathlib import Path
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry


class ZeekToolInput(BaseModel):
    log_path: str | None = Field(default=None, description="Path to a Zeek log file such as conn.log, dns.log, or http.log.")
    log_data: str | None = Field(default=None, description="Raw Zeek TSV, JSONL, or JSON array log content.")
    log_type: str = Field(default="auto", description="Zeek log type: auto, conn, dns, http, or all.")
    limit: int = Field(default=100, description="Maximum number of log records to parse.")


def _clean_value(value: str) -> Any:
    if value in {"-", "(empty)"}:
        return ""
    if value in {"T", "F"}:
        return value == "T"
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _read_content(log_path: str | None, log_data: str | None) -> str:
    if log_path:
        return Path(log_path).read_text(encoding="utf-8")
    if log_data:
        return log_data
    raise ValueError("Provide log_path or log_data.")


def _parse_json_records(content: str, limit: int) -> list[dict[str, Any]]:
    stripped = content.strip()
    if stripped.startswith("["):
        parsed = json.loads(stripped)
        if not isinstance(parsed, list):
            raise ValueError("JSON array must contain Zeek event objects.")
        return [item for item in parsed if isinstance(item, dict)][:limit]

    records = []
    for line_number, line in enumerate(stripped.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on Zeek line {line_number}: {exc}") from exc
        if isinstance(item, dict):
            records.append(item)
        if len(records) >= limit:
            break
    return records


def _parse_tsv_records(content: str, limit: int) -> list[dict[str, Any]]:
    fields: list[str] = []
    records = []
    for line in content.splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            raise ValueError("Zeek TSV log is missing #fields header.")
        values = line.split("\t")
        record = {
            field: _clean_value(values[index]) if index < len(values) else ""
            for index, field in enumerate(fields)
        }
        records.append(record)
        if len(records) >= limit:
            break
    return records


def parse_zeek_records(content: str, limit: int) -> list[dict[str, Any]]:
    stripped = content.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        return _parse_json_records(stripped, limit)
    return _parse_tsv_records(stripped, limit)


def _infer_log_type(record: dict[str, Any], fallback: str) -> str:
    if fallback != "auto":
        return fallback
    if "query" in record or "qtype_name" in record:
        return "dns"
    if "method" in record or "host" in record or "uri" in record:
        return "http"
    if "id.orig_h" in record or "orig_h" in record or "uid" in record:
        return "conn"
    return "unknown"


def _get(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in ("", None):
            return record[key]
    return ""


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


def normalize_zeek_record(record: dict[str, Any], log_type: str) -> dict[str, Any]:
    inferred = _infer_log_type(record, log_type)
    base = {
        "source": "zeek",
        "event_type": inferred,
        "timestamp": _get(record, "ts", "timestamp"),
        "uid": _get(record, "uid"),
        "src_ip": _get(record, "id.orig_h", "orig_h", "src_ip"),
        "src_port": _get(record, "id.orig_p", "orig_p", "src_port"),
        "dest_ip": _get(record, "id.resp_h", "resp_h", "dest_ip"),
        "dest_port": _get(record, "id.resp_p", "resp_p", "dest_port"),
        "protocol": _get(record, "proto", "protocol"),
        "service": _get(record, "service"),
    }

    if inferred == "conn":
        base.update(
            {
                "duration": _get(record, "duration"),
                "orig_bytes": _get(record, "orig_bytes"),
                "resp_bytes": _get(record, "resp_bytes"),
                "conn_state": _get(record, "conn_state"),
                "missed_bytes": _get(record, "missed_bytes"),
                "history": _get(record, "history"),
            }
        )
    elif inferred == "dns":
        answers = _get(record, "answers")
        if isinstance(answers, str):
            answer_items = [item for item in answers.split(",") if item]
        else:
            answer_items = answers if isinstance(answers, list) else []
        base.update(
            {
                "query": _get(record, "query"),
                "qtype": _get(record, "qtype_name", "qtype"),
                "rcode": _get(record, "rcode_name", "rcode"),
                "answers": answer_items,
                "iocs": {
                    "domains": _unique([_get(record, "query")]),
                    "ips": _unique([str(item) for item in answer_items if str(item).count(".") == 3]),
                },
            }
        )
    elif inferred == "http":
        host = _get(record, "host")
        uri = _get(record, "uri")
        url = f"http://{host}{uri}" if host and uri else ""
        base.update(
            {
                "method": _get(record, "method"),
                "host": host,
                "uri": uri,
                "url": url,
                "user_agent": _get(record, "user_agent"),
                "status_code": _get(record, "status_code"),
                "request_body_len": _get(record, "request_body_len"),
                "response_body_len": _get(record, "response_body_len"),
                "iocs": {
                    "domains": _unique([host]),
                    "urls": _unique([url]),
                },
            }
        )

    return base


@ToolRegistry.register("zeek_tool")
class ZeekTool(BaseTool):
    name: str = "ZeekTool"
    description: str = (
        "Parse Zeek logs, extract connection sessions, DNS activity, and HTTP activity, "
        "and return structured telemetry events."
    )
    args_schema: type[BaseModel] = ZeekToolInput

    def _run(
        self,
        log_path: str | None = None,
        log_data: str | None = None,
        log_type: str = "auto",
        limit: int = 100,
    ) -> str:
        try:
            safe_limit = max(1, min(int(limit), 10000))
            records = parse_zeek_records(_read_content(log_path, log_data), safe_limit)
            events = [
                normalize_zeek_record(record, log_type)
                for record in records
                if log_type in {"auto", "all"} or _infer_log_type(record, "auto") == log_type
            ]
            return json.dumps(
                {
                    "count": len(events),
                    "sessions": [event for event in events if event["event_type"] == "conn"],
                    "dns_activity": [event for event in events if event["event_type"] == "dns"],
                    "http_activity": [event for event in events if event["event_type"] == "http"],
                    "events": events,
                },
                indent=2,
            )
        except Exception as exc:
            logger.exception("ZeekTool failed.")
            return json.dumps({"error": "zeek_tool_error", "message": str(exc)}, indent=2)
