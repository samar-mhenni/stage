import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    yaml = None


DEFAULT_SIGMA_PATHS = ("./sigma", "./rules", "./detections", "./cti/sigma")
REQUIRED_SIGMA_FIELDS = ("title", "id", "status", "description", "logsource", "detection", "level")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}


class SigmaToolInput(BaseModel):
    action: str = Field(
        default="generate",
        description="Action to run: search, generate, validate, or package.",
    )
    attack_technique: str | None = Field(
        default=None,
        description="ATT&CK technique ID or name, for example T1059.001 PowerShell.",
    )
    threat_actor: str | None = Field(
        default=None,
        description="Threat actor name, intrusion set, or campaign context.",
    )
    detection_requirement: str | None = Field(
        default=None,
        description="Plain-language detection requirement or behavior to detect.",
    )
    sigma_rule: str | None = Field(
        default=None,
        description="Sigma YAML rule to validate.",
    )
    logsource_product: str = Field(default="windows", description="Sigma logsource product.")
    logsource_category: str = Field(default="process_creation", description="Sigma logsource category.")
    level: str = Field(default="medium", description="Sigma severity level.")
    rule_paths: str | None = Field(
        default=None,
        description="Comma-separated directories/files to search for Sigma YAML rules.",
    )
    limit: int = Field(default=10, description="Maximum number of search results.")


def _require_yaml() -> None:
    if yaml is None:
        raise ValueError("PyYAML is required to use SigmaTool. Install pyyaml.")


def _safe_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9_.-]+", text or "") if len(token) > 2}


def _title_from_requirement(requirement: str | None, technique: str | None) -> str:
    source = requirement or technique or "Suspicious Activity"
    words = re.findall(r"[A-Za-z0-9]+", source)[:8]
    return " ".join(word.capitalize() for word in words) or "Suspicious Activity"


def _extract_attack_id(attack_technique: str | None) -> str:
    match = re.search(r"T\d{4}(?:\.\d{3})?", attack_technique or "", re.IGNORECASE)
    return match.group(0).upper() if match else ""


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "selection"


def _infer_detection_keywords(requirement: str | None, technique: str | None, actor: str | None) -> list[str]:
    text = " ".join(part for part in (requirement, technique, actor) if part)
    keywords = []
    keyword_map = {
        "powershell": "powershell.exe",
        "cmd": "cmd.exe",
        "wscript": "wscript.exe",
        "cscript": "cscript.exe",
        "rundll32": "rundll32.exe",
        "regsvr32": "regsvr32.exe",
        "mimikatz": "mimikatz",
        "credential": "lsass",
        "dump": "comsvcs.dll",
        "smb": "\\\\",
        "psexec": "psexec",
        "encoded": "-enc",
        "base64": "-enc",
        "download": "downloadstring",
        "scheduled": "schtasks",
        "service": "sc.exe",
    }
    lowered = text.lower()
    for key, value in keyword_map.items():
        if key in lowered:
            keywords.append(value)
    if not keywords:
        keywords = ["suspicious", "execution"]
    return sorted(set(keywords))


def _build_sigma_rule(
    attack_technique: str | None,
    threat_actor: str | None,
    detection_requirement: str | None,
    logsource_product: str,
    logsource_category: str,
    level: str,
) -> dict[str, Any]:
    attack_id = _extract_attack_id(attack_technique)
    title = _title_from_requirement(detection_requirement, attack_technique)
    selection_name = f"selection_{_slug(title)[:40]}"
    keywords = _infer_detection_keywords(detection_requirement, attack_technique, threat_actor)
    tags = []
    if attack_id:
        tags.append(f"attack.{attack_id.lower()}")
    if threat_actor:
        tags.append(f"threat_actor.{_slug(threat_actor)}")

    rule = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": detection_requirement or f"Detect behavior associated with {attack_technique or 'the requested activity'}.",
        "references": [],
        "author": "CrewAI SigmaTool",
        "date": "2026/06/24",
        "tags": tags,
        "logsource": {
            "product": logsource_product,
            "category": logsource_category,
        },
        "detection": {
            selection_name: {
                "CommandLine|contains": keywords,
            },
            "condition": selection_name,
        },
        "fields": ["UtcTime", "Image", "CommandLine", "ParentImage", "User"],
        "falsepositives": ["Administrative scripts", "Security testing", "Software deployment tooling"],
        "level": level.lower() if level.lower() in VALID_LEVELS else "medium",
    }
    return rule


def _validate_sigma_dict(rule: dict[str, Any]) -> dict[str, Any]:
    errors = []
    warnings = []
    for field in REQUIRED_SIGMA_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    status = str(rule.get("status", "")).lower()
    if status and status not in VALID_STATUSES:
        warnings.append(f"Unexpected status: {status}")

    level = str(rule.get("level", "")).lower()
    if level and level not in VALID_LEVELS:
        errors.append(f"Invalid level: {level}")

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not any(logsource.get(key) for key in ("product", "service", "category")):
        errors.append("logsource must include product, service, or category.")

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping.")
    elif "condition" not in detection:
        errors.append("detection.condition is required.")
    else:
        condition = str(detection.get("condition", ""))
        selections = [key for key in detection.keys() if key != "condition"]
        if not selections:
            errors.append("detection must include at least one selection.")
        if condition and not any(selection in condition for selection in selections):
            warnings.append("detection.condition does not reference a defined selection by name.")

    return {"valid": not errors, "errors": errors, "warnings": warnings}


def _rule_text(rule: dict[str, Any]) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=False)


def _iter_rule_files(rule_paths: str | None) -> list[Path]:
    paths = [Path(item.strip()) for item in (rule_paths or ",".join(DEFAULT_SIGMA_PATHS)).split(",") if item.strip()]
    files = []
    for path in paths:
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.yml")))
            files.extend(sorted(path.rglob("*.yaml")))
    return files


def _search_rules(
    attack_technique: str | None,
    threat_actor: str | None,
    detection_requirement: str | None,
    rule_paths: str | None,
    limit: int,
) -> dict[str, Any]:
    _require_yaml()
    query_text = " ".join(part for part in (attack_technique, threat_actor, detection_requirement) if part)
    query_tokens = _tokenize(query_text)
    results = []
    for path in _iter_rule_files(rule_paths):
        try:
            text = path.read_text(encoding="utf-8")
            rule = yaml.safe_load(text) or {}
            haystack = " ".join(
                [
                    str(rule.get("title", "")),
                    str(rule.get("description", "")),
                    " ".join(str(tag) for tag in _safe_list(rule.get("tags"))),
                    text,
                ]
            )
            tokens = _tokenize(haystack)
            overlap = sorted(query_tokens.intersection(tokens))
            if query_tokens and not overlap:
                continue
            results.append(
                {
                    "path": str(path),
                    "title": rule.get("title", ""),
                    "id": rule.get("id", ""),
                    "level": rule.get("level", ""),
                    "tags": _safe_list(rule.get("tags")),
                    "match_terms": overlap,
                    "score": len(overlap),
                }
            )
        except Exception as exc:
            logger.warning("Skipping Sigma rule %s: %s", path, exc)
    results.sort(key=lambda item: item["score"], reverse=True)
    return {"results": results[:limit], "searched_files": len(_iter_rule_files(rule_paths))}


@ToolRegistry.register("sigma_tool")
class SigmaTool(BaseTool):
    name: str = "SigmaTool"
    description: str = (
        "Detection engineering tool for searching Sigma rules, generating Sigma YAML rules, "
        "and validating Sigma rules from ATT&CK technique, threat actor, and detection requirement inputs."
    )
    args_schema: type[BaseModel] = SigmaToolInput

    def _run(
        self,
        action: str = "generate",
        attack_technique: str | None = None,
        threat_actor: str | None = None,
        detection_requirement: str | None = None,
        sigma_rule: str | None = None,
        logsource_product: str = "windows",
        logsource_category: str = "process_creation",
        level: str = "medium",
        rule_paths: str | None = None,
        limit: int = 10,
    ) -> str:
        try:
            _require_yaml()
            safe_limit = max(1, min(int(limit), 100))
            if action == "search":
                return json.dumps(
                    _search_rules(attack_technique, threat_actor, detection_requirement, rule_paths, safe_limit),
                    indent=2,
                )

            if action == "generate":
                rule = _build_sigma_rule(
                    attack_technique,
                    threat_actor,
                    detection_requirement,
                    logsource_product,
                    logsource_category,
                    level,
                )
                validation = _validate_sigma_dict(rule)
                return json.dumps(
                    {
                        "sigma_rule": _rule_text(rule),
                        "detection_logic": rule["detection"],
                        "validation": validation,
                    },
                    indent=2,
                )

            if action == "validate":
                if not sigma_rule:
                    raise ValueError("sigma_rule is required for validate action.")
                parsed = yaml.safe_load(sigma_rule)
                if not isinstance(parsed, dict):
                    raise ValueError("sigma_rule must parse to a YAML mapping.")
                return json.dumps(
                    {
                        "validation": _validate_sigma_dict(parsed),
                        "detection_logic": parsed.get("detection", {}),
                    },
                    indent=2,
                )

            if action == "package":
                search_results = _search_rules(attack_technique, threat_actor, detection_requirement, rule_paths, safe_limit)
                rule = _build_sigma_rule(
                    attack_technique,
                    threat_actor,
                    detection_requirement,
                    logsource_product,
                    logsource_category,
                    level,
                )
                return json.dumps(
                    {
                        "search_results": search_results,
                        "sigma_rule": _rule_text(rule),
                        "detection_logic": rule["detection"],
                        "validation": _validate_sigma_dict(rule),
                    },
                    indent=2,
                )

            raise ValueError("Unsupported action. Use search, generate, validate, or package.")
        except Exception as exc:
            logger.exception("SigmaTool failed.")
            return json.dumps({"error": "sigma_tool_error", "message": str(exc)}, indent=2)
