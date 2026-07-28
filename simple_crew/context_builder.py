import json
from typing import Any

from simple_crew.config import settings
from simple_crew.models import WorkflowState


def redact_pre_exploitation_context(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return value
    redacted = json.loads(json.dumps(value))
    audit = redacted.get("credential_audit")
    if isinstance(audit, dict) and "passwords" in audit:
        passwords = audit.get("passwords")
        audit["passwords"] = [f"<redacted:{len(passwords)} candidates>"] if isinstance(passwords, list) else "<redacted>"
    if isinstance(audit, dict) and audit.get("password_file"):
        audit["password_file"] = "<validated dictionary file>"
    return redacted


def _short(value: Any, limit: int = 700) -> Any:
    if isinstance(value, str):
        return value[:limit]
    return value


def build_planner_context(state: WorkflowState, database_context: list[dict[str, Any]]) -> dict[str, Any]:
    history = []
    for item in state.results[-settings.max_history_items :]:
        history.append(
            {
                "agent": item.get("agent"),
                "status": item.get("status"),
                "summary": _short(item.get("summary", "")),
                "findings": item.get("findings", [])[:3],
                "missing": item.get("missing_information", [])[:3],
            }
        )
    return {
        "workflow": state.workflow_type,
        "objective": state.objective,
        "target": state.target,
        "target_port": state.target_port,
        "scope": state.authorized_scope,
        "evidence_path": state.evidence_path,
        "context_path": state.context_path,
        "pre_exploitation_context": state.pre_exploitation_context,
        "authorization_matrix": state.authorization_matrix,
        "authorization_validation": state.authorization_validation,
        "iteration": state.iteration,
        "max_iterations": state.max_iterations,
        "history": history,
        "generated_tools": [
            {key: tool.get(key) for key in ("tool_id", "name", "purpose", "risk_level")}
            for tool in state.generated_tools[-3:]
        ],
        "executions": state.execution_results[-3:],
        "live_evidence_available": any(
            item.get("status") == "success" and bool(item.get("stdout"))
            for item in state.execution_results
        ),
        "failed_actions": state.failed_actions[-3:],
        "database_context": database_context[: settings.max_database_results],
    }


def build_agent_context(
    state: WorkflowState,
    objective: str,
    database_context: list[dict[str, Any]],
) -> dict[str, Any]:
    context = build_planner_context(state, database_context)
    if state.pre_exploitation_context and state.execution_results:
        execution = state.execution_results[-1]
        try:
            raw_items = json.loads(execution.get("stdout") or "[]")
        except (TypeError, json.JSONDecodeError):
            raw_items = []
        if isinstance(raw_items, dict):
            raw_items = raw_items.get("attempts", [])
        if not isinstance(raw_items, list):
            raw_items = []
        compact_evidence = []
        for index, item in enumerate(raw_items, 1):
            if not isinstance(item, dict):
                continue
            request_headers = item.get("request_headers") or item.get("request", {}).get("headers") or {}
            normalized_headers = {str(key).lower(): value for key, value in request_headers.items()}
            security_headers = {
                key: value for key, value in normalized_headers.items()
                if any(marker in key for marker in (
                    "user", "role", "scope", "tenant", "account", "auth", "token", "cookie"
                ))
            }
            request_body = item.get("request_body") or item.get("request", {}).get("body")
            response_body = item.get("response_body") or item.get("response", {}).get("body")
            compact_evidence.append({
                "case_id": item.get("case_id") or f"attempt-{index}",
                "test": item.get("test"),
                "phase": item.get("phase"),
                "method": item.get("method") or item.get("request", {}).get("method"),
                "path": item.get("path") or item.get("request", {}).get("url"),
                "security_headers": security_headers,
                "request_body": _short(request_body, 120),
                "status": item.get("status") or item.get("status_code") or item.get("response", {}).get("status_code"),
                "response_body": _short(response_body, 220),
            })
        supplied = redact_pre_exploitation_context(state.pre_exploitation_context)
        context = {
            "workflow": state.workflow_type,
            "objective": state.objective,
            "target": state.target,
            "scope": state.authorized_scope,
            "pre_exploitation_context": supplied,
            "identity": supplied.get("identity"),
            "verdict_rules": supplied.get("rules"),
            "authorization_matrix": state.authorization_matrix,
            "authorization_validation": state.authorization_validation,
            "execution": {
                key: execution.get(key)
                for key in ("tool_id", "status", "exit_code", "duration_seconds", "stderr")
            },
            "assessment_evidence": compact_evidence,
        }
    context["current_objective"] = objective
    return context
