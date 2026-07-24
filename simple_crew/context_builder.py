import json
from typing import Any

from simple_crew.config import settings
from simple_crew.models import WorkflowState


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
    if "medflow" in state.objective.lower() and state.execution_results:
        execution = state.execution_results[-1]
        try:
            raw_items = json.loads(execution.get("stdout") or "[]")
        except (TypeError, json.JSONDecodeError):
            raw_items = []
        compact_evidence = [{
            "case_id": item.get("case_id"),
            "method": item.get("method"),
            "path": item.get("path"),
            "role": item.get("role"),
            "request_headers": item.get("request_headers"),
            "request_body": item.get("request_body"),
            "status": item.get("status"),
            "response_body": item.get("response_body"),
        } for item in raw_items]
        if "web" in objective.lower() or "get" in objective.lower():
            compact_evidence = [
                item for item in compact_evidence
                if item["method"] == "GET"
                or (item["path"] == "/patients/1/prescribe" and item["role"] == "patient")
            ]
        elif "write" in objective.lower() or "escalation" in objective.lower():
            compact_evidence = [
                item for item in compact_evidence
                if "/prescribe" in str(item["path"]) or item["path"] == "/admin/dashboard"
            ]
        context = {
            "workflow": state.workflow_type,
            "objective": state.objective,
            "target": state.target,
            "scope": state.authorized_scope,
            "authenticated_identity": "x-user-id 301, actual role patient",
            "attacker_controlled_input": "Every doctor/admin x-user-role value is forged",
            "verdict_rule": "PASS means attack resisted; FAIL means unauthorized access/write succeeded",
            "execution": {
                key: execution.get(key)
                for key in ("tool_id", "status", "exit_code", "duration_seconds", "stderr")
            },
            "medflow_evidence": compact_evidence,
        }
    context["current_objective"] = objective
    return context
