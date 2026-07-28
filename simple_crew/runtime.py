from pathlib import Path
from typing import Any, Callable
import json

from crewai import Agent

from simple_crew.context_builder import (
    build_agent_context,
    redact_pre_exploitation_context,
)
from simple_crew.database import save_workflow_result
from simple_crew.models import (
    AgentResult,
    AuthorizationTestMatrix,
    GeneratedTool,
    PlannerDecision,
    WorkflowState,
)
from simple_crew.tasks.task_runner import run_agent_task


def save_state(state: WorkflowState) -> Path:
    output_dir = Path(__file__).resolve().parent / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{state.workflow_id}.json"
    path.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return path


def ask_planner(
    agent: Agent,
    context: dict[str, Any],
    allowed: list[str],
    build_task: Callable[[dict[str, Any], list[str]], str],
) -> PlannerDecision:
    prompt = build_task(context, allowed)
    return run_agent_task(agent, prompt, "One PlannerDecision JSON object.", PlannerDecision)


def run_worker(
    agent: Agent,
    name: str,
    state: WorkflowState,
    objective: str,
    database_context: list[dict[str, Any]],
    build_task: Callable[[dict[str, Any]], str],
    extra_context: dict[str, Any] | None = None,
) -> AgentResult:
    context = build_agent_context(state, objective, database_context)
    if extra_context:
        context.update(extra_context)
    prompt = build_task(context)
    result = run_agent_task(agent, prompt, "One AgentResult JSON object.", AgentResult)
    result = result.model_copy(update={"agent": name})
    save_workflow_result(state.workflow_id, name, {**result.model_dump(), "target": state.target})
    return result


def run_tool_generator(
    agent: Agent,
    state: WorkflowState,
    objective: str,
    context: dict[str, Any],
    build_task: Callable[[str, dict[str, Any]], str],
) -> GeneratedTool:
    prompt = build_task(objective, context)
    return run_agent_task(agent, prompt, "One GeneratedTool JSON object.", GeneratedTool)


def run_authorization_matrix(
    agent: Agent,
    context: dict[str, Any],
    build_task: Callable[[dict[str, Any]], str],
) -> AuthorizationTestMatrix:
    prompt = build_task(context)
    return run_agent_task(
        agent,
        prompt,
        "One AuthorizationTestMatrix JSON object.",
        AuthorizationTestMatrix,
    )


def _fallback_report(state: WorkflowState) -> str:
    lines = [
        f"# {state.workflow_type.replace('_', ' ').title()} Report",
        "",
        f"Workflow ID: `{state.workflow_id}`",
        f"Objective: {state.objective}",
        f"Target: {state.target or 'N/A'}" + (f":{state.target_port}" if state.target_port else ""),
        f"Finished: {state.finished}",
        "",
        "## Results",
    ]
    lines.extend(f"- **{item.get('agent')}** ({item.get('status')}): {item.get('summary')}" for item in state.results)
    lines.extend(["", "## Executions"])
    lines.extend(f"- `{item.get('tool_id')}`: {item.get('status')} (exit {item.get('exit_code')})" for item in state.execution_results)
    lines.extend(["", "## Failures"])
    lines.extend(f"- Iteration {item.get('iteration')}: {item.get('error')}" for item in state.failed_actions)
    lines.extend(["", "## Limitations", "- This deterministic fallback was used because the report agent was unavailable."])
    return "\n".join(lines) + "\n"


def _execution_ledger(state: WorkflowState) -> str:
    lines = ["", "## Authoritative execution ledger", "", "This section is generated directly from workflow state.", ""]
    if not state.execution_results:
        lines.append("- No generated tool was executed.")
    for index, item in enumerate(state.execution_results, 1):
        reason = f" — {item.get('reason')}" if item.get("reason") else ""
        display_status = f"**{item.get('status')}**"
        try:
            structured_output = json.loads(item.get("stdout") or "{}")
        except (TypeError, json.JSONDecodeError):
            structured_output = {}
        if not isinstance(structured_output, dict):
            structured_output = {}
        deployment_status = structured_output.get("deployment_status")
        corrective_status = structured_output.get("corrective_status")
        if deployment_status in {"drafted_not_deployed", "not_deployed"} or corrective_status == "not_applied":
            display_status = "**tool executed; corrective action not applied**"
        lines.append(
            f"- {index}. `{item.get('tool_id')}`: {display_status}, "
            f"exit code `{item.get('exit_code')}`{reason}"
        )
    return "\n".join(lines) + "\n"


def write_report(
    agent: Agent,
    state: WorkflowState,
    dry_run: bool,
    build_task: Callable[[dict[str, Any]], str],
) -> str:
    report_dir = Path(__file__).resolve().parent / "outputs"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{state.workflow_id}.md"
    summary = {
        "objective": state.objective,
        "target": state.target,
        "target_port": state.target_port,
        "scope": state.authorized_scope,
        "results": state.results[-8:],
        "generated_tools": state.generated_tools,
        "executions": state.execution_results,
        "failures": state.failed_actions,
        "remediation_results": state.remediation_results,
        "planner_decisions": state.planner_decisions,
        "database_context": state.database_context,
    }
    if state.pre_exploitation_context and state.execution_results:
        latest = state.execution_results[-1]
        try:
            raw_items = json.loads(latest.get("stdout") or "[]")
        except (TypeError, json.JSONDecodeError):
            raw_items = []
        if isinstance(raw_items, dict):
            raw_items = raw_items.get("attempts", [])
        if not isinstance(raw_items, list):
            raw_items = []
        summary = {
            "objective": state.objective,
            "target": state.target,
            "scope": state.authorized_scope,
            "pre_exploitation_context": redact_pre_exploitation_context(
                state.pre_exploitation_context
            ),
            "authorization_validation": state.authorization_validation,
            "execution": {
                key: latest.get(key)
                for key in ("tool_id", "status", "exit_code", "duration_seconds", "stderr")
            },
            "generated_tools": [{
                key: tool.get(key) for key in ("tool_id", "name", "purpose", "filename")
            } for tool in state.generated_tools],
            "raw_evidence_artifact": str(report_dir / f"{state.workflow_id}.json"),
            "assessment_evidence": [{
                "evidence_id": f"E-{index:03d}",
                **{
                    key: item.get(key)
                    for key in (
                        "test", "phase", "method", "path", "request_headers",
                        "request_body", "status", "response_headers", "response_body",
                    )
                },
                "response_body": str(item.get("response_body") or "")[:220],
            } for index, item in enumerate(raw_items, 1) if isinstance(item, dict)],
            "analysis_results": [{
                "agent": item.get("agent"),
                "status": item.get("status"),
                "summary": item.get("summary"),
                "findings": item.get("findings"),
            } for item in state.results],
            "failures": state.failed_actions,
            "remediation_results": state.remediation_results,
        }
    if dry_run:
        lines = [
            f"# {state.workflow_type.replace('_', ' ').title()} Report",
            "",
            f"Workflow ID: `{state.workflow_id}`",
            f"Objective: {state.objective}",
            "",
            "## Results",
        ]
        lines.extend(f"- **{item.get('agent')}**: {item.get('summary')}" for item in state.results)
        lines.extend(["", "## Generated tools", *[f"- {item.get('name')}: {item.get('purpose')}" for item in state.generated_tools]])
        lines.extend(["", "## Limitations", "- Dry-run mode used simulated agent results and executed no security commands."])
        report = "\n".join(lines) + "\n"
    else:
        try:
            prompt = build_task(summary)
            report = str(run_agent_task(agent, prompt, "A concise Markdown report."))
        except Exception as exc:
            state.failed_actions.append({"iteration": state.iteration, "error": f"report agent failed: {str(exc)[:500]}"})
            report = _fallback_report(state)
    report = report.rstrip() + "\n" + _execution_ledger(state)
    path.write_text(report, encoding="utf-8")
    state.report_path = str(path)
    save_state(state)
    return report
