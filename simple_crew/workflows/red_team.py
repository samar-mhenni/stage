import json
from pathlib import Path
from uuid import uuid4

from simple_crew.agents import create_red_team_agents
from simple_crew.authorization_matrix import (
    build_authorization_collector,
    is_authorization_context,
    validate_authorization_matrix,
)
from simple_crew.config import PROJECT_ROOT, get_llm, settings
from simple_crew.context_builder import build_planner_context
from simple_crew.database import search_relevant_context
from simple_crew.models import (
    AgentResult,
    AuthorizationTestMatrix,
    PlannerDecision,
    WorkflowState,
)
from simple_crew.runtime import (
    ask_planner,
    run_authorization_matrix,
    run_tool_generator,
    run_worker,
    save_state,
    write_report,
)
from simple_crew.tasks.red_team import TASKS
from simple_crew.tools.generated_tool_manager import dry_run_tool, save_generated_tool
from simple_crew.tools.safe_executor import execute_generated_tool, target_in_scope


ACTIONS = [
    "recon",
    "web_analysis",
    "exploit_validation",
    "authorization_matrix",
    "generate_tool",
    "execute_tool",
    "finish",
]


def _authorization_decision(state: WorkflowState) -> PlannerDecision:
    completed = {item.get("agent") for item in state.results}
    collector = next(
        (
            item for item in state.generated_tools
            if str(item.get("tool_id", "")).startswith("authorization-matrix-")
        ),
        None,
    )
    if not state.authorization_matrix or not (state.authorization_validation or {}).get("valid"):
        action = "authorization_matrix"
        objective = "Build one complete validated Web authorization test matrix"
    elif collector is None:
        action = "generate_tool"
        objective = "Build the deterministic collector for the validated authorization matrix"
    elif not any(item.get("tool_id") == collector.get("tool_id") for item in state.execution_results):
        action = "execute_tool"
        objective = "Execute the complete validated authorization matrix"
    elif "web_analysis" not in completed:
        action = "web_analysis"
        objective = "Interpret all authorization-matrix HTTP evidence"
    elif "exploit_validation" not in completed:
        action = "exploit_validation"
        objective = "Classify every named authorization test and verify cleanup evidence"
    else:
        action = "finish"
        objective = "Produce the complete evidence-backed authorization report"
    return PlannerDecision(
        action=action,
        objective=objective,
        reason="Generic HTTP authorization contexts use one validated matrix and one bounded collector.",
        expected_output="Complete request/response evidence for every required authorization test.",
        tool_id=collector.get("tool_id") if action == "execute_tool" and collector else None,
    )


def _dry_decision(state: WorkflowState) -> PlannerDecision:
    completed = {item.get("agent") for item in state.results}
    if "recon" not in completed:
        action, objective = "recon", "Summarize the authorized lab attack surface"
    elif "web_analysis" not in completed:
        action, objective = "web_analysis", "Analyze the simulated web surface without exploitation"
    elif not state.generated_tools:
        action, objective = "generate_tool", "Create a harmless local validation helper"
    elif not state.execution_results:
        action, objective = "execute_tool", "Demonstrate planner-controlled tool routing"
    elif "exploit_validation" not in completed:
        action, objective = "exploit_validation", "Record that active validation is skipped in dry-run mode"
    else:
        action, objective = "finish", "Produce the final report"
    return PlannerDecision(action=action, objective=objective, reason="Lowest-cost useful dry-run action", expected_output="Structured result")


def _dry_result(action: str, target: str) -> AgentResult:
    return AgentResult(
        agent=action,
        status="success",
        summary=f"Dry-run {action} completed for authorized target {target}; no network command executed.",
        findings=[{"type": "dry_run", "description": "Simulated result only", "target": target, "confirmed": False}],
        missing_information=["Live evidence is unavailable in dry-run mode."],
    )


def run_red_team(
    target: str,
    authorized_scope: list[str],
    objective: str,
    max_iterations: int = 12,
    dry_run: bool = True,
    target_port: int | None = None,
    context_path: str | None = None,
) -> WorkflowState:
    if not authorized_scope or not target_in_scope(target, authorized_scope):
        raise ValueError("target must be explicitly listed in authorized_scope or an authorized CIDR")
    loaded_context = None
    loaded_context_path = None
    if context_path:
        samples_dir = (PROJECT_ROOT / "simple_crew" / "samples").resolve()
        requested = Path(context_path)
        path = requested.resolve() if requested.is_absolute() else (PROJECT_ROOT / requested).resolve()
        if samples_dir not in path.parents or not path.is_file() or path.suffix.lower() != ".json":
            raise ValueError("context_path must reference a JSON file under simple_crew/samples")
        loaded_context = json.loads(path.read_text(encoding="utf-8"))
        loaded_context_path = str(path.relative_to(PROJECT_ROOT))
        objective = (
            f"{objective} Use the supplied pre-exploitation context exactly: "
            f"{json.dumps(loaded_context, separators=(',', ':'))}"
        )
    state = WorkflowState(
        workflow_id=f"rt-{uuid4().hex[:12]}", workflow_type="red_team", objective=objective,
        target=target, authorized_scope=authorized_scope, max_iterations=max_iterations, dry_run=dry_run,
        target_port=target_port,
        context_path=loaded_context_path,
        pre_exploitation_context=loaded_context,
    )
    agents = create_red_team_agents(get_llm(), get_llm(3600))
    authorization_mode = is_authorization_context(loaded_context)
    for iteration in range(max_iterations):
        state.iteration = iteration + 1
        database_context = search_relevant_context(objective, "red_team", target, settings.max_database_results)
        state.database_context = database_context
        context = build_planner_context(state, database_context)
        try:
            if dry_run:
                decision = _dry_decision(state)
            elif authorization_mode:
                decision = _authorization_decision(state)
            else:
                decision = ask_planner(agents["planner"], context, ACTIONS, TASKS["planner"])
            state.planner_decisions.append(decision.model_dump())
            if decision.action == "finish":
                state.finished = True
                break
            if decision.action == "authorization_matrix":
                matrix = run_authorization_matrix(
                    agents["authorization_matrix"],
                    context,
                    TASKS["authorization_matrix"],
                )
                validation = validate_authorization_matrix(matrix, loaded_context or {})
                state.authorization_matrix = matrix.model_dump()
                state.authorization_validation = validation
                if not validation["valid"]:
                    raise ValueError(
                        "authorization matrix incomplete: "
                        + "; ".join(validation["errors"][:12])
                    )
            elif decision.action == "generate_tool":
                if authorization_mode and state.authorization_matrix:
                    matrix = AuthorizationTestMatrix.model_validate(state.authorization_matrix)
                    context_target = (loaded_context or {}).get("target", {})
                    base_url = (
                        context_target.get("url")
                        if isinstance(context_target, dict)
                        else None
                    )
                    if not base_url:
                        scheme = "http" if target_port else "https"
                        port = f":{target_port}" if target_port else ""
                        base_url = f"{scheme}://{target}{port}"
                    tool = build_authorization_collector(matrix, base_url)
                else:
                    tool = dry_run_tool("red_team") if dry_run else run_tool_generator(
                        agents["generate_tool"], state, decision.objective, context, TASKS["generate_tool"]
                    )
                state.generated_tools.append(save_generated_tool(tool).model_dump())
            elif decision.action == "execute_tool":
                if not state.generated_tools:
                    raise ValueError("planner selected execute_tool without a generated tool")
                from simple_crew.models import GeneratedTool
                candidates = [item for item in state.generated_tools if not decision.tool_id or item.get("tool_id") == decision.tool_id]
                if not candidates:
                    raise ValueError("planner selected execute_tool but no matching tool exists")
                selected = candidates[-1]
                attempts = [item for item in state.execution_results if item.get("tool_id") == selected.get("tool_id")]
                if attempts and attempts[-1].get("status") == "success":
                    raise ValueError("planner cannot repeat a successfully executed tool; generate a new tool or finish")
                if len(attempts) >= 2:
                    raise ValueError("tool retry limit reached; generate a corrected tool or finish")
                execution = execute_generated_tool(
                    GeneratedTool.model_validate(selected), "red_team", target,
                    authorized_scope, dry_run,
                )
                state.execution_results.append(execution)
            else:
                completed_actions = {item.get("agent") for item in state.results}
                if decision.action in completed_actions:
                    raise ValueError(f"planner repeated completed action: {decision.action}")
                result = _dry_result(decision.action, target) if dry_run else run_worker(
                    agents[decision.action], decision.action, state, decision.objective,
                    database_context, TASKS[decision.action]
                )
                state.results.append(result.model_dump())
        except Exception as exc:
            state.failed_actions.append({"iteration": state.iteration, "error": str(exc)[:500]})
        finally:
            save_state(state)
    write_report(agents["report"], state, dry_run, TASKS["report"])
    return state
