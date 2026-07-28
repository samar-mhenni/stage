import json
from pathlib import Path
from uuid import uuid4

from simple_crew.agents import create_threat_intel_agents
from simple_crew.config import get_llm, settings
from simple_crew.context_builder import build_planner_context
from simple_crew.database import search_relevant_context
from simple_crew.evidence import load_and_normalize
from simple_crew.models import AgentResult, GeneratedTool, PlannerDecision, WorkflowState
from simple_crew.notifications import send_confirmed_finding_email
from simple_crew.remediation import apply_named_ssh_block
from simple_crew.runtime import ask_planner, run_tool_generator, run_worker, save_state, write_report
from simple_crew.tasks.threat_intel import TASKS
from simple_crew.tools.generated_tool_manager import dry_run_tool, save_generated_tool
from simple_crew.tools.safe_executor import execute_generated_tool


ACTIONS = ["process_evidence", "analyze_evidence", "corrective_actions", "generate_tool", "execute_tool", "finish"]
REQUIRED_PHASES = (
    ("process_evidence", {"process_evidence", "evidence"}, "Normalize and validate the supplied evidence"),
    ("analyze_evidence", {"analyze_evidence", "intelligence"}, "Correlate the normalized evidence and assess supported threats"),
    ("corrective_actions", {"corrective_actions"}, "Produce prioritized evidence-based corrective actions"),
)


def _fallback_corrective_tool(evidence_path: str) -> GeneratedTool:
    tool_id = f"corrective-{uuid4().hex[:12]}"
    filename = "build_detection_plan.py"
    code = """import json, sys

def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"status": "failed", "reason": "evidence path required"}))
        raise SystemExit(2)
    with open(sys.argv[1], encoding="utf-8") as handle:
        evidence = json.load(handle)
    paths = sorted({
        node["http"]["path"] for node in walk(evidence)
        if isinstance(node.get("http"), dict) and isinstance(node["http"].get("path"), str)
    })
    target = "/api/index.php/v1/config/application?public=true"
    observed = target in paths
    output = {
        "status": "success" if observed else "failed",
        "corrective_action": "deploy_detection_rules",
        "observed_path": target if observed else None,
        "wazuh_rule": {
            "level": 12,
            "match": target,
            "description": "Joomla configuration API public access attempt"
        },
        "suricata_rule": (
            'alert http any any -> $HOME_NET any '
            '(msg:"Joomla public configuration API access"; '
            'flow:to_server,established; http.uri; '
            'content:"/api/index.php/v1/config/application?public=true"; '
            'sid:900320; rev:1;)'
        ),
        "corrective_status": "not_applied",
        "deployment_status": "drafted_not_deployed",
        "requires_human_approval": True
    }
    print(json.dumps(output, sort_keys=True))
    raise SystemExit(0 if observed else 1)

if __name__ == "__main__":
    main()
"""
    return GeneratedTool(
        tool_id=tool_id,
        name="build_joomla_detection_plan",
        purpose=(
            "Generate evidence-backed Wazuh and Suricata detection content for the observed "
            "Joomla public configuration API access without deploying production changes."
        ),
        language="python",
        filename=filename,
        required_programs=["python3"],
        command=["python3", filename, evidence_path],
        code=code,
        expected_output="Structured JSON containing evidence-backed detection rules and deployment status.",
        risk_level="low",
    )


def _has_joomla_public_config_evidence(evidence_path: str) -> bool:
    try:
        text = Path(evidence_path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "/api/index.php/v1/config/application?public=true" in text


def _completed_agents(state: WorkflowState) -> set[str]:
    return {
        str(item.get("agent"))
        for item in state.results
        if item.get("status") in {"success", "inconclusive"}
    }


def _enforce_required_phase(
    state: WorkflowState,
    decision: PlannerDecision,
    require_corrective_tool: bool = True,
) -> PlannerDecision:
    completed = _completed_agents(state)
    for action, aliases, objective in REQUIRED_PHASES:
        if not completed.intersection(aliases):
            if decision.action == action:
                return decision
            return PlannerDecision(
                action=action,
                objective=objective,
                reason=(
                    f"Required threat-intelligence phase '{action}' must complete before "
                    f"the planner may select '{decision.action}'."
                ),
                expected_output="One structured AgentResult with evidence-supported conclusions.",
            )
    if not require_corrective_tool:
        return PlannerDecision(
            action="finish",
            objective="Produce the final evidence-backed report",
            reason="All required analysis and named corrective-action phases are complete.",
            expected_output="Final report and notification record.",
        )
    attempts_by_tool = {
        tool.get("tool_id"): [
            item for item in state.execution_results if item.get("tool_id") == tool.get("tool_id")
        ]
        for tool in state.generated_tools
    }
    pending = [
        tool for tool in state.generated_tools
        if not attempts_by_tool[tool.get("tool_id")]
        or (
            len(attempts_by_tool[tool.get("tool_id")]) < 2
            and attempts_by_tool[tool.get("tool_id")][-1].get("status") == "failed"
        )
    ]
    execution_complete = any(
        item.get("status") == "success"
        or (state.dry_run and item.get("status") == "skipped")
        for item in state.execution_results
    )
    if pending:
        selected = pending[-1]
        if decision.action == "execute_tool" and (
            not decision.tool_id or decision.tool_id == selected.get("tool_id")
        ):
            return decision
        return PlannerDecision(
            action="execute_tool",
            objective="Execute the generated bounded corrective-action helper and record its evidence",
            reason=(
                "A corrective-action helper has been generated but must be executed and recorded "
                f"before the planner may select '{decision.action}'."
            ),
            expected_output="A recorded execution result with status, exit code, stdout, and stderr.",
            tool_id=selected.get("tool_id"),
        )
    if not state.generated_tools or not execution_complete:
        if decision.action == "generate_tool":
            return decision
        reason = (
            "A previous corrective-action helper did not complete successfully; generate one corrected "
            "bounded helper before finishing."
            if state.generated_tools
            else "Corrective actions are recorded; generate one bounded implementation or verification helper before finishing."
        )
        return PlannerDecision(
            action="generate_tool",
            objective=(
                "Generate one bounded defensive helper that implements a safe reversible corrective action "
                "supported by the findings, or verifies/drafts the highest-priority control when automatic "
                "remediation is unsafe. It must produce explicit evidence and must not claim a control was applied "
                "unless execution can prove it."
            ),
            reason=reason,
            expected_output="One complete GeneratedTool JSON object for a corrective action or control verification.",
        )
    return decision


def _dry_decision(state: WorkflowState) -> PlannerDecision:
    completed = _completed_agents(state)
    missing = next(
        ((action, objective) for action, aliases, objective in REQUIRED_PHASES if not completed.intersection(aliases)),
        None,
    )
    if missing:
        action, objective = missing
    elif not state.generated_tools:
        action, objective = "generate_tool", "Create a harmless local evidence helper"
    elif not state.execution_results:
        action, objective = "execute_tool", "Demonstrate planner-controlled tool routing"
    else:
        action, objective = "finish", "Produce the final report"
    return PlannerDecision(action=action, objective=objective, reason="Use available evidence before additional work", expected_output="Structured result")


def _dry_result(action: str, normalized: dict) -> AgentResult:
    names = {"process_evidence": "evidence", "analyze_evidence": "intelligence", "corrective_actions": "corrective_actions"}
    summaries = {
        "process_evidence": f"Normalized {normalized['event_count']} unique events with local parsing.",
        "analyze_evidence": "Dry-run correlation preserved facts as synthetic and identified no real attribution.",
        "corrective_actions": "Recommended review, targeted detection, and human-approved remediation; nothing was applied.",
    }
    return AgentResult(
        agent=names[action], status="success", summary=summaries[action],
        evidence=[{
            "type": "normalized_indicators",
            "description": "Locally normalized synthetic indicators",
            "value": json.dumps(normalized["indicators"], default=str)[:2000],
        }],
    )


def run_threat_intel(
    evidence_path: str,
    objective: str,
    max_iterations: int = 12,
    dry_run: bool = True,
    require_corrective_tool: bool = True,
) -> WorkflowState:
    normalized = load_and_normalize(evidence_path)
    state = WorkflowState(
        workflow_id=f"ti-{uuid4().hex[:12]}", workflow_type="threat_intel", objective=objective,
        evidence_path=evidence_path, max_iterations=max_iterations, dry_run=dry_run,
    )
    agents = create_threat_intel_agents(get_llm())
    for iteration in range(max_iterations):
        state.iteration = iteration + 1
        query = objective + " " + " ".join(normalized["indicators"]["ips"][:3])
        database_context = search_relevant_context(query, "threat_intel", limit=settings.max_database_results)
        state.database_context = database_context
        context = build_planner_context(state, database_context) | {"normalized_evidence": normalized}
        try:
            proposed = _dry_decision(state) if dry_run else ask_planner(
                agents["planner"], context, ACTIONS, TASKS["planner"]
            )
            decision = _enforce_required_phase(state, proposed, require_corrective_tool)
            state.planner_decisions.append(decision.model_dump())
            if decision.action == "finish":
                state.finished = True
                break
            if decision.action == "generate_tool":
                failed_executions = [
                    item for item in state.execution_results if item.get("status") == "failed"
                ]
                if dry_run:
                    tool = dry_run_tool("threat_intel")
                elif _has_joomla_public_config_evidence(evidence_path) or len(failed_executions) >= 2:
                    tool = _fallback_corrective_tool(evidence_path)
                else:
                    tool = run_tool_generator(
                        agents["generate_tool"], state, decision.objective, context, TASKS["generate_tool"]
                    )
                state.generated_tools.append(save_generated_tool(tool).model_dump())
            elif decision.action == "execute_tool":
                if not state.generated_tools:
                    raise ValueError("planner selected execute_tool without a generated tool")
                candidates = [
                    item for item in state.generated_tools
                    if len([
                        result for result in state.execution_results
                        if result.get("tool_id") == item.get("tool_id")
                    ]) < 2
                    and not any(
                        result.get("tool_id") == item.get("tool_id") and result.get("status") == "success"
                        for result in state.execution_results
                    )
                    and (not decision.tool_id or item.get("tool_id") == decision.tool_id)
                ]
                if not candidates:
                    raise ValueError("planner selected execute_tool but no matching unexecuted tool exists")
                state.execution_results.append(execute_generated_tool(
                    GeneratedTool.model_validate(candidates[-1]), "threat_intel", None, [], dry_run,
                ))
            else:
                completed_actions = _completed_agents(state)
                if decision.action in completed_actions:
                    raise ValueError(f"planner repeated completed action: {decision.action}")
                result = _dry_result(decision.action, normalized) if dry_run else run_worker(
                    agents[decision.action], decision.action, state, decision.objective,
                    database_context, TASKS[decision.action], {"normalized_evidence": normalized}
                )
                state.results.append(result.model_dump())
                if decision.action == "corrective_actions" and not dry_run:
                    state.remediation_results.append(
                        apply_named_ssh_block(result.model_dump())
                    )
        except Exception as exc:
            state.failed_actions.append({"iteration": state.iteration, "error": str(exc)[:500]})
        finally:
            save_state(state)
    write_report(agents["report"], state, dry_run, TASKS["report"])
    state.notifications.append(send_confirmed_finding_email(state))
    save_state(state)
    return state
