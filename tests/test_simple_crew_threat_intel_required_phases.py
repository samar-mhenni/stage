from simple_crew.models import PlannerDecision, WorkflowState
from simple_crew.runtime import _execution_ledger
from simple_crew.workflows.threat_intel import (
    _enforce_required_phase,
    _has_joomla_public_config_evidence,
)


def _state(results=None):
    return WorkflowState(
        workflow_id="ti-test",
        workflow_type="threat_intel",
        objective="Analyze evidence and recommend corrective actions.",
        evidence_path="evidence.json",
        dry_run=False,
        results=results or [],
    )


def _decision(action):
    return PlannerDecision(
        action=action,
        objective="Planner objective",
        reason="Planner reason",
        expected_output="Planner output",
    )


def _result(agent):
    return {"agent": agent, "status": "success", "summary": "done"}


def test_finish_is_overridden_until_process_evidence_runs():
    decision = _enforce_required_phase(_state(), _decision("finish"))

    assert decision.action == "process_evidence"


def test_tool_generation_is_overridden_until_analysis_runs():
    state = _state([_result("process_evidence")])

    decision = _enforce_required_phase(state, _decision("generate_tool"))

    assert decision.action == "analyze_evidence"


def test_finish_is_overridden_until_corrective_actions_run():
    state = _state([_result("process_evidence"), _result("analyze_evidence")])

    decision = _enforce_required_phase(state, _decision("finish"))

    assert decision.action == "corrective_actions"


def test_finish_is_allowed_after_all_required_phases():
    state = _state([
        _result("process_evidence"),
        _result("analyze_evidence"),
        _result("corrective_actions"),
    ])

    decision = _enforce_required_phase(state, _decision("finish"))

    assert decision.action == "generate_tool"


def test_dry_run_agent_aliases_count_as_completed():
    state = _state([
        _result("evidence"),
        _result("intelligence"),
        _result("corrective_actions"),
    ])

    decision = _enforce_required_phase(state, _decision("finish"))

    assert decision.action == "generate_tool"


def test_generated_corrective_tool_must_execute_before_finish():
    state = _state([
        _result("process_evidence"),
        _result("analyze_evidence"),
        _result("corrective_actions"),
    ])
    state.generated_tools.append({"tool_id": "tool-1", "name": "verify_control"})

    decision = _enforce_required_phase(state, _decision("finish"))

    assert decision.action == "execute_tool"
    assert decision.tool_id == "tool-1"


def test_finish_is_allowed_after_corrective_tool_succeeds():
    state = _state([
        _result("process_evidence"),
        _result("analyze_evidence"),
        _result("corrective_actions"),
    ])
    state.generated_tools.append({"tool_id": "tool-1", "name": "verify_control"})
    state.execution_results.append({"tool_id": "tool-1", "status": "success", "exit_code": 0})

    decision = _enforce_required_phase(state, _decision("finish"))

    assert decision.action == "finish"


def test_joomla_evidence_selects_schema_aware_corrective_generator(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(
        '{"http":{"path":"/api/index.php/v1/config/application?public=true"}}',
        encoding="utf-8",
    )

    assert _has_joomla_public_config_evidence(str(evidence)) is True


def test_drafted_corrective_tool_is_not_reported_as_applied():
    state = _state()
    state.execution_results.append({
        "tool_id": "tool-1",
        "status": "success",
        "exit_code": 0,
        "stdout": '{"deployment_status":"drafted_not_deployed"}',
    })

    ledger = _execution_ledger(state)

    assert "tool executed; corrective action not applied" in ledger
    assert "`tool-1`: **success**" not in ledger
