import json
from pathlib import Path

from simple_crew.authorization_matrix import (
    build_authorization_collector,
    is_authorization_context,
    validate_authorization_matrix,
)
from simple_crew.models import AuthorizationTestMatrix
from simple_crew.models import WorkflowState
from simple_crew.workflows.red_team import _authorization_decision


CONTEXT_PATH = (
    Path(__file__).resolve().parents[1]
    / "simple_crew"
    / "samples"
    / "medflow_pre_exploitation_context.json"
)


def _case(evidence_id, test, method, path, role, body=None, cleanup=None):
    return {
        "evidence_id": evidence_id,
        "test": test,
        "request": {
            "method": method,
            "path": path,
            "headers": {"x-user-id": "301", "x-user-role": role},
            "body": body,
        },
        "expected_security_behavior": "Enforce the supplied authorization boundary.",
        "cleanup": cleanup,
    }


def _complete_matrix():
    cases = []
    for role in ("patient", "doctor", "admin"):
        for resource_id in (1, 2, 3):
            cases.append(_case(
                f"E-{len(cases) + 1:03d}",
                "Recon" if role == "patient" and resource_id == 1 else "IDOR",
                "GET",
                f"/patients/{resource_id}",
                role,
            ))
    for role in ("patient", "doctor", "admin"):
        cases.append(_case(
            f"E-{len(cases) + 1:03d}",
            "Function authorization",
            "GET",
            "/patients",
            role,
        ))
    for role in ("patient", "doctor", "admin"):
        cases.append(_case(
            f"E-{len(cases) + 1:03d}",
            "Admin escalation",
            "GET",
            "/admin/dashboard",
            role,
        ))
    for role, resource_id in (
        ("patient", 1),
        ("doctor", 2),
        ("doctor", 3),
        ("admin", 2),
        ("admin", 3),
    ):
        cleanup = None if role == "patient" else {
            "method": "PUT",
            "path": f"/patients/{resource_id}/prescribe",
            "headers": {"x-user-id": "301", "x-user-role": role},
            "body": {"medication": "original-value"},
        }
        cases.append(_case(
            f"E-{len(cases) + 1:03d}",
            "Write escalation",
            "PUT",
            f"/patients/{resource_id}/prescribe",
            role,
            {"medication": "authorization-test-marker"},
            cleanup,
        ))
    return AuthorizationTestMatrix.model_validate({"cases": cases})


def test_medflow_context_activates_generic_authorization_mode():
    context = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))
    assert is_authorization_context(context)


def test_complete_matrix_validates_account_and_resource_namespaces():
    context = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))
    result = validate_authorization_matrix(_complete_matrix(), context)
    assert result["valid"], result["errors"]
    assert result["case_count"] == 20
    assert result["covered_roles"] == ["admin", "doctor", "patient"]
    assert result["covered_resource_ids"] == ["1", "2", "3"]


def test_validator_rejects_account_id_in_resource_path_and_missing_coverage():
    context = json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))
    matrix = AuthorizationTestMatrix.model_validate({
        "cases": [_case("E-001", "Recon", "GET", "/patients/301", "patient")]
    })
    result = validate_authorization_matrix(matrix, context)
    assert not result["valid"]
    assert "resource identifier not covered: 1" in result["errors"]
    assert "missing required test: idor" in result["errors"]


def test_collector_captures_http_errors_as_responses():
    tool = build_authorization_collector(_complete_matrix(), "authorized.example")
    assert "except urllib.error.HTTPError" in tool.code
    assert '"response_body"' in tool.code
    assert tool.command[-1] == "authorized.example"


def test_authorization_route_requires_matrix_collector_execution_and_analysis():
    state = WorkflowState(
        workflow_id="rt-test",
        workflow_type="red_team",
        objective="authorized API assessment",
        target="authorized.example",
        authorized_scope=["authorized.example"],
        dry_run=False,
    )
    assert _authorization_decision(state).action == "authorization_matrix"
    state.authorization_matrix = _complete_matrix().model_dump()
    state.authorization_validation = {"valid": True}
    assert _authorization_decision(state).action == "generate_tool"
    state.generated_tools.append({
        "tool_id": "authorization-matrix-test",
        "name": "collector",
    })
    assert _authorization_decision(state).action == "execute_tool"
    state.execution_results.append({
        "tool_id": "authorization-matrix-test",
        "status": "success",
    })
    assert _authorization_decision(state).action == "web_analysis"
    state.results.append({"agent": "web_analysis", "status": "success"})
    assert _authorization_decision(state).action == "exploit_validation"
    state.results.append({"agent": "exploit_validation", "status": "success"})
    assert _authorization_decision(state).action == "finish"
