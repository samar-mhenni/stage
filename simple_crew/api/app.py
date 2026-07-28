from pathlib import Path
import hmac
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException

from simple_crew.api.dependencies import get_red_team_runner, get_threat_intel_runner
from simple_crew.api.schemas import RedTeamRequest, ThreatIntelRequest, WorkflowResponse
from simple_crew.config import PROJECT_ROOT
from simple_crew.config import settings
from simple_crew.wazuh_ingest import ingest_alert


app = FastAPI(title="Simple Crew Cybersecurity API", version="1.0.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _authorize_wazuh(authorization: str) -> None:
    if not settings.wazuh_ingest_token:
        raise HTTPException(status_code=503, detail="WAZUH_INGEST_TOKEN is not configured")
    expected = f"Bearer {settings.wazuh_ingest_token}"
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid bearer token")


def _latest_wazuh_incident() -> Path:
    output_dir = PROJECT_ROOT / "simple_crew" / "outputs"
    incidents = list(output_dir.glob("wazuh_bruteforce_*.json"))
    if not incidents:
        raise HTTPException(status_code=404, detail="no correlated Wazuh incident is ready")
    return max(incidents, key=lambda path: path.stat().st_mtime)


def _run_wazuh_analysis(evidence_path: str):
    return get_threat_intel_runner()(
        evidence_path=evidence_path,
        objective=(
            "Analyze the Wazuh failed-login threshold incident, distinguish confirmed repeated "
            "authentication failures from inferred malicious intent and credential compromise, "
            "select evidence-supported corrective actions, provide executable specifications, "
            "execute validated corrective tools through guarded executors, verify their effects "
            "and rollback, generate the complete report, and email confirmed findings with the report."
        ),
        max_iterations=8,
        dry_run=False,
        require_corrective_tool=True,
    )


@app.post("/threat-intel/ingest/wazuh")
def ingest_wazuh_alert(
    alert: dict[str, Any] = Body(...),
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    _authorize_wazuh(authorization)
    result = ingest_alert(alert)
    result["workflow_started"] = False
    result["start_mode"] = "manual"
    return result


@app.post("/threat-intel/wazuh/run", response_model=WorkflowResponse)
def run_latest_wazuh_incident(
    authorization: str = Header(default=""),
) -> WorkflowResponse:
    _authorize_wazuh(authorization)
    incident = _latest_wazuh_incident()
    try:
        return _response(_run_wazuh_analysis(str(incident)))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Wazuh threat-intel workflow failed: {exc}") from exc


def _response(state) -> WorkflowResponse:
    return WorkflowResponse(
        workflow_id=state.workflow_id,
        status="complete" if state.finished else "complete_with_limitations",
        report_path=state.report_path,
        state=state.model_dump(),
    )


@app.post("/red-team/run", response_model=WorkflowResponse)
@app.post("/api/red-team/run", response_model=WorkflowResponse, include_in_schema=False)
def red_team_run(request: RedTeamRequest, runner=Depends(get_red_team_runner)) -> WorkflowResponse:
    try:
        return _response(runner(**request.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"red-team workflow failed: {exc}") from exc


@app.post("/threat-intel/run", response_model=WorkflowResponse)
@app.post("/api/threat-intel/run", response_model=WorkflowResponse, include_in_schema=False)
def threat_intel_run(request: ThreatIntelRequest, runner=Depends(get_threat_intel_runner)) -> WorkflowResponse:
    try:
        return _response(runner(**request.model_dump()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"threat-intel workflow failed: {exc}") from exc


@app.get("/reports/{workflow_id}")
def get_report(workflow_id: str) -> dict[str, str]:
    safe_id = Path(workflow_id).name
    path = PROJECT_ROOT / "simple_crew" / "outputs" / f"{safe_id}.md"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    return {"workflow_id": safe_id, "report_path": str(path), "report": path.read_text(encoding="utf-8")}
