from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException

from simple_crew.api.dependencies import get_red_team_runner, get_threat_intel_runner
from simple_crew.api.schemas import RedTeamRequest, ThreatIntelRequest, WorkflowResponse
from simple_crew.config import PROJECT_ROOT


app = FastAPI(title="Simple Crew Cybersecurity API", version="1.0.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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

