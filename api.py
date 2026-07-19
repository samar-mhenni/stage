import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

import agents.red_team  # noqa: F401 - registers red-team agents
import agents.threat_intel  # noqa: F401 - registers threat-intel agents
from agents.registry import AgentRegistry
from crews.red_team.pipeline import (
    RED_TEAM_SPECIALISTS,
    next_artifact_run_id,
    run_dynamic_red_team_recon_stage,
    run_red_team_pipeline,
    run_red_team_specialist_pipeline,
)
from crews.threat_intel.pipeline import DEFAULT_DB_PATH, run_threat_intel_pipeline


app = FastAPI(title="CrewAI SOC Threat Intelligence API")


class ThreatIntelRunRequest(BaseModel):
    target: str = Field(..., description="Evidence label or authorized target name.")
    evidence_path: str = Field(default="", description="Required JSON/text logs or tool-output evidence file.")
    db_path: str = Field(default=str(DEFAULT_DB_PATH), description="SQLite output DB path.")
    reuse_scan: str = Field(default="", description="Deprecated alias for evidence_path.")
    include_full_output: bool = Field(
        default=False,
        description="Return full reports inline. Default false returns compact metadata and artifact paths.",
    )
    auto_execute_remediation: bool = Field(
        default=True,
        description="Automatically execute LLM-generated tool scripts after each run.",
    )
    include_remediation_plan: bool = Field(
        default=True,
        description="Run the response/remediation planning and generated remediation script stages.",
    )
    auto_apply_remediation: bool = Field(
        default=False,
        description="Run LLM-generated tool scripts with --apply. Default false executes dry-run only.",
    )
    remediation_timeout: int = Field(
        default=120,
        ge=1,
        le=1200,
        description="Timeout in seconds for each generated tool script.",
    )


class RedTeamRunRequest(BaseModel):
    target: str = Field(..., description="Authorized lab target.")
    ports: str = Field(default="1-10000", description="Nmap port expression.")
    timeout: int = Field(default=180, ge=1, le=1200, description="Nmap timeout in seconds.")
    reuse_scan: str = Field(default="", description="Deprecated; red-team recon is generated fresh every run.")
    use_agents: bool = Field(default=True, description="Deprecated compatibility field; red-team runs use LLM agents.")
    execute: bool = Field(default=False, description="Execute generated red-team validation scripts.")
    execution_timeout: int = Field(default=180, ge=1, le=1200, description="Timeout per generated script.")
    use_lab_notes: bool = Field(
        default=True,
        description="Use local lab README/context when available. Set false to infer from recon/database only.",
    )
    environment_context: str = Field(default="", description="Optional notes about the authorized target environment.")


class RedTeamAgentRunRequest(BaseModel):
    target: str = Field(..., description="Authorized lab target.")
    domain: str = Field(..., description="One of: web, linux, windows, blockchain.")
    ports: str = Field(default="1-10000", description="Nmap port expression if reuse_scan is not provided.")
    timeout: int = Field(default=180, ge=1, le=1200, description="Nmap timeout in seconds.")
    reuse_scan: str = Field(default="", description="Deprecated; red-team recon is generated fresh every run.")
    use_nmap_agent: bool = Field(
        default=True,
        description="Deprecated compatibility field; collection uses configured agent/database flow unless reuse_scan is provided.",
    )
    use_llm_agent: bool = Field(
        default=True,
        description="Deprecated compatibility field; specialist runs use the CrewAI specialist agent.",
    )
    execute: bool = Field(default=False, description="Execute only this specialist's generated validation script.")
    execution_timeout: int = Field(default=180, ge=1, le=1200, description="Timeout for the specialist script.")
    use_lab_notes: bool = Field(
        default=True,
        description="Use local lab README/context when available. Set false to infer from recon/database only.",
    )
    environment_context: str = Field(default="", description="Optional notes about the authorized target environment.")


class RedTeamReconRunRequest(BaseModel):
    target: str = Field(..., description="Authorized lab target.")
    ports: str = Field(default="1-10000", description="Nmap port expression.")
    timeout: int = Field(default=180, ge=1, le=1200, description="Nmap timeout in seconds.")


def _compact_run_response(result: dict[str, Any]) -> dict[str, Any]:
    scan = result.get("scan") or {}
    open_ports = []
    for host in scan.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports.append(
                    {
                        "host": host.get("host"),
                        "port": port.get("port"),
                        "protocol": port.get("protocol"),
                        "service": port.get("service"),
                        "product": port.get("product"),
                        "version": port.get("version"),
                    }
                )

    return {
        "run_id": result.get("run_id"),
        "artifact_run_id": result.get("artifact_run_id"),
        "status": result.get("status"),
        "target": result.get("target"),
        "evidence_path": result.get("evidence_path"),
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
        "service_summary": result.get("service_summary"),
        "evidence_summary": result.get("evidence_summary"),
        "soc_report": result.get("soc_report"),
        "db_path": result.get("db_path"),
        "artifacts": result.get("artifacts"),
        "generated_scripts": result.get("generated_scripts"),
        "remediation_plan_excluded": result.get("remediation_plan_excluded"),
        "remediation_execution_status": result.get("remediation_execution_status"),
        "remediation_summary": result.get("remediation_summary"),
        "remediation_execution": result.get("remediation_execution"),
    }


def _connect(db_path: str = str(DEFAULT_DB_PATH)) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Database not found: {db_path}")
    return sqlite3.connect(path)


def _pipeline_error(error: str, exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=500,
        detail={
            "error": error,
            "message": str(exc),
            "type": exc.__class__.__name__,
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/agents")
def list_agents() -> dict[str, Any]:
    names = AgentRegistry.get_all_agent_names()
    return {
        "agents": names,
        "red_team_specialists": RED_TEAM_SPECIALISTS,
    }


@app.post("/api/threat-intel/run")
def run_threat_intel(request: ThreatIntelRunRequest) -> dict[str, Any]:
    try:
        result = run_threat_intel_pipeline(
            target=request.target,
            evidence_path=request.evidence_path,
            db_path=request.db_path,
            reuse_scan=request.reuse_scan,
            include_remediation_plan=request.include_remediation_plan,
            auto_execute_remediation=request.auto_execute_remediation,
            auto_apply_remediation=request.auto_apply_remediation,
            remediation_timeout=request.remediation_timeout,
        )
    except Exception as exc:
        raise _pipeline_error("threat_intel_run_failed", exc) from exc

    response = result if request.include_full_output else _compact_run_response(result)
    return jsonable_encoder(response)


@app.post("/api/red-team/run")
def run_red_team(request: RedTeamRunRequest) -> dict[str, Any]:
    try:
        result = run_red_team_pipeline(
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
            reuse_scan=request.reuse_scan,
            use_agents=request.use_agents,
            execute=request.execute,
            execution_timeout=request.execution_timeout,
            use_lab_notes=request.use_lab_notes,
            environment_context=request.environment_context,
        )
    except Exception as exc:
        raise _pipeline_error("red_team_run_failed", exc) from exc
    return jsonable_encoder(result)


@app.post("/api/red-team/recon/run")
def run_red_team_recon(request: RedTeamReconRunRequest) -> dict[str, Any]:
    try:
        artifact_run_id = next_artifact_run_id()
        scan, nmap_output, recon_artifacts, execution = run_dynamic_red_team_recon_stage(
            artifact_run_id=artifact_run_id,
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
        )
        return jsonable_encoder(
            {
                "status": "success",
                "artifact_run_id": artifact_run_id,
                "agent": "red_team_recon_agent",
                "target": request.target,
                "ports": request.ports,
                "manifest": recon_artifacts.get("manifest"),
                "manifest_path": str(recon_artifacts.get("manifest_path")),
                "execution": execution,
                "scan": scan,
                "nmap_output": nmap_output,
            }
        )
    except Exception as exc:
        raise _pipeline_error("red_team_recon_run_failed", exc) from exc


@app.post("/api/red-team/agents/{agent_name}/run")
def run_red_team_agent(agent_name: str, request: RedTeamAgentRunRequest) -> dict[str, Any]:
    if request.domain not in RED_TEAM_SPECIALISTS:
        raise HTTPException(status_code=400, detail=f"Unknown red-team domain: {request.domain}")
    expected_agent = RED_TEAM_SPECIALISTS[request.domain]
    if agent_name != expected_agent:
        raise HTTPException(
            status_code=400,
            detail=f"Agent {agent_name} does not match domain {request.domain}; expected {expected_agent}.",
        )

    try:
        result = run_red_team_specialist_pipeline(
            domain=request.domain,
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
            reuse_scan=request.reuse_scan,
            use_nmap_agent=request.use_nmap_agent,
            use_llm_agent=request.use_llm_agent,
            execute=request.execute,
            execution_timeout=request.execution_timeout,
            use_lab_notes=request.use_lab_notes,
            environment_context=request.environment_context,
        )
        return jsonable_encoder(result)
    except Exception as exc:
        raise _pipeline_error("red_team_agent_run_failed", exc) from exc


@app.get("/api/threat-intel/runs")
def list_runs(db_path: str = str(DEFAULT_DB_PATH)) -> list[dict[str, Any]]:
    with _connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, created_at, target, ports, service_summary
            FROM threat_intel_runs
            ORDER BY id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]


@app.get("/api/threat-intel/runs/{run_id}")
def get_run(run_id: int, db_path: str = str(DEFAULT_DB_PATH)) -> dict[str, Any]:
    with _connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM threat_intel_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")

        record = dict(row)
        try:
            record["scan_json"] = json.loads(record["scan_json"])
        except Exception:
            pass
        return record
