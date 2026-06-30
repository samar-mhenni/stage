import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from crew_threat_intel import DEFAULT_DB_PATH, run_threat_intel_pipeline


app = FastAPI(title="CrewAI SOC Threat Intelligence API")


class ThreatIntelRunRequest(BaseModel):
    target: str = Field(default="172.17.0.2", description="Authorized lab target.")
    ports: str = Field(default="1-10000", description="Nmap port expression.")
    timeout: int = Field(default=180, ge=1, le=1200, description="Nmap timeout in seconds.")
    db_path: str = Field(default=str(DEFAULT_DB_PATH), description="SQLite output DB path.")
    reuse_scan: str = Field(default="", description="Optional existing Nmap JSON path.")
    use_agents: bool = Field(
        default=False,
        description="Run CrewAI LLM reporting agents. Default false uses the faster deterministic tool-only path.",
    )
    include_full_output: bool = Field(
        default=False,
        description="Return full reports inline. Default false returns compact metadata and artifact paths.",
    )
    auto_execute_remediation: bool = Field(
        default=True,
        description="Automatically execute generated remediation scripts after each run.",
    )
    auto_apply_remediation: bool = Field(
        default=False,
        description="Run generated remediation scripts with --apply. Default false executes dry-run only.",
    )
    remediation_timeout: int = Field(
        default=120,
        ge=1,
        le=1200,
        description="Timeout in seconds for each generated remediation script.",
    )


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
        "ports": result.get("ports"),
        "open_port_count": len(open_ports),
        "open_ports": open_ports,
        "service_summary": result.get("service_summary"),
        "db_path": result.get("db_path"),
        "artifacts": result.get("artifacts"),
        "integrated_tools": result.get("integrated_tools"),
        "generated_scripts": result.get("generated_scripts"),
        "remediation_execution_status": result.get("remediation_execution_status"),
        "remediation_summary": result.get("remediation_summary"),
        "remediation_execution": result.get("remediation_execution"),
    }


def _connect(db_path: str = str(DEFAULT_DB_PATH)) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Database not found: {db_path}")
    return sqlite3.connect(path)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/threat-intel/run")
def run_threat_intel(request: ThreatIntelRunRequest) -> dict[str, Any]:
    try:
        result = run_threat_intel_pipeline(
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
            db_path=request.db_path,
            reuse_scan=request.reuse_scan,
            use_agents=request.use_agents,
            auto_execute_remediation=request.auto_execute_remediation,
            auto_apply_remediation=request.auto_apply_remediation,
            remediation_timeout=request.remediation_timeout,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "threat_intel_run_failed",
                "message": str(exc),
                "type": exc.__class__.__name__,
            },
        ) from exc

    response = result if request.include_full_output else _compact_run_response(result)
    return jsonable_encoder(response)


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
