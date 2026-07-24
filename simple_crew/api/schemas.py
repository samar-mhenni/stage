from pydantic import BaseModel, Field, field_validator


class RedTeamRequest(BaseModel):
    target: str
    target_port: int | None = Field(default=None, ge=1, le=65535)
    authorized_scope: list[str]
    objective: str = "Perform an authorized security assessment of the lab target"
    max_iterations: int = Field(default=12, ge=1, le=20)
    dry_run: bool = True

    @field_validator("authorized_scope")
    @classmethod
    def scope_must_not_be_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("authorized_scope must not be empty")
        return value


class ThreatIntelRequest(BaseModel):
    evidence_path: str
    objective: str = "Analyze suspicious activity and recommend corrective actions"
    max_iterations: int = Field(default=12, ge=1, le=20)
    dry_run: bool = True


class WorkflowResponse(BaseModel):
    workflow_id: str
    status: str
    report_path: str | None
    state: dict
