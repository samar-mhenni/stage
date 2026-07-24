from typing import Any, Literal

import json

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ResultItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    description: str
    target: str | None = None
    source: str | None = None
    value: str | None = None
    status: str | None = None
    confidence: str | None = None
    confirmed: bool | None = None
    timestamp: str | None = None
    reference: str | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_item(cls, value):
        if isinstance(value, str):
            return {"type": "statement", "description": value}
        if isinstance(value, dict):
            item = dict(value)
            item.setdefault("type", str(item.get("category") or item.get("name") or "statement"))
            item.setdefault(
                "description",
                str(item.get("summary") or item.get("item") or item.get("value") or item["type"]),
            )
            if item.get("confidence") is not None:
                item["confidence"] = str(item["confidence"])
            if item.get("status") is not None:
                item["status"] = str(item["status"])
            if item.get("value") is not None and not isinstance(item["value"], str):
                item["value"] = json.dumps(item["value"], default=str, separators=(",", ":"))
            allowed = set(cls.model_fields)
            return {key: val for key, val in item.items() if key in allowed}
        return value


class PlannerDecision(BaseModel):
    action: Literal[
        "recon",
        "web_analysis",
        "exploit_validation",
        "process_evidence",
        "analyze_evidence",
        "corrective_actions",
        "generate_tool",
        "execute_tool",
        "finish",
    ]
    objective: str
    reason: str
    expected_output: str
    tool_id: str | None = None
    finding_id: str | None = None


class WorkflowState(BaseModel):
    workflow_id: str
    workflow_type: Literal["red_team", "threat_intel"]
    objective: str
    target: str | None = None
    target_port: int | None = None
    authorized_scope: list[str] = Field(default_factory=list)
    evidence_path: str | None = None
    iteration: int = 0
    max_iterations: int = 12
    dry_run: bool = True
    results: list[dict[str, Any]] = Field(default_factory=list)
    generated_tools: list[dict[str, Any]] = Field(default_factory=list)
    execution_results: list[dict[str, Any]] = Field(default_factory=list)
    failed_actions: list[dict[str, Any]] = Field(default_factory=list)
    planner_decisions: list[dict[str, Any]] = Field(default_factory=list)
    database_context: list[dict[str, Any]] = Field(default_factory=list)
    finished: bool = False
    report_path: str | None = None


class GeneratedTool(BaseModel):
    tool_id: str
    name: str
    purpose: str
    language: Literal["python", "shell", "command"]
    filename: str | None = None
    required_programs: list[str] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)
    code: str | None = None
    expected_output: str
    risk_level: Literal["low", "medium", "high"] = "low"


class AgentResult(BaseModel):
    agent: str
    status: Literal["success", "failed", "blocked", "skipped", "inconclusive"]
    summary: str
    findings: list[ResultItem] = Field(default_factory=list)
    evidence: list[ResultItem] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)

    @field_validator("findings", "evidence", mode="before")
    @classmethod
    def normalize_result_items(cls, value):
        if not isinstance(value, list):
            return value
        return [
            {"type": "statement", "description": item}
            if isinstance(item, str) else item
            for item in value
        ]

    @field_validator("missing_information", mode="before")
    @classmethod
    def normalize_missing_information(cls, value):
        if not isinstance(value, list):
            return value
        return [item if isinstance(item, str) else json.dumps(item, default=str) for item in value]
