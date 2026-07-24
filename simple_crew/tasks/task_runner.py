import json
import logging
import ast
from pathlib import Path
from datetime import datetime, timezone
from typing import TypeVar

from crewai import Agent, Crew, Process, Task
from pydantic import BaseModel


logger = logging.getLogger(__name__)
ModelT = TypeVar("ModelT", bound=BaseModel)


def _json_object(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("agent did not return a JSON object")
    candidate = text[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as json_error:
        try:
            repaired = ast.literal_eval(candidate)
        except (ValueError, SyntaxError):
            try:
                from json_repair import repair_json

                repaired = json.loads(repair_json(candidate))
            except Exception:
                raise json_error
        if not isinstance(repaired, dict):
            raise ValueError("agent JSON output is not an object")
        return repaired


def _save_invalid_output(role: str, output: str, error: Exception) -> None:
    path = Path(__file__).resolve().parents[1] / "outputs" / "invalid_agent_outputs.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": role,
        "error": str(error)[:1000],
        "raw_output": output[:12000],
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


def run_agent_task(
    agent: Agent,
    description: str,
    expected_output: str,
    output_model: type[ModelT] | None = None,
) -> ModelT | str:
    task = Task(description=description, expected_output=expected_output, agent=agent)
    try:
        crew_output = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False).kickoff()
    except Exception as exc:
        raise RuntimeError(f"{agent.role} failed: {exc}") from exc
    output = str(getattr(crew_output, "raw", crew_output) or "").strip()
    if not output:
        raise RuntimeError(f"{agent.role} returned empty output")
    if output_model:
        try:
            data = _json_object(output)
            if output_model.__name__ == "GeneratedTool":
                data.setdefault("expected_output", "Structured execution evidence for the requested validation.")
            return output_model.model_validate(data)
        except Exception as exc:
            _save_invalid_output(agent.role, output, exc)
            raise RuntimeError(f"{agent.role} returned invalid structured output: {exc}") from exc
    return output
