from typing import Any

from simple_crew.tasks.common import PLANNER_SCHEMA, compact


def build_task(context: dict[str, Any], allowed: list[str]) -> str:
    return f"""Choose exactly one next Threat Intelligence action.
Allowed actions: {compact(allowed)}
Rules:
- Use normalized evidence and database matches before LLM inference.
- Do not repeat completed or failed work without new evidence.
- Process evidence before correlation and correlate before corrective actions.
- When the objective requests remediation or corrective-action verification, complete corrective_actions before generate_tool or execute_tool.
- Select generate_tool only for a specific local evidence gap; execute_tool only when a suitable tool exists.
- Select finish when an evidence-based report can be produced or no useful safe action remains.
Return only JSON matching: {PLANNER_SCHEMA}
Workflow context: {compact(context)}"""
