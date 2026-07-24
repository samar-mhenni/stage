from typing import Any

from simple_crew.tasks.common import PLANNER_SCHEMA, compact


def build_task(context: dict[str, Any], allowed: list[str]) -> str:
    return f"""Choose exactly one next Red Team action.
Allowed actions: {compact(allowed)}
Rules:
- Stay inside the explicit authorized scope.
- Use database matches and completed results before requesting new work.
- Treat every CVE identifier as exact. Never substitute a similar CVE, vulnerability family, protocol, or technique.
- If database_context says no exact CVE record exists, do not invent or attribute a CVE mechanism. You may still plan a generic, evidence-driven capability validation based on observed service behavior.
- For an authorized HTTP lab, a suitable generic validation may use OPTIONS or other observations, then create, verify, and remove one unpredictable harmless text marker. Report only the demonstrated capability, never an unverified CVE.
- If live_evidence_available is false and the objective requires live target evidence, select generate_tool before recon, web_analysis, or exploit_validation.
- When the workflow objective is the MedFlow authorization assignment, the first evidence tool must execute the complete requested endpoint/role matrix in one bounded run, emit one JSON document containing every request and response, and restore any temporary prescription markers. Do not decompose that matrix into one tool per endpoint.
- After a successful evidence-collection execution, select the appropriate analysis agent before generating a validation tool.
- Never repeat recon, web_analysis, or exploit_validation when that action already appears in recent results unless a later tool execution supplied new evidence.
- When an analysis result says live target evidence is missing, select generate_tool for one bounded collection or validation tool instead of repeating the analysis.
- Never select execute_tool again when the latest execution of that tool failed or was blocked. Select generate_tool for a corrected replacement or finish with the limitation.
- You may execute multiple distinct generated tools. A failed or blocked tool may be retried once only when the same tool can succeed without code changes. Never repeat a successful tool; generate a different evidence-specific tool or finish.
- Prefer passive analysis and least-invasive validation.
- Select generate_tool only for a specific evidence gap; execute_tool only when a suitable, not-yet-executed tool exists.
- When selecting execute_tool, set tool_id to the exact generated tool to execute.
- Select finish when evidence is sufficient or no safe useful action remains.
Return only JSON matching: {PLANNER_SCHEMA}
Workflow context: {compact(context)}"""
