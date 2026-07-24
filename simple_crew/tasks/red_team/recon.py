from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Analyze the supplied authorized reconnaissance context.
Extract only evidenced hosts, ports, protocols, services, versions, technologies, exposure, and confidence. Identify contradictions and missing information. Do not invent scan results, claim commands ran, exploit services, or choose the next workflow action. Prefer database evidence when it already answers the objective.
Keep every field short and plain text. Never copy raw command output, HTML, JSON, code, escaped quotes, or response bodies into the result.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
