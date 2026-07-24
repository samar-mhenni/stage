from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Review the locally normalized evidence and relevant database records.
Summarize important events, timestamps, sources, assets, users, and indicators. Identify duplicates, malformed or missing fields, chronology problems, and collection gaps. Preserve the distinction between raw facts and inference. Do not attribute actors, correlate campaigns, recommend remediation, or invent missing log values.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
