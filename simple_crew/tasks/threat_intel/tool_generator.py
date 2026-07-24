from typing import Any

from simple_crew.tasks.common import TOOL_SCHEMA, compact


def build_task(objective: str, context: dict[str, Any]) -> str:
    return f"""Generate one small defensive local tool for this objective: {objective}
Limit it to evidence parsing, IOC extraction, timeline creation, local validation, or detection drafting. It must be complete, deterministic, reviewable, and non-destructive. Prefer Python standard library, never use shell=True, never embed secrets, and do not perform offensive execution or automatic production remediation.
The helper must print explicit structured evidence and exit nonzero when its validation objective is not satisfied. Keep Python source compact and complete (at most 60 non-blank lines), include a called entrypoint, and include the interpreter, generated filename, and all required literal arguments in the command array. When a recommended change needs human approval or target access that the workflow does not have, generate a verification or detection artifact locally instead of pretending to apply the change.
Return only one JSON object matching: {TOOL_SCHEMA}
Context: {compact(context, 7000)}"""
