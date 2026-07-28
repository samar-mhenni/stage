from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Analyze the authorized web evidence for the stated objective.
Cover observed HTTP behavior, routes, methods, headers, cookies, forms, parameters, authentication, technologies, scripts, errors, and security controls. Separate confirmed observations from hypotheses. Record the exact evidence needed to validate each hypothesis. Do not exploit or invent responses.
When pre-exploitation context is supplied, apply its identity assumptions, test names, expected
security properties, and evidence rules. Interpret attacker-controlled variations relative to the
fixed authenticated identity. Cite evidence identifiers and mark missing coverage inconclusive.
Keep every field short and plain text. Summarize HTML and headers; never copy raw HTML, JSON, code, escaped quotes, backslashes, or complete response bodies into the result.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
