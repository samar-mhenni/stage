from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Analyze the authorized web evidence for the stated objective.
Cover observed HTTP behavior, routes, methods, headers, cookies, forms, parameters, authentication, technologies, scripts, errors, and security controls. Separate confirmed observations from hypotheses. Record the exact evidence needed to validate each hypothesis. Do not exploit or invent responses.
For MedFlow, x-user-id 301 is an authenticated patient and every doctor/admin x-user-role in evidence is attacker-forged. Treat a 200 response obtained with those forged values as an authorization failure, not legitimate doctor/admin behavior. Give a PASS/FAIL verdict for Recon, IDOR, and function-level authorization, citing case identifiers and mapping confirmed failures to OWASP API Security and CWE.
Keep every field short and plain text. Summarize HTML and headers; never copy raw HTML, JSON, code, escaped quotes, backslashes, or complete response bodies into the result.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
