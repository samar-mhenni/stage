from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Correlate only the supplied normalized events and database knowledge.
Build a supported timeline, connect repeated behavior, list affected assets and indicators, map ATT&CK techniques only when evidence supports them, and assign explicit confidence. Separate confirmed facts, plausible hypotheses, contradictions, and collection gaps. Avoid unsupported actor or campaign attribution.
Set `confirmed: true` only on findings directly established by supplied event evidence. Set it to
`false` for hypotheses, inferred intent, attribution, and unsupported exploit success. This flag
controls external alerting, so do not omit it from security findings.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
