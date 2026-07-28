from typing import Any

from simple_crew.tasks.common import compact


def build_task(summary: dict[str, Any]) -> str:
    return f"""Write a concise evidence-based Red Team report in Markdown.
Include objective and authorized scope, database knowledge reused, actions performed, confirmed findings, unconfirmed hypotheses, validation outcomes, risk and impact, generated tools, cleanup, prioritized recommendations, failures, and limitations. Cite supplied evidence by filename or identifier where available. Never invent findings or imply an action executed when it did not.
When pre-exploitation context is supplied, report one verdict for every named test using its own
PASS/FAIL definitions, identity assumptions, evidence requirements, classifications, remediation,
and cleanup rules. Cite actual request/response evidence and generated tool IDs. Never invent
provider details, scripts, classifications, or missing evidence.
The architecture is the existing Simple Crew Red Team planner, LLM-generated matrix collector, bounded safe executor, web/exploitation analysis agents, and report agent. Do not describe the Markdown formatter as the generated tool.
Keep the report concise, avoid duplicate findings or tables, and report incomplete coverage as
INCONCLUSIVE rather than guessing.
Treat CVE identifiers as exact and reproduce database records faithfully. Never rename a CVE, substitute another vulnerability, or claim a mechanism that is absent from the supplied state.
The executions array is authoritative. Report every execution with its tool_id, status, exit_code, reason, and outcome; never say a tool was not executed when an execution entry exists.
Report state: {compact(summary)}"""
