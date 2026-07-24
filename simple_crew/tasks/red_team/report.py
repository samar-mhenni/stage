from typing import Any

from simple_crew.tasks.common import compact


def build_task(summary: dict[str, Any]) -> str:
    return f"""Write a concise evidence-based Red Team report in Markdown.
Include objective and authorized scope, database knowledge reused, actions performed, confirmed findings, unconfirmed hypotheses, validation outcomes, risk and impact, generated tools, cleanup, prioritized recommendations, failures, and limitations. Cite supplied evidence by filename or identifier where available. Never invent findings or imply an action executed when it did not.
For MedFlow, state that x-user-id 301 is an authenticated patient and doctor/admin x-user-role values were forged. Use security-test semantics (PASS when the attack is resisted, FAIL when unauthorized access or write succeeds). Include a test summary and separate verdicts for Recon and Tests 1-4, request/response evidence references, root cause, OWASP API Security and CWE mappings, remediation, cleanup status, Groq/openai-gpt-oss-120b provider details, the OpenAI-compatible endpoint, prompt design, and planner/generated-tool/executor architecture.
Use OWASP API1:2023 and CWE-639 for BOLA/IDOR; OWASP API5:2023 with CWE-862/CWE-863 for broken function-level authorization; CWE-269 and CWE-345 for forged-role escalation; and CWE-200 for sensitive disclosure. Do not use obsolete category numbers, invent scripts/tools/CVSS values, or claim raw evidence is missing when medflow_evidence and raw_evidence_artifact are present. Only name actual generated_tools and execution tool IDs supplied in state.
The architecture is the existing Simple Crew Red Team planner, LLM-generated matrix collector, bounded safe executor, web/exploitation analysis agents, and report agent. Do not describe the Markdown formatter as the generated tool.
For this evidence, Recon is PASS and each of Tests 1, 2, 3, and 4 is overall FAIL because x-user-id 301 is a patient and at least one forged doctor/admin request succeeded. Never describe forged doctor/admin access as expected or authorized. Keep the entire report under 1,500 words, avoid duplicate findings/tables, and finish all required provider and architecture fields before any optional detail.
Treat CVE identifiers as exact and reproduce database records faithfully. Never rename a CVE, substitute another vulnerability, or claim a mechanism that is absent from the supplied state.
The executions array is authoritative. Report every execution with its tool_id, status, exit_code, reason, and outcome; never say a tool was not executed when an execution entry exists.
Report state: {compact(summary)}"""
