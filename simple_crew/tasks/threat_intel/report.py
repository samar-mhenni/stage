from typing import Any

from simple_crew.tasks.common import compact


def build_task(summary: dict[str, Any]) -> str:
    return f"""Write a concise evidence-based Threat Intelligence report in Markdown.
Include objective, evidence sources, database knowledge reused, timeline, indicators, affected assets, correlations, confirmed facts, hypotheses with confidence, supported ATT&CK mappings, impact, collection gaps, prioritized corrective actions, generated tools, failures, and limitations. Avoid unsupported attribution and never claim recommended actions were executed.
Treat remediation_results as authoritative. Clearly distinguish proposed, blocked, failed, and
applied_verified actions. Claim an IP block was applied only when its remediation result is
applied_verified, and include verification and rollback status.
Report state: {compact(summary)}"""
