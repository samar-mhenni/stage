from typing import Any

from simple_crew.tasks.common import RESULT_RULE, RESULT_SCHEMA, compact


def build_task(context: dict[str, Any]) -> str:
    return f"""Create prioritized corrective actions from the supplied evidence and analysis.
Cover immediate containment, eradication, recovery, prevention, detection, and further collection where justified. For each action state evidence basis, urgency, expected effect, operational impact, effort, owner type, validation method, rollback need, and whether human approval is required. Prefer reversible targeted actions. Do not claim any remediation was executed.
Every action must trace to an observed fact or a supported hypothesis in the supplied analysis. Do not claim or recommend removal of web shells, backdoors, malware, persistence, stolen credentials, or altered files unless evidence specifically supports that artifact. When evidence is absent, place the activity under further collection as a conditional investigation step and explicitly say it is unconfirmed. Do not recommend credential rotation merely because a credential field name was observed; require evidence that a credential value was exposed or accessed.
For each supported corrective action, provide an executable specification: the action type,
validated target, intended command or script behavior, prerequisites, verification evidence,
rollback procedure, and safety constraints. Commands and scripts may be proposed, but never embed
credentials or claim execution; execution status comes only from the guarded executor. For a
confirmed SSH brute-force pattern with a valid source IP, include exactly one machine-readable
finding with `type: temporary_source_ip_block`, `target` set to the source IP, `value` set to
`ssh`, and `confirmed: true`. This names the approved action; a separate guarded executor decides
whether it can be applied.
Return only JSON matching: {RESULT_SCHEMA}
{RESULT_RULE}
Context: {compact(context)}"""
