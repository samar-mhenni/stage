from email.message import EmailMessage
from pathlib import Path
import smtplib
from typing import Any

from simple_crew.config import settings
from simple_crew.models import WorkflowState


def _confirmed_findings(state: WorkflowState) -> list[dict[str, Any]]:
    return [
        finding
        for result in state.results
        for finding in result.get("findings", [])
        if (
            isinstance(finding, dict)
            and finding.get("confirmed") is True
            and str(finding.get("type", "")).lower() not in {"action", "recommendation"}
            and str(finding.get("status", "")).lower() not in {"proposed", "recommended"}
        )
    ]


def send_confirmed_finding_email(state: WorkflowState) -> dict[str, Any]:
    findings = _confirmed_findings(state)
    base = {
        "channel": "email",
        "recipient": settings.alert_email_to,
        "finding_count": len(findings),
    }
    if state.dry_run:
        return base | {"status": "skipped", "reason": "dry-run mode"}
    if not findings:
        return base | {"status": "skipped", "reason": "no explicitly confirmed finding"}
    if not settings.email_alerts_enabled:
        return base | {"status": "skipped", "reason": "EMAIL_ALERTS_ENABLED is false"}
    if not all((settings.alert_email_to, settings.smtp_host, settings.smtp_username, settings.smtp_password)):
        return base | {"status": "skipped", "reason": "SMTP configuration is incomplete"}

    lines = [
        "Simple Crew detected confirmed security activity.",
        f"Workflow: {state.workflow_id}",
        f"Objective: {state.objective}",
        f"Evidence: {state.evidence_path or 'embedded workflow evidence'}",
        f"Report: {state.report_path or 'not available'}",
        "",
        "Confirmed findings:",
    ]
    lines.extend(
        f"- {item.get('type', 'finding')}: {str(item.get('description', ''))[:500]}"
        for item in findings[:10]
    )
    if state.report_path and Path(state.report_path).is_file():
        report = Path(state.report_path).read_text(encoding="utf-8", errors="replace")
        lines.extend(["", "Full report:", "", report[:30000]])
    message = EmailMessage()
    message["Subject"] = f"[Simple Crew Alert] Confirmed security finding — {state.workflow_id}"
    message["From"] = settings.smtp_username
    message["To"] = settings.alert_email_to
    message.set_content("\n".join(lines))
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as client:
            if settings.smtp_starttls:
                client.starttls()
            client.login(settings.smtp_username, settings.smtp_password)
            client.send_message(message)
        return base | {"status": "sent"}
    except Exception as exc:
        return base | {
            "status": "failed",
            "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
        }
