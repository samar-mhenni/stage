import re
from pathlib import Path
from typing import Any


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n\n[truncated]"


def redact_sensitive_evidence(text: str) -> str:
    redacted = str(text or "")
    sensitive_keys = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "user",
        "username",
        "host",
    )
    for key in sensitive_keys:
        redacted = re.sub(
            rf'("[^"]*{re.escape(key)}[^"]*"\s*:\s*)("[^"]*"|[^,}}\]\s]+)',
            rf'\1"***REDACTED***"',
            redacted,
            flags=re.IGNORECASE,
        )
        redacted = re.sub(
            rf"(\b{re.escape(key)}\b\s*[:=]\s*)([^\s,;]+)",
            rf"\1***REDACTED***",
            redacted,
            flags=re.IGNORECASE,
        )
    return redacted


def _read_short_file(path_value: Any, limit: int = 900) -> str:
    path = Path(str(path_value or ""))
    if not path.exists():
        return ""
    return _truncate(redact_sensitive_evidence(path.read_text(encoding="utf-8", errors="replace").strip()), limit)


def _read_observation_files(execution_dir: Path, limit: int = 1600) -> str:
    if not execution_dir.exists():
        return ""
    chunks = []
    for path in sorted(execution_dir.glob("observations*.txt")):
        text = _read_short_file(path, limit)
        if text:
            chunks.append(f"[{path.name}]\n{text}")
    return _truncate("\n\n".join(chunks), limit)


def red_team_execution_status(execution: dict[str, Any] | None) -> str:
    if not execution:
        return "not_executed"
    statuses = {item.get("status") for item in execution.get("results", [])}
    if statuses == {"ok"}:
        return "success"
    if "timeout" in statuses:
        return "timeout"
    if "failed" in statuses and "ok" in statuses:
        return "partial_failure"
    if "failed" in statuses:
        return "failed"
    if "skipped" in statuses:
        return "partial_skipped"
    return "unknown"


def _looks_like_negative_confirmation(line: str) -> bool:
    text = str(line or "").lower()
    negative_terms = (
        "no marker",
        "not found",
        "not confirmed",
        "not vulnerable",
        "failed",
        "absent",
        "missing",
        "did not",
        "does not",
        "unable to confirm",
    )
    return any(term in text for term in negative_terms)


def extract_confirmed_exploits(execution: dict[str, Any] | None) -> list[str]:
    if not execution:
        return []
    confirmed_path = Path(str(execution.get("execution_dir", ""))) / "confirmed_exploits.txt"
    if not confirmed_path.exists():
        return []
    return [
        redact_sensitive_evidence(line.strip())
        for line in confirmed_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not _looks_like_negative_confirmation(line)
    ]


def extract_created_credentials(execution: dict[str, Any] | None) -> list[str]:
    if not execution:
        return []
    credentials_path = Path(str(execution.get("execution_dir", ""))) / "created_credentials.txt"
    if not credentials_path.exists():
        return []
    return [
        line.strip()
        for line in credentials_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def build_human_execution_summary(execution: dict[str, Any] | None) -> dict[str, Any]:
    if not execution:
        return {
            "headline": "Generated scripts were not executed.",
            "status": "not_executed",
            "scripts_total": 0,
            "scripts_ok": 0,
            "scripts_failed": 0,
            "active_validation": False,
            "confirmed_findings": [],
            "created_credentials": [],
            "script_results": [],
        }

    execution_dir = Path(str(execution.get("execution_dir", "")))
    script_results = []
    confirmed_findings = extract_confirmed_exploits(execution)
    created_credentials = extract_created_credentials(execution)
    active_validation = False
    dry_run_outputs = 0
    for item in execution.get("results", []):
        stdout = _read_short_file(item.get("stdout_path"))
        stderr = _read_short_file(item.get("stderr_path"), 500)
        command = [str(part) for part in item.get("command", [])]
        active_validation = active_validation or "--execute" in command
        dry_run_outputs += 1 if "[DRY-RUN]" in stdout else 0
        script_results.append(
            {
                "script": item.get("script"),
                "status": item.get("status"),
                "returncode": item.get("returncode"),
                "active_args": [arg for arg in command if arg.startswith("--")],
                "observation": stdout or stderr or "No output captured.",
                "stderr": stderr,
            }
        )

    scripts_total = len(script_results)
    scripts_ok = sum(1 for item in script_results if item.get("status") == "ok")
    scripts_failed = sum(1 for item in script_results if item.get("status") in {"failed", "timeout"})
    if confirmed_findings:
        headline = f"{len(confirmed_findings)} confirmed validation finding(s)."
    elif scripts_total and scripts_ok == scripts_total:
        headline = "All generated scripts ran, but no exploit was confirmed."
    elif scripts_failed:
        headline = "Some generated scripts failed or timed out."
    else:
        headline = "No generated scripts ran."

    return {
        "headline": headline,
        "status": red_team_execution_status(execution),
        "scripts_total": scripts_total,
        "scripts_ok": scripts_ok,
        "scripts_failed": scripts_failed,
        "active_validation": active_validation,
        "dry_run_outputs": dry_run_outputs,
        "confirmed_findings": confirmed_findings,
        "created_credentials": created_credentials,
        "observations": _read_observation_files(execution_dir, 1600),
        "script_results": script_results,
    }


def render_human_execution_summary(summary: dict[str, Any]) -> str:
    lines = [
        "## Human-Readable Execution Result",
        "",
        summary.get("headline", "No summary available."),
        "",
        f"- Status: `{summary.get('status', 'unknown')}`",
        f"- Scripts run: `{summary.get('scripts_ok', 0)}/{summary.get('scripts_total', 0)}`",
        f"- Failed or timed out: `{summary.get('scripts_failed', 0)}`",
        f"- Active validation requested: `{bool(summary.get('active_validation'))}`",
    ]
    if summary.get("dry_run_outputs"):
        lines.append(f"- Scripts that still printed dry-run output: `{summary.get('dry_run_outputs')}`")
    if summary.get("observations"):
        lines.extend(["", "### Run Observations", ""])
        lines.extend(str(summary["observations"]).splitlines()[:12])
    lines.extend(["", "### Script Observations", ""])
    for item in summary.get("script_results", []):
        lines.append(f"- `{item.get('script')}`: `{item.get('status')}` rc={item.get('returncode')}")
        for line in str(item.get("observation") or "No output captured.").splitlines()[:8]:
            lines.append(f"  {line}")
    if not summary.get("script_results"):
        lines.append("- No script output available.")
    return "\n".join(lines).rstrip() + "\n"


def _observed_surface_lines(scan: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for host in scan.get("hosts", []):
        host_id = host.get("host") or scan.get("target") or "unknown-host"
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = " ".join(
                str(port.get(key) or "").strip()
                for key in ("service", "product", "version", "extra_info")
                if port.get(key)
            ).strip() or "open service"
            lines.append(f"- `{host_id}:{port.get('port')}/{port.get('protocol', 'tcp')}` {service}")
    for fingerprint in scan.get("web_fingerprints", []):
        if not isinstance(fingerprint, dict) or not fingerprint.get("application"):
            continue
        versions = ", ".join(str(version) for version in fingerprint.get("versions", []) if version)
        version_text = f" `{versions}`" if versions else ""
        confidence = fingerprint.get("confidence", "unknown")
        lines.append(f"- Web fingerprint: `{fingerprint['application']}`{version_text} confidence `{confidence}`")
    return lines or ["- No open service evidence was recorded."]


def render_red_team_evidence_report(
    target: str,
    scan: dict[str, Any],
    scripts: list[dict[str, Any]],
    summary: dict[str, Any],
) -> str:
    """Render the final red-team report from saved evidence only."""
    confirmed = summary.get("confirmed_findings") if isinstance(summary.get("confirmed_findings"), list) else []
    created_credentials = (
        summary.get("created_credentials") if isinstance(summary.get("created_credentials"), list) else []
    )

    lines = [
        f"- Target: `{target}`",
        f"- Execution status: `{summary.get('status', 'unknown')}`",
        f"- Confirmed findings: `{len(confirmed)}`",
        f"- Scripts run: `{summary.get('scripts_ok', 0)}/{summary.get('scripts_total', 0)}`",
        "",
        "### Observed Surface",
        "",
        *_observed_surface_lines(scan),
        "",
        "### Validation Results",
        "",
    ]
    if confirmed:
        lines.extend(f"- {finding}" for finding in confirmed)
    else:
        lines.append("- No exploit was confirmed by the generated validation scripts.")

    if created_credentials:
        lines.extend(["", "### Created Credentials", ""])
        lines.extend(f"- {item}" for item in created_credentials)

    if scripts:
        lines.extend(["", "### Generated Scripts", ""])
        for script in scripts:
            lines.append(f"- `{script.get('filename')}`: {script.get('purpose', 'validation script')}")

    observations = str(summary.get("observations") or "").strip()
    if observations:
        lines.extend(["", "### Evidence Notes", ""])
        lines.extend(observations.splitlines()[:10])

    lines.extend(
        [
            "",
            "### Guardrails",
            "",
            "- Candidate CVEs and exploit paths are not reported as confirmed unless they appear in confirmed findings.",
            "- Redirects, HTTP 200/302, product versions, and missing markers are evidence only, not proof of exploitability.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def target_only_context(text: str, target: str) -> str:
    lines = []
    current_block: list[str] = []
    include_block = False
    target_pattern = re.escape(str(target))

    def flush() -> None:
        nonlocal current_block, include_block
        if current_block and include_block:
            lines.extend(current_block)
            lines.append("")
        current_block = []
        include_block = False

    for line in str(text or "").splitlines():
        starts_numbered = bool(re.match(r"^\s*\d+\.\s+\*\*Host:", line))
        if starts_numbered:
            flush()
        if starts_numbered or current_block:
            current_block.append(line)
            if re.search(target_pattern, line):
                include_block = True
        elif str(target) in line or not re.search(r"\bHost:\s+\d+\.\d+\.\d+", line):
            lines.append(line)
    flush()
    cleaned = "\n".join(line for line in lines if line is not None).strip()
    return cleaned or str(text or "")
