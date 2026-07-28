import ipaddress
import re
import secrets
import subprocess
from typing import Any

from simple_crew.config import settings


def _requested_ip(result: dict[str, Any]) -> str | None:
    for item in result.get("findings", []):
        if (
            isinstance(item, dict)
            and item.get("type") == "temporary_source_ip_block"
            and item.get("confirmed") is True
        ):
            return str(item.get("target") or "")
    return None


def apply_named_ssh_block(result: dict[str, Any]) -> dict[str, Any]:
    action = "temporary_source_ip_block"
    source = _requested_ip(result)
    base = {"action": action, "target": source, "protected_host": settings.remediation_ssh_host}
    if not settings.remediation_enabled:
        return base | {"status": "skipped", "reason": "REMEDIATION_ENABLED is false"}
    if not source:
        return base | {"status": "skipped", "reason": "agent did not select the named action"}
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return base | {"status": "blocked", "reason": "invalid source IP"}
    trusted = {
        ipaddress.ip_address(item.strip())
        for item in settings.remediation_trusted_ips.split(",") if item.strip()
    }
    if address.is_private or address.is_loopback or address.is_multicast or address in trusted:
        return base | {"status": "blocked", "reason": "source is private, special, or trusted"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", settings.remediation_ssh_host):
        return base | {"status": "blocked", "reason": "invalid remediation host"}
    key = settings.remediation_ssh_key.expanduser()
    if not key.is_file() or key.stat().st_mode & 0o077:
        return base | {"status": "blocked", "reason": "SSH key missing or permissions are too open"}
    seconds = settings.remediation_block_seconds
    if not 60 <= seconds <= 86400:
        return base | {"status": "blocked", "reason": "block duration must be 60-86400 seconds"}
    unit = f"simplecrew-unblock-{str(address).replace('.', '-')}-{secrets.token_hex(4)}"
    remote = (
        f"set -eu; "
        f"admin_src=${{SSH_CONNECTION%% *}}; "
        f"[ \"$admin_src\" != '{address}' ] || exit 20; "
        f"if ! sudo ufw status | grep -Fq '{address}'; then "
        f"sudo ufw deny from {address} to any port 22 proto tcp "
        f"comment 'SimpleCrew agent containment'; fi; "
        f"sudo systemctl stop {unit}.timer {unit}.service 2>/dev/null || true; "
        f"sudo systemctl reset-failed {unit}.timer {unit}.service 2>/dev/null || true; "
        f"sudo systemd-run --unit={unit} --on-active={seconds}s "
        f"/usr/sbin/ufw --force delete deny from {address} to any port 22 proto tcp >/dev/null; "
        f"sudo ufw status | grep -F '{address}'; "
        f"systemctl list-timers --all --no-pager | grep -F '{unit}'"
    )
    command = [
        "ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes",
        f"{settings.remediation_ssh_user}@{settings.remediation_ssh_host}", remote,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return base | {"status": "failed", "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
    evidence = (completed.stdout + completed.stderr)[:2000]
    if completed.returncode != 0:
        reason = "refused to block current administrative source" if completed.returncode == 20 else "remote application failed"
        return base | {"status": "failed", "exit_code": completed.returncode, "reason": reason, "evidence": evidence}
    return base | {
        "status": "applied_verified",
        "duration_seconds": seconds,
        "rollback": "scheduled",
        "evidence": evidence,
    }
