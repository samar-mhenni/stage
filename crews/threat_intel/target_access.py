import subprocess


def discover_target_access(target: str) -> dict[str, str]:
    access = {"TARGET": target}
    try:
        completed = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        access["ACCESS_MODE"] = "network_only"
        access["ACCESS_REASON"] = "docker_unavailable"
        return access
    for container_id in [item for item in completed.stdout.splitlines() if item.strip()]:
        try:
            inspect = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{.Name}} {{range.NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                    container_id,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        fields = inspect.stdout.strip().split()
        if not fields:
            continue
        name = fields[0].lstrip("/")
        ips = fields[1:]
        if target in ips:
            access.update(
                {
                    "ACCESS_MODE": "docker_container",
                    "TARGET_CONTAINER": container_id,
                    "TARGET_CONTAINER_NAME": name,
                }
            )
            access.update(discover_container_runtime_facts(container_id))
            return access
    access["ACCESS_MODE"] = "network_only"
    access["ACCESS_REASON"] = "no_matching_docker_container"
    return access


def _docker_exec_text(container_id: str, command: str, limit: int = 900) -> str:
    try:
        completed = subprocess.run(
            ["docker", "exec", container_id, "sh", "-lc", command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = (completed.stdout or completed.stderr).strip()
    return text[:limit].rstrip() + "\n[truncated]" if len(text) > limit else text


def discover_container_runtime_facts(container_id: str) -> dict[str, str]:
    command_facts = _docker_exec_text(
        container_id,
        "printf 'PATH=%s\n' \"$PATH\"; "
        "for d in ${PATH//:/ }; do "
        "test -d \"$d\" && find \"$d\" -maxdepth 1 -type f -perm /111 -printf '%f\n' 2>/dev/null; "
        "done | sort -u | sed -n '1,80p'",
        limit=450,
    )
    listeners = _docker_exec_text(
        container_id,
        "netstat -tulpn 2>/dev/null | sed -n '1,40p'",
        limit=650,
    )
    init_services = _docker_exec_text(
        container_id,
        "find /etc/init.d -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort | sed -n '1,40p'",
        limit=250,
    )
    inet_services = _docker_exec_text(container_id, "ls /etc/xinetd.d 2>/dev/null | sed -n '1,30p'", limit=350)
    inet_config_facts = _docker_exec_text(
        container_id,
        "for f in /etc/xinetd.d/*; do "
        "name=$(basename \"$f\"); "
        "echo [$name]; grep -E '^[[:space:]]*(service|disable|server|socket_type|protocol)[[:space:]]' \"$f\" 2>/dev/null; "
        "done",
        limit=900,
    )
    inetd_config_facts = _docker_exec_text(
        container_id,
        "test -f /etc/inetd.conf && grep -E '^[[:space:]]*[^#[:space:]]+' /etc/inetd.conf | sed -n '1,40p' || true",
        limit=550,
    )
    return {
        "TARGET_COMMAND_FACTS": command_facts,
        "TARGET_LISTENERS": listeners,
        "TARGET_INIT_SERVICES": init_services,
        "TARGET_INET_SERVICES": inet_services,
        "TARGET_INET_CONFIG_FACTS": inet_config_facts,
        "TARGET_INETD_CONFIG_FACTS": inetd_config_facts,
    }


def format_target_access_context(target: str, access: dict[str, str]) -> str:
    lines = [
        f"Target IP/host: {target}",
        "Generated scripts receive TARGET as an environment variable.",
    ]
    if access.get("ACCESS_MODE") == "docker_container":
        lines.extend(
            [
                "Docker context: target is a local Docker container.",
                f"TARGET_CONTAINER={access.get('TARGET_CONTAINER', '')}",
                f"TARGET_CONTAINER_NAME={access.get('TARGET_CONTAINER_NAME', '')}",
                "Generated scripts receive TARGET_CONTAINER and TARGET_CONTAINER_NAME as environment variables.",
                "For apply mode, prefer docker exec against TARGET_CONTAINER for service changes inside the target.",
                "Validate changes with approved follow-up tool logs for TARGET.",
                "Detected target command availability:",
                access.get("TARGET_COMMAND_FACTS", "unknown"),
                "Detected listening services:",
                access.get("TARGET_LISTENERS", "unknown"),
                "Detected /etc/init.d services:",
                access.get("TARGET_INIT_SERVICES", "unknown"),
                "Detected /etc/xinetd.d services:",
                access.get("TARGET_INET_SERVICES", "unknown"),
                "Relevant xinetd config snippets:",
                access.get("TARGET_INET_CONFIG_FACTS", "unknown"),
                "Relevant inetd.conf snippets:",
                access.get("TARGET_INETD_CONFIG_FACTS", "unknown"),
            ]
        )
    else:
        lines.extend(
            [
                f"Target access mode: {access.get('ACCESS_MODE', 'network_only')}.",
                f"Reason: {access.get('ACCESS_REASON', 'no direct execution context discovered')}.",
                "If no authenticated remote execution path is available, generate validation-only checks or scripts that clearly skip with exit 20.",
            ]
        )
    return "\n".join(lines)
