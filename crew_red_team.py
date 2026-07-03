import argparse
import importlib
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import agents.intel_agents  # noqa: F401 - registers agents
from agents.registry import AgentRegistry
from agents.tool_config import configured_tool_names, load_agent_config
from crew_threat_intel import (
    RUNS_DIR,
    build_run_artifacts,
    extract_json_object,
    next_artifact_run_id,
    previous_output_context,
    run_agent_task,
    run_nmap_stage,
    run_vulnerability_stage,
    salvage_generated_script_objects,
    summarize_services,
    truncate_context,
)
from tasks.registry import TaskRegistry
from tasks.red_team_tasks import (
    create_red_team_exploit_planning_task,
    create_red_team_recon_tool_generation_task,
    create_red_team_reporting_task,
    create_red_team_tool_generation_task,
)


def _red_team_config() -> dict[str, Any]:
    return dict(load_agent_config().get("red_team", {}))


def _red_team_artifact_config() -> dict[str, str]:
    artifacts = _red_team_config().get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("Missing red_team.artifacts config.")
    return {str(key): str(value) for key, value in artifacts.items()}


def _red_team_artifact_path(key: str) -> Path:
    artifacts = _red_team_artifact_config()
    if key not in artifacts:
        raise ValueError(f"Missing red_team.artifacts.{key} config.")
    return Path(artifacts[key])


def _red_team_artifact_name(key: str) -> str:
    artifacts = _red_team_artifact_config()
    if key not in artifacts:
        raise ValueError(f"Missing red_team.artifacts.{key} config.")
    return Path(artifacts[key]).name


def _red_team_pipeline_agents() -> list[str]:
    agents = _red_team_config().get("pipeline_agents")
    if not isinstance(agents, list) or not agents:
        raise ValueError("Missing red_team.pipeline_agents config.")
    return [str(agent) for agent in agents]


def _red_team_generated_tool_active_args() -> list[str]:
    generated_tools = _red_team_config().get("generated_tools", {})
    if not isinstance(generated_tools, dict):
        return []
    active_args = generated_tools.get("active_args", [])
    if not isinstance(active_args, list):
        return []
    return [str(arg) for arg in active_args]


def _red_team_previous_context_files() -> tuple[str, ...]:
    return (
        "red_team_plan.md",
        "red_team_report.md",
        "red_team_used.json",
        f"{_red_team_artifact_name('tools_subdir')}/manifest.json",
    )


def _red_team_specialist_config() -> dict[str, dict[str, str]]:
    specialists = _red_team_config().get("specialists")
    if not isinstance(specialists, dict) or not specialists:
        raise ValueError("Missing red_team.specialists config.")
    normalized: dict[str, dict[str, str]] = {}
    for domain, spec in specialists.items():
        if not isinstance(spec, dict) or not spec.get("agent") or not spec.get("planning_task"):
            raise ValueError(f"Invalid red_team.specialists.{domain} config.")
        normalized[str(domain)] = {
            "agent": str(spec["agent"]),
            "planning_task": str(spec["planning_task"]),
            "agent_module": str(spec.get("agent_module", "")),
            "task_module": str(spec.get("task_module", "")),
        }
    return normalized


def _load_red_team_specialist_modules() -> None:
    agent_modules = _red_team_config().get("agent_modules", {})
    if isinstance(agent_modules, dict):
        for module_name in agent_modules.values():
            if module_name:
                importlib.import_module(str(module_name))
    for spec in _red_team_specialist_config().values():
        for module_key in ("agent_module", "task_module"):
            module_name = spec.get(module_key)
            if module_name:
                importlib.import_module(module_name)


_load_red_team_specialist_modules()
RED_TEAM_SPECIALISTS = {domain: spec["agent"] for domain, spec in _red_team_specialist_config().items()}


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o750)


def _normalize_generated_script_body(body: str) -> str:
    body = str(body or "").strip()
    first_line = body.splitlines()[0] if body.splitlines() else body
    if "\\n" in body and ("\n" not in body or "\\n" in first_line):
        body = body.replace("\\r\\n", "\n").replace("\\n", "\n")
    body = body.replace("\\$", "$").replace("\\\"", "\"")
    return body.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the authorized lab red-team validation pipeline.")
    parser.add_argument("target", help="Authorized lab target.")
    parser.add_argument("--domain", choices=sorted(RED_TEAM_SPECIALISTS), help="Run only one specialist domain.")
    parser.add_argument("--ports", default="1-10000", help="Nmap port expression.")
    parser.add_argument("--timeout", type=int, default=180, help="Nmap timeout in seconds.")
    parser.add_argument("--reuse-scan", default="", help="Optional existing Nmap JSON file.")
    parser.add_argument("--use-agents", action="store_true", help="Deprecated; red-team planning now uses agents.")
    parser.add_argument("--no-nmap-agent", action="store_true", help="Deprecated compatibility flag.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated validation scripts. Default only generates the scripts.",
    )
    parser.add_argument("--execution-timeout", type=int, default=180, help="Timeout per generated script.")
    return parser.parse_args()


def write_llm_red_team_tools(
    artifact_run_id: int,
    target: str,
    manifest: dict[str, Any],
    tool_subdir: str | None = None,
    current_tools_dir: Path | None = None,
) -> dict[str, Any]:
    tool_subdir = tool_subdir or _red_team_artifact_name("tools_subdir")
    tools_dir = (RUNS_DIR / f"run_{artifact_run_id:04d}" / tool_subdir).resolve()
    current_tools_dir = (current_tools_dir or _red_team_artifact_path("current_tools_dir")).resolve()
    if tools_dir.exists():
        shutil.rmtree(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)

    if current_tools_dir.exists():
        shutil.rmtree(current_tools_dir)
    current_tools_dir.mkdir(parents=True, exist_ok=True)

    manifest = dict(manifest)
    manifest.setdefault("agent", "red_team_tool_generation_agent")
    manifest.setdefault("target", target)
    manifest.setdefault("mode", "llm_generated_each_run")
    manifest.setdefault("safety", "Scripts default to dry-run and require --execute for active validation.")

    written_scripts = []
    for index, script in enumerate(manifest.get("scripts", []), start=1):
        filename = str(script.get("filename") or f"{index:02d}_{script.get('name', 'red_team_tool')}.sh")
        filename = Path(filename).name
        body = _normalize_generated_script_body(str(script.get("body") or ""))
        if not body:
            continue
        script_path = tools_dir / filename
        current_script_path = current_tools_dir / filename
        _write_executable(script_path, body + "\n")
        shutil.copy2(script_path, current_script_path)
        written_scripts.append(
            {
                **{key: value for key, value in script.items() if key != "body"},
                "filename": filename,
                "path": str(script_path),
                "current_path": str(current_script_path),
                "agent": script.get("agent", manifest.get("agent", "red_team_tool_generation_agent")),
                "domain": script.get("domain", "coordinator"),
            }
        )
    manifest["scripts"] = written_scripts

    manifest_path = tools_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path = current_tools_dir / "manifest.json"
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "tools_dir": tools_dir,
        "manifest_path": manifest_path,
        "current_tools_dir": current_tools_dir,
        "current_manifest_path": current_manifest_path,
        "scripts_dir": tools_dir,
        "current_scripts_dir": current_tools_dir,
        "manifest": manifest,
    }


def run_red_team_tool_generation_stage(
    artifact_run_id: int,
    target: str,
    scan_context: str,
    plan_context: str,
) -> dict[str, Any]:
    tool_agent = AgentRegistry.get_agent("red_team_tool_generation_agent")
    retry_plan_context = truncate_context(plan_context, 6000)
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    for attempt in range(2):
        tool_task = create_red_team_tool_generation_task(
            tool_agent,
            target,
            truncate_context(scan_context, 4500),
            retry_plan_context,
        )
        raw_manifest = run_agent_task("red_team_tool_generation_agent", tool_task)
        try:
            manifest = extract_json_object(raw_manifest)
        except Exception:
            repaired_manifest = raw_manifest.replace("\\$", "$")
            try:
                manifest = extract_json_object(repaired_manifest)
            except Exception:
                manifest = {
                    "agent": "red_team_tool_generation_agent",
                    "mode": "llm_generated_each_run",
                    "safety": "Tool generation output could not be parsed as JSON.",
                    "scripts": salvage_generated_script_objects(repaired_manifest),
                    "raw_output": raw_manifest,
                }
        if manifest.get("scripts"):
            break
        retry_plan_context = (
            "Previous tool manifest was invalid, empty, or had no scripts. "
            "Return only complete valid minified JSON. Do not escape dollar signs. "
            "Generate scripts for the distinct validation candidates.\n\n"
            f"Original plan:\n{truncate_context(plan_context, 3500)}\n\n"
            f"Previous output excerpt:\n{truncate_context(raw_manifest, 1200)}"
        )
    return write_llm_red_team_tools(artifact_run_id, target, manifest)


def _safe_recon_args(args: Any) -> list[str]:
    recon_config = _red_team_config().get("recon")
    if not isinstance(recon_config, dict):
        raise ValueError("Missing red_team.recon config.")
    blocked = {str(item) for item in recon_config.get("blocked_args", [])}
    blocked_shell_tokens = [str(item) for item in recon_config.get("blocked_shell_tokens", [])]
    required_service_detection_args = [str(item) for item in recon_config.get("required_service_detection_args", [])]
    max_args = int(recon_config.get("max_args") or 12)
    safe_args: list[str] = []
    skip_next = False
    for raw_arg in args if isinstance(args, list) else []:
        if skip_next:
            skip_next = False
            continue
        arg = str(raw_arg).strip()
        if not arg or any(token in arg for token in blocked_shell_tokens):
            continue
        if arg in blocked:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in blocked):
            continue
        if arg.startswith("-o") or arg.startswith("-iL"):
            skip_next = True
            continue
        safe_args.append(arg)
    if required_service_detection_args and not any(required in safe_args for required in required_service_detection_args):
        expected = ", ".join(required_service_detection_args)
        raise ValueError(f"Recon agent command manifest must include one configured service-detection arg: {expected}.")
    return safe_args[:max_args]


def _nmap_xml_to_scan(xml_path: Path, target: str, ports: str, manifest: dict[str, Any]) -> dict[str, Any]:
    root = ET.parse(xml_path).getroot()
    hosts: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        host_id = address_node.attrib.get("addr", target) if address_node is not None else target
        status_node = host_node.find("status")
        host_status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"
        host_entry = {"host": host_id, "status": host_status, "ports": []}
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.attrib.get("state", "") if state_node is not None else ""
            service = service_node.attrib if service_node is not None else {}
            host_entry["ports"].append(
                {
                    "port": int(port_node.attrib.get("portid", "0") or 0),
                    "protocol": port_node.attrib.get("protocol", "tcp"),
                    "state": state,
                    "service": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extra_info": service.get("extrainfo", ""),
                }
            )
        hosts.append(host_entry)
    return {
        "scanner": "red_team_recon_agent_dynamic_command",
        "target": target,
        "ports": ports,
        "command_manifest": manifest,
        "hosts": hosts,
    }


def run_dynamic_red_team_recon_stage(
    artifact_run_id: int,
    target: str,
    ports: str,
    timeout: int,
) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    local_context = previous_output_context(
        ("nmap_scan.json", "red_team_used.json", "red_team_recon/manifest.json"),
        max_runs=2,
        chars_per_file=650,
    )
    recon_agent = AgentRegistry.get_agent("red_team_recon_agent")
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    retry_context = truncate_context(local_context, 1600)
    for attempt in range(2):
        recon_task = create_red_team_recon_tool_generation_task(
            recon_agent,
            target,
            ports,
            timeout,
            retry_context,
        )
        raw_manifest = run_agent_task("red_team_recon_agent", recon_task)
        try:
            manifest = extract_json_object(raw_manifest)
        except Exception:
            manifest = {
                "agent": "red_team_recon_agent",
                "mode": "llm_generated_each_run",
                "safety": "Recon command output could not be parsed as JSON.",
                "raw_output": raw_manifest,
            }
        if str(manifest.get("tool", "")).lower() == "nmap":
            break
        retry_context = (
            "Previous recon command manifest was invalid, truncated, or empty. "
            "Return only a complete minified JSON object with tool=nmap and args array. No script body.\n\n"
            f"Previous output excerpt:\n{truncate_context(raw_manifest, 1200)}"
        )
    if str(manifest.get("tool", "")).lower() != "nmap":
        raise ValueError("Recon agent did not return a valid dynamic Nmap command manifest.")

    recon_subdir = _red_team_artifact_name("recon_subdir")
    current_recon_dir = _red_team_artifact_path("current_recon_dir").resolve()
    tools_dir = (RUNS_DIR / f"run_{artifact_run_id:04d}" / recon_subdir).resolve()
    if tools_dir.exists():
        shutil.rmtree(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    if current_recon_dir.exists():
        shutil.rmtree(current_recon_dir)
    current_recon_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "agent": "red_team_recon_agent",
        "mode": "llm_generated_each_run",
        "safety": "Authorized bounded recon only.",
        "tool": "nmap",
        "target": target,
        "ports": ports,
        "args": _safe_recon_args(manifest.get("args", [])),
        "timeout_seconds": int(manifest.get("timeout_seconds") or timeout),
        "raw_agent_output": raw_manifest,
    }
    manifest_path = tools_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path = current_recon_dir / "manifest.json"
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    execution_dir = tools_dir / "execution"
    execution_dir.mkdir(parents=True, exist_ok=True)
    xml_path = execution_dir / "recon_nmap.xml"
    gnmap_path = execution_dir / "recon_nmap.gnmap"
    scan_path = execution_dir / "recon_scan.json"
    stdout_path = execution_dir / "dynamic_recon.stdout.txt"
    stderr_path = execution_dir / "dynamic_recon.stderr.txt"
    command = [
        "nmap",
        *manifest["args"],
        "-p",
        ports,
        "-oX",
        str(xml_path),
        "-oG",
        str(gnmap_path),
        target,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
        status = "ok" if returncode == 0 else "failed"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        returncode = 124
        status = "timeout"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    if status != "ok" or not xml_path.exists():
        raise RuntimeError(
            "Dynamic recon command failed before XML normalization. "
            f"Status: {status}. Stderr: {truncate_context(stderr, 1200) or 'empty'}"
        )

    scan = _nmap_xml_to_scan(xml_path, target, ports, manifest)
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    execution = {
        "mode": "execute",
        "tools_dir": str(tools_dir),
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "command": command,
        "results": [
            {
                "script": "dynamic_recon_command",
                "domain": "recon",
                "agent": "red_team_recon_agent",
                "status": status,
                "returncode": returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "dependencies": ["nmap"],
            }
        ],
    }
    results_path = execution_dir / "execution_results.json"
    execution["results_path"] = str(results_path)
    results_path.write_text(json.dumps(execution, indent=2), encoding="utf-8")
    recon_artifacts = {
        "tools_dir": tools_dir,
        "manifest_path": manifest_path,
        "current_tools_dir": current_recon_dir,
        "current_manifest_path": current_manifest_path,
        "scripts_dir": tools_dir,
        "current_scripts_dir": current_recon_dir,
        "manifest": manifest,
    }
    nmap_output = stdout.strip() or json.dumps(scan, indent=2)
    return scan, nmap_output, recon_artifacts, execution


def execute_red_team_tools(
    tool_artifacts: dict[str, Any],
    timeout: int = 180,
    active_args: list[str] | None = None,
) -> dict[str, Any]:
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
        script_args = script.get("active_args", active_args or [])
        if not isinstance(script_args, list):
            script_args = []
        command = [str(path), str(execution_dir), *[str(arg) for arg in script_args]]
        stdout_path = execution_dir / f"{path.stem}.stdout.txt"
        stderr_path = execution_dir / f"{path.stem}.stderr.txt"
        try:
            completed = subprocess.run(
                command,
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
                "command": command,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "dependencies": script.get("dependencies", []),
            }
        )

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def _read_short_file(path_value: Any, limit: int = 900) -> str:
    path = Path(str(path_value or ""))
    if not path.exists():
        return ""
    return truncate_context(path.read_text(encoding="utf-8", errors="replace").strip(), limit)


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
            "script_results": [],
        }

    script_results = []
    confirmed_findings = extract_confirmed_exploits(execution)
    active_validation = False
    dry_run_outputs = 0
    for item in execution.get("results", []):
        stdout = _read_short_file(item.get("stdout_path"))
        stderr = _read_short_file(item.get("stderr_path"), 500)
        command = [str(part) for part in item.get("command", [])]
        if "--execute" in command:
            active_validation = True
        if "[DRY-RUN]" in stdout:
            dry_run_outputs += 1
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
    lines.extend(["", "### Script Observations", ""])
    for item in summary.get("script_results", []):
        lines.append(f"- `{item.get('script')}`: `{item.get('status')}` rc={item.get('returncode')}")
        observation = str(item.get("observation") or "No output captured.")
        for line in observation.splitlines()[:8]:
            lines.append(f"  {line}")
        if item.get("stderr"):
            lines.append("  stderr:")
            for line in str(item["stderr"]).splitlines()[:4]:
                lines.append(f"  {line}")
    if not summary.get("script_results"):
        lines.append("- No script output available.")
    if summary.get("confirmed_findings"):
        lines.extend(["", "### Confirmed Findings", ""])
        for finding in summary["confirmed_findings"]:
            lines.append(f"- {finding}")
    return "\n".join(lines).rstrip() + "\n"


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


def run_red_team_specialist_pipeline(
    domain: str,
    target: str,
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
        scan, nmap_output = run_nmap_stage(target, ports, timeout, reuse_scan)
        nmap_source = f"reused scan: {reuse_scan}"
        recon_artifacts = None
        recon_execution = None
    else:
        scan, nmap_output, recon_artifacts, recon_execution = run_dynamic_red_team_recon_stage(
            artifact_run_id,
            target,
            ports,
            timeout,
        )
        nmap_source = "red_team_recon_agent_dynamic_command"

    vulnerability_scan, vulnerability_context = run_vulnerability_stage(scan)
    scan_context = json.dumps(scan, indent=2)
    local_context = previous_output_context(_red_team_previous_context_files(), max_runs=2, chars_per_file=650)

    specialist_spec = _red_team_specialist_config()[domain]
    agent_name = specialist_spec["agent"]
    agent = AgentRegistry.get_agent(agent_name)
    task = TaskRegistry.get_task(
        specialist_spec["planning_task"],
        agent=agent,
        target=target,
        scan_context=truncate_context(scan_context, 2200),
        vulnerability_context=(
            truncate_context(vulnerability_context, 1800)
            + "\n\nLocal context:\n"
            + truncate_context(local_context, 1400)
        ),
    )
    agent_output = run_agent_task(agent_name, task)

    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        truncate_context(scan_context, 2200),
        f"Specialist domain: {domain}\n\n{agent_output}",
    )
    execution = (
        execute_red_team_tools(tool_artifacts, execution_timeout, _red_team_generated_tool_active_args())
        if execute
        else None
    )
    working_exploits = extract_confirmed_exploits(execution)
    human_summary = build_human_execution_summary(execution)
    human_result_text = render_human_execution_summary(human_summary)
    summary_lines = [
        "# Executive Summary",
        "",
        f"Target: `{target}`",
        f"Specialist: `{domain}`",
        f"Enumeration source: `{nmap_source}`",
        "",
        "## Specialist Plan",
        "",
        agent_output,
        "",
        "## Validation Scripts",
        "",
    ]
    if tool_artifacts["manifest"].get("scripts"):
        for script in tool_artifacts["manifest"]["scripts"]:
            summary_lines.append(f"- `{script['filename']}`: {script.get('purpose', 'LLM-generated validation script')}")
    else:
        summary_lines.append("- No scripts were generated.")
    summary_lines.extend(["", "## Execution", ""])
    summary_lines.append(human_result_text)
    summary_lines.extend(["", "## Raw Execution JSON", ""])
    summary_lines.append(json.dumps(execution or {"status": "not_executed"}, indent=2))
    summary = "\n".join(summary_lines).rstrip() + "\n"

    run_dir = Path(tool_artifacts["tools_dir"])
    result_path = run_dir / "result.json"
    summary_path = run_dir / "executive_summary.md"
    human_result_path = run_dir / "human_result.md"
    scan_path = run_dir / "nmap_scan.json"
    nmap_output_path = run_dir / "nmap_output.txt"
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    nmap_output_path.write_text(nmap_output, encoding="utf-8")
    summary_path.write_text(summary, encoding="utf-8")
    human_result_path.write_text(human_result_text, encoding="utf-8")

    result = {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "domain": domain,
        "agent": agent_name,
        "target": target,
        "nmap_source": nmap_source,
        "candidate_count": None,
        "candidates": [],
        "execute": execute,
        "execution": execution,
        "execution_status": red_team_execution_status(execution),
        "human_summary": human_summary,
        "working_exploits": working_exploits,
        "executive_summary": summary,
        "agent_output": agent_output,
        "generated_scripts": tool_artifacts["manifest"],
        "artifacts": {
            "run_dir": str(run_dir),
            "result": str(result_path),
            "executive_summary": str(summary_path),
            "human_result": str(human_result_path),
            "tool_manifest": str(tool_artifacts["manifest_path"]),
            "nmap_scan": str(scan_path),
            "nmap_output": str(nmap_output_path),
        },
    }
    if recon_artifacts:
        result["artifacts"]["red_team_recon_manifest"] = str(recon_artifacts["manifest_path"])
    if recon_execution:
        result["artifacts"]["red_team_recon_execution_results"] = recon_execution["results_path"]
    if execution:
        result["artifacts"]["execution_results"] = execution["results_path"]
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def run_red_team_pipeline(
    target: str,
    ports: str = "1-10000",
    timeout: int = 180,
    reuse_scan: str = "",
    use_agents: bool = False,
    execute: bool = False,
    execution_timeout: int = 180,
) -> dict[str, Any]:
    artifact_run_id = next_artifact_run_id()
    if reuse_scan:
        scan, nmap_output = run_nmap_stage(target, ports, timeout, reuse_scan)
        nmap_source = f"reused scan: {reuse_scan}"
        recon_artifacts = None
        recon_execution = None
    else:
        scan, nmap_output, recon_artifacts, recon_execution = run_dynamic_red_team_recon_stage(
            artifact_run_id,
            target,
            ports,
            timeout,
        )
        nmap_source = "red_team_recon_agent_dynamic_command"
    vulnerability_scan, vulnerability_output = run_vulnerability_stage(scan)

    service_summary = summarize_services(scan)
    scan_context = json.dumps(scan, indent=2)
    local_context = previous_output_context(_red_team_previous_context_files(), max_runs=2, chars_per_file=650)

    agents_used = _red_team_pipeline_agents()
    tools_used = sorted(
        {tool for agent_name in agents_used for tool in configured_tool_names(agent_name)}
        | {"llm_generated_red_team_tools"}
    )

    planner = AgentRegistry.get_agent("red_team_exploit_planner_agent")
    planning_task = create_red_team_exploit_planning_task(
        planner,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(vulnerability_output, 2000),
        truncate_context(local_context, 1800),
    )
    plan_text = run_agent_task("red_team_exploit_planner_agent", planning_task)

    tool_artifacts = run_red_team_tool_generation_stage(
        artifact_run_id,
        target,
        truncate_context(scan_context, 2200),
        truncate_context(plan_text, 3500),
    )
    execution = (
        execute_red_team_tools(tool_artifacts, execution_timeout, _red_team_generated_tool_active_args())
        if execute
        else None
    )
    human_summary = build_human_execution_summary(execution)
    human_result_text = render_human_execution_summary(human_summary)
    execution_context = human_result_text
    reporter = AgentRegistry.get_agent("red_team_reporting_agent")
    report_task = create_red_team_reporting_task(
        reporter,
        target,
        truncate_context(scan_context, 1800),
        truncate_context(plan_text, 2500),
        truncate_context(execution_context, 1200),
    )
    report = run_agent_task("red_team_reporting_agent", report_task)

    run_dir = RUNS_DIR / f"run_{artifact_run_id:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)
    plan_path = run_dir / "red_team_plan.md"
    plan_path.write_text(plan_text.rstrip() + "\n", encoding="utf-8")
    report_path = run_dir / "red_team_report.md"
    report_path.write_text(report, encoding="utf-8")
    human_result_path = run_dir / "human_result.md"
    human_result_path.write_text(human_result_text, encoding="utf-8")
    used_path = run_dir / "red_team_used.json"
    used = {
        "agents": agents_used,
        "tools": tools_used,
        "scripts": tool_artifacts["manifest"]["scripts"],
        "nmap_source": nmap_source,
        "artifacts": {
            "run_dir": str(run_dir),
            "red_team_plan": str(plan_path),
            "red_team_report": str(report_path),
            "human_result": str(human_result_path),
            "red_team_tools_manifest": str(tool_artifacts["manifest_path"]),
            "current_red_team_tools": str(tool_artifacts["current_tools_dir"]),
        },
    }
    if recon_artifacts:
        used["artifacts"]["red_team_recon_manifest"] = str(recon_artifacts["manifest_path"])
        used["artifacts"]["current_red_team_recon"] = str(recon_artifacts["current_tools_dir"])
    if recon_execution:
        used["artifacts"]["red_team_recon_execution_results"] = recon_execution["results_path"]
    if execution:
        used["artifacts"]["execution_results"] = execution["results_path"]
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
        plan_text,
        "Red-team remediation is intentionally not generated by this pipeline.",
        report,
        nmap_output,
        tool_artifacts,
        execution,
    )

    return {
        "status": "complete",
        "artifact_run_id": artifact_run_id,
        "target": target,
        "ports": ports,
        "nmap_source": nmap_source,
        "candidate_count": None,
        "execute": execute,
        "agents_used": agents_used,
        "tools_used": tools_used,
        "artifacts": used["artifacts"],
        "recon_execution": recon_execution,
        "execution": execution,
        "execution_status": red_team_execution_status(execution),
        "human_summary": human_summary,
        "plan": plan_text,
        "generated_scripts": tool_artifacts["manifest"],
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
