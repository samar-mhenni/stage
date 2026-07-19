import json
import os
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener
from pathlib import Path

from agents.execution import run_agent_task
from agents.registry import AgentRegistry
from crews.red_team.config import red_team_artifact_name, red_team_artifact_path, red_team_config
from crews.red_team.fingerprints import detect_web_app_fingerprints, format_web_fingerprint_summary
from crews.threat_intel.pipeline import (
    RUNS_DIR,
    extract_json_object,
    truncate_context,
)
from tasks.red_team import create_red_team_recon_tool_generation_task


def _safe_recon_args(args: Any) -> list[str]:
    recon_config = red_team_config().get("recon")
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
            service = service_node.attrib if service_node is not None else {}
            host_entry["ports"].append(
                {
                    "port": int(port_node.attrib.get("portid", "0") or 0),
                    "protocol": port_node.attrib.get("protocol", "tcp"),
                    "state": state_node.attrib.get("state", "") if state_node is not None else "",
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


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body.rstrip() + "\n", encoding="utf-8")
    path.chmod(0o750)


def _normalize_enum_script_body(body: str) -> str:
    body = str(body or "").strip()
    first_line = body.splitlines()[0] if body.splitlines() else body
    if "\\n" in body and ("\n" not in body or "\\n" in first_line):
        body = body.replace("\\r\\n", "\n").replace("\\n", "\n")
    if body and not body.startswith("#!"):
        body = "#!/usr/bin/env bash\n" + body
    return body


def _safe_enumeration_tools(value: Any, limit: int = 4) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return tools
    for item in value:
        if not isinstance(item, dict):
            continue
        body = _normalize_enum_script_body(str(item.get("body") or ""))
        if not body:
            continue
        filename = Path(str(item.get("filename") or "")).name
        if not filename.endswith(".sh"):
            filename = f"{len(tools) + 2:02d}_{str(item.get('name') or 'enum_helper')}.sh"
        tools.append(
            {
                "name": str(item.get("name") or Path(filename).stem),
                "filename": filename,
                "purpose": str(item.get("purpose") or "Safe bounded enumeration helper."),
                "interpreter": str(item.get("interpreter") or "bash"),
                "body": body,
            }
        )
        if len(tools) >= limit:
            break
    return tools


def _write_recon_tool_scripts(
    tools_dir: Path,
    current_recon_dir: Path,
    manifest: dict[str, Any],
    command: list[str],
) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    nmap_script = tools_dir / "01_nmap_recon.sh"
    nmap_body = "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            " ".join(shlex.quote(part) for part in command),
        ]
    )
    _write_executable(nmap_script, nmap_body)
    shutil.copy2(nmap_script, current_recon_dir / nmap_script.name)
    scripts.append(
        {
            "name": "nmap_recon",
            "filename": nmap_script.name,
            "purpose": "Fresh bounded Nmap service/version enumeration generated for this run.",
            "interpreter": "bash",
            "path": str(nmap_script),
            "current_path": str(current_recon_dir / nmap_script.name),
            "executed": True,
        }
    )

    for index, tool in enumerate(manifest.get("enumeration_tools", []), start=2):
        if not isinstance(tool, dict):
            continue
        body = _normalize_enum_script_body(str(tool.get("body") or ""))
        if not body:
            continue
        filename = Path(str(tool.get("filename") or f"{index:02d}_{tool.get('name', 'enum_helper')}.sh")).name
        script_path = tools_dir / filename
        _write_executable(script_path, body)
        shutil.copy2(script_path, current_recon_dir / filename)
        scripts.append(
            {
                **{key: value for key, value in tool.items() if key != "body"},
                "filename": filename,
                "path": str(script_path),
                "current_path": str(current_recon_dir / filename),
                "executed": False,
            }
        )
    return scripts


def _safe_post_recon_enum_scripts(scan: dict[str, Any]) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    for host in scan.get("hosts", []):
        host_id = str(host.get("host") or scan.get("target") or "")
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = str(port.get("service") or "").lower()
            port_number = int(port.get("port") or 0)
            if service not in {"http", "https", "http-proxy"} and port_number not in {80, 443, 8080, 8081, 8443, 9090, 9091}:
                continue
            scheme = "https" if service == "https" or port_number in {443, 8443} else "http"
            name = f"http_enum_{port_number}"
            url = f"{scheme}://{host_id}:{port_number}/"
            body = f"""#!/usr/bin/env bash
set -uo pipefail
OUT_DIR="${{OUT_DIR:-.}}"
mkdir -p "$OUT_DIR"
OBS="$OUT_DIR/observations.txt"
BASE={shlex.quote(url)}
echo "[enum] HTTP snapshot for $BASE" >> "$OBS"
if ! command -v curl >/dev/null 2>&1; then
  echo "[skip] curl is unavailable" >> "$OBS"
  exit 20
fi
curl -ksSI --max-time 8 "$BASE" > "$OUT_DIR/{name}_headers.txt" 2>>"$OBS" || true
curl -ksSL --max-time 12 "$BASE" > "$OUT_DIR/{name}_body.html" 2>>"$OBS" || true
curl -ksSI -X OPTIONS --max-time 8 "$BASE" > "$OUT_DIR/{name}_options.txt" 2>>"$OBS" || true
python3 - "$OUT_DIR/{name}_headers.txt" "$OUT_DIR/{name}_body.html" "$OBS" <<'PY'
import re, sys
headers_path, body_path, obs_path = sys.argv[1:]
headers = open(headers_path, encoding="utf-8", errors="replace").read()
text = open(body_path, encoding="utf-8", errors="replace").read()[:12000]
title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
summary = re.sub(r"\\s+", " ", title.group(1)).strip() if title else "no title"
with open(obs_path, "a", encoding="utf-8") as handle:
    handle.write(f"[enum] title: {{summary}}\\n")
PY
"""
            scripts.append(
                {
                    "name": name,
                    "filename": f"{len(scripts) + 2:02d}_{name}.sh",
                    "purpose": f"Collect safe HTTP headers, body title, and method snapshot for observed port {port_number}.",
                    "interpreter": "bash",
                    "body": body,
                }
            )
    return scripts[:4]


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _fetch_http_snapshot(url: str, timeout: int = 5, follow_redirects: bool = False) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "stage-red-team/1.0"})
    opener = build_opener() if follow_redirects else build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(12000).decode("utf-8", errors="replace")
            return {
                "url": response.geturl(),
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body": body,
                "error": "",
            }
    except HTTPError as exc:
        body = exc.read(12000).decode("utf-8", errors="replace")
        return {
            "url": url,
            "status": exc.code,
            "headers": dict(exc.headers.items()),
            "body": body,
            "error": "",
        }
    except (OSError, URLError, TimeoutError) as exc:
        return {"url": url, "status": 0, "headers": {}, "body": "", "error": str(exc)}


def _html_summary(body: str) -> tuple[str, str]:
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\s+", " ", text).strip()[:900]
    return title or "unknown", text


def _write_and_run_post_recon_enum(
    scan: dict[str, Any],
    tools_dir: Path,
    current_recon_dir: Path,
    execution_dir: Path,
    timeout: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    scripts = []
    results = []
    for script in _safe_post_recon_enum_scripts(scan):
        script_path = tools_dir / script["filename"]
        current_path = current_recon_dir / script["filename"]
        _write_executable(script_path, _normalize_enum_script_body(script["body"]))
        shutil.copy2(script_path, current_path)
        scripts.append(
            {
                **{key: value for key, value in script.items() if key != "body"},
                "path": str(script_path),
                "current_path": str(current_path),
                "executed": True,
            }
        )
        env = {**os.environ, "OUT_DIR": str(execution_dir)}
        try:
            completed = subprocess.run(
                [str(script_path)],
                capture_output=True,
                text=True,
                timeout=min(timeout, 30),
                check=False,
                env=env,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            returncode = completed.returncode
            status = "ok" if returncode == 0 else "skipped" if returncode == 20 else "failed"
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            returncode = 124
            status = "timeout"
        stdout_path = execution_dir / f"{script_path.stem}.stdout.txt"
        stderr_path = execution_dir / f"{script_path.stem}.stderr.txt"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        results.append(
            {
                "script": script["filename"],
                "domain": "recon",
                "agent": "red_team_recon_agent",
                "status": status,
                "returncode": returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "dependencies": ["curl"],
            }
        )
    return scripts, results


def _http_fingerprint(host: str, port: int, scheme: str = "http", timeout: int = 5) -> str:
    url = f"{scheme}://{host}:{port}/"
    initial = _fetch_http_snapshot(url, timeout=timeout, follow_redirects=False)
    if initial.get("error"):
        return ""

    snapshots = [initial]
    location = initial.get("headers", {}).get("Location") or initial.get("headers", {}).get("location")
    if location:
        snapshots.append(_fetch_http_snapshot(urljoin(url, str(location)), timeout=timeout, follow_redirects=True))
    elif not initial.get("body"):
        snapshots.append(_fetch_http_snapshot(url, timeout=timeout, follow_redirects=True))

    combined_text = "\n".join(
        "\n".join(f"{key}: {value}" for key, value in snapshot.get("headers", {}).items())
        + "\n"
        + str(snapshot.get("body") or "")
        for snapshot in snapshots
    )
    fingerprints = detect_web_app_fingerprints(combined_text)
    lines = [f"[{url}]"]
    for index, snapshot in enumerate(snapshots, start=1):
        title, text = _html_summary(str(snapshot.get("body") or ""))
        headers = "\n".join(f"{key}: {value}" for key, value in snapshot.get("headers", {}).items())
        label = "Initial" if index == 1 else "Followed"
        lines.extend(
            [
                f"{label} URL: {snapshot.get('url')}",
                f"{label} status: {snapshot.get('status')}",
                f"{label} title: {title}",
                f"{label} headers:\n{headers[:900]}",
                f"{label} body excerpt: {text}",
            ]
        )
    lines.append(format_web_fingerprint_summary(fingerprints))
    return "\n".join(lines)


def _scan_web_fingerprints_from_execution(scan: dict[str, Any], execution_dir: Path) -> list[dict[str, Any]]:
    combined_parts = []
    for path in sorted(execution_dir.glob("http_enum_*_*.txt")) + sorted(execution_dir.glob("http_enum_*_body.html")):
        try:
            combined_parts.append(path.read_text(encoding="utf-8", errors="replace")[:20000])
        except OSError:
            continue
    fingerprints = detect_web_app_fingerprints("\n".join(combined_parts))
    for fingerprint in fingerprints:
        fingerprint["source"] = "safe_post_recon_http_enum"
    return fingerprints


def local_http_context(scan: dict[str, Any]) -> str:
    http_chunks = []
    for host in scan.get("hosts", []):
        host_id = str(host.get("host") or "")
        for port in host.get("ports", []):
            service = str(port.get("service") or "").lower()
            port_number = int(port.get("port") or 0)
            if service in {"http", "http-proxy"} or port_number in {80, 443, 8080, 8081, 8443, 9090, 9091}:
                scheme = "https" if service == "https" or port_number in {443, 8443} else "http"
                chunk = _http_fingerprint(host_id, port_number, scheme=scheme)
                if chunk:
                    http_chunks.append(chunk)
    http_context = "\n\n".join(http_chunks)
    return "[HTTP fingerprint]\n" + truncate_context(http_context, 1800) if http_context else ""


def run_dynamic_red_team_recon_stage(
    artifact_run_id: int,
    target: str,
    ports: str,
    timeout: int,
) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, Any]]:
    recon_agent = AgentRegistry.get_agent("red_team_recon_agent")
    manifest: dict[str, Any] = {}
    raw_manifest = ""
    retry_context = ""
    for _ in range(2):
        recon_task = create_red_team_recon_tool_generation_task(recon_agent, target, ports, timeout, retry_context)
        try:
            raw_manifest = run_agent_task("red_team_recon_agent", recon_task)
        except Exception as exc:
            raw_manifest = f"Recon LLM unavailable: {exc.__class__.__name__}: {exc}"
            manifest = {
                "agent": "red_team_recon_agent",
                "mode": "local_fallback_no_llm_output",
                "safety": "LLM recon generation failed; using safe bounded Nmap defaults.",
                "tool": "nmap",
                "target": target,
                "ports": ports,
                "args": ["-sV", "--version-light", "-Pn", "--open", "-T4"],
                "timeout_seconds": timeout,
                "enumeration_tools": [],
                "raw_output": raw_manifest,
            }
            break
        try:
            manifest = extract_json_object(raw_manifest)
        except Exception:
            if '"tool"' in raw_manifest.lower() and "nmap" in raw_manifest.lower():
                manifest = {
                    "agent": "red_team_recon_agent",
                    "mode": "llm_generated_each_run",
                    "safety": "Recon command JSON was malformed; using safe Nmap defaults from visible agent intent.",
                    "tool": "nmap",
                    "target": target,
                    "ports": ports,
                    "args": ["-sV", "--version-light", "-Pn", "--open", "-T4"],
                    "timeout_seconds": timeout,
                    "enumeration_tools": [],
                    "raw_output": raw_manifest,
                }
            else:
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

    tools_dir = (RUNS_DIR / f"run_{artifact_run_id:04d}" / red_team_artifact_name("recon_subdir")).resolve()
    current_recon_dir = red_team_artifact_path("current_recon_dir").resolve()
    if tools_dir.exists():
        shutil.rmtree(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    if current_recon_dir.exists():
        shutil.rmtree(current_recon_dir)
    current_recon_dir.mkdir(parents=True, exist_ok=True)

    enumeration_tools = _safe_enumeration_tools(manifest.get("enumeration_tools"))
    manifest = {
        "agent": "red_team_recon_agent",
        "mode": "llm_generated_each_run",
        "safety": "Authorized bounded recon only.",
        "tool": "nmap",
        "target": target,
        "ports": ports,
        "args": _safe_recon_args(manifest.get("args", [])),
        "timeout_seconds": int(manifest.get("timeout_seconds") or timeout),
        "enumeration_tools": enumeration_tools,
        "raw_agent_output": raw_manifest,
    }
    manifest_path = tools_dir / "manifest.json"
    current_manifest_path = current_recon_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    execution_dir = tools_dir / "execution"
    execution_dir.mkdir(parents=True, exist_ok=True)
    xml_path = execution_dir / "recon_nmap.xml"
    gnmap_path = execution_dir / "recon_nmap.gnmap"
    scan_path = execution_dir / "recon_scan.json"
    stdout_path = execution_dir / "dynamic_recon.stdout.txt"
    stderr_path = execution_dir / "dynamic_recon.stderr.txt"
    command = ["nmap", *manifest["args"], "-p", ports, "-oX", str(xml_path), "-oG", str(gnmap_path), target]
    generated_scripts = _write_recon_tool_scripts(tools_dir, current_recon_dir, manifest, command)
    manifest["scripts"] = generated_scripts
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
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
    enum_scripts, enum_results = _write_and_run_post_recon_enum(
        scan,
        tools_dir,
        current_recon_dir,
        execution_dir,
        timeout,
    )
    if enum_scripts:
        generated_scripts.extend(enum_scripts)
        manifest["scripts"] = generated_scripts
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        scan["enumeration"] = {
            "mode": "safe_post_recon",
            "scripts": enum_scripts,
            "execution_dir": str(execution_dir),
        }
        web_fingerprints = _scan_web_fingerprints_from_execution(scan, execution_dir)
        if web_fingerprints:
            scan["web_fingerprints"] = web_fingerprints
    scan_path.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    execution = {
        "mode": "execute",
        "tools_dir": str(tools_dir),
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "command": command,
        "generated_scripts": generated_scripts,
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
        ]
        + enum_results,
    }
    results_path = execution_dir / "execution_results.json"
    execution["results_path"] = str(results_path)
    results_path.write_text(json.dumps(execution, indent=2), encoding="utf-8")
    return (
        scan,
        stdout.strip() or json.dumps(scan, indent=2),
        {
            "tools_dir": tools_dir,
            "manifest_path": manifest_path,
            "current_tools_dir": current_recon_dir,
            "current_manifest_path": current_manifest_path,
            "scripts_dir": tools_dir,
            "current_scripts_dir": current_recon_dir,
            "manifest": {**manifest, "scripts": generated_scripts},
        },
        execution,
    )
