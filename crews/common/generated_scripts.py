import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o750)


def _script_syntax_error(body: str, interpreter: str = "bash") -> str:
    interpreter_name = str(interpreter or "").lower()
    if "bash" not in interpreter_name and "sh" not in interpreter_name:
        return ""
    shell = "bash" if shutil.which("bash") else "sh"
    try:
        completed = subprocess.run(
            [shell, "-n"],
            input=body,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"syntax validation unavailable: {exc}"
    if completed.returncode == 0:
        return ""
    return (completed.stderr or completed.stdout or f"{shell} -n failed").strip()


def generated_script_quality_error(body: str, interpreter: str = "bash") -> str:
    syntax_error = _script_syntax_error(body, interpreter)
    if syntax_error:
        return f"script_syntax_error: {syntax_error}"
    interpreter_name = str(interpreter or "").lower()
    shell_scan_body = re.sub(r"'[^'\n]*'", "''", body)
    if ("bash" in interpreter_name or "sh" in interpreter_name) and re.search(r"(?<!\\)\$\{[^A-Za-z_#?!*@0-9-]", shell_scan_body):
        return "unsafe_literal_dollar_brace: literal ${...} payload is not shell-escaped and can fail at runtime"
    body_lower = body.lower()
    if "confirmed_exploits.txt" in body_lower and re.search(
        r"(confirmed_exploits\.txt[^\n]*(no marker|not found|not confirmed|failed|absent|missing|did not|does not)|"
        r"(no marker|not found|not confirmed|failed|absent|missing|did not|does not)[^\n]*confirmed_exploits\.txt)",
        body_lower,
    ):
        return "negative_confirmation_write: non-confirmation text must be written to observations.txt, not confirmed_exploits.txt"
    if ".raw" in body_lower and "$(date +%s)" in body:
        dynamic_raw_refs = [
            line
            for line in body.splitlines()
            if ".raw" in line.lower() and "$(date +%s)" in line
        ]
        has_stable_raw_var = re.search(r"(?m)^\s*(RAW|RAW_PATH|BODY|BODY_PATH)=", body) is not None
        if len(dynamic_raw_refs) > 1 and not has_stable_raw_var:
            return "unstable_response_artifact_path: assign RAW once and reuse it for curl output and marker checks"
    return ""


def _unescape_shell_dollars(body: str) -> str:
    body = re.sub(r"\\\$(?=\()", "$", body)
    body = re.sub(r"\\\$(?=[A-Za-z_][A-Za-z0-9_]*)", "$", body)
    body = re.sub(r"\\\$\{(?=[A-Za-z_][A-Za-z0-9_]*[}:])", "${", body)
    body = re.sub(r"\\\$([#?*!@0-9-])", r"$\1", body)
    return body


def normalize_red_team_script_body(body: str) -> str:
    body = str(body or "").strip()
    first_line = body.splitlines()[0] if body.splitlines() else body
    if "\\n" in body and ("\n" not in body or "\\n" in first_line):
        body = body.replace("\\r\\n", "\n").replace("\\n", "\n")
    body = _unescape_shell_dollars(body)
    body = re.sub(r"'([^'\n]*\$(?:TARGET|USER|PASS)[^'\n]*)'", r'"\1"', body)
    body = body.replace("grep -q 'User created'", "grep -Eq 'User created|Exception|NullPointerException'")
    body = body.replace('grep -q "User created"', 'grep -Eq "User created|Exception|NullPointerException"')
    if body and not body.startswith("#!"):
        body = "#!/usr/bin/env bash\n" + body
    return body.strip()


def normalize_remediation_script_body(body: str) -> str:
    body = str(body or "").strip()
    if "\\n" in body and ("\n" not in body or "\\n" in body.splitlines()[0]):
        body = body.replace("\\r\\n", "\n").replace("\\n", "\n")
    body = body.replace('[ "$1" = "--apply" ]', '[ "${1:-}" = "--apply" ]')
    body = body.replace("[ '$1' = '--apply' ]", '[ "${1:-}" = "--apply" ]')
    body = re.sub(
        r'\[\s*"\$@"\s*==\s*"--apply"\s*\]',
        'printf "%s\\n" "$@" | grep -qx -- "--apply"',
        body,
    )
    body = body.replace('grep -q "disable = no"', 'grep -Eq "disable[[:space:]]*=[[:space:]]*no"')
    body = body.replace("grep -q 'disable = no'", "grep -Eq 'disable[[:space:]]*=[[:space:]]*no'")
    body = body.replace(
        'grep -E "^disable[[:space:]]*=[[:space:]]*"',
        'grep -E "^[[:space:]]*disable[[:space:]]*=[[:space:]]*"',
    )
    body = body.replace(
        "grep -E '^disable[[:space:]]*=[[:space:]]*'",
        "grep -E '^[[:space:]]*disable[[:space:]]*=[[:space:]]*'",
    )
    body = re.sub(
        r"docker exec ([^\n;&|]+) systemctl restart ([A-Za-z0-9_.@-]+)",
        r"docker exec \1 sh -c 'if command -v systemctl >/dev/null 2>&1; then systemctl restart \2; else service \2 restart; fi'",
        body,
    )
    body = re.sub(r"docker exec [^\n;&|]+ nmap -p", "nmap -p", body)
    body = re.sub(r"(?m)^set -e\s*$", "set -uo pipefail", body)
    if body and not body.startswith("#!"):
        body = "#!/usr/bin/env bash\n" + body
    return body


def write_script_manifest(
    run_dir: Path,
    current_dir: Path,
    target: str,
    manifest: dict[str, Any],
    default_agent: str,
    default_mode: str,
    safety: str,
    normalizer,
) -> dict[str, Any]:
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    if current_dir.exists():
        shutil.rmtree(current_dir)
    current_dir.mkdir(parents=True, exist_ok=True)

    manifest = dict(manifest)
    manifest.setdefault("agent", default_agent)
    manifest.setdefault("target", target)
    manifest.setdefault("mode", default_mode)
    manifest.setdefault("safety", safety)

    written_scripts = []
    skipped_scripts = []
    for index, script in enumerate(manifest.get("scripts", []), start=1):
        filename = str(script.get("filename") or f"{index:02d}_{script.get('name', 'generated_tool')}.sh")
        filename = Path(filename).name
        body = normalizer(str(script.get("body") or ""))
        if not body:
            continue
        quality_error = generated_script_quality_error(body, script.get("interpreter", "bash"))
        if quality_error:
            skipped_scripts.append(
                {
                    "filename": filename,
                    "name": script.get("name", filename),
                    "reason": "script_quality_error",
                    "error": quality_error[:1000],
                }
            )
            continue

        script_path = run_dir / filename
        current_script_path = current_dir / filename
        write_executable(script_path, body.rstrip() + "\n")
        shutil.copy2(script_path, current_script_path)
        script_record = {
            **{key: value for key, value in script.items() if key != "body"},
            "filename": filename,
            "path": str(script_path),
            "current_path": str(current_script_path),
            "agent": script.get("agent", manifest.get("agent", default_agent)),
        }
        if default_agent == "red_team_tool_generation_agent":
            script_record.setdefault("domain", "coordinator")
        written_scripts.append(script_record)
    manifest["scripts"] = written_scripts
    if skipped_scripts:
        manifest["skipped_scripts"] = skipped_scripts

    manifest_path = run_dir / "manifest.json"
    current_manifest_path = current_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    current_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "scripts_dir": run_dir,
        "tools_dir": run_dir,
        "manifest_path": manifest_path,
        "current_scripts_dir": current_dir,
        "current_tools_dir": current_dir,
        "current_manifest_path": current_manifest_path,
        "manifest": manifest,
    }


def run_generated_script(
    script_path: Path,
    execution_dir: Path,
    mode: str,
    timeout: int,
    command: list[str],
    env: dict[str, str] | None = None,
    attempt_label: str = "",
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
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

    stem = script_path.stem + (f".{attempt_label}" if attempt_label else "")
    stdout_path = execution_dir / f"{stem}.stdout.txt"
    stderr_path = execution_dir / f"{stem}.stderr.txt"
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    return {
        "path": str(script_path),
        "mode": mode,
        "status": status,
        "returncode": returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stderr": stderr,
    }


def execute_remediation_scripts(
    script_artifacts: dict[str, Any],
    apply_changes: bool = False,
    timeout: int = 120,
) -> dict[str, Any]:
    scripts_dir = Path(script_artifacts["scripts_dir"])
    execution_dir = scripts_dir / "execution"
    if execution_dir.exists():
        shutil.rmtree(execution_dir)
    execution_dir.mkdir(parents=True, exist_ok=True)

    mode = "apply" if apply_changes else "dry_run"
    results = {
        "mode": mode,
        "scripts_dir": str(scripts_dir),
        "execution_dir": str(execution_dir),
        "timeout_seconds": timeout,
        "results": [],
    }
    extra_env = {
        "TARGET": str(script_artifacts["manifest"].get("target") or ""),
        "OUT_DIR": str(execution_dir),
    }
    access = script_artifacts["manifest"].get("target_access", {})
    if isinstance(access, dict):
        extra_env.update({str(key): str(value) for key, value in access.items() if value})
    env = {**os.environ, **extra_env}

    for script in script_artifacts["manifest"].get("scripts", []):
        script_path = Path(script["path"])
        command = [str(script_path), "--apply"] if apply_changes else [str(script_path)]
        attempt = run_generated_script(script_path, execution_dir, mode, timeout, command, env=env)
        results["results"].append(
            {
                "script": script["filename"],
                "path": str(script_path),
                "mode": mode,
                "status": attempt["status"],
                "returncode": attempt["returncode"],
                "stdout_path": attempt["stdout_path"],
                "stderr_path": attempt["stderr_path"],
                "adapted": False,
                "attempts": [
                    {
                        "script": script["filename"],
                        "status": attempt["status"],
                        "returncode": attempt["returncode"],
                        "stdout_path": attempt["stdout_path"],
                        "stderr_path": attempt["stderr_path"],
                    }
                ],
            }
        )

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def execute_red_team_scripts(
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
    env = {**os.environ, "OUT_DIR": str(execution_dir)}
    for script in tool_artifacts["manifest"].get("scripts", []):
        path = Path(script["path"])
        script_args = script.get("active_args", active_args or [])
        if not isinstance(script_args, list):
            script_args = []
        command = [str(path), *[str(arg) for arg in script_args], str(execution_dir)]
        attempt = run_generated_script(path, execution_dir, "execute", timeout, command, env=env)
        results["results"].append(
            {
                "script": script["filename"],
                "domain": script.get("domain", "coordinator"),
                "agent": script.get("agent", "red_team_tool_generation_agent"),
                "status": attempt["status"],
                "returncode": attempt["returncode"],
                "command": command,
                "stdout_path": attempt["stdout_path"],
                "stderr_path": attempt["stderr_path"],
                "dependencies": script.get("dependencies", []),
            }
        )

    results_path = execution_dir / "execution_results.json"
    results["results_path"] = str(results_path)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results
