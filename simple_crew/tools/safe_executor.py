import ipaddress
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from simple_crew.config import PROJECT_ROOT, settings
from simple_crew.models import GeneratedTool
from simple_crew.tools.generated_tool_manager import TOOLS_DIR


ALLOWED_PROGRAMS = {"python", "python3", "bash", "curl", "nmap"}
BLOCKED_TOKENS = {";", "&&", "||", "|", ">", "<", "`"}
BLOCKED_SOURCE = {
    "shell=true",
    "os.system",
    "subprocess.",
    "shutil.rmtree",
    ".unlink(",
    " rm ",
    "sudo ",
    "chmod 777",
    "useradd",
    "crontab",
    "nc -e",
    "/dev/tcp/",
}


def target_in_scope(target: str, scope: list[str]) -> bool:
    if target in scope:
        return True
    try:
        address = ipaddress.ip_address(target)
        return any(address in ipaddress.ip_network(item, strict=False) for item in scope)
    except ValueError:
        return False


def execute_generated_tool(
    tool: GeneratedTool,
    workflow_type: str,
    target: str | None,
    authorized_scope: list[str],
    dry_run: bool,
    timeout: int = 60,
) -> dict[str, Any]:
    if workflow_type == "red_team" and (not target or not authorized_scope or not target_in_scope(target, authorized_scope)):
        return {"status": "blocked", "reason": "target is not inside the explicit authorized scope", "tool_id": tool.tool_id}
    if dry_run:
        return {"status": "skipped", "reason": "dry-run mode", "tool_id": tool.tool_id, "exit_code": None}
    program = tool.command[0] if tool.command else ("python" if tool.language == "python" else "bash")
    if program not in ALLOWED_PROGRAMS or not shutil.which(program):
        return {"status": "blocked", "reason": f"program is not allowed or unavailable: {program}", "tool_id": tool.tool_id}
    args = list(tool.command)
    if tool.filename and tool.language in {"python", "shell"}:
        path = (TOOLS_DIR / Path(tool.filename).name).resolve()
        if TOOLS_DIR.resolve() not in path.parents or not path.is_file():
            return {"status": "blocked", "reason": "generated file is outside generated_tools or missing", "tool_id": tool.tool_id}
        source = path.read_text(encoding="utf-8", errors="ignore").lower()
        if any(marker in source for marker in BLOCKED_SOURCE):
            return {"status": "blocked", "reason": "generated source contains a blocked destructive or process primitive", "tool_id": tool.tool_id}
        tool_args = args[1:]
        if tool_args and Path(tool_args[0]).name == path.name:
            tool_args = tool_args[1:]
        tool_args = [
            str((PROJECT_ROOT / argument).resolve())
            if not Path(argument).is_absolute() and (PROJECT_ROOT / argument).exists()
            else argument
            for argument in tool_args
        ]
        args = [program, str(path), *tool_args]
    if any(token in part for part in args for token in BLOCKED_TOKENS) or any("$(" in part for part in args):
        return {"status": "blocked", "reason": "shell operators are not allowed", "tool_id": tool.tool_id}
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=TOOLS_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout[: settings.max_tool_output_chars]
        first_line = next((line.strip().upper() for line in stdout.splitlines() if line.strip()), "")
        empty_evidence = not stdout.strip()
        semantic_failure = empty_evidence or first_line.startswith(("FAILURE:", "FAILED:", "ERROR:"))
        result = {
            "status": "success" if completed.returncode == 0 and not semantic_failure else "failed",
            "exit_code": completed.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout,
            "stderr": completed.stderr[: settings.max_tool_output_chars],
            "tool_id": tool.tool_id,
        }
        if completed.returncode == 0 and empty_evidence:
            result["reason"] = "tool exited successfully but produced no evidence"
        return result
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": f"tool timed out after {timeout}s", "exit_code": 124, "tool_id": tool.tool_id}
