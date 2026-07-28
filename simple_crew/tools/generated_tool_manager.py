import json
from pathlib import Path
import re
import ast
from uuid import uuid4

from simple_crew.models import GeneratedTool


TOOLS_DIR = Path(__file__).resolve().parents[1] / "generated_tools"
UNSAFE_COMMAND_PARTS = ("$(`", "`", ";", "&&", "||", "|", ">", "<")


def _validate_python_evidence_source(source: str, filename: str) -> None:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        location = f"line {exc.lineno}" if exc.lineno else "unknown line"
        raise ValueError(f"generated Python is incomplete or invalid at {location}: {exc.msg}") from exc
    calls = [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]
    emits_evidence = any(
        isinstance(func, ast.Name) and func.id == "print"
        or isinstance(func, ast.Attribute) and func.attr in {"write", "dump"}
        for func in calls
    )
    if not emits_evidence:
        raise ValueError("generated Python has no evidence output call")
    defines_main = any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main" for node in tree.body)
    calls_main = any(isinstance(func, ast.Name) and func.id == "main" for func in calls)
    if defines_main and not calls_main:
        raise ValueError("generated Python defines main() but never calls it")
    if "matrix" in filename.lower():
        lowered = source.lower()
        required = (
            "request_headers", "response_headers", "response_body",
            "status", "method", "path",
        )
        missing = [item for item in required if item not in lowered]
        if missing:
            raise ValueError(
                "matrix collector is missing required evidence semantics: " + ", ".join(missing)
            )


def parse_generated_tool(output: str) -> GeneratedTool:
    start, end = output.find("{"), output.rfind("}")
    if start < 0 or end < start:
        raise ValueError("tool generator did not return JSON")
    data = json.loads(output[start : end + 1])
    data.setdefault("tool_id", uuid4().hex[:12])
    data.setdefault("expected_output", "Structured execution evidence for the requested validation.")
    return GeneratedTool.model_validate(data)


def save_generated_tool(tool: GeneratedTool) -> GeneratedTool:
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    for argument in tool.command:
        if "$(" in argument or any(part in argument for part in UNSAFE_COMMAND_PARTS):
            raise ValueError("generated command contains shell syntax; generate dynamic values inside the tool")
    suffix = ".py" if tool.language == "python" else ".sh" if tool.language == "shell" else ".json"
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", tool.filename or tool.name)
    base_name = Path(safe_name).name
    if base_name.endswith(suffix):
        base_name = base_name[: -len(suffix)]
    safe_tool_id = re.sub(r"[^a-zA-Z0-9_-]", "_", tool.tool_id)[:36]
    filename = f"{base_name}_{safe_tool_id}{suffix}"
    path = (TOOLS_DIR / filename).resolve()
    if TOOLS_DIR.resolve() not in path.parents:
        raise ValueError("generated tool path escapes generated_tools")
    if tool.language in {"python", "shell"}:
        source = (tool.code or "").rstrip() + "\n"
        if not source.strip():
            raise ValueError("generated tool source is empty")
        if tool.language == "python":
            _validate_python_evidence_source(source, filename)
        path.write_text(source, encoding="utf-8")
        path.chmod(0o750)
    else:
        path.write_text(json.dumps(tool.command), encoding="utf-8")
    command = list(tool.command)
    if tool.language in {"python", "shell"} and command:
        if len(command) >= 2:
            command[1] = filename
        else:
            command.append(filename)
    return tool.model_copy(update={"filename": filename, "command": command})


def dry_run_tool(workflow_type: str) -> GeneratedTool:
    code = (
        "from pathlib import Path\n"
        "print('dry-run helper: no security command executed')\n"
        "print(f'workspace={Path.cwd()}')\n"
    )
    return GeneratedTool(
        tool_id=uuid4().hex[:12],
        name=f"{workflow_type}_dry_run_helper",
        purpose="Demonstrate planner-controlled generated-tool storage and execution.",
        language="python",
        filename=f"{workflow_type}_dry_run_helper.py",
        required_programs=["python"],
        command=["python"],
        code=code,
        expected_output="A dry-run message.",
        risk_level="low",
    )
