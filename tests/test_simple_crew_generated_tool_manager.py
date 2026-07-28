from pathlib import Path
from subprocess import CompletedProcess

import pytest

from simple_crew.models import GeneratedTool
from simple_crew.tools import generated_tool_manager
from simple_crew.tools import safe_executor


def _python_tool(tool_id: str, code: str, filename: str = "validator.py") -> GeneratedTool:
    return GeneratedTool(
        tool_id=tool_id,
        name="validator",
        purpose="Validate a bounded lab behavior.",
        language="python",
        filename=filename,
        required_programs=["python3"],
        command=["python3", filename, "127.0.0.1", "18081"],
        code=code,
        expected_output="Structured validation result.",
        risk_level="low",
    )


def test_save_rejects_truncated_python_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(generated_tool_manager, "TOOLS_DIR", tmp_path)
    tool = _python_tool("broken-001", 'print(f"unterminated {value}\n')

    with pytest.raises(ValueError, match="incomplete or invalid"):
        generated_tool_manager.save_generated_tool(tool)

    assert list(tmp_path.iterdir()) == []


def test_save_rejects_main_that_is_never_called(tmp_path, monkeypatch):
    monkeypatch.setattr(generated_tool_manager, "TOOLS_DIR", tmp_path)
    tool = _python_tool("silent-main-001", "def main():\n    print('evidence')\n")

    with pytest.raises(ValueError, match=r"never calls it"):
        generated_tool_manager.save_generated_tool(tool)

    assert list(tmp_path.iterdir()) == []


def test_save_uses_unique_filename_and_preserves_each_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(generated_tool_manager, "TOOLS_DIR", tmp_path)
    first = generated_tool_manager.save_generated_tool(
        _python_tool("tool-001", "print('first')\n")
    )
    second = generated_tool_manager.save_generated_tool(
        _python_tool("tool-002", "print('second')\n")
    )

    assert first.filename != second.filename
    assert first.command[1] == first.filename
    assert second.command[1] == second.filename
    assert Path(tmp_path, first.filename).read_text(encoding="utf-8") == "print('first')\n"
    assert Path(tmp_path, second.filename).read_text(encoding="utf-8") == "print('second')\n"


def test_executor_rejects_zero_exit_without_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(generated_tool_manager, "TOOLS_DIR", tmp_path)
    monkeypatch.setattr(safe_executor, "TOOLS_DIR", tmp_path)
    saved = generated_tool_manager.save_generated_tool(
        _python_tool("silent-001", "pass\n")
    )
    monkeypatch.setattr(
        safe_executor.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(args[0], 0, stdout="", stderr=""),
    )

    result = safe_executor.execute_generated_tool(
        saved, "red_team", "127.0.0.1", ["127.0.0.1"], False
    )

    assert result["status"] == "failed"
    assert result["reason"] == "tool exited successfully but produced no evidence"
