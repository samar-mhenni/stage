import json
import re
from typing import Any

def extract_json_object(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in agent output.")
    return json.loads(match.group(0))


def salvage_generated_script_objects(text: str, max_scripts: int = 2) -> list[dict[str, Any]]:
    scripts: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    script_start = text.find('"scripts"')
    if script_start == -1:
        return scripts

    scan_position = script_start
    while len(scripts) < max_scripts:
        object_start = text.find("{", scan_position)
        if object_start == -1:
            break
        try:
            candidate, object_end = decoder.raw_decode(text[object_start:])
        except json.JSONDecodeError:
            scan_position = object_start + 1
            continue

        scan_position = object_start + object_end
        if not isinstance(candidate, dict):
            continue
        if not candidate.get("body"):
            continue
        candidate.setdefault("name", f"generated_tool_{len(scripts) + 1}")
        candidate.setdefault("filename", f"{len(scripts) + 1:02d}_{candidate['name']}.sh")
        candidate.setdefault("interpreter", "bash")
        scripts.append(candidate)
    return scripts

