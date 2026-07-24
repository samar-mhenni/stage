import json
from typing import Any


def compact(value: Any, limit: int = 9000) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))[:limit]


PLANNER_SCHEMA = (
    '{"action":"allowed action","objective":"one bounded objective",'
    '"reason":"evidence-based reason","expected_output":"specific output",'
    '"tool_id":null,"finding_id":null}'
)

RESULT_SCHEMA = (
    '{"agent":"agent name","status":"success|failed|blocked|skipped|inconclusive",'
    '"summary":"short factual summary","findings":[{"type":"category",'
    '"description":"factual detail","target":null,"source":null,"value":null,'
    '"status":null,"confidence":null,"confirmed":null,"timestamp":null,'
    '"reference":null}],"evidence":[],'
    '"missing_information":[]}'
)

RESULT_RULE = "Include every top-level field exactly once. Use empty arrays for findings, evidence, or missing_information when there are no items."

TOOL_SCHEMA = (
    '{"tool_id":"unique_safe_id","name":"safe_name","purpose":"bounded purpose",'
    '"language":"python|shell|command","filename":null,"required_programs":[],'
    '"command":[],"code":"complete source","risk_level":"low",'
    '"expected_output":"observable result"}'
)
