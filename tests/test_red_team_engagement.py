from pathlib import Path
import importlib
import sys
from types import ModuleType
from unittest.mock import patch

from agents.red_team.engagement import ENGAGEMENT_FILE, ENGAGEMENT_TEXT, load_engagement_letter


def test_every_red_team_agent_receives_binding_engagement_rules():
    stub_base_agent = ModuleType("agents.base_agent")
    stub_tool_config = ModuleType("agents.tool_config")

    class StubBaseAgentFactory:
        @classmethod
        def create(cls, **kwargs):
            return kwargs

    stub_base_agent.BaseAgentFactory = StubBaseAgentFactory
    stub_tool_config.configured_agent_tools = lambda _name: []

    with patch.dict(
        sys.modules,
        {
            "agents.base_agent": stub_base_agent,
            "agents.tool_config": stub_tool_config,
        },
    ):
        factory = importlib.import_module("agents.red_team.factory")
        importlib.reload(factory)
        create_red_team_agent = factory.create_red_team_agent
        result = create_red_team_agent(
            agent_key="example",
            agent_role="Role",
            goal="Original goal",
            backstory="Original backstory",
        )

    prompt = result["goal"]
    assert "Stay within the exact target and ports" in prompt
    assert "denial-of-service" in prompt
    assert "refuse the conflicting action" in prompt
    assert "binding instructions from docs/red_team_letter_of_engagement.txt" in prompt
    assert "cite the relevant clause from docs/red_team_letter_of_engagement.txt" in prompt
    assert "explicitly state which engagement constraints are shaping your plan" in prompt
    assert result["backstory"] == "Original backstory"
    assert result["allow_delegation"] is False


def test_engagement_letter_file_is_the_canonical_policy_source():
    letter_from_file = Path(ENGAGEMENT_FILE).read_text(encoding="utf-8").strip()
    assert load_engagement_letter() == letter_from_file
    assert letter_from_file.startswith("Red Team Letter of Engagement and Rules of Engagement")
    assert "The agent MAY:" in ENGAGEMENT_TEXT
    assert "The agent MUST NOT:" in ENGAGEMENT_TEXT
    assert "explicitly enables execution" in ENGAGEMENT_TEXT
    assert "out-of-scope systems" in ENGAGEMENT_TEXT
