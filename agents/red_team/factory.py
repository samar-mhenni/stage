from agents.red_team.engagement import red_team_engagement_instructions


def create_red_team_agent(
    agent_key: str,
    agent_role: str,
    goal: str,
    backstory: str,
    llm_max_tokens: int | None = None,
):
    from agents.base_agent import BaseAgentFactory
    from agents.tool_config import configured_agent_tools

    kwargs = {
        "role": agent_role,
        "goal": goal + red_team_engagement_instructions(),
        "backstory": backstory,
        "tools": configured_agent_tools(agent_key),
        "allow_delegation": False,
    }
    if llm_max_tokens is not None:
        kwargs["llm_max_tokens"] = llm_max_tokens
    return BaseAgentFactory.create(**kwargs)
