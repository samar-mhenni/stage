from crewai import Agent, LLM

from simple_crew.agents.red_team.exploitation import create_agent as exploitation_agent
from simple_crew.agents.red_team.authorization import create_agent as authorization_agent
from simple_crew.agents.red_team.planner import create_agent as planner_agent
from simple_crew.agents.red_team.recon import create_agent as recon_agent
from simple_crew.agents.red_team.report import create_agent as report_agent
from simple_crew.agents.red_team.tool_generator import create_agent as tool_generator_agent
from simple_crew.agents.red_team.web import create_agent as web_agent


def create_agents(llm: LLM, tool_llm: LLM | None = None) -> dict[str, Agent]:
    return {
        "planner": planner_agent(llm),
        "authorization_matrix": authorization_agent(tool_llm or llm),
        "recon": recon_agent(llm),
        "web_analysis": web_agent(llm),
        "exploit_validation": exploitation_agent(llm),
        "generate_tool": tool_generator_agent(tool_llm or llm),
        "report": report_agent(llm),
    }
