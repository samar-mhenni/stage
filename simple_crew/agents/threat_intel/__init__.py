from crewai import Agent, LLM

from simple_crew.agents.threat_intel.corrective_actions import create_agent as corrective_actions_agent
from simple_crew.agents.threat_intel.evidence import create_agent as evidence_agent
from simple_crew.agents.threat_intel.intelligence import create_agent as intelligence_agent
from simple_crew.agents.threat_intel.planner import create_agent as planner_agent
from simple_crew.agents.threat_intel.report import create_agent as report_agent
from simple_crew.agents.threat_intel.tool_generator import create_agent as tool_generator_agent


def create_agents(llm: LLM) -> dict[str, Agent]:
    return {
        "planner": planner_agent(llm),
        "process_evidence": evidence_agent(llm),
        "analyze_evidence": intelligence_agent(llm),
        "corrective_actions": corrective_actions_agent(llm),
        "generate_tool": tool_generator_agent(llm),
        "report": report_agent(llm),
    }

