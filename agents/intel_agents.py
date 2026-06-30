from agents.base_agent import BaseAgentFactory
from agents.registry import AgentRegistry
from tools.registry import ToolRegistry

import tools.exploitdb_tool  # noqa: F401 - registers exploitdb_tool
import tools.knowledge_base_tool  # noqa: F401 - registers knowledge_base_tool
import tools.nmap_tool  # noqa: F401 - registers nmap_tool
import tools.vulnerability_scan_tool  # noqa: F401 - registers vulnerability_scan_tool


@AgentRegistry.register("nmap_scan_agent")
def create_nmap_scan_agent():
    return BaseAgentFactory.create(
        role="Nmap Scan Agent",
        goal="Run authorized Nmap service discovery against the lab target and return structured scan evidence.",
        backstory=(
            "You are a controlled-lab reconnaissance agent. You only scan explicitly authorized "
            "targets, preserve raw evidence, and return machine-readable Nmap results."
        ),
        tools=[ToolRegistry.get_tool("nmap_tool")],
        allow_delegation=False,
    )


@AgentRegistry.register("vulnerability_scan_agent")
def create_vulnerability_scan_agent():
    return BaseAgentFactory.create(
        role="Vulnerability Scan Agent",
        goal=(
            "Turn Nmap service evidence into defensive vulnerability findings using local "
            "ExploitDB and knowledge-base data."
        ),
        backstory=(
            "You are a vulnerability analyst for a SOC lab. You map exposed products and "
            "versions to likely weaknesses and exploit references without giving exploit steps."
        ),
        tools=[
            ToolRegistry.get_tool("vulnerability_scan_tool"),
            ToolRegistry.get_tool("exploitdb_tool"),
            ToolRegistry.get_tool("knowledge_base_tool"),
        ],
        allow_delegation=False,
    )


@AgentRegistry.register("reporting_agent")
def create_reporting_agent():
    return BaseAgentFactory.create(
        role="SOC Reporting Agent",
        goal="Write a clear SOC report from scan and vulnerability evidence.",
        backstory=(
            "You write concise, evidence-grounded SOC reports that separate confirmed scan "
            "facts from likely vulnerability intelligence and uncertainty."
        ),
        tools=[ToolRegistry.get_tool("knowledge_base_tool")],
        allow_delegation=False,
    )


@AgentRegistry.register("remediation_agent")
def create_remediation_agent():
    return BaseAgentFactory.create(
        role="Remediation Agent",
        goal="Produce prioritized remediation actions that correct the identified weaknesses safely.",
        backstory=(
            "You are a defensive remediation specialist. You translate SOC findings into patching, "
            "hardening, segmentation, monitoring, and validation tasks that system owners can execute."
        ),
        tools=[ToolRegistry.get_tool("knowledge_base_tool")],
        allow_delegation=False,
    )


@AgentRegistry.register("remediation_script_generation_agent")
def create_remediation_script_generation_agent():
    return BaseAgentFactory.create(
        role="Remediation Script Generation Agent",
        goal=(
            "Generate safe defensive remediation and validation scripts from scan findings, "
            "without embedding offensive exploitation steps."
        ),
        backstory=(
            "You are an automation engineer for a SOC lab. You convert remediation plans into "
            "reviewable scripts that default to dry-run behavior and require explicit operator "
            "approval before changing services or firewall rules."
        ),
        tools=[],
        allow_delegation=False,
    )
