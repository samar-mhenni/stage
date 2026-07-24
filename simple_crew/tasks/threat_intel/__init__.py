from simple_crew.tasks.threat_intel.corrective_actions import build_task as corrective_actions
from simple_crew.tasks.threat_intel.evidence import build_task as evidence
from simple_crew.tasks.threat_intel.intelligence import build_task as intelligence
from simple_crew.tasks.threat_intel.planner import build_task as planner
from simple_crew.tasks.threat_intel.report import build_task as report
from simple_crew.tasks.threat_intel.tool_generator import build_task as tool_generator


TASKS = {
    "planner": planner,
    "process_evidence": evidence,
    "analyze_evidence": intelligence,
    "corrective_actions": corrective_actions,
    "generate_tool": tool_generator,
    "report": report,
}
