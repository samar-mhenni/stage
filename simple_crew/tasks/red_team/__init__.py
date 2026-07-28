from simple_crew.tasks.red_team.exploitation import build_task as exploitation
from simple_crew.tasks.red_team.authorization import build_task as authorization
from simple_crew.tasks.red_team.planner import build_task as planner
from simple_crew.tasks.red_team.recon import build_task as recon
from simple_crew.tasks.red_team.report import build_task as report
from simple_crew.tasks.red_team.tool_generator import build_task as tool_generator
from simple_crew.tasks.red_team.web import build_task as web


TASKS = {
    "planner": planner,
    "authorization_matrix": authorization,
    "recon": recon,
    "web_analysis": web,
    "exploit_validation": exploitation,
    "generate_tool": tool_generator,
    "report": report,
}
