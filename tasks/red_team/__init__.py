"""Red-team task registrations."""

from . import blockchain, linux, web, windows
from .core import (
    create_red_team_exploit_planning_task,
    create_red_team_recon_task,
    create_red_team_recon_tool_generation_task,
    create_red_team_tool_generation_task,
)

__all__ = [
    "blockchain",
    "create_red_team_exploit_planning_task",
    "create_red_team_recon_task",
    "create_red_team_recon_tool_generation_task",
    "create_red_team_tool_generation_task",
    "linux",
    "web",
    "windows",
]
