"""Generate runtime tools from the specifications an agent actually needs."""

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from tools.nmap_tool import run_nmap_scan
from tools.registry import ToolRegistry


def generate_nmap_scan_tool() -> type[BaseTool]:
    """Generate the Nmap tool surface needed by nmap_scan_agent."""

    class GeneratedNmapScanInput(BaseModel):
        target: str = Field(
            ...,
            description="Approved lab target, CIDR, hostname, or comma-separated target list.",
        )
        scan_type: str = Field(
            default="service",
            description="Scan mode: host_discovery, port_scan, service, version, or os.",
        )
        ports: str | None = Field(
            default=None,
            description="Optional port expression. Use None or top-1000 for default Nmap ports.",
        )
        timeout: int = Field(
            default=180,
            description="Timeout in seconds for the nmap process.",
        )
        fast_mode: bool = Field(
            default=True,
            description="Use faster timing and host-up assumptions for approved lab targets.",
        )

    class GeneratedNmapScanTool(BaseTool):
        name: str = "GeneratedNmapScanTool"
        description: str = (
            "Generated tool for nmap_scan_agent. Executes authorized Nmap scans "
            "against approved lab targets and returns parsed JSON."
        )
        args_schema: type[BaseModel] = GeneratedNmapScanInput

        def _run(
            self,
            target: str,
            scan_type: str = "service",
            ports: str | None = None,
            timeout: int = 180,
            fast_mode: bool = True,
        ) -> str:
            return run_nmap_scan(target, scan_type, ports, timeout, fast_mode)

    return GeneratedNmapScanTool


ToolRegistry.register("generated_nmap_tool")(generate_nmap_scan_tool())
