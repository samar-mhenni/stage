import json
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry


TARGET_PATTERN = re.compile(r"^[A-Za-z0-9_.:/\-\s,]+$")
COMMON_LAB_PORTS = (
    "21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,"
    "2049,2121,3306,5432,5900,6000,6667,8009,8180"
)


class NmapToolInput(BaseModel):
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
        description="Optional port expression, for example '22,80,443' or '1-1024'.",
    )
    timeout: int = Field(
        default=120,
        description="Timeout in seconds for the nmap process.",
    )
    fast_mode: bool = Field(
        default=True,
        description="Use faster timing and host-up assumptions for approved lab targets.",
    )


def _validate_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")
    if not TARGET_PATTERN.match(cleaned):
        raise ValueError("Target contains unsupported characters.")
    return cleaned


def _normalize_ports(ports: str | None) -> str | None:
    if ports is None:
        return None
    cleaned = ports.strip()
    if not cleaned or cleaned == "top-1000":
        return None
    return cleaned


def _scan_args(scan_type: str, fast_mode: bool = True) -> list[str]:
    scan_modes = {
        "host_discovery": ["-sn"],
        "port_scan": ["-sS"],
        "service": ["-sV", "--version-light"],
        "version": ["-sV", "--version-light"],
        "os": ["-O", "-sV"],
    }
    if scan_type not in scan_modes:
        raise ValueError(
            "Unsupported scan_type. Use host_discovery, port_scan, service, version, or os."
        )
    args = list(scan_modes[scan_type])
    if fast_mode and scan_type != "host_discovery":
        args.extend(["-T4", "-Pn", "--host-timeout", "90s", "--max-retries", "2"])
    return args


def _text_or_empty(element: ET.Element | None, key: str) -> str:
    if element is None:
        return ""
    return element.attrib.get(key, "")


def _parse_host(host: ET.Element) -> dict[str, Any]:
    address = host.find("address")
    hostnames = [
        item.attrib.get("name", "")
        for item in host.findall("./hostnames/hostname")
        if item.attrib.get("name")
    ]
    status = host.find("status")

    host_data: dict[str, Any] = {
        "host": _text_or_empty(address, "addr"),
        "status": _text_or_empty(status, "state"),
        "hostnames": hostnames,
        "ports": [],
    }

    os_matches = []
    for osmatch in host.findall("./os/osmatch"):
        os_matches.append(
            {
                "name": osmatch.attrib.get("name", ""),
                "accuracy": osmatch.attrib.get("accuracy", ""),
            }
        )
    if os_matches:
        host_data["os_matches"] = os_matches

    for port in host.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")
        port_data = {
            "port": int(port.attrib.get("portid", "0")),
            "protocol": port.attrib.get("protocol", ""),
            "state": _text_or_empty(state, "state"),
            "service": _text_or_empty(service, "name"),
            "product": _text_or_empty(service, "product"),
            "version": _text_or_empty(service, "version"),
            "extra_info": _text_or_empty(service, "extrainfo"),
        }
        host_data["ports"].append(port_data)

    return host_data


def parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    root = ET.fromstring(xml_output)
    run_stats = root.find("./runstats/finished")
    return {
        "scanner": "nmap",
        "args": root.attrib.get("args", ""),
        "start": root.attrib.get("startstr", ""),
        "finished": _text_or_empty(run_stats, "timestr"),
        "summary": _text_or_empty(run_stats, "summary"),
        "hosts": [_parse_host(host) for host in root.findall("host")],
    }


@ToolRegistry.register("nmap_tool")
class NmapTool(BaseTool):
    name: str = "NmapTool"
    description: str = (
        "Execute authorized Nmap discovery scans against approved lab environments. "
        "Supports host discovery, port scanning, service detection, version detection, "
        "and OS fingerprinting. Returns structured JSON parsed from Nmap XML output."
    )
    args_schema: type[BaseModel] = NmapToolInput

    def _run(
        self,
        target: str,
        scan_type: str = "service",
        ports: str | None = None,
        timeout: int = 120,
        fast_mode: bool = True,
    ) -> str:
        return run_nmap_scan(target, scan_type, ports, timeout, fast_mode)


def run_nmap_scan(
    target: str,
    scan_type: str = "service",
    ports: str | None = None,
    timeout: int = 120,
    fast_mode: bool = True,
) -> str:
    try:
        return _run_nmap_once(target, scan_type, ports, timeout, fast_mode)
    except subprocess.TimeoutExpired:
        logger.warning("Nmap scan timed out: target=%s timeout=%s", target, timeout)
        if scan_type in {"service", "version"} and _normalize_ports(ports) is None:
            logger.info("Retrying timed-out broad service scan with common lab ports.")
            return _run_nmap_once(
                target,
                scan_type,
                COMMON_LAB_PORTS,
                max(timeout, 180),
                fast_mode,
            )
        return json.dumps(
            {"error": "timeout", "message": f"Nmap scan exceeded {timeout} seconds."},
            indent=2,
        )
    except FileNotFoundError:
        logger.error("Nmap executable was not found in PATH.")
        return json.dumps(
            {"error": "nmap_not_found", "message": "Install nmap and ensure it is in PATH."},
            indent=2,
        )
    except Exception as exc:
        logger.exception("Unexpected NmapTool error.")
        return json.dumps({"error": "nmap_tool_error", "message": str(exc)}, indent=2)


def _run_nmap_once(
    target: str,
    scan_type: str,
    ports: str | None,
    timeout: int,
    fast_mode: bool,
) -> str:
    approved_target = _validate_target(target)
    normalized_ports = _normalize_ports(ports)
    args = ["nmap", *(_scan_args(scan_type, fast_mode)), "-oX", "-"]
    if normalized_ports:
        args.extend(["-p", normalized_ports])
    args.extend(approved_target.split())

    logger.info(
        "Starting Nmap scan: scan_type=%s target=%s ports=%s timeout=%s",
        scan_type,
        approved_target,
        normalized_ports or "top-1000",
        timeout,
    )
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if result.returncode != 0:
        logger.warning("Nmap scan failed: %s", result.stderr.strip())
        return json.dumps(
            {
                "error": "nmap_failed",
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            },
            indent=2,
        )

    parsed = parse_nmap_xml(result.stdout)
    logger.info("Completed Nmap scan: hosts=%s", len(parsed.get("hosts", [])))
    return json.dumps(parsed, indent=2)
