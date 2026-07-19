from collections.abc import Callable

from crewai.tools import BaseTool

from tools import (
    john_the_ripper_hash_crack,
    red_team_database_search,
    threat_intel_database_search,
)


GENERATED_TOOL_SPECS = {
    "knowledge_base_tool": {
        "name": "threat_intel_database_search",
        "description": (
            "Search the Detection, Attack, and Actor databases for defensive CTI analysis, "
            "detection guidance, mitigations, attribution scoring, and SIEM rules. "
            "Input should be a specific search query like 'MFA fatigue detection' or 'APT29 mitigations'. "
            "Returns source collection, object type, name, match score, and matching source text."
        ),
        "runtime": "threat_intel_database_search",
    },
    "threat_intel_database_search": {
        "name": "threat_intel_database_search",
        "description": (
            "Search the Detection, Attack, and Actor databases for defensive CTI analysis, "
            "detection guidance, mitigations, attribution scoring, and SIEM rules. "
            "Input should be a specific search query like 'MFA fatigue detection' or 'APT29 mitigations'. "
            "Returns source collection, object type, name, match score, and matching source text."
        ),
        "runtime": "threat_intel_database_search",
    },
    "red_team_database_search": {
        "name": "Red Team Database Search",
        "description": (
            "Search the Red Team, Exploit, Attack, and Actor databases for operational red team knowledge, "
            "adversary simulation procedures, exploits, vulnerabilities, CVEs, and MITRE ATT&CK techniques. "
            "Input should be a specific search query like 'Credential Dumping', 'Ryuk ransomware', or 'CVE-2021-44228'."
        ),
        "runtime": "red_team_database_search",
    },
    "john_the_ripper_hash_crack": {
        "name": "john_the_ripper_hash_crack",
        "description": (
            "Attempt to crack authorized password hashes with local John the Ripper. "
            "Input should be one or more hashes, optionally followed by lines like "
            "'format=raw-md5', 'wordlist=/path/to/wordlist', or 'timeout=300'. "
            "Supported common formats include raw-md5, raw-sha1, raw-sha256, raw-sha512, "
            "nt, bcrypt, and md5crypt. Returns only local John results."
        ),
        "runtime": "john_the_ripper_hash_crack",
    },
}


RUNTIME_FUNCTIONS: dict[str, Callable[[str], str]] = {
    "threat_intel_database_search": threat_intel_database_search,
    "red_team_database_search": red_team_database_search,
    "john_the_ripper_hash_crack": john_the_ripper_hash_crack,
}


class GeneratedRuntimeTool(BaseTool):
    name: str
    description: str
    runtime: str

    def _run(self, query: str) -> str:
        return RUNTIME_FUNCTIONS[self.runtime](query)


def build_generated_tool(tool_name: str) -> GeneratedRuntimeTool:
    spec = GENERATED_TOOL_SPECS.get(tool_name)
    if not spec:
        raise ValueError(f"Unknown generated tool: {tool_name}")
    return GeneratedRuntimeTool(**spec)
