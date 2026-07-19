import argparse
import json
from pathlib import Path

from crews.red_team.config import RED_TEAM_SPECIALISTS
from crews.red_team.pipeline import run_red_team_pipeline, run_red_team_specialist_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the authorized red-team validation pipeline.")
    parser.add_argument("target", help="Authorized target.")
    parser.add_argument("--domain", choices=sorted(RED_TEAM_SPECIALISTS), help="Run only one specialist domain.")
    parser.add_argument("--ports", default="1-10000", help="Nmap port expression.")
    parser.add_argument("--timeout", type=int, default=180, help="Nmap timeout in seconds.")
    parser.add_argument("--reuse-scan", default="", help="Deprecated; red-team recon is generated fresh every run.")
    parser.add_argument("--use-agents", action="store_true", help="Deprecated; red-team planning now uses agents.")
    parser.add_argument("--no-nmap-agent", action="store_true", help="Deprecated compatibility flag.")
    parser.add_argument("--execute", action="store_true", help="Execute generated validation scripts. Default only generates the scripts.")
    parser.add_argument("--execution-timeout", type=int, default=180, help="Timeout per generated script.")
    parser.add_argument("--environment-context", default="", help="Optional notes about the authorized target environment.")
    parser.add_argument("--environment-file", default="", help="Optional file with authorized environment details.")
    return parser.parse_args()


def _load_environment_context(environment_context: str = "", environment_file: str = "") -> str:
    parts = []
    if environment_context.strip():
        parts.append(environment_context.strip())
    if environment_file:
        path = Path(environment_file)
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "\n\n".join(parts)


def main() -> None:
    args = parse_args()
    environment_context = _load_environment_context(args.environment_context, args.environment_file)
    if args.domain:
        result = run_red_team_specialist_pipeline(
            domain=args.domain,
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_nmap_agent=not args.no_nmap_agent,
            use_llm_agent=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
            environment_context=environment_context,
        )
    else:
        result = run_red_team_pipeline(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            reuse_scan=args.reuse_scan,
            use_agents=args.use_agents,
            execute=args.execute,
            execution_timeout=args.execution_timeout,
            environment_context=environment_context,
        )
    print(json.dumps(result, indent=2))
