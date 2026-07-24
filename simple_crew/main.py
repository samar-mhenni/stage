import argparse
import json
import logging

import uvicorn

from simple_crew.workflows import run_red_team, run_threat_intel


def _mode_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", dest="dry_run", action="store_true", help="Simulate agents and skip commands.")
    group.add_argument("--live", dest="dry_run", action="store_false", help="Use the configured LLM and bounded executor.")
    parser.set_defaults(dry_run=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple planner-driven CrewAI cybersecurity workflows.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    red = subparsers.add_parser("red-team")
    red.add_argument("--target", required=True)
    red.add_argument("--target-port", type=int, choices=range(1, 65536))
    red.add_argument("--scope", action="append", required=True, help="Authorized target or CIDR; repeat as needed.")
    red.add_argument("--objective", default="Perform an authorized assessment of the lab target")
    red.add_argument("--max-iterations", type=int, default=12)
    _mode_flags(red)

    threat = subparsers.add_parser("threat-intel")
    threat.add_argument("--evidence", required=True)
    threat.add_argument("--objective", default="Analyze suspicious activity and recommend corrective actions")
    threat.add_argument("--max-iterations", type=int, default=12)
    _mode_flags(threat)

    api = subparsers.add_parser("api")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8010)
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    if args.command == "api":
        uvicorn.run("simple_crew.api.app:app", host=args.host, port=args.port)
        return 0
    try:
        if args.command == "red-team":
            state = run_red_team(
                args.target, args.scope, args.objective, args.max_iterations,
                args.dry_run, target_port=args.target_port,
            )
        else:
            state = run_threat_intel(args.evidence, args.objective, args.max_iterations, args.dry_run)
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps({"workflow_id": state.workflow_id, "finished": state.finished, "report": state.report_path}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
