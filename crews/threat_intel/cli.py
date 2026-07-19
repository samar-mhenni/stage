import argparse
import json

from crews.threat_intel.pipeline import DEFAULT_DB_PATH, run_threat_intel_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CrewAI SOC threat-intel pipeline.")
    parser.add_argument("target", nargs="?", default="provided-evidence", help="Evidence label or target name.")
    parser.add_argument("--evidence-path", default="", help="Required JSON/text logs or tool-output evidence file.")
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="SQLite output path.")
    parser.add_argument("--reuse-scan", default="", help="Deprecated alias for --evidence-path.")
    parser.add_argument("--no-auto-remediation", action="store_true", help="Generate tool scripts without automatically executing them.")
    parser.add_argument("--skip-remediation-plan", action="store_true", help="Skip response/remediation planning and generated remediation scripts for this run.")
    parser.add_argument("--auto-apply-remediation", action="store_true", help="Execute generated remediation scripts with --apply instead of dry-run mode.")
    parser.add_argument("--remediation-timeout", type=int, default=120, help="Timeout in seconds for each generated remediation script.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = run_threat_intel_pipeline(
        target=args.target,
        db_path=args.db_path,
        evidence_path=args.evidence_path,
        reuse_scan=args.reuse_scan,
        auto_execute_remediation=not args.no_auto_remediation,
        include_remediation_plan=not args.skip_remediation_plan,
        auto_apply_remediation=args.auto_apply_remediation,
        remediation_timeout=args.remediation_timeout,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "scan"}, indent=2))
