"""Command line interface for Rygnal Core."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rygnal.cli_audit import run_audit_cli
from rygnal.cli_doctor import run_doctor_cli
from rygnal.cli_run import default_guarded_run_root, run_guarded_cli
from rygnal.cli_serve import run_serve_cli
from rygnal.policy_engine import PolicyEngine
from rygnal.version import package_version


def main(argv: list[str] | None = None) -> int:
    """Run the Rygnal CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.command(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the Rygnal CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="rygnal",
        description="Rygnal Core CLI for runtime AI-agent security workflows.",
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    version_parser = subparsers.add_parser("version", help="Show Rygnal version.")
    version_parser.set_defaults(command=run_version)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check local Rygnal installation readiness.",
    )
    doctor_parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Override the private Rygnal data directory.",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable diagnostic output.",
    )
    doctor_parser.add_argument(
        "--skip-containment",
        action="store_true",
        help="Skip optional execution-containment probes.",
    )
    doctor_parser.set_defaults(command=run_doctor_cli)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Query locally persisted audit events.",
    )
    audit_parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Override the private Rygnal data directory.",
    )
    audit_parser.add_argument("--event-id", default=None)
    audit_parser.add_argument("--trace-id", default=None)
    audit_parser.add_argument("--decision", default=None)
    audit_parser.add_argument("--tool-name", default=None)
    audit_parser.add_argument("--action", default=None)
    audit_parser.add_argument("--severity", default=None)
    audit_parser.add_argument("--policy-id", default=None)
    audit_parser.add_argument("--since", default=None)
    audit_parser.add_argument("--until", default=None)
    audit_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum events to return.",
    )
    audit_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Number of matching events to skip.",
    )
    audit_parser.add_argument(
        "--newest-first",
        action="store_true",
        help="Show newest events first.",
    )
    audit_parser.add_argument(
        "--verify-integrity",
        action="store_true",
        help="Verify the JSONL audit hash chain.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable audit output.",
    )
    audit_parser.set_defaults(command=run_audit_cli)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the private local Rygnal API.",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host. Defaults to private loopback.",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="Bind port. Defaults to 8787.",
    )
    serve_parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Override the private Rygnal data directory.",
    )
    serve_parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Permit an explicit non-loopback bind.",
    )
    serve_parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the local Swagger interface.",
    )
    serve_parser.add_argument(
        "--log-level",
        choices=[
            "critical",
            "error",
            "warning",
            "info",
            "debug",
            "trace",
        ],
        default="info",
    )
    serve_parser.add_argument(
        "--no-access-log",
        action="store_true",
        help="Disable HTTP access logging.",
    )
    serve_parser.set_defaults(command=run_serve_cli)

    run_parser = subparsers.add_parser(
        "run",
        help="Run an agent command inside a guarded workspace.",
        description=(
            "EXPERIMENTAL DEVELOPER PREVIEW: run an agent command through "
            "Rygnal and produce reviewable change evidence. This command "
            "does not guarantee prevention or rollback on every host."
        ),
    )
    run_parser.add_argument(
        "--repo",
        type=Path,
        default=Path.cwd(),
        help="Trusted repository path. Defaults to current directory.",
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Command timeout in seconds.",
    )
    run_parser.add_argument(
        "--run-root",
        type=Path,
        default=default_guarded_run_root(),
        help="Directory for guarded run workspaces.",
    )
    run_parser.add_argument(
        "--preserve-workspace",
        action="store_true",
        help="Preserve guarded workspace after run for debugging.",
    )
    run_parser.add_argument(
        "--unsafe-local",
        action="store_true",
        help="Explicitly allow unsafe local execution. Not a containment backend.",
    )
    run_parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow tracked dirty trusted repo state. Use carefully.",
    )
    run_parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Write audit events to this JSONL file.",
    )
    run_parser.add_argument(
        "--intent",
        type=Path,
        default=None,
        help="Load a Rygnal intent contract YAML file for this guarded run.",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON summary.",
    )
    run_parser.add_argument(
        "--show-stdout",
        action="store_true",
        help="Print guarded command stdout.",
    )
    run_parser.add_argument(
        "--show-stderr",
        action="store_true",
        help="Print guarded command stderr.",
    )
    run_parser.add_argument(
        "agent_command",
        nargs=argparse.REMAINDER,
        help="Command to run after --.",
    )
    run_parser.set_defaults(command=run_guarded_cli, command_name="run")

    demo_parser = subparsers.add_parser("demo", help="Run Rygnal demo commands.")
    demo_subparsers = demo_parser.add_subparsers(dest="demo_command", required=True)

    demo_run_parser = demo_subparsers.add_parser("run", help="Run real workflow scenarios.")
    demo_run_parser.add_argument(
        "--approval-mode",
        choices=["default", "cli"],
        default="default",
        help="Use default safe rejection or interactive CLI approval.",
    )
    demo_run_parser.add_argument(
        "--approver",
        default="cli_user",
        help="Identity recorded for CLI approval decisions.",
    )
    demo_run_parser.add_argument(
        "--approval-timeout",
        type=int,
        default=30,
        help="Seconds before CLI approval rejects by default.",
    )
    demo_run_parser.set_defaults(command=run_demo)

    policy_parser = subparsers.add_parser("policy", help="Run Rygnal policy commands.")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command", required=True)

    policy_validate_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate a Rygnal policy YAML file.",
    )
    policy_validate_parser.add_argument("policy_path", help="Path to policy YAML file.")
    policy_validate_parser.set_defaults(command=run_policy_validate)

    return parser


def run_version(_args: argparse.Namespace) -> int:
    """Print Rygnal package version."""
    print(f"rygnal-core {package_version()}")
    return 0


def run_policy_validate(args: argparse.Namespace) -> int:
    """Validate a policy file."""
    policy_path = Path(args.policy_path)

    try:
        engine = PolicyEngine.from_file(policy_path)
    except Exception as exc:
        print(f"Policy file invalid: {policy_path}", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Policy file valid: {policy_path}")
    print(f"Policy version: {engine.policy_version}")
    print(f"Rules: {len(engine.rules)}")
    return 0


def run_demo(args: argparse.Namespace) -> int:
    """Run the real scenario demo through the CLI."""
    from demo.cli_output import render_run_report
    from demo.scenario_runner import ScenarioRunner
    from rygnal.cli_approval import build_cli_approval_workflow

    approval_workflow = None

    if args.approval_mode == "cli":
        approval_workflow = build_cli_approval_workflow(
            approver=args.approver,
            timeout_seconds=args.approval_timeout,
        )

    runner = ScenarioRunner(approval_workflow=approval_workflow)
    outcomes = runner.run_all()
    print(render_run_report(outcomes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
