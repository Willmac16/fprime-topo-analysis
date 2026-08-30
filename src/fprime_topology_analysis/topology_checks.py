#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
Topology checks CLI - run every analysis over one topology

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import sys
import argparse
import json
import logging
from typing import List

from . import cli
from .checks import CHECKS, Finding, run_checks
from .port_flow import UnresolvedFlowError
from .topology_graph import Severity

logger = logging.getLogger(__name__)


def format_report(findings: List[Finding], skipped: List[str], graph) -> str:
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("Topology Checks")
    lines.append("=" * 72)
    lines.append("")
    flow_lookups = graph.flow.stats_precise + graph.flow.stats_conservative
    flow_summary = (
        f"{graph.flow.stats_precise}/{flow_lookups}"
        if flow_lookups
        else ("not available" if graph.flow.is_empty else "not required")
    )
    if graph.flow.stats_conservative:
        flow_summary += f" ({graph.flow.stats_conservative} conservative)"
    summary = (
        ("Component instances", str(len(graph.instances))),
        ("C++ handlers resolved", flow_summary),
        ("Findings", str(len(findings))),
    )
    width = max(len(label) for label, _ in summary)
    lines.extend(f"{label + ':':<{width + 2}} {value}" for label, value in summary)
    lines.append("")

    blocking = graph.blocking_ports()
    if blocking:
        lines.append(
            f"NOTE: {len(blocking)} port(s) declare 'queue full block' and are "
            f"analyzed as ordinary async hops."
        )
        lines.append("")

    lines.extend(f"SKIPPED {note}" for note in skipped)
    if skipped:
        lines.append("")

    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    ordered = sorted(
        findings, key=lambda f: (-f.severity.rank, f.check, f.subject)
    )
    current = None
    for finding in ordered:
        if finding.check != current:
            current = finding.check
            lines.append("-" * 72)
            lines.append(finding.check)
            lines.append("-" * 72)
        lines.append(f"  [{finding.severity.value.upper()}] {finding.subject}")
        lines.append(f"    {finding.message}")
        lines.extend(f"      {item}" for item in finding.evidence)
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run static checks over an F' topology",
        epilog="Check ids: " + ", ".join(c.id for c in CHECKS),
    )
    cli.add_topology_args(parser)
    cli.add_report_args(parser)
    parser.add_argument(
        "--checks", help="Comma separated check ids to run (default: all)"
    )
    parser.add_argument("--list-checks", action="store_true", help="List checks and exit")
    args = cli.parse_args(parser)
    cli.configure_logging(args.verbose)

    if args.list_checks:
        for check in CHECKS:
            needs = " (needs C++ analysis)" if check.requires_flow else ""
            print(f"{check.id:26} {check.name}{needs}")
        return 0

    selected = set(args.checks.split(",")) if args.checks else None
    if selected:
        unknown = selected - {c.id for c in CHECKS}
        if unknown:
            logger.error(f"Unknown check(s): {', '.join(sorted(unknown))}")
            return 1

    try:
        # Checks whose C++ inputs are unavailable report as skipped.
        graph = cli.load_graph(args, cli.load_flow(args, allow_empty=True))
        findings, skipped = run_checks(graph, selected)
    except UnresolvedFlowError as e:
        return cli.report_unresolved(e)
    except cli.CliError as e:
        return cli.report_error(e, args.verbose)

    cli.write_or_print(format_report(findings, skipped, graph), args.output)

    if args.json:
        cli.write_or_print(
            json.dumps(
                {
                    "findings": [
                        {
                            "check": f.check,
                            "severity": str(f.severity),
                            "subject": f.subject,
                            "message": f.message,
                            "evidence": f.evidence,
                        }
                        for f in findings
                    ],
                    "skipped": skipped,
                },
                indent=2,
            ),
            args.json,
        )

    if args.fail_on == "never":
        return 0
    threshold = Severity(args.fail_on).rank
    return len([f for f in findings if f.severity.rank >= threshold])


if __name__ == "__main__":
    sys.exit(main())
