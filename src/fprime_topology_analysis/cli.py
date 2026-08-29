#!/usr/bin/env python3
"""
Shared entry-point plumbing for the analyzer CLIs

Every analyzer answers a different question, but they all get there the same
way: point at a directory of ``fpp-to-json`` output, load a flow map produced by
``component_call_graph.py``, build one ``TopologyGraph``, then report findings
and exit non-zero when any of them are severe enough.

That common half lives here so the three CLIs cannot drift apart on the flags a
user has to remember, on what happens when a flow map is missing, or on what an
unresolved handler is allowed to mean.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import argparse
import logging
import traceback
from pathlib import Path
from typing import Optional

from .port_flow import PortFlowMap, UnresolvedFlowError
from .topology_graph import Severity, TopologyGraph

logger = logging.getLogger(__name__)


class CliError(Exception):
    """A condition the user has to fix, reported without a traceback"""


def add_topology_args(parser: argparse.ArgumentParser, *, require_path: bool = True):
    """Add the flags every analyzer needs to build a graph"""
    parser.add_argument(
        "--topology-path",
        type=Path,
        required=require_path,
        help="Path to topology JSON files (e.g., build-dir/Deployment/Top)",
    )
    parser.add_argument(
        "--topology",
        default=None,
        help="Topology name, when the model holds more than one deployment",
    )
    parser.add_argument(
        "--flow-map",
        type=Path,
        help=(
            "Flow map from component_call_graph.py, giving which output ports "
            "each handler actually calls. Required unless --permissive is given"
        ),
    )
    parser.add_argument(
        "--permissive",
        action="store_true",
        help=(
            "Assume any handler the flow map cannot resolve may call every "
            "output port, instead of failing. Sound but very imprecise: on a "
            "real deployment this manufactures chains the C++ never takes"
        ),
    )
    parser.add_argument("--verbose", "-v", action="store_true")


def add_report_args(parser: argparse.ArgumentParser):
    """Add the flags every analyzer uses to emit its report"""
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the text report to this file instead of stdout",
    )
    parser.add_argument("--json", type=Path, help="Write findings as JSON to this file")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["never"],
        default="error",
        help="Exit non-zero when a finding at or above this severity is found",
    )


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def load_flow(args, *, allow_empty: bool = False) -> PortFlowMap:
    """Build the flow map named by the parsed arguments

    ``allow_empty`` is for callers that can still say something useful without
    intra-component flow, by reporting the flow-dependent analyses as skipped
    rather than failing outright.

    Raises:
        CliError: If no flow map was given and the caller neither opted in to
            the over-approximation nor accepts an empty map, or if the flow map
            cannot be read.
    """
    if not args.flow_map:
        if args.permissive:
            return PortFlowMap.permissive()
        if allow_empty:
            return PortFlowMap.empty()
        raise CliError(
            "No --flow-map given. Which output ports a handler calls comes "
            "from the C++, and without it every handler would have to be "
            "assumed to call every port, which buries real findings in false "
            "positives. Generate one with component_call_graph.py, or pass "
            "--permissive to accept that over-approximation deliberately."
        )

    try:
        flow = PortFlowMap.load(args.flow_map, strict=not args.permissive)
    except (FileNotFoundError, ValueError) as e:
        raise CliError(str(e)) from e
    logger.debug(f"Loaded flow map: {args.flow_map}")
    return flow


def load_graph(args, flow: PortFlowMap) -> TopologyGraph:
    """Build the topology graph named by the parsed arguments

    Raises:
        CliError: If the topology path is missing or the model cannot be read.
    """
    if not args.topology_path.exists():
        raise CliError(f"Topology path not found: {args.topology_path}")
    try:
        return TopologyGraph(
            args.topology_path.resolve(), flow=flow, topology_name=args.topology
        ).load()
    except (FileNotFoundError, ValueError) as e:
        raise CliError(str(e)) from e


def report_error(error: CliError, verbose: bool = False) -> int:
    """Print a CliError the way every analyzer prints it, and give an exit code"""
    logger.error(str(error))
    if verbose:
        traceback.print_exc()
    return 1


def report_unresolved(error: UnresolvedFlowError) -> int:
    """Explain a strict-mode resolution failure and give an exit code"""
    logger.error(
        f"Could not resolve intra-component call flow for {error.component}."
        f"{error.entry}: {error.reason}"
    )
    logger.error(
        "Refusing to guess. Fix the flow map, or pass --permissive to assume "
        "unresolved handlers call every output port."
    )
    return 1


def write_or_print(text: str, path: Optional[Path]) -> None:
    """Write a report to ``path``, creating its directory, or print it"""
    if path is None:
        print(text)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    logger.debug(f"Wrote {path}")
