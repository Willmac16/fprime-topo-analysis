#!/usr/bin/env python3
"""
Parity harness: original fprime_async_analyzer vs the ported analyzer

Runs both tools over the same topology and accounts for every difference, so
the port can be shown to do the old tool's job rather than merely claimed to.

Differences are classified rather than just counted:

* ``equivalent``  - same fact, written differently (a resolved enum index where
  the original printed the unevaluated symbol).
* ``old-missing`` - a real connection the original did not find. Its pattern
  expansion was hand-rolled, so pattern-generated connections such as health
  pings were dropped.
* ``old-mangled`` - the original derived instance names with
  ``split(".")[-1]``, which turns ``CdhCore.Subtopology.cmdDisp`` into
  ``Subtopology``.
* ``regression``  - present in the original, absent from the port. Any of these
  is a genuine problem with the port and fails the check.

Usage:
    python3 tools/parity_check.py \\
        --old /path/to/fprime_async_analyzer.py \\
        --fprime-root /path/to/fprime \\
        --topology-path /path/to/topology-json \\
        --topology Ref.Ref

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Set

# An index printed as an unevaluated enum member, e.g. CycleOut[Ports.rg1]
SYMBOLIC_INDEX_RE = re.compile(r"^(?P<port>[^\[]+)\[[A-Za-z_][\w.]*\]$")
NUMERIC_INDEX_RE = re.compile(r"^(?P<port>[^\[]+)\[\d+\]$")


def leaf(name: str) -> str:
    """Last path element of a qualified instance name"""
    return name.split(".")[-1]


def strip_module(producer: str) -> str:
    """Drop a leading module qualifier from ``Module.instance.port``"""
    return re.sub(r"^[A-Za-z0-9_]+\.(?=[A-Za-z0-9_]+\.)", "", producer)


def base_port(producer: str) -> str:
    """Producer name with any index removed, for equivalence comparison"""
    for pattern in (SYMBOLIC_INDEX_RE, NUMERIC_INDEX_RE):
        match = pattern.match(producer)
        if match:
            return match.group("port")
    return producer


def run_old(old_tool: Path, fprime_root: Path, topology: str) -> List[Dict]:
    """Run the original analyzer and return its JSON rows

    Raises:
        RuntimeError: If the original tool fails
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "old.json"
        result = subprocess.run(
            [
                sys.executable, str(old_tool),
                "--root", str(fprime_root),
                "--topology", topology,
                "--format", "json",
                "--output", str(out),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0 or not out.exists():
            raise RuntimeError(
                f"original analyzer failed (exit {result.returncode}): "
                f"{result.stderr.strip()[-500:]}"
            )
        return json.loads(out.read_text())


def run_ported(topology_path: Path, topology: str, flow_map: Path = None) -> List[Dict]:
    """Run the ported analyzer and return its JSON rows

    Raises:
        RuntimeError: If the ported tool fails
    """
    from fprime_topology_analysis.async_queue_analyzer import analyze, rows_to_payload
    from fprime_topology_analysis.port_flow import PortFlowMap
    from fprime_topology_analysis.topology_graph import TopologyGraph

    flow = (
        PortFlowMap.load(flow_map) if flow_map else PortFlowMap.permissive()
    )
    graph = TopologyGraph(topology_path, flow=flow, topology_name=topology).load()
    return rows_to_payload(analyze(graph, {}), include_rates=False)


def producers_of(row: Dict) -> Set[str]:
    return {p for g in row["inbound_by_port"] for p in g["producers"]}


def classify(old_rows: List[Dict], new_rows: List[Dict]) -> Dict:
    """Compare the two result sets and classify every difference"""
    old = {leaf(r["destination"]): r for r in old_rows}
    new = {leaf(r["destination"]): r for r in new_rows}

    report = {
        "old_queues": len(old),
        "new_queues": len(new),
        "queues_only_in_old": sorted(set(old) - set(new)),
        "queues_only_in_new": sorted(set(new) - set(old)),
        "equivalent": [],
        "old_missing": [],
        "old_mangled": [],
        "regression": [],
    }

    for name in sorted(set(old) & set(new)):
        old_producers = producers_of(old[name])
        new_producers = {strip_module(p) for p in producers_of(new[name])}

        for producer in sorted(new_producers - old_producers):
            # An index the original printed symbolically is the same fact
            equivalent_old = {
                o for o in old_producers if base_port(o) == base_port(producer)
            }
            if equivalent_old:
                report["equivalent"].append(
                    {"queue": name, "old": sorted(equivalent_old)[0], "new": producer}
                )
            else:
                report["old_missing"].append({"queue": name, "producer": producer})

        for producer in sorted(old_producers - new_producers):
            if any(base_port(n) == base_port(producer) for n in new_producers):
                continue  # already recorded as equivalent
            # A name the original mangled has a matching port on another instance
            port = producer.split(".", 1)[-1]
            if any(n.split(".", 1)[-1] == port for n in new_producers):
                report["old_mangled"].append(
                    {"queue": name, "old": producer, "port": port}
                )
            else:
                report["regression"].append({"queue": name, "producer": producer})

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True, help="Original analyzer .py")
    parser.add_argument("--fprime-root", type=Path, required=True)
    parser.add_argument("--topology-path", type=Path, required=True)
    parser.add_argument("--topology", default="Ref.Ref")
    parser.add_argument("--flow-map", type=Path, default=None)
    parser.add_argument("--json-output", type=Path, default=None)
    args = parser.parse_args()

    old_rows = run_old(args.old, args.fprime_root, args.topology)
    new_rows = run_ported(args.topology_path, args.topology, args.flow_map)
    report = classify(old_rows, new_rows)

    print(f"original : {report['old_queues']} queues")
    print(f"ported   : {report['new_queues']} queues")
    print(f"  queues only the port finds : {len(report['queues_only_in_new'])}")
    print(f"  queues only the original finds : {len(report['queues_only_in_old'])}")
    print(f"  equivalent renderings : {len(report['equivalent'])}")
    print(f"  connections the original missed : {len(report['old_missing'])}")
    print(f"  names the original mangled : {len(report['old_mangled'])}")
    print(f"  REGRESSIONS : {len(report['regression'])}")
    for item in report["regression"]:
        print(f"    {item['queue']}: {item['producer']}")

    if args.json_output:
        args.json_output.write_text(json.dumps(report, indent=2))

    # Only a regression, or a queue the port lost, is a failure
    return len(report["regression"]) + len(report["queues_only_in_old"])


if __name__ == "__main__":
    sys.exit(main())
