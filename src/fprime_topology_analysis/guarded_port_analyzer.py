#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
Guarded Port Deadlock Analyzer - fprime_python_model Implementation

Analyzes an F' topology for lock-ordering hazards between guarded ports.

Every F' component instance owns exactly one guarded-port mutex
(``m_guardedPortMutex``). The generated ``*_handlerBase`` for a guarded input
port locks that mutex, calls the user handler, and only then unlocks it, so any
port the handler invokes is invoked *while the mutex is held*. When such a call
is synchronous it runs on the caller's thread and may lock a second component's
mutex, producing a nested lock acquisition.

This tool reconstructs those nested acquisitions from the topology and reports
lock-order cycles:

* ``SELF_DEADLOCK`` - one synchronous chain re-enters a mutex it already holds.
  ``Os::Mutex`` is not recursive, so this hangs unconditionally once the chain
  is taken.
* ``ABBA`` - a lock-order cycle two distinct real threads can drive in opposite
  orders: one thread takes A-then-B while another takes B-then-A. "Real" means a
  ``<thread:...>`` origin (an active/queued instance's own thread).

A cycle that no two distinct real threads are known to drive in opposite orders
(only one thread reaches it, or its only other attribution is ``<unknown>``) is
latent, not a current hazard, and is *not reported*. It becomes a real ABBA only
once a second thread reaches either side.

Only ``m_guardedPortMutex`` is modeled. The parameter mutex ``m_paramLock`` is a
leaf lock: the generated code always releases it before invoking an output port,
so it cannot take part in a cross-component cycle. (It *is* held across calls
into a user-supplied external-parameter delegate, which is C++ the topology does
not describe.)

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import sys
import argparse
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from . import cli
from .port_flow import UnresolvedFlowError
from .topology_graph import (
    STOP,
    THREAD_ORIGIN_PREFIX,
    UNKNOWN_THREAD,
    Hop,
    InstanceInfo,
    PortKey,
    Severity,
    SyncKind,
    TopologyGraph,
)

logger = logging.getLogger(__name__)

# Traversal bounds. A pathological topology can otherwise blow up: the search
# state includes the held-lock stack, which is exponential in the worst case.
DEFAULT_MAX_LOCK_DEPTH = 8
DEFAULT_MAX_STATES = 500000
DEFAULT_MAX_CYCLES = 50


class FindingKind(Enum):
    SELF_DEADLOCK = "SELF_DEADLOCK"
    ABBA = "ABBA"
    ABBA_SINGLE_THREAD = "ABBA_SINGLE_THREAD"

    def __str__(self):
        return self.value


@dataclass
class LockEdge:
    """``holder`` is held while ``acquired`` is locked"""

    holder: str
    acquired: str
    # The guarded input port whose handler was running when the chain started
    entry: PortKey
    # Human readable hop-by-hop witness, e.g. "a.out -> b.gIn [guarded]"
    witness: List[str] = field(default_factory=list)
    threads: Set[str] = field(default_factory=set)

    @property
    def key(self) -> Tuple[str, str]:
        return (self.holder, self.acquired)


@dataclass
class Finding:
    kind: FindingKind
    severity: Severity
    cycle: List[str]
    edges: List[LockEdge]
    detail: str = ""


class GuardedPortAnalyzer:
    """Builds and checks the guarded-mutex lock-order graph of a topology"""

    def __init__(
        self,
        graph: TopologyGraph,
        max_lock_depth: int = DEFAULT_MAX_LOCK_DEPTH,
        max_states: int = DEFAULT_MAX_STATES,
        max_cycles: int = DEFAULT_MAX_CYCLES,
        suppressions: Optional[Set[Tuple[str, str]]] = None,
        show_call_chains: bool = False,
    ):
        #: A loaded graph. The analyzer is policy over it and never reads the
        #: model itself, so every analysis sees the same topology.
        self.graph = graph
        self.max_lock_depth = max_lock_depth
        self.max_states = max_states
        self.max_cycles = max_cycles
        self.suppressions = suppressions or set()
        # Attach each edge's source-thread -> entry call chains to the report.
        self.show_call_chains = show_call_chains
        # (holder, acquired) -> representative edge
        self.lock_edges: Dict[Tuple[str, str], LockEdge] = {}
        self.findings: List[Finding] = []
        self.truncated = False

    @property
    def instances(self) -> Dict[str, InstanceInfo]:
        """Component instances, indexed by qualified name"""
        return self.graph.instances

    @property
    def connections(self) -> Dict[str, List[PortKey]]:
        """Topology connections, indexed by source port"""
        return self.graph.connections

    # ------------------------------------------------------------------
    # Thread-origin propagation
    # ------------------------------------------------------------------

    def _entry_threads(self, entry: PortKey) -> Set[str]:
        """Thread origins that can invoke a guarded entry port.

        Computed by TopologyGraph, which owns thread-origin propagation so the
        analyses cannot disagree about which threads reach a port.
        """
        return self.graph.threads_reaching(entry)

    # ------------------------------------------------------------------
    # Lock-order graph
    # ------------------------------------------------------------------

    def build_lock_graph(self) -> None:
        """Walk every guarded entry point, recording nested lock acquisitions.

        The traversal itself lives in TopologyGraph. All this supplies is the
        lock policy: a guarded hop takes a mutex and descends with it held, a
        sync hop descends unchanged, and an async hop ends the chain because
        the caller's locks are released before the message is serviced.
        """
        budget = [self.max_states]
        connected = self.graph.connected_inputs()
        for name in sorted(self.instances):
            info = self.instances[name]
            for port_name in info.guarded_entries():
                entry = PortKey(name, port_name)
                # Nothing drives an unconnected entry, so its handler never runs
                # and it starts no real lock chain. Walking it would only
                # manufacture phantom edges attributed to <unknown>.
                if str(entry) not in connected:
                    continue
                threads = self._entry_threads(entry)
                logger.debug(
                    f"Walking guarded entry {entry} threads={sorted(threads)}"
                )
                self.truncated |= self.graph.walk_chains(
                    entry=entry,
                    entry_kind=SyncKind.GUARDED,
                    on_hop=self._on_hop(entry, threads),
                    # State is the ordered stack of instance mutexes held
                    initial_state=(name,),
                    state_key=frozenset,
                    budget=budget,
                )

    def _on_hop(self, entry: PortKey, threads: Set[str]):
        """Build the lock policy callback for one guarded entry point"""

        def on_hop(hop: Hop):
            held: Tuple[str, ...] = hop.state

            if hop.kind == SyncKind.ASYNC:
                # The message is queued; the chain ends here and the caller's
                # locks are released before it is serviced.
                return STOP

            if hop.kind == SyncKind.SYNC:
                # Runs on this thread, takes no mutex of its own.
                return held

            # Guarded: acquires the destination instance's mutex
            if hop.dest.instance in held:
                self._record_self_deadlock(entry, hop.dest, held, hop.path, threads)
                return STOP

            for holder in held:
                self._record_edge(
                    holder, hop.dest.instance, entry, hop.path, threads
                )

            if len(held) >= self.max_lock_depth:
                logger.debug(
                    f"  Max lock depth {self.max_lock_depth} reached at {hop.dest}"
                )
                self.truncated = True
                return STOP

            return (*held, hop.dest.instance)

        return on_hop

    def _record_edge(
        self,
        holder: str,
        acquired: str,
        entry: PortKey,
        path: List[str],
        threads: Set[str],
    ) -> None:
        """Record that ``holder``'s mutex is held while ``acquired``'s is taken"""
        if (holder, acquired) in self.suppressions:
            return
        existing = self.lock_edges.get((holder, acquired))
        if existing is None:
            self.lock_edges[(holder, acquired)] = LockEdge(
                holder=holder,
                acquired=acquired,
                entry=entry,
                witness=list(path),
                threads=set(threads),
            )
        else:
            existing.threads |= threads
            # Keep the shortest witness; it is the easiest one to read
            if len(path) < len(existing.witness):
                existing.witness = list(path)
                existing.entry = entry

    def _record_self_deadlock(
        self,
        entry: PortKey,
        dest: PortKey,
        held: Tuple[str, ...],
        path: List[str],
        threads: Set[str],
    ) -> None:
        """Record a chain that re-enters a mutex it already holds"""
        if (dest.instance, dest.instance) in self.suppressions:
            return
        edge = LockEdge(
            holder=dest.instance,
            acquired=dest.instance,
            entry=entry,
            witness=list(path),
            threads=set(threads),
        )
        detail = (
            f"{dest.instance} re-enters its own guarded mutex while it is already "
            f"held (lock stack: {' -> '.join(held)}). Os::Mutex is not recursive, "
            f"so this hangs whenever the chain is taken."
        )
        for existing in self.findings:
            if (
                existing.kind == FindingKind.SELF_DEADLOCK
                and existing.cycle == [dest.instance]
            ):
                existing.edges[0].threads |= threads
                return
        self.findings.append(
            Finding(
                kind=FindingKind.SELF_DEADLOCK,
                severity=Severity.ERROR,
                cycle=[dest.instance],
                edges=[edge],
                detail=detail,
            )
        )

    # ------------------------------------------------------------------
    # Cycle detection
    # ------------------------------------------------------------------

    def _strongly_connected_components(self) -> List[List[str]]:
        """Tarjan's SCC over the lock-order graph (iterative)"""
        graph: Dict[str, List[str]] = {}
        for holder, acquired in self.lock_edges:
            graph.setdefault(holder, []).append(acquired)
            graph.setdefault(acquired, [])

        index_counter = [0]
        index: Dict[str, int] = {}
        lowlink: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: Set[str] = set()
        result: List[List[str]] = []

        for root in sorted(graph):
            if root in index:
                continue
            work: List[Tuple[str, int]] = [(root, 0)]
            while work:
                node, child_idx = work[-1]
                if child_idx == 0:
                    index[node] = lowlink[node] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(node)
                    on_stack.add(node)

                recursed = False
                children = graph[node]
                for i in range(child_idx, len(children)):
                    child = children[i]
                    if child not in index:
                        work[-1] = (node, i + 1)
                        work.append((child, 0))
                        recursed = True
                        break
                    if child in on_stack:
                        lowlink[node] = min(lowlink[node], index[child])
                if recursed:
                    continue

                if lowlink[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    result.append(component)

                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])

        return result

    def _elementary_cycles(self, component: List[str]) -> List[List[str]]:
        """Enumerate elementary cycles inside one SCC, shortest first"""
        members = set(component)
        adjacency: Dict[str, List[str]] = {
            node: sorted(
                acquired
                for (holder, acquired) in self.lock_edges
                if holder == node and acquired in members and acquired != node
            )
            for node in sorted(members)
        }

        cycles: List[List[str]] = []

        def dfs(node: str, start: str, path: List[str], on_path: Set[str]) -> None:
            if len(cycles) >= self.max_cycles:
                return
            for nxt in adjacency.get(node, []):
                if nxt == start:
                    cycles.append(list(path))
                    if len(cycles) >= self.max_cycles:
                        return
                    continue
                if nxt in on_path or nxt < start:
                    continue
                path.append(nxt)
                on_path.add(nxt)
                dfs(nxt, start, path, on_path)
                on_path.discard(nxt)
                path.pop()

        for start in sorted(members):
            # Only enumerate cycles whose smallest member is the start node,
            # so each elementary cycle is emitted exactly once.
            dfs(start, start, [start], {start})
            if len(cycles) >= self.max_cycles:
                self.truncated = True
                break

        cycles.sort(key=lambda c: (len(c), c))
        return cycles

    def _classify_cycle(self, cycle: List[str]) -> Tuple[FindingKind, Severity, str]:
        """Decide whether a lock-order cycle can actually interleave.

        A live deadlock needs two *distinct real threads* taking the locks in
        opposite orders - one edge driven by thread A, another by thread B != A.
        Only a ``<thread:...>`` origin counts as a real thread; ``<unknown>`` is
        not proof of a concurrent thread, so a cycle whose only "second thread"
        is ``<unknown>`` is latent (warning), not live (error).
        """
        edges = self._cycle_edges(cycle)
        real_sets = [
            {t for t in edge.threads if t.startswith(THREAD_ORIGIN_PREFIX)}
            for edge in edges
        ]
        distinct_possible = any(
            t1 != t2
            for i in range(len(real_sets))
            for j in range(i + 1, len(real_sets))
            for t1 in real_sets[i]
            for t2 in real_sets[j]
        )
        order = " -> ".join([*cycle, cycle[0]])

        if distinct_possible:
            return (
                FindingKind.ABBA,
                Severity.ERROR,
                f"Lock order cycle {order}. Different threads can take these "
                f"mutexes in opposite orders, so the chains can deadlock against "
                f"each other.",
            )

        real = sorted(set().union(*real_sets)) if real_sets else []
        reach = ", ".join(real) if real else "no attributed thread"
        return (
            FindingKind.ABBA_SINGLE_THREAD,
            Severity.WARNING,
            f"Lock order cycle {order}, but no two distinct threads are known to "
            f"drive it in opposite orders (real threads: {reach}). It cannot "
            f"interleave today; it becomes a deadlock as soon as a second thread "
            f"reaches either side.",
        )

    def _cycle_edges(self, cycle: List[str]) -> List[LockEdge]:
        edges = []
        for i, node in enumerate(cycle):
            nxt = cycle[(i + 1) % len(cycle)]
            edge = self.lock_edges.get((node, nxt))
            if edge is not None:
                edges.append(edge)
        return edges

    def detect_cycles(self) -> None:
        """Turn lock-order cycles into findings"""
        for component in self._strongly_connected_components():
            if len(component) < 2:
                continue
            for cycle in self._elementary_cycles(component):
                kind, severity, detail = self._classify_cycle(cycle)
                # Latent single-thread cycles are not a current hazard - they
                # need a second real thread wired in to deadlock - so they are
                # not reported.
                if kind == FindingKind.ABBA_SINGLE_THREAD:
                    continue
                self.findings.append(
                    Finding(
                        kind=kind,
                        severity=severity,
                        cycle=cycle,
                        edges=self._cycle_edges(cycle),
                        detail=detail,
                    )
                )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    @staticmethod
    def _thread_label(origin: str) -> str:
        """A thread origin as shown in the report, without the <thread:...> wrap."""
        if origin.startswith(THREAD_ORIGIN_PREFIX):
            return origin[len(THREAD_ORIGIN_PREFIX) : -1]
        return origin

    def _edge_call_chains(self, edge: LockEdge) -> Dict[str, List[str]]:
        """Per real thread, the call chain from its origin down to ``edge.entry``."""
        chains: Dict[str, List[str]] = {}
        for thread in sorted(self.graph.threads_reaching(edge.entry)):
            if not thread.startswith(THREAD_ORIGIN_PREFIX):
                continue
            path = self.graph.origin_call_path(thread, edge.entry)
            if path:
                chains[thread] = path
        return chains

    def format_report(self) -> str:
        lines: List[str] = []
        lines.append("=" * 72)
        lines.append("Guarded Port Deadlock Analysis")
        lines.append("=" * 72)
        lines.append("")
        guarded = {
            name: info.guarded_entries()
            for name, info in self.instances.items()
            if info.guarded_entries()
        }
        flow = self.graph.flow
        flow_lookups = flow.stats_precise + flow.stats_conservative
        if flow_lookups:
            flow_label = "C++ handlers resolved"
            flow_summary = f"{flow.stats_precise}/{flow_lookups}"
            if flow.stats_conservative:
                flow_summary += f" ({flow.stats_conservative} conservative)"
        else:
            flow_label = "C++ handler flow"
            flow_summary = "not required" if not flow.is_empty else "not available"
        summary_rows = (
            ("Component instances", str(len(self.instances))),
            ("Instances with guarded ports", str(len(guarded))),
            ("Lock-order edges", str(len(self.lock_edges))),
            (flow_label, flow_summary),
            ("Findings", str(len(self.findings))),
        )
        label_width = max(len(label) for label, _ in summary_rows) + 1
        lines.extend(
            f"{label + ':':<{label_width}}  {value}" for label, value in summary_rows
        )
        if self.truncated:
            lines.append(
                "NOTE: traversal hit a configured bound; results may be partial."
            )
        lines.append("")

        if not self.findings:
            lines.append("No guarded-port lock-order hazards found.")
            lines.append("")
            return "\n".join(lines)

        ordered = sorted(
            self.findings, key=lambda f: (-f.severity.rank, f.kind.value, f.cycle)
        )
        for i, finding in enumerate(ordered, start=1):
            lines.append("-" * 72)
            lines.append(
                f"[{i}] {finding.severity.value.upper()}: {finding.kind} "
                f"({' -> '.join([*finding.cycle, finding.cycle[0]])})"
            )
            lines.append("-" * 72)
            lines.append(f"  {finding.detail}")
            lines.append("")
            for edge in finding.edges:
                lines.append(
                    f"  While holding {edge.holder}, locks {edge.acquired}:"
                )
                lines.append(f"    entry:   {edge.entry}")
                # Only real <thread:...> origins interleave; <unknown> is latent,
                # so summarize any non-thread tokens as a count.
                real = sorted(
                    t for t in edge.threads if t.startswith(THREAD_ORIGIN_PREFIX)
                )
                labels = [self._thread_label(t) for t in real]
                threads_label = ", ".join(labels) if labels else "none attributed"
                if UNKNOWN_THREAD in edge.threads:
                    threads_label += "  (+unknown)"
                lines.append(f"    threads: {threads_label}")
                if self.show_call_chains:
                    for thread, path in self._edge_call_chains(edge).items():
                        lines.append(f"    reached by {self._thread_label(thread)}:")
                        lines.extend(f"        {hop}" for hop in path)
                lines.extend(f"      {hop}" for hop in edge.witness)
                lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        payload = {
            "topology": str(self.graph.topology_path),
            "truncated": self.truncated,
            "instances": {
                name: {
                    "kind": str(info.kind),
                    "guarded_entries": info.guarded_entries(),
                }
                for name, info in sorted(self.instances.items())
            },
            "lock_edges": [
                {
                    "holder": edge.holder,
                    "acquired": edge.acquired,
                    "entry": str(edge.entry),
                    "threads": sorted(edge.threads),
                    "witness": edge.witness,
                }
                for edge in sorted(
                    self.lock_edges.values(), key=lambda e: (e.holder, e.acquired)
                )
            ],
            "findings": [
                {
                    "kind": str(finding.kind),
                    "severity": str(finding.severity),
                    "cycle": finding.cycle,
                    "detail": finding.detail,
                    "edges": [
                        {
                            "holder": edge.holder,
                            "acquired": edge.acquired,
                            "entry": str(edge.entry),
                            "threads": sorted(edge.threads),
                            "witness": edge.witness,
                            **(
                                {"call_chains": self._edge_call_chains(edge)}
                                if self.show_call_chains
                                else {}
                            ),
                        }
                        for edge in finding.edges
                    ],
                }
                for finding in self.findings
            ],
        }
        return json.dumps(payload, indent=2)

    def to_dot(self) -> str:
        in_cycle = {
            edge.key for finding in self.findings for edge in finding.edges
        }
        lines = ["digraph guarded_lock_order {", '  rankdir="LR";', "  node [shape=box];"]
        lines.extend(
            f'  "{name}";'
            for name in sorted(
                {e.holder for e in self.lock_edges.values()}
                | {e.acquired for e in self.lock_edges.values()}
            )
        )
        for edge in sorted(
            self.lock_edges.values(), key=lambda e: (e.holder, e.acquired)
        ):
            attrs = 'color="red", penwidth=2' if edge.key in in_cycle else ""
            suffix = f' [{attrs}]' if attrs else ""
            lines.append(f'  "{edge.holder}" -> "{edge.acquired}"{suffix};')
        lines.append("}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        """Run the full analysis and return the findings"""
        logger.info(
            f"Found {len(self.instances)} component instances, "
            f"{self.graph.connection_count} connections"
        )

        self.build_lock_graph()
        self.detect_cycles()
        logger.info(
            f"Lock-order graph: {len(self.lock_edges)} edges, "
            f"{len(self.findings)} findings"
        )
        return self.findings


def load_suppressions(path: Path) -> Set[Tuple[str, str]]:
    """Read a suppression file of ``holder -> acquired`` lock-order pairs.

    A bare instance name suppresses that instance's self-deadlock edge. Use
    this to record a lock ordering that is enforced by construction outside the
    topology; each entry hides a real edge, so keep them commented.
    """
    suppressions: Set[Tuple[str, str]] = set()
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "->" in line:
            holder, acquired = (part.strip() for part in line.split("->", 1))
            if holder and acquired:
                suppressions.add((holder, acquired))
        else:
            suppressions.add((line, line))
    return suppressions


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an F' topology for guarded-port lock-order hazards "
            "(ABBA deadlocks) using fprime_python_model"
        ),
        epilog="Requires FPRIME_ENABLE_JSON_MODEL_GENERATION in CMakeLists.txt",
    )
    cli.add_topology_args(parser)
    cli.add_report_args(parser)
    parser.add_argument(
        "--suppress",
        type=Path,
        help="File of 'holder -> acquired' lock orderings to ignore",
    )
    parser.add_argument(
        "--call-chains",
        action="store_true",
        help="Show, per finding edge, the full call chain from each driving "
        "thread's origin down to the guarded entry",
    )
    for flag, default, what in (
        ("--max-lock-depth", DEFAULT_MAX_LOCK_DEPTH, "nested guarded locks to explore"),
        ("--max-states", DEFAULT_MAX_STATES, "traversal states"),
        ("--max-cycles", DEFAULT_MAX_CYCLES, "cycles to report per lock group"),
    ):
        parser.add_argument(
            flag, type=int, default=default, help=f"Maximum {what} (default {default})"
        )
    args = cli.parse_args(parser)
    cli.configure_logging(args.verbose)

    suppressions = set()
    if args.suppress:
        if not args.suppress.exists():
            logger.error(f"Suppression file not found: {args.suppress}")
            return 1
        suppressions = load_suppressions(args.suppress)
        logger.info(f"Loaded {len(suppressions)} suppressions from {args.suppress}")

    try:
        graph = cli.load_graph(args, cli.load_flow(args))
    except cli.CliError as e:
        return cli.report_error(e, args.verbose)

    analyzer = GuardedPortAnalyzer(
        graph=graph,
        max_lock_depth=args.max_lock_depth,
        max_states=args.max_states,
        max_cycles=args.max_cycles,
        suppressions=suppressions,
        show_call_chains=args.call_chains,
    )

    try:
        findings = analyzer.run()
    except UnresolvedFlowError as e:
        return cli.report_unresolved(e)

    cli.write_or_print(analyzer.format_report(), args.output)
    if args.json:
        cli.write_or_print(analyzer.to_json(), args.json)
    if args.fail_on == "never":
        return 0

    threshold = Severity(args.fail_on).rank
    failing = [f for f in findings if f.severity.rank >= threshold]
    if failing:
        logger.error(
            f"{len(failing)} finding(s) at or above severity '{args.fail_on}'"
        )
    return len(failing)


if __name__ == "__main__":
    sys.exit(main())
