#!/usr/bin/env python3
"""
Topology checks - one registry of analyses over the shared graph

Each check is policy over the tagged topology graph and the C++ flow map. They
share the graph's traversal, its dispatch tagging and its thread-origin
propagation, so they cannot disagree about what "async" means or which threads
reach a port.

A check declares whether it needs the flow map. Checks that do are skipped with
a note when none is supplied, rather than reporting on guesses.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .topology_graph import (
    UNKNOWN_THREAD,
    InstanceInfo,
    PortKey,
    Severity,
    SyncKind,
    TopologyGraph,
)

logger = logging.getLogger(__name__)

# Port types the checks recognize structurally, rather than by instance name
PING_TYPE = "Svc.Ping"
SCHED_TYPE = "Svc.Sched"
CYCLE_TYPE = "Svc.Cycle"
BUFFER_SEND_TYPE = "Fw.BufferSend"
BUFFER_GET_TYPE = "Fw.BufferGet"
TIME_TYPE = "Fw.Time"
LOG_TYPE = "Fw.Log"
TLM_TYPE = "Fw.Tlm"

FATAL_SEVERITY = "FATAL"


@dataclass
class Finding:
    """One result from one check"""

    check: str
    severity: Severity
    subject: str
    message: str
    evidence: List[str] = field(default_factory=list)


class Check(ABC):
    """A single analysis over the graph"""

    id: str = ""
    name: str = ""
    #: Whether the check's answer is only meaningful with real C++ call flow
    requires_flow: bool = False

    @abstractmethod
    def run(self, graph: TopologyGraph) -> List[Finding]:
        """Produce findings for one topology"""

    def finding(
        self,
        severity: Severity,
        subject: str,
        message: str,
        evidence: Optional[List[str]] = None,
    ) -> Finding:
        """One finding from this check, stamped with its id"""
        return Finding(self.id, severity, subject, message, evidence or [])

    # -- helpers shared by several checks --------------------------------

    @staticmethod
    def thread_priority(graph: TopologyGraph, origin: str) -> Optional[int]:
        """Task priority behind a thread origin label, when it names one"""
        if not origin.startswith("<thread:"):
            return None
        instance = origin[len("<thread:") : -1]
        info = graph.instances.get(instance)
        return info.task_priority if info else None

    @staticmethod
    def handlers(info: InstanceInfo) -> List[Tuple[str, str, SyncKind]]:
        """Every (port, flow entry, kind) triple on an instance"""
        return [
            (port, entry, kind)
            for port, kinds in sorted(info.input_ports.items())
            for kind in sorted(kinds, key=str)
            for entry in info.flow_entries(port, kind)
        ]

    @staticmethod
    def ports_of_type(info: InstanceInfo, type_name: str) -> List[str]:
        """Every port of one FPP port type, input or output"""
        return sorted(port for port, ty in info.port_types.items() if ty == type_name)

    @staticmethod
    def outputs_of_type(info: InstanceInfo, type_name: str) -> List[str]:
        return [p for p in Check.ports_of_type(info, type_name) if p in info.output_ports]

    @staticmethod
    def inputs_of_type(info: InstanceInfo, type_name: str) -> List[str]:
        return [p for p in Check.ports_of_type(info, type_name) if p in info.input_ports]

    @staticmethod
    def reached_by_type(
        graph: TopologyGraph, instance: str, info: InstanceInfo, type_name: str
    ) -> Set[str]:
        """Instances wired to this one's output ports of a given port type"""
        return {
            dest.instance
            for port in Check.outputs_of_type(info, type_name)
            for dest in graph.destinations(instance, port)
        }


# ----------------------------------------------------------------------
# 2 - priority inversion window
# ----------------------------------------------------------------------


class PriorityInversionWindow(Check):
    """Spread of task priorities contending for one instance's mutex"""

    id = "priority-inversion-window"
    name = "Priority inversion window"
    # Thread-origin propagation walks the flow map
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            guarded = info.guarded_entries()
            if not guarded:
                continue

            origins: Set[str] = set()
            for port in guarded:
                origins |= graph.threads_reaching(PortKey(name, port))

            priorities = {
                origin: self.thread_priority(graph, origin) for origin in origins
            }
            known = {o: p for o, p in priorities.items() if p is not None}
            if len(set(known.values())) < 2:
                continue

            low = min(known.items(), key=lambda kv: kv[1])
            high = max(known.items(), key=lambda kv: kv[1])
            window = high[1] - low[1]

            evidence = [f"guarded ports: {', '.join(guarded)}"]
            evidence += [
                f"  {origin} priority {priority}"
                for origin, priority in sorted(known.items(), key=lambda kv: (-kv[1], kv[0]))
            ]
            unknown = sorted(o for o, p in priorities.items() if p is None)
            if unknown:
                evidence.append(f"  unattributed callers: {', '.join(unknown)}")

            findings.append(
                self.finding(
                    severity=Severity.WARNING if window >= 10 else Severity.INFO,
                    subject=name,
                    message=(
                        f"{name}'s mutex is taken by threads spanning "
                        f"{window} priority levels ({low[1]} to {high[1]}). While "
                        f"the lowest holds it, the highest waits for the whole "
                        f"critical section. Severity depends on the Os layer: a "
                        f"priority-inheriting mutex bounds this, a plain one "
                        f"does not."
                    ),
                    evidence=evidence,
                )
            )
        return findings


# ----------------------------------------------------------------------
# 3 - unconnected output port actually invoked
# ----------------------------------------------------------------------


class UnconnectedPortInvoked(Check):
    """A handler invokes an output port nothing is wired to, which asserts"""

    id = "unconnected-port-invoked"
    name = "Unconnected port invoked"
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            unconnected = {
                port
                for port in info.output_ports
                if not graph.destinations(name, port)
            }
            if not unconnected:
                continue

            for port, entry, _kind in self.handlers(info):
                invoked = set(graph.outputs_for(info, entry))
                # A call guarded by isConnected_<port>_OutputPort is correct
                guarded = set(
                    graph.flow.facet(info.component_name, entry, "guarded_ports")
                )
                offending = sorted((invoked & unconnected) - guarded)
                if not offending:
                    continue

                reachable = graph.threads_reaching(PortKey(name, port))
                findings.append(
                    self.finding(
                        severity=Severity.WARNING,
                        subject=f"{name}.{port}",
                        message=(
                            f"Handler {entry} can reach "
                            f"{', '.join(offending)}, which nothing is connected "
                            f"to and which it does not guard with isConnected. "
                            f"Calling an unconnected output port asserts. This is "
                            f"call-graph reachability, not proof of execution: a "
                            f"data-condition guard - a flag only set when the "
                            f"feature is wired - is a common and legitimate "
                            f"reason for the path never to be taken."
                        ),
                        evidence=[
                            f"reachable from: {', '.join(sorted(reachable))}"
                        ],
                    )
                )
        return findings


# ----------------------------------------------------------------------
# 4 - pure sync cycles
# ----------------------------------------------------------------------


class SyncCycle(Check):
    """A cycle of sync ports takes no mutex, so it is unbounded recursion"""

    id = "sync-cycle"
    name = "Pure sync cycle"
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        reported: Set[Tuple[str, ...]] = set()

        for name, info in sorted(graph.instances.items()):
            for port, entry, kind in self.handlers(info):
                if kind != SyncKind.SYNC:
                    continue
                self._walk(
                    graph, name, entry, [f"{name}.{port}"], set(), findings, reported
                )
        return findings

    def _walk(self, graph, instance, entry, path, on_path, findings, reported):
        """Follow sync-only hops, reporting a revisit of the current path"""
        node = (instance, entry)
        if node in on_path:
            cycle = tuple(sorted({step.split(".")[0] for step in path}))
            if cycle in reported:
                return
            reported.add(cycle)
            findings.append(
                self.finding(
                    severity=Severity.WARNING,
                    subject=" -> ".join(path[-6:]),
                    message=(
                        "These handlers call each other through sync ports only. "
                        "No mutex is taken, so this is not a deadlock - it is "
                        "unbounded recursion on a fixed stack if the chain does "
                        "not terminate on a data condition."
                    ),
                    evidence=path[-8:],
                )
            )
            return
        if len(path) > 24:
            return

        on_path = on_path | {node}

        for _source, dest, dest_info, _kind in graph.outward_hops(instance, entry):
            # Sync only: a guarded hop is the deadlock analyzer's business, and
            # an async hop is a thread boundary. The port has to be purely
            # sync, not sync under one alias and guarded under another.
            if dest_info.input_ports.get(dest.port) != {SyncKind.SYNC}:
                continue
            for nxt in dest_info.flow_entries(dest.port, SyncKind.SYNC):
                self._walk(
                    graph,
                    dest.instance,
                    nxt,
                    [*path, f"{dest}"],
                    on_path,
                    findings,
                    reported,
                )


# ----------------------------------------------------------------------
# 5 - ping coverage and vacuous liveness
# ----------------------------------------------------------------------


class PingCoverage(Check):
    """Threads that are unmonitored, or monitored in a way that proves nothing"""

    id = "ping-coverage"
    name = "Liveness monitoring"

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            if not info.is_own_thread:
                continue

            ping_inputs = self.inputs_of_type(info, PING_TYPE)
            connected = [
                port for port in ping_inputs if str(PortKey(name, port)) in graph.connected_inputs()
            ]

            if not connected:
                findings.append(
                    self.finding(
                        severity=Severity.WARNING,
                        subject=name,
                        message=(
                            f"{name} runs its own thread but no health ping "
                            f"reaches it. If that thread wedges, nothing notices."
                        ),
                        evidence=[f"kind: {info.kind}"],
                    )
                )
                continue

            for port in connected:
                kinds = info.input_ports.get(port, set())
                if SyncKind.ASYNC in kinds:
                    continue
                findings.append(
                    self.finding(
                        severity=Severity.ERROR,
                        subject=f"{name}.{port}",
                        message=(
                            f"The ping port is {'/'.join(str(k) for k in sorted(kinds, key=str))}, "
                            f"not async, so it is answered on the pinger's thread. "
                            f"It proves nothing about {name}'s own thread, while "
                            f"reporting healthy."
                        ),
                        evidence=[f"instance kind: {info.kind}"],
                    )
                )
        return findings


# ----------------------------------------------------------------------
# 6 - member data race
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class MemberAccess:
    """One handler's touch of one component member"""

    handler: str
    kind: SyncKind
    threads: FrozenSet[str]
    writes: bool
    #: Locks the handler holds across the access, beyond the component mutex
    locks: Tuple[str, ...] = ()


class DataRace(Check):
    """Members reached by more than one thread, with at least one writer"""

    id = "data-race"
    name = "Member data race"
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            for member, accesses in sorted(self._access_map(graph, name, info).items()):
                finding = self.classify(name, member, accesses)
                if finding:
                    findings.append(finding)
        return findings

    def _access_map(
        self, graph: TopologyGraph, name: str, info: InstanceInfo
    ) -> Dict[str, List[MemberAccess]]:
        """Which threads reach each member of one instance, and how.

        An async handler runs on the instance's own thread and is serialized
        with its other async handlers by the queue, so it is recorded as that
        one thread. A sync or guarded handler runs on whichever thread called
        it, which is what makes the same member reachable from several.
        """
        access: Dict[str, List[MemberAccess]] = {}
        for port, entry, kind in self.handlers(info):
            reads = graph.flow.facet(info.component_name, entry, "fields_read")
            writes = graph.flow.facet(info.component_name, entry, "fields_written")
            locks = graph.flow.facet(info.component_name, entry, "locks_taken")
            if not reads and not writes:
                continue

            if kind == SyncKind.ASYNC:
                threads = frozenset({f"<thread:{name}>"})
            else:
                threads = frozenset(graph.threads_reaching(PortKey(name, port)))

            for member, writing in [(m, False) for m in reads] + [
                (m, True) for m in writes
            ]:
                access.setdefault(member, []).append(
                    MemberAccess(
                        handler=f"{port}:{entry}",
                        kind=kind,
                        threads=threads,
                        writes=writing,
                        locks=tuple(sorted(locks)),
                    )
                )
        return access

    @staticmethod
    def _is_synchronized(accesses: List[MemberAccess]) -> bool:
        """Whether something already serializes every access to this member"""
        # A component may synchronize with its own mutex member instead of
        # relying on guarded ports. If every accessor takes a common lock, the
        # member is protected just as well.
        common = set(accesses[0].locks)
        for entry in accesses[1:]:
            common &= set(entry.locks)
        if common:
            return True
        # The component mutex serializes guarded handlers with each other.
        if all(e.kind == SyncKind.GUARDED or e.locks for e in accesses):
            return True
        # An async-only member is serialized by the instance's own queue.
        return all(e.kind == SyncKind.ASYNC for e in accesses)

    @staticmethod
    def _summarize(unguarded: List[MemberAccess]) -> Tuple[Severity, str]:
        """How bad the unsynchronized access pattern is, and how to say it"""
        writing = [e for e in unguarded if e.writes]
        writers = sorted(e.handler for e in writing)
        writer_threads = set().union(*(e.threads for e in writing)) if writing else set()

        if not writers:
            # Every write is synchronized; an unguarded reader can still see a
            # torn value, but that is a weaker claim.
            return Severity.INFO, (
                "is written only under synchronization, but read outside it"
            )
        if len(writing) >= 2 and len(writer_threads) >= 2:
            # Two unsynchronized writers on different threads: the writes
            # themselves interleave, which can lose one entirely.
            return Severity.WARNING, (
                f"is written from {len(writer_threads)} threads with no "
                f"synchronization, by {', '.join(writers)}"
            )
        # One writer, with readers on other threads. A reader can observe a
        # stale or partially written value, but the writes cannot lose each
        # other.
        return Severity.INFO, (
            f"is written without synchronization by {', '.join(writers)} "
            f"while other threads read it"
        )

    def classify(
        self, name: str, member: str, accesses: List[MemberAccess]
    ) -> Optional[Finding]:
        """Decide whether one member's access pattern is a race"""
        if not accesses:
            return None
        threads: Set[str] = set().union(*(e.threads for e in accesses))

        # One thread cannot race with itself, and shared reads are safe
        if len(threads) < 2 and UNKNOWN_THREAD not in threads:
            return None
        if not any(e.writes for e in accesses):
            return None
        if self._is_synchronized(accesses):
            return None

        unguarded = [e for e in accesses if e.kind != SyncKind.GUARDED and not e.locks]
        severity, summary = self._summarize(unguarded)

        short = member.rsplit("::", 1)[-1]
        reach = (
            "is reached from a caller no thread origin accounts for"
            if threads == {UNKNOWN_THREAD}
            else f"is reached by {len(threads)} threads"
        )
        return self.finding(
            severity=severity,
            subject=f"{name}.{short}",
            message=(
                f"{short} {reach} and {summary}. Concurrent access to it is "
                f"unsynchronized."
            ),
            evidence=[
                f"threads reaching this member: {', '.join(sorted(threads))}",
                *(
                    f"  {e.handler} [{e.kind}] "
                    f"{'writes' if e.writes else 'reads'} - "
                    f"{', '.join(sorted(e.threads))}"
                    for e in sorted(accesses, key=lambda e: e.handler)
                ),
            ],
        )


# ----------------------------------------------------------------------
# 7 - buffer ownership
# ----------------------------------------------------------------------


class BufferOwnership(Check):
    """A buffer must go back to the manager it came from"""

    id = "buffer-ownership"
    name = "Buffer ownership"

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []

        for name, info in sorted(graph.instances.items()):
            # Where does this instance allocate from?
            allocators = self.reached_by_type(graph, name, info, BUFFER_GET_TYPE)
            if not allocators:
                continue

            # Where does it hand buffers back to? Only a manager counts as a
            # return; a peer that takes the buffer on is a handoff.
            returns = {
                dest
                for dest in self.reached_by_type(graph, name, info, BUFFER_SEND_TYPE)
                if self.ports_of_type(graph.instances[dest], BUFFER_GET_TYPE)
            }

            crossed = returns - allocators
            if crossed:
                findings.append(
                    self.finding(
                        severity=Severity.ERROR,
                        subject=name,
                        message=(
                            f"{name} allocates from {', '.join(sorted(allocators))} "
                            f"but returns buffers to {', '.join(sorted(crossed))}. "
                            f"A buffer manager asserts on a buffer it did not "
                            f"hand out."
                        ),
                        evidence=[
                            f"allocates from: {', '.join(sorted(allocators))}",
                            f"returns to: {', '.join(sorted(returns))}",
                        ],
                    )
                )

        # A component that receives buffers and can never pass one on
        for name, info in sorted(graph.instances.items()):
            receives = [
                port
                for port in self.inputs_of_type(info, BUFFER_SEND_TYPE)
                if str(PortKey(name, port)) in graph.connected_inputs()
            ]
            if receives and not self.outputs_of_type(info, BUFFER_SEND_TYPE):
                findings.append(
                    self.finding(
                        severity=Severity.WARNING,
                        subject=name,
                        message=(
                            f"{name} receives buffers on "
                            f"{', '.join(receives)} but declares no "
                            f"{BUFFER_SEND_TYPE} output. A buffer that arrives "
                            f"here cannot leave."
                        ),
                        evidence=[f"inbound: {', '.join(receives)}"],
                    )
                )
        return findings


# ----------------------------------------------------------------------
# 8 - synchronous stack depth
# ----------------------------------------------------------------------


class StackDepth(Check):
    """Deepest synchronous chain per thread, against the declared stack"""

    id = "stack-depth"
    name = "Synchronous stack depth"
    requires_flow = True

    #: Report a chain at least this deep; shallower ones are noise
    MIN_DEPTH = 4

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            if not info.is_own_thread:
                continue
            deepest: List[str] = []
            for port, entry, kind in self.handlers(info):
                if kind != SyncKind.ASYNC:
                    continue
                chain = self._deepest(graph, name, entry, [f"{name}.{port}"], set())
                if len(chain) > len(deepest):
                    deepest = chain
            if len(deepest) < self.MIN_DEPTH:
                continue
            findings.append(
                self.finding(
                    severity=Severity.INFO,
                    subject=name,
                    message=(
                        f"Deepest synchronous chain on this thread is "
                        f"{len(deepest)} components. They all run on "
                        f"{name}'s stack"
                        + (
                            f", declared {info.stack_size} bytes."
                            if info.stack_size
                            else ", whose size is not declared."
                        )
                    ),
                    evidence=deepest,
                )
            )
        return findings

    def _deepest(self, graph, instance, entry, path, seen):
        node = (instance, entry)
        if node in seen or len(path) > 24:
            return path
        seen = seen | {node}

        best = path
        for _source, dest, dest_info, kind in graph.outward_hops(instance, entry):
            if kind == SyncKind.ASYNC:
                continue  # a new thread, and a new stack
            for nxt in dest_info.flow_entries(dest.port, kind):
                candidate = self._deepest(
                    graph, dest.instance, nxt, [*path, f"{dest}"], seen
                )
                if len(candidate) > len(best):
                    best = candidate
        return best


# ----------------------------------------------------------------------
# 9 - rate group members
# ----------------------------------------------------------------------


class RateGroupBudget(Check):
    """A rate group member's sync closure runs inside one cycle"""

    id = "rate-group"
    name = "Rate group members"
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            sched_outputs = self.outputs_of_type(info, SCHED_TYPE)
            cycle_inputs = self.inputs_of_type(info, CYCLE_TYPE)
            if not (sched_outputs and cycle_inputs):
                continue

            members = [
                str(dest)
                for port in sched_outputs
                for dest in graph.destinations(name, port)
            ]

            contended: List[str] = []
            for port in sched_outputs:
                for dest in graph.destinations(name, port):
                    dest_info = graph.instances.get(dest.instance)
                    if dest_info is None:
                        continue
                    if SyncKind.ASYNC in dest_info.input_ports.get(dest.port, set()):
                        continue
                    if dest_info.guarded_entries():
                        others = graph.threads_reaching(dest) - {f"<thread:{name}>"}
                        if others:
                            contended.append(
                                f"{dest} takes {dest.instance}'s mutex, also "
                                f"reached from {', '.join(sorted(others))}"
                            )

            findings.append(
                self.finding(
                    severity=Severity.WARNING if contended else Severity.INFO,
                    subject=name,
                    message=(
                        f"Rate group with {len(members)} member call(s), all "
                        f"running to completion on this thread each cycle"
                        + (
                            f". {len(contended)} member(s) take a mutex another "
                            f"thread also takes, which can stall the cycle."
                            if contended
                            else "."
                        )
                    ),
                    evidence=(contended or members)[:10],
                )
            )
        return findings


# ----------------------------------------------------------------------
# 10 - FATAL path
# ----------------------------------------------------------------------


class FatalPath(Check):
    """Whether a FATAL report can be dropped or queued before it is seen"""

    id = "fatal-path"
    name = "FATAL reporting path"
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            emitters = [
                (port, entry)
                for port, entry, _kind in self.handlers(info)
                if FATAL_SEVERITY
                in graph.flow.facet(info.component_name, entry, "event_severities")
            ]
            if not emitters:
                continue

            hazards: List[str] = []
            for log_port in self.ports_of_type(info, LOG_TYPE):
                if log_port not in info.output_ports:
                    continue
                for dest in graph.destinations(name, log_port):
                    dest_info = graph.instances.get(dest.instance)
                    if dest_info is None:
                        continue
                    behavior = dest_info.port_queue_full.get(dest.port, "assert")
                    kinds = dest_info.input_ports.get(dest.port, set())
                    if SyncKind.ASYNC in kinds:
                        hazards.append(
                            f"{dest} is async ({behavior}) - the report is queued "
                            f"before it is downlinked"
                        )
                    if behavior == "drop":
                        hazards.append(f"{dest} may drop the report under load")

            if not hazards:
                continue
            findings.append(
                self.finding(
                    severity=Severity.WARNING,
                    subject=name,
                    message=(
                        f"{name} emits a FATAL event, but its reporting path can "
                        f"queue or drop before the report leaves the vehicle."
                    ),
                    evidence=[
                        f"emitters: {', '.join(e for _p, e in emitters)}",
                        *sorted(set(hazards)),
                    ],
                )
            )
        return findings


# ----------------------------------------------------------------------
# 11 - provable queue overflow
# ----------------------------------------------------------------------


class QueueOverflow(Check):
    """One stimulus enqueuing more messages than a queue can hold"""

    id = "queue-overflow"
    name = "Queue fan-out"
    requires_flow = True

    #: A dispatcher's port array reaches every component, but one opcode routes
    #: to exactly one of them. Static reachability cannot see that, so counts
    #: through a wide port array overstate what one stimulus really enqueues.
    ARRAY_FANOUT_CAVEAT = (
        "Counts follow every wired connection. Where a port array is routed by "
        "opcode or index at run time, only one destination actually fires, so "
        "the count is an upper bound."
    )

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            for port, entry, kind in self.handlers(info):
                if kind != SyncKind.ASYNC:
                    continue
                counts: Dict[str, int] = {}
                via_array: Set[str] = set()
                self._count(graph, name, entry, counts, set(), via_array)
                for target, messages in sorted(counts.items()):
                    target_info = graph.instances.get(target)
                    if target_info is None or target_info.queue_size is None:
                        continue
                    if messages <= target_info.queue_size:
                        continue

                    # Only a self-enqueue is a proof. When the target is another
                    # instance it drains on its own thread while this handler is
                    # still running, so "more messages than the queue holds"
                    # says nothing about whether they are ever queued at once.
                    # A count that reached the target through a port array wider
                    # than one is an upper bound, not a proof: the array is
                    # routed at run time and only one entry fires.
                    provable = target == name and target not in via_array
                    behavior = target_info.port_queue_full.get(port, "assert")
                    if provable:
                        message = (
                            f"One message on {name}.{port} can enqueue "
                            f"{messages} messages back onto {name}'s own queue, "
                            f"which holds {target_info.queue_size}. The thread is "
                            f"inside this handler, so nothing drains them "
                            f"meanwhile. Under the {behavior} policy an overflow "
                            f"is a FATAL. {self.ARRAY_FANOUT_CAVEAT}"
                        )
                    else:
                        message = (
                            f"One message on {name}.{port} fans out to "
                            f"{messages} messages onto {target}, which holds "
                            f"{target_info.queue_size}. {target} drains on its "
                            f"own thread concurrently, so this is an "
                            f"amplification ratio to look at, not a proof of "
                            f"overflow."
                        )
                    findings.append(
                        self.finding(
                            severity=Severity.ERROR if provable else Severity.INFO,
                            subject=target,
                            message=message,
                            evidence=[f"stimulus: {name}.{port} (handler {entry})"],
                        )
                    )
        return findings

    def _count(self, graph, instance, entry, counts, seen, via_array, depth=0):
        """Count async messages one stimulus produces, following sync hops"""
        node = (instance, entry)
        if node in seen or depth > 12:
            return
        seen = seen | {node}
        info = graph.instances.get(instance)
        if info is None:
            return

        for source, dest, dest_info, kind in graph.outward_hops(instance, entry):
            wide = info.port_sizes.get(source.port, 1) > 1
            if wide:
                via_array.add(dest.instance)
            if kind == SyncKind.ASYNC:
                # One wired connection is one message. The port array size is
                # already reflected in how many destinations there are, so
                # multiplying by it again double-counts.
                counts[dest.instance] = counts.get(dest.instance, 0) + 1
                continue
            for nxt in dest_info.flow_entries(dest.port, kind):
                self._count(
                    graph, dest.instance, nxt, counts, seen, via_array, depth + 1
                )


# ----------------------------------------------------------------------
# 12 - command and telemetry completeness
# ----------------------------------------------------------------------


class CommandTelemetryPaths(Check):
    """Ports a deployment needs wired, that fpp-check does not require"""

    id = "cmd-tlm-paths"
    name = "Command and telemetry paths"

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            connected = graph.connected_inputs()

            if (
                info.command_kinds
                and info.cmd_port
                and str(PortKey(name, info.cmd_port)) not in connected
            ):
                    findings.append(
                        self.finding(
                            severity=Severity.ERROR,
                            subject=f"{name}.{info.cmd_port}",
                            message=(
                                f"{name} defines "
                                f"{len(info.command_kinds)} command(s) but its "
                                f"command port is not connected to a dispatcher, "
                                f"so none can be sent."
                            ),
                        )
                    )

            for type_name, label in (
                (TIME_TYPE, "time"),
                (LOG_TYPE, "event"),
                (TLM_TYPE, "telemetry"),
            ):
                for port in self.ports_of_type(info, type_name):
                    if port not in info.output_ports:
                        continue
                    if graph.destinations(name, port):
                        continue
                    severity = (
                        Severity.WARNING if type_name == TIME_TYPE else Severity.INFO
                    )
                    detail = (
                        "every event and channel from this component is "
                        "timestamped zero"
                        if type_name == TIME_TYPE
                        else f"its {label} output goes nowhere"
                    )
                    findings.append(
                        self.finding(
                            severity=severity,
                            subject=f"{name}.{port}",
                            message=f"{label.capitalize()} port unconnected: {detail}.",
                        )
                    )
        return findings


# ----------------------------------------------------------------------
# 13 - CPU affinity
# ----------------------------------------------------------------------


class CpuAffinity(Check):
    """Mutexes contended by threads pinned to different CPUs run truly parallel"""

    id = "cpu-affinity"
    name = "CPU affinity"
    # Needs to know which threads reach the mutex
    requires_flow = True

    def run(self, graph: TopologyGraph) -> List[Finding]:
        findings: List[Finding] = []
        for name, info in sorted(graph.instances.items()):
            guarded = info.guarded_entries()
            if not guarded:
                continue
            cpus: Dict[int, Set[str]] = {}
            for port in guarded:
                for origin in graph.threads_reaching(PortKey(name, port)):
                    if not origin.startswith("<thread:"):
                        continue
                    holder = graph.instances.get(origin[len("<thread:") : -1])
                    if holder is None or holder.cpu is None:
                        continue
                    cpus.setdefault(holder.cpu, set()).add(origin)
            if len(cpus) < 2:
                continue
            findings.append(
                self.finding(
                    severity=Severity.INFO,
                    subject=name,
                    message=(
                        f"{name}'s mutex is contended by threads pinned to "
                        f"{len(cpus)} different CPUs, which execute in genuine "
                        f"parallel. Any lock-order finding on this instance is "
                        f"more likely to be hit. Note the asymmetry: same-CPU "
                        f"threads still interleave by preemption, so affinity "
                        f"only raises confidence, never lowers it."
                    ),
                    evidence=[
                        f"cpu {cpu}: {', '.join(sorted(origins))}"
                        for cpu, origins in sorted(cpus.items())
                    ],
                )
            )
        return findings


#: Every check, in the order they are reported
CHECKS: List[Check] = [
    PriorityInversionWindow(),
    UnconnectedPortInvoked(),
    SyncCycle(),
    PingCoverage(),
    DataRace(),
    BufferOwnership(),
    StackDepth(),
    RateGroupBudget(),
    FatalPath(),
    QueueOverflow(),
    CommandTelemetryPaths(),
    CpuAffinity(),
]


def run_checks(
    graph: TopologyGraph, selected: Optional[Set[str]] = None
) -> Tuple[List[Finding], List[str]]:
    """Run the selected checks over one graph

    :returns: (findings, notes about checks that were skipped)
    """
    findings: List[Finding] = []
    skipped: List[str] = []
    for check in CHECKS:
        if selected and check.id not in selected:
            continue
        # Skip only when there is no flow map and the caller has not opted into
        # the over-approximation. In permissive mode the caller has explicitly
        # accepted "every handler may call every output port", so run and let
        # the results carry that caveat.
        if check.requires_flow and graph.flow.is_empty and graph.flow.strict:
            skipped.append(
                f"{check.id}: needs the C++ flow map; run with --flow-map "
                f"(or --permissive to accept the over-approximation)"
            )
            continue
        try:
            findings.extend(check.run(graph))
        except Exception as e:  # pragma: no cover - one check must not kill the run
            logger.error(f"check {check.id} failed: {e}")
            skipped.append(f"{check.id}: failed with {type(e).__name__}: {e}")
    return findings, skipped
