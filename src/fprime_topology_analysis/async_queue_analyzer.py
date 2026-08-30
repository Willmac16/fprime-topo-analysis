#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
Async Queue Analyzer - hybrid FPP + C++ Implementation

Reports queue pressure across an F' topology: for every component queue, which
producers feed it, on which threads, at what priorities, and - given a rate
model - how fast it would fill.

The queue report, JSON output, and diagram all use the shared topology graph
and C++ flow model.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import sys
import argparse
import json
import logging
import math
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from . import cli
from .port_flow import UnresolvedFlowError
from .topology_graph import (
    DEFAULT_QUEUE_FULL,
    STOP,
    Hop,
    InstanceInfo,
    PortKey,
    SyncKind,
    TopologyGraph,
)

logger = logging.getLogger(__name__)

EMOJI_STATUS_ERROR = "\U0001F534"
EMOJI_STATUS_WARNING = "\U0001F7E1"
EMOJI_STATUS_WARNING_PASSIVE = "\U0001F7E0"
EMOJI_STATUS_GOOD = "\U0001F7E2"
PRODUCER_PRIORITY_PREFIX_WIDTH = 6
EMIT_CONTEXT_SUPPRESS = {"cpp:async-only", "cpp:autocoded-base"}

# Ports whose handler drains a queued component, used to infer the thread a
# queued instance is dispatched on.
QUEUED_DRAIN_PORTS = {"run", "schedin"}

# An async port with no explicit priority sits at the bottom of its queue
DEFAULT_PORT_PRIORITY = 0


@dataclass
class QueueGroup:
    destination: str
    queue_size: Optional[int]
    drain_thread_kind: str
    drain_thread_priority: Optional[int]
    drain_drain_source: Optional[str]
    drain_context: str
    inbound_ports: List["InboundAsyncPortGroup"]
    inbound: List[str]
    data_types: List[str]
    total_production_hz: Optional[float]
    consumer_rate_hz: Optional[float]
    queue_fill_time_s: Optional[float]
    destination_type: str = ""


@dataclass
class InboundAsyncPortGroup:
    # Defaults describe the placeholder row rendered for a queue with no
    # producers, so a table cell is empty rather than missing.
    destination_port: str = ""
    data_type: str = ""
    overflow_behavior: str = ""
    producers: List["InboundProducer"] = field(default_factory=list)
    total_production_hz: Optional[float] = None


@dataclass
class InboundProducer:
    source: str = ""
    thread_kind: str = ""
    thread_priority: Optional[int] = None
    drain_source: Optional[str] = None
    thread_context: str = ""
    emit_context: str = ""
    production_hz: Optional[float] = None


@dataclass
class InstanceThreadInfo:
    kind: str
    context: str
    priority: Optional[int]
    drain_source: Optional[str]


def load_rate_model(path: Optional[Path]) -> Dict:
    if path is None:
        return {}
    raw = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise SystemExit("YAML rate files require PyYAML. Install PyYAML or use JSON.") from exc
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise SystemExit("Rate model must be a JSON/YAML object.")
    return data


def lookup_rate(rate_model: Dict, keys: List[str]) -> Optional[float]:
    for key in keys:
        value = rate_model
        ok = True
        for part in key.split("."):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                ok = False
                break
        if ok and isinstance(value, (int, float)):
            return float(value)
    return None


def estimate_fill_time(queue_size: Optional[int], prod: Optional[float], cons: Optional[float]) -> Optional[float]:
    if queue_size is None or prod is None or cons is None:
        return None
    net = prod - cons
    return math.inf if net <= 0 else queue_size / net


def classify_priority_relation(
    source_kind: str,
    source_priority: Optional[int],
    sink_priority: Optional[int],
    emit_context: str = "",
) -> Tuple[int, str]:
    def has_sync_or_unknown_context(context: str) -> bool:
        if not context or context in {"cpp:async-only", "cpp:autocoded-base"}:
            return False
        markers = (
            "sync input handler ",
            "sync command handler ",
            "handler (unknown kind) ",
            "command handler (kind unknown) ",
            "non-handler method ",
            "unknown method",
            "cpp:external-entry",
            "cpp:unknown-component",
        )
        return any(marker in context for marker in markers)

    if source_kind == "passive":
        # Passive components run on caller's thread, so check the calling context
        if has_sync_or_unknown_context(emit_context):
            # Unknown or sync context means potential priority inversion
            return 2, EMOJI_STATUS_WARNING_PASSIVE
        # Known safe context (async-only, autocoded-base, or verified safe)
        return 1, EMOJI_STATUS_GOOD

    severity = 0
    emoji = ""
    if source_priority is None or sink_priority is None:
        severity = 0
        emoji = ""
    elif source_priority > sink_priority:
        if source_kind == "active":
            severity = 3
            emoji = EMOJI_STATUS_ERROR
        elif source_kind == "queued":
            severity = 2
            emoji = EMOJI_STATUS_WARNING
    elif source_priority < sink_priority:
        severity = 1
        emoji = EMOJI_STATUS_GOOD

    if severity < 3 and has_sync_or_unknown_context(emit_context):
        return 2, EMOJI_STATUS_WARNING_PASSIVE
    return severity, emoji


def summarize_component_priority_status(row: QueueGroup) -> List[str]:
    emoji_counts: Dict[str, int] = {}
    for group in row.inbound_ports:
        for producer in group.producers:
            _severity, emoji = classify_priority_relation(
                producer.thread_kind,
                producer.thread_priority,
                row.drain_thread_priority,
                producer.emit_context,
            )
            if emoji:
                emoji_counts[emoji] = emoji_counts.get(emoji, 0) + 1

    def status_token(emoji: str, count: int) -> str:
        return f"{emoji} {count}"

    order = [
        EMOJI_STATUS_ERROR,
        EMOJI_STATUS_WARNING_PASSIVE,
        EMOJI_STATUS_WARNING,
        EMOJI_STATUS_GOOD,
    ]
    parts: List[str] = []
    for emoji in order:
        count = emoji_counts.get(emoji, 0)
        if count > 0:
            parts.append(status_token(emoji, count))
    return parts


# How a call-site description from the C++ pass is abbreviated for a table
# cell: (prefix, short form, whether the tail names a port, whether it survives
# non-verbose rendering). A part that does not survive is dropped entirely,
# because in the common case it says only "this arrived on its own thread".
CONTEXT_PREFIXES = (
    ("sync input handler ", "sync in", True, True),
    ("async input handler ", "async in", True, False),
    ("sched input handler ", "sched in", True, False),
    ("guarded input handler ", "guarded in", True, False),
    ("sync command handler ", "sync cmd", False, True),
    ("async command handler ", "async cmd", False, False),
    ("handler (unknown kind) ", "unknown handler", False, True),
    ("command handler (kind unknown) ", "unknown cmd", False, True),
)


def _port_tail(tail: str) -> str:
    """Render a ``name:type`` tail the way it reads in a table: ``type name``"""
    if ":" in tail:
        port_name, port_type = tail.split(":", 1)
        return f"{port_type} {port_name}"
    return tail


def _short_context_part(part: str, include_async: bool) -> Optional[str]:
    for prefix, short, names_port, always in CONTEXT_PREFIXES:
        if not part.startswith(prefix):
            continue
        if not (always or include_async):
            return None
        tail = part[len(prefix) :]
        return f"{short} {_port_tail(tail) if names_port else tail}"

    if part.startswith("non-handler method "):
        body = part[len("non-handler method ") :]
        if " via " in body:
            method_name, via_detail = body.split(" via ", 1)
            via_parts = [p for p in via_detail.split(", ") if p]
            rendered_via: List[str] = []
            for via_part in via_parts:
                short_via = _short_context_part(via_part, include_async)
                if short_via:
                    rendered_via.append(short_via)
            if rendered_via:
                return ", ".join(rendered_via)
            return None if not include_async else f"unknown path {method_name}"
        return f"unknown path {body}"
    if part == "unknown method":
        # Suppress "unknown method" in non-verbose mode since it doesn't add useful info
        return None if not include_async else "unknown method"
    return part


def _extract_context_parts(context: str) -> List[str]:
    """Split an emit context into the individual call sites it names"""
    if context.startswith("cpp:passive via "):
        return [p for p in context[len("cpp:passive via ") :].split(", ") if p]
    if context.startswith("cpp:mixed (") and context.endswith(")"):
        return [p for p in context[len("cpp:mixed (") : -1].split(", ") if p]
    return [context]


def format_emit_context_for_display(context: str, producer_verbose: bool) -> str:
    if context == "cpp:autocoded-base":
        return ""
    if context == "cpp:external-entry":
        return "external/lifecycle entry"
    if context == "cpp:unknown-component":
        return "unknown component"

    rendered = [
        short
        for part in _extract_context_parts(context)
        if (short := _short_context_part(part, producer_verbose))
    ]
    return ", ".join(rendered)


def _type_order_key(
    max_prio_by_type: Dict[str, Optional[int]], data_type: str
) -> Tuple[bool, int, str]:
    """Order data types by their highest producer priority, unknowns last"""
    type_max = max_prio_by_type.get(data_type)
    return (type_max is None, -(type_max if type_max is not None else 0), data_type)


# Table columns, in order. ``scope`` says when a cell repeats: a "dest" cell is
# written once per destination queue, a "port" cell once per inbound port, and
# a "producer" cell on every row. Repeats are blanked so the table reads as
# nested groups. Rate columns appear only when a rate model was supplied.
DEST_SCOPE = (
    "Destination Queue",
    "Destination Component Type",
    "Queue Size",
    "Drain Thread Kind",
    "Drain Thread Priority",
    "Drain Sched Source",
    "Total Prod Hz",
    "Cons Hz",
    "Fill Time (s)",
)
PORT_SCOPE = ("Port Type", "Destination Port", "Overflow Behavior")
RATE_COLUMNS = ("Total Prod Hz", "Cons Hz", "Fill Time (s)")
COLUMNS = (
    *DEST_SCOPE,
    *PORT_SCOPE,
    "Async Producer",
    "Producer Thread Kind",
    "Producer Thread Priority",
    "Producer Sched Source",
)


def _fill_time_cell(seconds: Optional[float]) -> str:
    if seconds is math.inf:
        return "stable (drain >= fill)"
    return "unknown" if seconds is None else f"{seconds:.3f}"


def _producer_cells(
    producer: InboundProducer, priority_emoji: str, producer_verbose: bool
) -> Dict[str, str]:
    """The cells describing one producer of one queue"""
    context = (
        format_emit_context_for_display(producer.emit_context, producer_verbose)
        if producer.emit_context and producer.emit_context not in EMIT_CONTEXT_SUPPRESS
        else ""
    )
    if (
        producer.thread_kind == "passive"
        and not context
        and producer.emit_context != "cpp:autocoded-base"
    ):
        context = "source unknown"

    if producer.thread_priority is not None:
        prefix = f"{producer.thread_priority}:"
    elif producer.thread_kind == "passive":
        prefix = "N/A:"
    else:
        prefix = ""

    return {
        "Async Producer": producer.source,
        "Producer Thread Kind": (
            f"{producer.thread_kind} ({context})"
            if producer.thread_kind and context
            else (producer.thread_kind or context)
        ),
        "Producer Thread Priority": (
            f"{prefix:<{PRODUCER_PRIORITY_PREFIX_WIDTH}} {priority_emoji}".rstrip()
            if prefix
            else priority_emoji
        ),
        "Producer Sched Source": producer.drain_source or "",
    }


def _destination_cells(row: QueueGroup) -> Dict[str, str]:
    """The cells describing one destination queue, written on its first row"""
    drain_priority = (
        str(row.drain_thread_priority)
        if row.drain_thread_priority is not None
        else "unknown"
    )
    return {
        "Destination Queue": row.destination,
        "Destination Component Type": row.destination_type,
        "Queue Size": "unknown" if row.queue_size is None else str(row.queue_size),
        "Drain Thread Kind": row.drain_thread_kind,
        "Drain Thread Priority": drain_priority,
        "Drain Sched Source": row.drain_drain_source or "",
        "Total Prod Hz": row.total_production_hz,
        "Cons Hz": row.consumer_rate_hz,
        "Fill Time (s)": _fill_time_cell(row.queue_fill_time_s),
    }


def _visible_producers(
    row: QueueGroup, group: InboundAsyncPortGroup, hide_green_rows: bool
) -> List[Tuple[InboundProducer, str]]:
    """Producers of one inbound port, each with its priority-relation emoji"""
    visible = []
    for producer in group.producers or [InboundProducer()]:
        _severity, emoji = classify_priority_relation(
            producer.thread_kind,
            producer.thread_priority,
            row.drain_thread_priority,
            producer.emit_context,
        )
        if hide_green_rows and emoji == EMOJI_STATUS_GOOD:
            continue
        visible.append((producer, emoji))
    return visible


def _sorted_groups(row: QueueGroup) -> List[InboundAsyncPortGroup]:
    """Inbound ports, highest-priority data type first"""
    max_prio_by_type: Dict[str, Optional[int]] = {}
    for group in row.inbound_ports:
        group_max = max(
            (p.thread_priority for p in group.producers if p.thread_priority is not None),
            default=None,
        )
        existing = max_prio_by_type.get(group.data_type)
        if existing is None or (group_max is not None and group_max > existing):
            max_prio_by_type[group.data_type] = group_max

    return sorted(
        row.inbound_ports,
        key=lambda g: (
            *_type_order_key(max_prio_by_type, g.data_type),
            g.destination_port,
        ),
    ) or [InboundAsyncPortGroup(producers=[InboundProducer()])]


def render_markdown(
    rows: List[QueueGroup],
    include_rates: bool,
    split_destination_tables: bool = False,
    producer_verbose: bool = False,
    hide_green_rows: bool = False,
) -> str:
    columns = [c for c in COLUMNS if include_rates or c not in RATE_COLUMNS]
    header = "| " + " | ".join(columns) + " |"
    rule = "|" + "---|" * len(columns)
    spacer = "|" + " |" * len(columns)

    lines = [
        "# Async Queue Group Analysis",
        "",
        "Priority relation:",
        "",
        "- 🔴 active producer outranks the drain thread",
        "- 🟠 caller-thread priority is unresolved",
        "- 🟡 queued producer outranks the drain thread",
        "- 🟢 producer priority is below the drain thread",
        "",
    ]
    if not split_destination_tables:
        lines.extend([header, rule])

    rendered = 0
    for row in rows:
        groups = [
            (group, producers)
            for group in _sorted_groups(row)
            if (producers := _visible_producers(row, group, hide_green_rows))
        ]
        if not groups:
            continue

        if split_destination_tables:
            if rendered:
                lines.append("")
            lines.extend([header, rule])
        elif rendered:
            lines.append(spacer)

        destination_cells = dict.fromkeys(COLUMNS, "")
        destination_cells.update(_destination_cells(row))
        lines.append(
            "| " + " | ".join(f"{destination_cells[c]}" for c in columns) + " |"
        )
        drain_statuses = iter(summarize_component_priority_status(row))
        previous_type: Optional[str] = None
        previous_producer: Optional[str] = None

        for group, producers in groups:
            for index, (producer, emoji) in enumerate(producers):
                cells = dict.fromkeys(COLUMNS, "")
                cells.update(_producer_cells(producer, emoji, producer_verbose))
                if producer.source and producer.source == previous_producer:
                    cells["Async Producer"] = ""
                    cells["Producer Thread Kind"] = ""
                    cells["Producer Thread Priority"] = ""
                    cells["Producer Sched Source"] = ""
                else:
                    previous_producer = producer.source or None
                cells["Drain Thread Priority"] = next(drain_statuses, "")
                if index == 0:
                    cells["Destination Port"] = group.destination_port
                    cells["Overflow Behavior"] = group.overflow_behavior
                    if group.data_type != previous_type:
                        cells["Port Type"] = group.data_type

                lines.append("| " + " | ".join(f"{cells[c]}" for c in columns) + " |")

            previous_type = group.data_type
        for status in drain_statuses:
            status_cells = dict.fromkeys(COLUMNS, "")
            status_cells["Drain Thread Priority"] = status
            lines.append(
                "| " + " | ".join(f"{status_cells[c]}" for c in columns) + " |"
            )
        rendered += 1

    return "\n".join(lines) + "\n"


def render_mermaid(rows: List[QueueGroup]) -> str:
    lines = ["flowchart LR"]
    for r in rows:
        dst = re.sub(r"[^A-Za-z0-9_]", "_", r.destination)
        lines.append(f"  {dst}[\"{r.destination}\\nqueue={r.queue_size if r.queue_size is not None else 'unknown'}\\n{r.drain_context}\"]")
        for src in r.inbound:
            sid = re.sub(r"[^A-Za-z0-9_]", "_", src)
            lines.append(f"  {sid}[\"{src}\"] --> {dst}")
    return "\n".join(lines) + "\n"

# ----------------------------------------------------------------------
# Thread context
# ----------------------------------------------------------------------


def _queued_drain_info(
    graph: TopologyGraph,
    instance_name: str,
    cache: Dict[str, InstanceThreadInfo],
    visiting: Set[str],
) -> InstanceThreadInfo:
    """Whose thread drains a queued instance, found through its sched port"""
    drains = sorted(
        (
            connection
            for connection in graph.connection_list
            if connection.dest.port.instance == instance_name
            and connection.dest.port.port.lower() in QUEUED_DRAIN_PORTS
        ),
        key=lambda c: str(c.source),
    )
    if not drains:
        return InstanceThreadInfo("queued", "queued drain context unknown", None, None)

    source = drains[0].source
    caller = infer_instance_thread_info(graph, source.port.instance, cache, visiting)
    context = f"queued drain via {source}"
    if caller.priority is not None:
        context += f" (priority {caller.priority})"
    return InstanceThreadInfo("queued", context, caller.priority, str(source))


def infer_instance_thread_info(
    graph: TopologyGraph,
    instance_name: Optional[str],
    cache: Dict[str, InstanceThreadInfo],
    visiting: Optional[Set[str]] = None,
) -> InstanceThreadInfo:
    """Work out which thread services an instance, and at what priority.

    An active instance runs on its own task. A queued instance has no task of
    its own: it is drained by whoever calls its scheduling port, so the answer
    is that caller's thread, found by recursion. A passive instance runs
    entirely on its callers' threads.
    """
    if instance_name is None or instance_name not in graph.instances:
        return InstanceThreadInfo("unknown", "thread context unknown", None, None)

    if instance_name in cache:
        return cache[instance_name]

    if visiting is None:
        visiting = set()
    if instance_name in visiting:
        return InstanceThreadInfo("unknown", "drain context cycle detected", None, None)
    visiting.add(instance_name)

    info = graph.instances[instance_name]
    kind = str(info.kind)

    if kind == "active":
        priority = info.task_priority
        context = (
            "active thread (priority unknown)"
            if priority is None
            else f"active thread priority {priority}"
        )
        result = InstanceThreadInfo("active", context, priority, None)
    elif kind == "queued":
        result = _queued_drain_info(graph, instance_name, cache, visiting)
    elif kind == "passive":
        result = InstanceThreadInfo("passive", "passive component context", None, None)
    else:
        result = InstanceThreadInfo("unknown", "drain context unknown", None, None)

    visiting.discard(instance_name)
    cache[instance_name] = result
    return result


# ----------------------------------------------------------------------
# Emit context, from the C++ flow map
# ----------------------------------------------------------------------


def _handler_label(info: InstanceInfo, entry: str) -> str:
    """Describe one handler the way the report vocabulary expects.

    A command handler is keyed ``cmd:<MNEMONIC>`` in the flow map; every other
    handler is named by its input port.
    """
    if entry.startswith("cmd:"):
        mnemonic = entry[len("cmd:") :]
        kinds = info.command_kinds.get(mnemonic, set())
        if SyncKind.ASYNC in kinds:
            return f"async command handler {mnemonic}"
        if SyncKind.GUARDED in kinds:
            return f"guarded command handler {mnemonic}"
        if SyncKind.SYNC in kinds:
            return f"sync command handler {mnemonic}"
        return f"command handler (kind unknown) {mnemonic}"

    kinds = info.input_ports.get(entry, set())
    if SyncKind.ASYNC in kinds:
        return f"async input handler {entry}"
    if SyncKind.GUARDED in kinds:
        return f"guarded input handler {entry}"
    if SyncKind.SYNC in kinds:
        return f"sync input handler {entry}"
    return f"handler (unknown kind) {entry}"


def emit_context_for_port(
    graph: TopologyGraph, instance_name: str, out_port: str
) -> str:
    """Which handlers of an instance can invoke one of its output ports.

    The flow map resolves every modeled handler to the ports it reaches. This
    function inverts that mapping to identify the handlers that emit here.

    Raises:
        UnresolvedFlowError: If any handler of this component is unresolved
    """
    info = graph.instances.get(instance_name)
    if info is None:
        return "cpp:unknown-component"

    emitters: List[str] = []
    for entry_port, kinds in sorted(info.input_ports.items()):
        for kind in sorted(kinds, key=str):
            for entry in info.flow_entries(entry_port, kind):
                outputs = graph.outputs_for(info, entry)
                if out_port in outputs:
                    label = _handler_label(info, entry)
                    if label not in emitters:
                        emitters.append(label)

    if not emitters:
        return "cpp:external-entry"
    if all(label.startswith("async ") for label in emitters):
        return "cpp:async-only"
    return ", ".join(emitters)


# ----------------------------------------------------------------------
# Self re-queue priority drops
# ----------------------------------------------------------------------


@dataclass
class RequeueDrop:
    """Work re-queued onto its own component's queue at a lower priority"""

    instance: str
    from_port: str
    to_port: str
    from_priority: int
    to_priority: int
    witness: List[str]

    def __str__(self) -> str:
        return (
            f"{self.instance}: {self.from_port} (priority {self.from_priority}) "
            f"-> {self.to_port} (priority {self.to_priority})"
        )


def find_requeue_drops(graph: TopologyGraph) -> List[RequeueDrop]:
    """Find work re-queued onto its own queue at a lower priority.

    Producer-versus-consumer thread priority is already classified per
    connection by classify_priority_relation. What that cannot see is a chain
    that comes back to the queue it started on: a message arriving at a high
    priority port whose handler posts to a low priority port of the same
    component. The remainder of an urgent chain then waits behind everything
    queued above the lower priority, on the same queue.
    """
    drops: Dict[Tuple[str, str, str], RequeueDrop] = {}

    for name in sorted(graph.instances):
        info = graph.instances[name]
        for entry_port in info.async_entries():
            entry_priority = info.port_priorities.get(
                entry_port, DEFAULT_PORT_PRIORITY
            )
            entry = PortKey(name, entry_port)

            def on_hop(hop: Hop, _entry=entry, _priority=entry_priority):
                if hop.kind != SyncKind.ASYNC:
                    # Sync and guarded hops stay on this thread and keep the
                    # chain's urgency, so keep descending.
                    return hop.state

                if hop.dest.instance == _entry.instance:
                    dest_info = graph.instances[hop.dest.instance]
                    dest_priority = dest_info.port_priorities.get(
                        hop.dest.port, DEFAULT_PORT_PRIORITY
                    )
                    if dest_priority < _priority:
                        key = (_entry.instance, _entry.port, hop.dest.port)
                        if key not in drops:
                            drops[key] = RequeueDrop(
                                instance=_entry.instance,
                                from_port=_entry.port,
                                to_port=hop.dest.port,
                                from_priority=_priority,
                                to_priority=dest_priority,
                                witness=list(hop.path),
                            )
                return STOP

            graph.walk_chains(
                entry=entry, entry_kind=SyncKind.ASYNC, on_hop=on_hop
            )

    return sorted(drops.values(), key=lambda d: (d.instance, d.from_port))


# ----------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------


def _add_rate(total: Optional[float], hz: Optional[float]) -> Optional[float]:
    """Accumulate a production rate, where None means "no rate is known\""""
    return total if hz is None else (total or 0.0) + hz


@dataclass
class _PortQueue:
    """Producers feeding one inbound async port, while they are being gathered"""

    overflow_behavior: str
    producers: List[InboundProducer] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)
    production_hz: Optional[float] = None


@dataclass
class _Queue:
    """One instance's message queue, while its producers are being gathered"""

    queue_size: Optional[int]
    thread: InstanceThreadInfo
    ports: Dict[Tuple[str, str], _PortQueue] = field(default_factory=dict)
    inbound: Set[str] = field(default_factory=set)
    data_types: Set[str] = field(default_factory=set)
    production_hz: Optional[float] = None


def _destination_queue_entries(
    info: InstanceInfo, port: str, data_type: str
) -> List[Tuple[str, str, str]]:
    """Expand a physical input into independently queued message kinds."""
    if port != info.cmd_port:
        return [
            (port, data_type, info.port_queue_full.get(port, DEFAULT_QUEUE_FULL))
        ]

    commands = [
        (
            f"{port}:{mnemonic}",
            data_type,
            info.command_queue_full.get(mnemonic, DEFAULT_QUEUE_FULL),
        )
        for mnemonic, kinds in sorted(info.command_kinds.items())
        if SyncKind.ASYNC in kinds
    ]
    return commands or [
        (port, data_type, info.port_queue_full.get(port, DEFAULT_QUEUE_FULL))
    ]


def analyze(graph: TopologyGraph, rate_model: Dict) -> List[QueueGroup]:
    """Group every async queue in the topology with the producers feeding it"""
    thread_cache: Dict[str, InstanceThreadInfo] = {}
    emit_cache: Dict[Tuple[str, str], str] = {}

    def thread_info(instance_name: str) -> InstanceThreadInfo:
        return infer_instance_thread_info(graph, instance_name, thread_cache, set())

    def emit_context(instance_name: str, out_port: str) -> str:
        key = (instance_name, out_port)
        if key not in emit_cache:
            emit_cache[key] = emit_context_for_port(graph, instance_name, out_port)
        return emit_cache[key]

    rates = rate_model if isinstance(rate_model, dict) else {}
    producer_overrides = rates.get("production_rate_hz", {})
    consumer_overrides = rates.get("consumption_rate_hz", {})

    queues: Dict[str, _Queue] = {}
    for connection in graph.connection_list:
        dest = connection.dest.port
        dest_info = graph.instances.get(dest.instance)
        if dest_info is None:
            continue
        # Only async destinations own a queue
        if SyncKind.ASYNC not in dest_info.input_ports.get(dest.port, set()):
            continue
        data_type = dest_info.port_types.get(dest.port)
        if not data_type:
            continue

        queue = queues.setdefault(
            dest.instance,
            _Queue(
                queue_size=dest_info.queue_size, thread=thread_info(dest.instance)
            ),
        )
        source_name = str(connection.source)
        queue.inbound.add(source_name)
        queue.data_types.add(data_type)

        source = connection.source.port
        source_thread = thread_info(source.instance)
        production_hz = lookup_rate(
            producer_overrides,
            [source_name, f"{source.instance}.{source.port}", source.instance],
        )
        queue.production_hz = _add_rate(queue.production_hz, production_hz)
        producer = InboundProducer(
            source=source_name,
            thread_kind=source_thread.kind,
            thread_priority=source_thread.priority,
            drain_source=source_thread.drain_source,
            thread_context=source_thread.context,
            emit_context=emit_context(source.instance, source.port),
            production_hz=production_hz,
        )
        for port_name, entry_type, queue_full in _destination_queue_entries(
            dest_info, dest.port, data_type
        ):
            port_queue = queue.ports.setdefault(
                (port_name, entry_type), _PortQueue(queue_full)
            )
            if source_name in port_queue.sources:
                continue
            port_queue.sources.add(source_name)
            port_queue.production_hz = _add_rate(
                port_queue.production_hz, production_hz
            )
            port_queue.producers.append(producer)

    rows: List[QueueGroup] = []
    for instance_name, queue in sorted(queues.items()):
        consumer_rate = lookup_rate(consumer_overrides, [instance_name])
        rows.append(
            QueueGroup(
                destination=instance_name,
                destination_type=graph.instances[instance_name].component_name,
                queue_size=queue.queue_size,
                drain_thread_kind=queue.thread.kind,
                drain_thread_priority=queue.thread.priority,
                drain_drain_source=queue.thread.drain_source,
                drain_context=queue.thread.context,
                inbound_ports=[
                    InboundAsyncPortGroup(
                        destination_port=port_name,
                        data_type=data_type,
                        overflow_behavior=port_queue.overflow_behavior,
                        producers=sorted(port_queue.producers, key=lambda p: p.source),
                        total_production_hz=port_queue.production_hz,
                    )
                    for (port_name, data_type), port_queue in sorted(queue.ports.items())
                ],
                inbound=sorted(queue.inbound),
                data_types=sorted(queue.data_types),
                total_production_hz=queue.production_hz,
                consumer_rate_hz=consumer_rate,
                queue_fill_time_s=estimate_fill_time(
                    queue.queue_size, queue.production_hz, consumer_rate
                ),
            )
        )
    return rows


def filter_drop_ports(rows: List[QueueGroup]) -> List[QueueGroup]:
    """Remove async input-port groups whose queue-full behavior is drop."""
    filtered: List[QueueGroup] = []
    for row in rows:
        groups = [
            group for group in row.inbound_ports if group.overflow_behavior != "drop"
        ]
        if not groups:
            continue
        inbound = sorted({producer.source for group in groups for producer in group.producers})
        data_types = sorted({group.data_type for group in groups})
        production_hz: Optional[float] = None
        for group in groups:
            production_hz = _add_rate(production_hz, group.total_production_hz)
        filtered.append(
            replace(
                row,
                inbound_ports=groups,
                inbound=inbound,
                data_types=data_types,
                total_production_hz=production_hz,
                queue_fill_time_s=estimate_fill_time(
                    row.queue_size, production_hz, row.consumer_rate_hz
                ),
            )
        )
    return filtered


def format_requeue_drops(drops: List[RequeueDrop]) -> str:
    """Render the self re-queue section of the report"""
    if not drops:
        return ""
    lines = ["", "## Self Re-queue Priority Drops", ""]
    lines.append(
        "Work arriving at these ports is re-queued onto the same component's "
        "queue at a lower priority, so the rest of the chain waits behind "
        "everything queued above it."
    )
    lines.append("")
    lines.append("| Component | From | To | Priority |")
    lines.append("|---|---|---|---|")
    lines.extend(
        f"| {drop.instance} | {drop.from_port} | {drop.to_port} | "
        f"{drop.from_priority} -> {drop.to_priority} |"
        for drop in drops
    )
    lines.append("")
    return "\n".join(lines)


def rows_to_payload(rows: List[QueueGroup], include_rates: bool) -> List[Dict]:
    """Build the structured queue-analysis output."""
    payload = []
    for row in rows:
        item = {
            "destination": row.destination,
            "destination_type": row.destination_type,
            "data_types": row.data_types,
            "inbound": row.inbound,
            "inbound_by_port": [
                {
                    "destination_port": group.destination_port,
                    "data_type": group.data_type,
                    "overflow_behavior": group.overflow_behavior,
                    "producers": [p.source for p in group.producers],
                    "producer_details": [
                        {
                            "source": p.source,
                            "thread_kind": p.thread_kind,
                            "thread_context": p.thread_context,
                            "priority": p.thread_priority,
                            "drain_source": p.drain_source,
                            "emit_context": p.emit_context,
                            "production_hz": p.production_hz,
                        }
                        for p in group.producers
                    ],
                }
                for group in row.inbound_ports
            ],
            "queue_size": row.queue_size,
            "drain_thread_kind": row.drain_thread_kind,
            "drain_thread_priority": row.drain_thread_priority,
            "drain_drain_source": row.drain_drain_source,
            "drain_context": row.drain_context,
        }
        if include_rates:
            item["total_production_hz"] = row.total_production_hz
            item["consumer_rate_hz"] = row.consumer_rate_hz
            item["queue_fill_time_s"] = row.queue_fill_time_s
            for entry, group in zip(
                item["inbound_by_port"], row.inbound_ports, strict=True
            ):
                entry["total_production_hz"] = group.total_production_hz
        payload.append(item)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze async queue pressure across an F' topology, using the FPP "
            "model for wiring and the C++ flow map for intra-component calls"
        )
    )
    cli.add_topology_args(parser)
    parser.add_argument("--rate-model", type=Path, default=None, help="Rate model JSON")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--producer-verbose",
        action="store_true",
        help="Show all discovered producer caller sources in context tags",
    )
    parser.add_argument(
        "--hide-green-rows",
        action="store_true",
        help="Hide producer rows whose priority status is green",
    )
    parser.add_argument(
        "--hide-drop-ports",
        action="store_true",
        help="Hide async input ports whose queue-full behavior is drop",
    )
    parser.add_argument(
        "--split-destination-tables",
        action="store_true",
        help="Render one table per destination queue",
    )
    parser.add_argument(
        "--diagram-output", type=Path, default=None, help="Mermaid diagram output path"
    )
    args = cli.parse_args(parser)
    cli.configure_logging(args.verbose)

    rate_model = load_rate_model(args.rate_model)
    include_rates = args.rate_model is not None

    try:
        graph = cli.load_graph(args, cli.load_flow(args))
        rows = analyze(graph, rate_model)
        drops = find_requeue_drops(graph)
    except UnresolvedFlowError as e:
        return cli.report_unresolved(e)
    except cli.CliError as e:
        return cli.report_error(e, args.verbose)

    if args.hide_drop_ports:
        dropped_ports = {
            (row.destination, group.destination_port)
            for row in rows
            for group in row.inbound_ports
            if group.overflow_behavior == "drop"
        }
        rows = filter_drop_ports(rows)
        drops = [
            drop
            for drop in drops
            if (drop.instance, drop.to_port) not in dropped_ports
        ]

    if args.diagram_output:
        cli.write_or_print(render_mermaid(rows), args.diagram_output)

    if args.format == "json":
        rendered = json.dumps(
            {
                "queues": rows_to_payload(rows, include_rates),
                "requeue_drops": [
                    {
                        "instance": d.instance,
                        "from_port": d.from_port,
                        "to_port": d.to_port,
                        "from_priority": d.from_priority,
                        "to_priority": d.to_priority,
                        "witness": d.witness,
                    }
                    for d in drops
                ],
            },
            indent=2,
        )
    else:
        rendered = render_markdown(
            rows,
            include_rates,
            split_destination_tables=args.split_destination_tables,
            producer_verbose=args.producer_verbose,
            hide_green_rows=args.hide_green_rows,
        ) + format_requeue_drops(drops)

    cli.write_or_print(rendered, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
