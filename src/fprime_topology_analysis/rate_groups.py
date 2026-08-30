"""Infer standard F Prime rate-group frequencies from deployment C++ and wiring."""

import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple

from .topology_graph import PortKey, SyncKind, TopologyGraph

logger = logging.getLogger(__name__)

RATE_GROUP_TYPES = {"Svc.ActiveRateGroup", "Svc.PassiveRateGroup"}
RATE_GROUP_DRIVER_TYPE = "Svc.RateGroupDriver"
RATE_GROUP_MEMBER_PORT = "RateGroupMemberOut"
DRIVER_CYCLE_PORT = "CycleOut"

CPP_INT = r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*"
DIVIDER_SET_RE = re.compile(
    r"\b(?:[A-Za-z_]\w*::)*DividerSet\s+([A-Za-z_]\w*)"
    r"\s*\{\s*\{\s*(.*?)\s*\}\s*\}\s*;",
    re.DOTALL,
)
DIVIDER_PAIR_RE = re.compile(
    rf"\{{\s*(?P<divisor>{CPP_INT})\s*,\s*(?P<offset>{CPP_INT})\s*\}}"
)
CONFIGURE_RE = re.compile(
    r"\b(?P<instance>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)"
    r"\s*\.\s*configure\s*\(\s*(?P<value>[A-Za-z_]\w*)\s*\)"
)
TIME_INTERVAL_RE = re.compile(
    rf"(?:Fw::)?TimeInterval\s*\(\s*(?P<seconds>{CPP_INT})"
    rf"\s*,\s*(?P<useconds>{CPP_INT})\s*\)"
)
INTERVAL_DECL_RE = re.compile(
    rf"(?:Fw::)?TimeInterval\s+(?P<name>[A-Za-z_]\w*)\s*\("
    rf"\s*(?P<seconds>{CPP_INT})\s*,\s*(?P<useconds>{CPP_INT})\s*\)"
)
START_RATE_GROUPS_RE = re.compile(
    rf"\bstartRateGroups\s*\(\s*(?P<interval>{TIME_INTERVAL_RE.pattern}|[A-Za-z_]\w*)\s*\)"
)
START_TIMER_RE = re.compile(
    rf"\b(?P<timer>(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*\.\s*startTimer"
    rf"\s*\(\s*(?P<interval>{TIME_INTERVAL_RE.pattern}|[A-Za-z_]\w*)\s*\)"
)


def _cpp_int(value: str) -> int:
    return int(re.sub(r"[uUlL]+$", "", value), 0)


def _frequency(seconds: str, useconds: str) -> Optional[float]:
    period = _cpp_int(seconds) + _cpp_int(useconds) / 1_000_000.0
    return None if period <= 0 else 1.0 / period


def _short_cpp_name(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def _source_files(compile_commands: Path, source_root: Path) -> Iterable[Path]:
    """Yield project-owned C++ sources represented by the selected build."""
    try:
        entries = json.loads(compile_commands.read_text())
    except (OSError, json.JSONDecodeError, TypeError):
        return
    seen: Set[Path] = set()
    for entry in entries:
        try:
            source = Path(entry["file"])
            if not source.is_absolute():
                source = Path(entry["directory"]) / source
            source = source.resolve()
            source.relative_to(source_root.resolve())
        except (KeyError, OSError, TypeError, ValueError):
            continue
        if source not in seen and source.suffix.lower() in {".cc", ".cpp", ".cxx"}:
            seen.add(source)
            yield source


@dataclass
class RateInference:
    """Frequencies recovered for rate groups, handlers, and output ports."""

    rate_groups: Dict[str, float] = field(default_factory=dict)
    production_rate_hz: Dict[str, float] = field(default_factory=dict)
    consumption_rate_hz: Dict[str, float] = field(default_factory=dict)

    def as_rate_model(self) -> Dict[str, Dict[str, float]]:
        return {
            "production_rate_hz": self.production_rate_hz,
            "consumption_rate_hz": self.consumption_rate_hz,
        }


@dataclass
class _CppRateConfig:
    divider_sets: Dict[str, List[int]] = field(default_factory=dict)
    driver_sets: Dict[str, str] = field(default_factory=dict)
    timer_hz: Dict[str, float] = field(default_factory=dict)
    base_hz: Set[float] = field(default_factory=set)


def _interval_frequency(expression: str, intervals: Dict[str, float]) -> Optional[float]:
    direct = TIME_INTERVAL_RE.search(expression)
    if direct:
        return _frequency(direct.group("seconds"), direct.group("useconds"))
    return intervals.get(expression.strip())


def _read_cpp_rate_config(files: Iterable[Path]) -> _CppRateConfig:
    config = _CppRateConfig()
    texts: List[str] = []
    intervals: Dict[str, float] = {}
    for source in files:
        try:
            text = source.read_text(errors="replace")
        except OSError:
            continue
        texts.append(text)
        for match in DIVIDER_SET_RE.finditer(text):
            config.divider_sets[match.group(1)] = [
                _cpp_int(pair.group("divisor"))
                for pair in DIVIDER_PAIR_RE.finditer(match.group(2))
            ]
        for match in CONFIGURE_RE.finditer(text):
            config.driver_sets[_short_cpp_name(match.group("instance"))] = match.group(
                "value"
            )
        for match in INTERVAL_DECL_RE.finditer(text):
            frequency = _frequency(match.group("seconds"), match.group("useconds"))
            if frequency is not None:
                intervals[match.group("name")] = frequency

    combined = "\n".join(texts)
    for match in START_RATE_GROUPS_RE.finditer(combined):
        frequency = _interval_frequency(match.group("interval"), intervals)
        if frequency is not None:
            config.base_hz.add(frequency)
    for match in START_TIMER_RE.finditer(combined):
        frequency = _interval_frequency(match.group("interval"), intervals)
        if frequency is not None:
            config.timer_hz[_short_cpp_name(match.group("timer"))] = frequency

    # A wrapper commonly passes its interval argument to startTimer. Associate
    # the statically known startRateGroups interval with that timer.
    if len(config.base_hz) == 1:
        base_hz = next(iter(config.base_hz))
        for match in START_TIMER_RE.finditer(combined):
            config.timer_hz.setdefault(_short_cpp_name(match.group("timer")), base_hz)
    return config


def _driver_base_hz(
    graph: TopologyGraph, driver: str, config: _CppRateConfig
) -> Optional[float]:
    incoming = [
        connection
        for connection in graph.connection_list
        if connection.dest.port.instance == driver
        and connection.dest.port.port.lower() == "cyclein"
    ]
    for connection in incoming:
        timer = connection.source.port.instance.rsplit(".", 1)[-1]
        if timer in config.timer_hz:
            return config.timer_hz[timer]
    return next(iter(config.base_hz)) if len(config.base_hz) == 1 else None


def _driver_divisors(driver: str, config: _CppRateConfig) -> Optional[List[int]]:
    short_name = driver.rsplit(".", 1)[-1]
    configured = config.driver_sets.get(short_name)
    if configured in config.divider_sets:
        return config.divider_sets[configured]
    if len(config.divider_sets) == 1:
        return next(iter(config.divider_sets.values()))
    return None


def _propagate_member_rates(
    graph: TopologyGraph,
    group_hz: Dict[str, float],
    production: Dict[str, float],
) -> Tuple[Dict[Tuple[str, str], float], Dict[str, float]]:
    """Propagate one invocation per rate-group tick through handler flow."""
    entry_contributions: DefaultDict[Tuple[str, str], Dict[str, float]] = defaultdict(dict)
    output_contributions: DefaultDict[str, Dict[str, float]] = defaultdict(dict)
    work = deque()

    for connection in graph.connection_list:
        source = connection.source.port
        if (
            source.instance not in group_hz
            or source.port != RATE_GROUP_MEMBER_PORT
        ):
            continue
        frequency = group_hz[source.instance]
        root = str(connection.source)
        production[root] = frequency
        destination = connection.dest.port
        kinds = graph.instances[destination.instance].input_ports.get(
            destination.port, set()
        )
        for kind in kinds:
            work.append((root, destination, kind, frequency))

    seen: Set[Tuple[str, str, str, str]] = set()
    while work:
        root, entry, kind, frequency = work.popleft()
        info = graph.instances.get(entry.instance)
        if info is None:
            continue
        entry_contributions[(entry.instance, entry.port)][root] = frequency
        for flow_entry in info.flow_entries(entry.port, kind):
            state = (root, entry.instance, flow_entry, str(kind))
            if state in seen:
                continue
            seen.add(state)
            for output in graph.outputs_for(info, flow_entry):
                source = PortKey(entry.instance, output)
                output_contributions[str(source)][root] = frequency
                for destination in graph.destinations(entry.instance, output):
                    dest_info = graph.instances.get(destination.instance)
                    if dest_info is None:
                        continue
                    for dest_kind in dest_info.input_ports.get(destination.port, set()):
                        # The offered rate at an async input is known, but the
                        # receiver's execution rate depends on queue service,
                        # overflow policy, and backlog. Do not invent it.
                        if dest_kind != SyncKind.ASYNC:
                            work.append((root, destination, dest_kind, frequency))

    for source, contributions in output_contributions.items():
        production[source] = sum(contributions.values())
    entry_rates = {
        entry: sum(contributions.values())
        for entry, contributions in entry_contributions.items()
    }
    return entry_rates, production


def infer_rate_groups(
    graph: TopologyGraph, compile_commands: Path, source_root: Path
) -> RateInference:
    """Recover rate-group frequencies and propagate them through the graph."""
    config = _read_cpp_rate_config(_source_files(compile_commands, source_root))
    result = RateInference()

    drivers = [
        name
        for name, info in graph.instances.items()
        if info.component_name == RATE_GROUP_DRIVER_TYPE
    ]
    for driver in drivers:
        base_hz = _driver_base_hz(graph, driver, config)
        divisors = _driver_divisors(driver, config)
        if base_hz is None or divisors is None:
            continue
        for connection in graph.connection_list:
            source = connection.source
            destination = connection.dest.port
            if (
                source.port.instance != driver
                or source.port.port != DRIVER_CYCLE_PORT
                or source.index is None
                or source.index >= len(divisors)
                or graph.instances[destination.instance].component_name
                not in RATE_GROUP_TYPES
            ):
                continue
            divisor = divisors[source.index]
            if divisor <= 0:
                continue
            frequency = base_hz / divisor
            result.rate_groups[destination.instance] = frequency
            result.production_rate_hz[str(source)] = frequency

    entry_rates, result.production_rate_hz = _propagate_member_rates(
        graph, result.rate_groups, result.production_rate_hz
    )
    for instance, info in graph.instances.items():
        if str(info.kind) != "queued":
            continue
        drain_rates = [
            frequency
            for (entry_instance, port), frequency in entry_rates.items()
            if entry_instance == instance and port.lower() in {"run", "schedin"}
        ]
        if drain_rates:
            result.consumption_rate_hz[instance] = sum(drain_rates)

    if result.rate_groups:
        rendered = ", ".join(
            f"{name}={frequency:g} Hz"
            for name, frequency in sorted(result.rate_groups.items())
        )
        logger.info(f"Inferred rate groups: {rendered}")
    return result
