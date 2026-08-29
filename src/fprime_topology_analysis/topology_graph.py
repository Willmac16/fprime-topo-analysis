#!/usr/bin/env python3
"""
Topology Graph - shared FPP topology model for the analysis tools

Loads the ``fpp-to-json`` artifacts and exposes the two facts every topology
analysis needs:

* how each input port is dispatched - sync, guarded or async - which decides
  whether a call crosses a thread boundary and whether it takes a mutex; and
* which output port is wired to which input port.

Combined with the intra-component flow map from ``port_flow``, this is enough to
walk real call chains across a topology. The guarded-port deadlock analysis and
the queue priority analysis both build on it, so they cannot disagree about what
"async" means.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import logging
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple
from dataclasses import dataclass, field

# Note: fpm_ prefixes on imports are intentional to make it clear which
# classes are from fprime_python_model vs. local definitions
from fprime_python_model.model import FprimePythonModel as fpm_FprimePythonModel
from fprime_python_model.semantics.topology import Topology as fpm_Topology
from fprime_python_model.semantics.component_instance import (
    ComponentInstance as fpm_ComponentInstance,
)
from fprime_python_model.semantics import port_instance as fpm_port_instance
from fprime_python_model.semantics import command as fpm_command
from fprime_python_model.semantics.interface_instance import (
    InterfaceComponentInstance as fpm_InterfaceComponentInstance,
)
from fprime_python_model import fpp_ast as fpm_fpp_ast
from fprime_python_model.semantics.symbol import Symbol as fpm_Symbol

from .port_flow import PortFlowMap

logger = logging.getLogger(__name__)

# Returned by a hop callback to stop descending past that hop
STOP = object()

# FPP's default when a port declares no queue full behavior. An overflow then
# trips FW_ASSERT, which on flight hardware means FATAL and a reboot.
DEFAULT_QUEUE_FULL = "assert"

# Used when no thread origin reaches a port. Unattributed means "could be
# anything", so consumers must widen severity on it, never narrow.
UNKNOWN_THREAD = "<unknown>"

DEFAULT_MAX_STATES = 500000

JSON_AST_FILE = "fpp-ast.json"
JSON_LOCATIONS_FILE = "fpp-loc-map.json"
JSON_ANALYSIS_FILE = "fpp-analysis.json"


class Severity(Enum):
    """Finding severity, ordered by ``rank``

    Shared by every analysis so that ``--fail-on`` means the same thing no
    matter which one produced the finding.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    def __str__(self):
        return self.value

    @property
    def rank(self) -> int:
        return {"info": 0, "warning": 1, "error": 2}[self.value]


class SyncKind(Enum):
    """How an input port is dispatched, and therefore what it costs to call"""

    SYNC = "sync"
    GUARDED = "guarded"
    ASYNC = "async"

    def __str__(self):
        return self.value


@dataclass(frozen=True)
class PortKey:
    """A port on a specific component instance"""

    instance: str
    port: str

    def __str__(self) -> str:
        return f"{self.instance}.{self.port}"


@dataclass
class InstanceInfo:
    """The topology facts about one component instance"""

    name: str
    ci: fpm_ComponentInstance
    kind: "fpm_fpp_ast.fpp_ast.ComponentKind"
    # FPP qualified name of the component definition, e.g. Svc.BufferManager.
    # Used to look this instance up in the C++ flow map.
    component_name: str = ""
    # Input port name -> the dispatch kinds it can run under. A command recv
    # port carries several, because the kind is per-command not per-port.
    input_ports: Dict[str, Set[SyncKind]] = field(default_factory=dict)
    output_ports: List[str] = field(default_factory=list)
    # Input port name -> queue priority, for async ports
    port_priorities: Dict[str, int] = field(default_factory=dict)
    # Port name -> qualified port type, e.g. Fw.BufferSend
    port_types: Dict[str, str] = field(default_factory=dict)
    # Input port name -> queue full behavior: assert, block, drop or hook
    port_queue_full: Dict[str, str] = field(default_factory=dict)
    # Port name -> declared array size; 1 unless the port declares [n]
    port_sizes: Dict[str, int] = field(default_factory=dict)
    # Name of the command recv port, when the component has one
    cmd_port: Optional[str] = None
    # Command mnemonic -> dispatch kinds
    command_kinds: Dict[str, Set[SyncKind]] = field(default_factory=dict)

    @property
    def queue_size(self) -> Optional[int]:
        """Declared queue depth, for instances that own a queue"""
        return self.ci.queue_size

    @property
    def stack_size(self) -> Optional[int]:
        """Declared task stack size in bytes, for instances with a task"""
        return self.ci.stack_size

    @property
    def cpu(self) -> Optional[int]:
        """Declared CPU affinity, when the instance pins its task"""
        return self.ci.cpu

    @property
    def task_priority(self) -> Optional[int]:
        """Thread priority of this instance's task, if it has one"""
        return self.ci.priority

    @property
    def is_own_thread(self) -> bool:
        """Whether handlers on this instance run on a thread of their own"""
        return self.kind in (
            fpm_fpp_ast.fpp_ast.ComponentKind.ACTIVE,
            fpm_fpp_ast.fpp_ast.ComponentKind.QUEUED,
        )

    def guarded_entries(self) -> List[str]:
        """Input ports that acquire this instance's guarded mutex"""
        return sorted(
            name
            for name, kinds in self.input_ports.items()
            if SyncKind.GUARDED in kinds
        )

    def async_entries(self) -> List[str]:
        """Input ports that enqueue a message onto this instance's queue"""
        return sorted(
            name
            for name, kinds in self.input_ports.items()
            if SyncKind.ASYNC in kinds
        )

    def flow_entries(self, port_name: str, kind: SyncKind) -> List[str]:
        """Flow-map handler keys for entering this instance at ``port_name``.

        A command recv port is not one handler but many: the dispatch kind is
        declared per command, so each command has its own handler and its own
        set of output calls. Every other input port maps to a single handler.
        """
        if port_name != self.cmd_port:
            return [port_name]
        # A command port with no user commands of this dispatch kind has no
        # user handler behind it, so there is nothing to resolve. Falling back
        # to the port name here would ask the flow map for a handler that the
        # generated code never emits.
        return [
            f"cmd:{mnemonic}"
            for mnemonic, kinds in sorted(self.command_kinds.items())
            if kind in kinds
        ]


@dataclass(frozen=True)
class ConnectionEnd:
    """One end of a connection, keeping the port array index for display.

    The index is deliberately not part of PortKey: collapsing every index of a
    port array onto one node keeps the reachability analyses sound and simple.
    It is kept here because reports name ports the way FPP does, including the
    index.
    """

    port: PortKey
    index: Optional[int] = None

    def __str__(self) -> str:
        # Index 0 is a real index, so test for None rather than truthiness
        if self.index is None:
            return str(self.port)
        return f"{self.port}[{self.index}]"


@dataclass(frozen=True)
class Connection:
    """A resolved topology connection, from an output port to an input port"""

    source: ConnectionEnd
    dest: ConnectionEnd


@dataclass
class Hop:
    """One call from an output port to an input port, during a chain walk"""

    # The input port the chain was entered through
    entry: PortKey
    # Handler key at the entry port, as used by the flow map
    entry_flow: str
    # The output port being invoked
    source: PortKey
    # The input port it reaches
    dest: PortKey
    # How ``dest`` is dispatched, and therefore what this hop costs
    kind: SyncKind
    # Hop-by-hop witness ending with this hop
    path: List[str]
    # Caller state carried into this hop
    state: Any = None

    def __str__(self) -> str:
        return f"{self.source} -> {self.dest} [{self.kind}]"


class TopologyGraph:
    """The dispatch and connection structure of one FPP topology"""

    def __init__(
        self,
        topology_path: Path,
        flow: Optional[PortFlowMap] = None,
        topology_name: Optional[str] = None,
    ):
        self.topology_path = Path(topology_path)
        self.flow = flow or PortFlowMap.empty()
        self.topology_name = topology_name
        self.model: Optional[fpm_FprimePythonModel] = None
        self.topology: Optional[fpm_Topology] = None
        self.instances: Dict[str, InstanceInfo] = {}
        # str(from PortKey) -> list of destination PortKeys
        self.connections: Dict[str, List[PortKey]] = {}
        # Every connection, with port array indices retained for reporting
        self.connection_list: List[Connection] = []
        # str(input PortKey) -> thread origins that can invoke it, computed
        # lazily: propagation walks the flow map, and an analysis that needs no
        # intra-component flow should not be forced to supply one.
        self.port_threads: Dict[str, Set[str]] = {}
        self._origins_computed = False

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _validate_json_files(self, directory: Path) -> bool:
        required = [JSON_AST_FILE, JSON_LOCATIONS_FILE, JSON_ANALYSIS_FILE]
        return all((directory / f).exists() for f in required)

    def load(self) -> "TopologyGraph":
        """Load the model and build the instance and connection tables

        Raises:
            FileNotFoundError: If required JSON files are missing
            ValueError: If no topology is present in the analysis
        """
        if not self._validate_json_files(self.topology_path):
            raise FileNotFoundError(
                f"Missing required JSON files in {self.topology_path}"
            )
        self.model = fpm_FprimePythonModel(
            str(self.topology_path / JSON_AST_FILE),
            str(self.topology_path / JSON_LOCATIONS_FILE),
            str(self.topology_path / JSON_ANALYSIS_FILE),
        )

        self.topology = self._select_topology(self.model.analysis)
        logger.debug(f"Loaded topology: {self.topology.get_qualified_name()}")

        self._build_instances()
        self._build_connections()
        self._warn_on_blocking_ports()
        return self

    def blocking_ports(self) -> List[PortKey]:
        """Async input ports declared ``queue full block``"""
        return [
            PortKey(name, port)
            for name, info in sorted(self.instances.items())
            for port, behavior in sorted(info.port_queue_full.items())
            if behavior == "block"
            and SyncKind.ASYNC in info.input_ports.get(port, set())
        ]

    def _warn_on_blocking_ports(self) -> None:
        """Warn about blocking sends, which the analyses do not model.

        A ``queue full block`` port blocks the sender inside the enqueue until
        the receiver drains, so it is not really a thread boundary. Every
        analysis here still treats it as an ordinary async hop - the chain ends
        and the caller's locks are considered released - which is the intended
        behavior, not an oversight. The warning exists so that a topology
        relying on blocking sends is not silently analyzed under an assumption
        that does not hold for it.
        """
        blocking = self.blocking_ports()
        if not blocking:
            return
        logger.warning(
            f"{len(blocking)} port(s) declare 'queue full block'. These are "
            f"analyzed as ordinary async hops, so a circular wait through a "
            f"blocking send is not detected:"
        )
        for port in blocking[:10]:
            logger.warning(f"  {port}")
        if len(blocking) > 10:
            logger.warning(f"  ... and {len(blocking) - 10} more")

    @staticmethod
    def _is_deployment(topology: fpm_Topology) -> bool:
        """Whether a topology is declared ``deployment topology``"""
        data = topology.a_node[1].data
        for attribute in ("isDeployment", "is_deployment"):
            if hasattr(data, attribute):
                return bool(getattr(data, attribute))
        return False

    def _select_topology(self, analysis) -> fpm_Topology:
        """Pick which topology to analyze.

        A model built for a deployment contains every subtopology it imports as
        a topology of its own, so the map usually holds many. Analyzing an
        arbitrary one silently analyzes a fragment: picking CdhCore.Subtopology
        out of the Ref model gives 8 instances and 1 connection instead of Ref's
        55 and 297. Prefer the topology declared ``deployment topology``, and
        require an explicit name when that is ambiguous.

        Raises:
            ValueError: If no topology matches, or the choice is ambiguous
        """
        topologies = list(analysis.topology_map.values())
        if not topologies:
            raise ValueError("No topology found in analysis")

        if self.topology_name:
            wanted = self.topology_name
            matches = [
                t
                for t in topologies
                if str(t.get_qualified_name()) == wanted
                or str(t.get_qualified_name()).endswith(f".{wanted}")
                or str(t.get_unqualified_name()) == wanted
            ]
            if not matches:
                available = ", ".join(
                    sorted(str(t.get_qualified_name()) for t in topologies)
                )
                raise ValueError(
                    f"No topology named {wanted!r}. Available: {available}"
                )
            if len(matches) > 1:
                names = ", ".join(sorted(str(t.get_qualified_name()) for t in matches))
                raise ValueError(f"Topology name {wanted!r} is ambiguous: {names}")
            return matches[0]

        deployments = [t for t in topologies if self._is_deployment(t)]
        if len(deployments) == 1:
            return deployments[0]
        if len(deployments) > 1:
            names = ", ".join(
                sorted(str(t.get_qualified_name()) for t in deployments)
            )
            raise ValueError(
                f"Multiple deployment topologies; pass an explicit name. Found: {names}"
            )
        if len(topologies) == 1:
            return topologies[0]

        available = ", ".join(sorted(str(t.get_qualified_name()) for t in topologies))
        raise ValueError(
            f"No deployment topology found and several topologies are present; "
            f"pass an explicit name. Available: {available}"
        )

    # ------------------------------------------------------------------
    # Dispatch-kind classification
    # ------------------------------------------------------------------

    def _command_sync_kinds(self, ci: fpm_ComponentInstance) -> Set[SyncKind]:
        """Dispatch kinds a component's command recv port can run under.

        The guarded mutex is taken per-command, so one cmdIn port may be async
        for one opcode and guarded for another. Param set/save commands only
        take the parameter mutex, which the generated code releases before any
        out-call, so they behave as sync for lock-ordering purposes.
        """
        kinds: Set[SyncKind] = set()
        for command in ci.component.command_map.values():
            kinds.add(self._command_kind(command))
        return kinds

    @staticmethod
    def _command_kind(command) -> SyncKind:
        if isinstance(command, fpm_command.CommandNonParam):
            if isinstance(command.kind, fpm_command.NonParamKindAsync):
                return SyncKind.ASYNC
            if isinstance(command.kind, fpm_command.NonParamKindGuarded):
                return SyncKind.GUARDED
        return SyncKind.SYNC

    def _special_input_kind(
        self, port_instance: fpm_port_instance.SpecialPortInstance
    ) -> SyncKind:
        """Dispatch kind of a special input port from its input kind"""
        input_kind = port_instance.specifier.input_kind
        if input_kind == fpm_fpp_ast.fpp_ast.SpecialInputKind.ASYNC:
            return SyncKind.ASYNC
        if input_kind == fpm_fpp_ast.fpp_ast.SpecialInputKind.GUARDED:
            return SyncKind.GUARDED
        return SyncKind.SYNC

    def _input_sync_kinds(
        self, ci: fpm_ComponentInstance, port_instance: fpm_port_instance.PortInstance
    ) -> Set[SyncKind]:
        """All dispatch kinds an input port can run under"""
        if isinstance(port_instance, fpm_port_instance.GeneralPortInstance):
            if port_instance.kind == fpm_fpp_ast.fpp_ast.GeneralKind.GUARDED_INPUT:
                return {SyncKind.GUARDED}
            if port_instance.kind == fpm_fpp_ast.fpp_ast.GeneralKind.SYNC_INPUT:
                return {SyncKind.SYNC}
            if port_instance.kind == fpm_fpp_ast.fpp_ast.GeneralKind.ASYNC_INPUT:
                return {SyncKind.ASYNC}
            return set()

        if isinstance(port_instance, fpm_port_instance.SpecialPortInstance):
            if (
                port_instance.specifier.kind
                == fpm_fpp_ast.fpp_ast.SpecialKind.COMMAND_RECV
            ):
                kinds = self._command_sync_kinds(ci)
                # A component may declare cmdIn but no commands of its own
                return kinds or {self._special_input_kind(port_instance)}
            return {self._special_input_kind(port_instance)}

        # Internal ports are always queued onto the component's own thread
        if isinstance(port_instance, fpm_port_instance.InternalPortInstance):
            return {SyncKind.ASYNC}

        return set()

    def _port_priority(
        self, port_instance: fpm_port_instance.PortInstance
    ) -> Optional[int]:
        """Queue priority declared on an input port, if any"""
        analysis = self.model.analysis
        if isinstance(port_instance, fpm_port_instance.GeneralPortInstance):
            specifier_priority = port_instance.specifier.priority
            if specifier_priority is None:
                return None
            expression = specifier_priority.data
            if isinstance(expression, fpm_fpp_ast.fpp_ast.ExprLiteralInt):
                return int(expression.value)
            if isinstance(expression, fpm_fpp_ast.fpp_ast.ExprIdent):
                # A named constant. The model keys its evaluated value by the
                # AST node's internal id, so reaching for it is the only way
                # to resolve "priority Ports.foo" to a number.
                value = analysis.value_map.get(specifier_priority._id)  # noqa: SLF001
                if value is not None and isinstance(value.value, int):
                    return value.value
            return None
        if isinstance(
            port_instance,
            (
                fpm_port_instance.SpecialPortInstance,
                fpm_port_instance.InternalPortInstance,
            ),
        ):
            priority = port_instance.priority
            return priority if isinstance(priority, int) else None
        return None

    def _port_type_name(
        self, port_instance: fpm_port_instance.PortInstance
    ) -> Optional[str]:
        """Qualified name of a port's type, e.g. Fw.BufferSend"""
        try:
            port_type = port_instance.get_type()
        except (AttributeError, TypeError):
            return None
        symbol = getattr(port_type, "symbol", None)
        if symbol is None:
            return None
        try:
            return str(self.model.analysis.get_qualified_name_from_map(symbol))
        except (AttributeError, KeyError, ValueError):
            return None

    @staticmethod
    def _queue_full_behavior(port_instance: fpm_port_instance.PortInstance) -> str:
        """Queue full behavior of an input port, defaulting to FPP's assert"""
        queue_full = None
        if isinstance(port_instance, fpm_port_instance.GeneralPortInstance):
            queue_full = port_instance.specifier.queue_full
        elif isinstance(
            port_instance,
            (
                fpm_port_instance.SpecialPortInstance,
                fpm_port_instance.InternalPortInstance,
            ),
        ):
            queue_full = port_instance.queue_full

        if queue_full is None:
            return DEFAULT_QUEUE_FULL
        # The specifier wraps the enum in an AST node
        value = getattr(queue_full, "data", queue_full)
        return str(value)

    # ------------------------------------------------------------------
    # Table construction
    # ------------------------------------------------------------------

    def _component_qualified_name(self, ci: fpm_ComponentInstance) -> str:
        """FPP qualified name of the component definition behind an instance"""
        try:
            symbol = fpm_Symbol.construct(ci.component.a_node)
            return str(self.model.analysis.get_qualified_name_from_map(symbol))
        except (AttributeError, KeyError, ValueError) as e:
            logger.debug(f"  Could not resolve component name: {e}")
            return ""

    def _command_kinds_by_mnemonic(
        self, ci: fpm_ComponentInstance
    ) -> Dict[str, Set[SyncKind]]:
        """Map each command mnemonic to the dispatch kinds it runs under"""
        result: Dict[str, Set[SyncKind]] = {}
        for command in ci.component.command_map.values():
            # Parameter set/save commands are generated in full by FPP; there is
            # no user-written handler to resolve, so they are not flow entries.
            # Their dispatch kind still counts towards the command port's kinds.
            if not isinstance(command, fpm_command.CommandNonParam):
                continue
            try:
                mnemonic = str(command.get_name())
            except (AttributeError, TypeError):
                continue
            result.setdefault(mnemonic, set()).add(self._command_kind(command))
        return result

    def _build_instances(self) -> None:
        """Index every component instance's ports by dispatch kind"""
        for interface_instance in self.topology.instance_map:
            if not isinstance(interface_instance, fpm_InterfaceComponentInstance):
                continue
            ci = interface_instance.ci
            name = str(ci.get_qualified_name())
            info = InstanceInfo(
                name=name,
                ci=ci,
                kind=ci.component.a_node[1].data.kind,
                component_name=self._component_qualified_name(ci),
            )

            for port_name, port_instance in ci.component.port_map.items():
                type_name = self._port_type_name(port_instance)
                if type_name:
                    info.port_types[str(port_name)] = type_name
                try:
                    info.port_sizes[str(port_name)] = int(port_instance.get_array_size())
                except (AttributeError, TypeError, ValueError):
                    info.port_sizes[str(port_name)] = 1

                if port_instance.get_direction() == fpm_port_instance.Direction.OUTPUT:
                    info.output_ports.append(str(port_name))
                    continue

                info.port_queue_full[str(port_name)] = self._queue_full_behavior(
                    port_instance
                )
                kinds = self._input_sync_kinds(ci, port_instance)
                if kinds:
                    info.input_ports[str(port_name)] = kinds
                priority = self._port_priority(port_instance)
                if priority is not None:
                    info.port_priorities[str(port_name)] = priority
                if (
                    isinstance(port_instance, fpm_port_instance.SpecialPortInstance)
                    and port_instance.specifier.kind
                    == fpm_fpp_ast.fpp_ast.SpecialKind.COMMAND_RECV
                ):
                    info.cmd_port = str(port_name)

            info.command_kinds = self._command_kinds_by_mnemonic(ci)
            self.instances[name] = info
            logger.debug(
                f"  {name} ({info.kind}): {len(info.input_ports)} inputs, "
                f"{len(info.output_ports)} outputs"
            )

    def _endpoint_port_key(self, endpoint) -> Optional[PortKey]:
        """Convert a resolved endpoint into a PortKey, if it names an instance"""
        pii = endpoint.port
        interface_instance = pii.interface_instance
        if not isinstance(interface_instance, fpm_InterfaceComponentInstance):
            return None
        return PortKey(
            instance=str(interface_instance.ci.get_qualified_name()),
            port=str(pii.port_instance.get_unqualified_name()),
        )

    def _build_connections(self) -> None:
        """Index topology connections from source port to destination ports

        The model hands connections back in an order that is not stable between
        runs, so the destination lists are sorted once here. Every report is
        then reproducible, which is what makes a checked-in baseline diffable.
        """
        for connections in self.topology.output_connection_map.values():
            for connection in connections:
                try:
                    from_ep = connection.from_endpoint.get_underlying_endpoint()
                    to_ep = connection.to_endpoint.get_underlying_endpoint()
                except Exception as e:  # pragma: no cover - defensive
                    logger.debug(f"  Skipping unresolvable connection: {e}")
                    continue

                from_key = self._endpoint_port_key(from_ep)
                to_key = self._endpoint_port_key(to_ep)
                if from_key is None or to_key is None:
                    continue

                self.connections.setdefault(str(from_key), []).append(to_key)
                self.connection_list.append(
                    Connection(
                        source=ConnectionEnd(from_key, from_ep.port_number),
                        dest=ConnectionEnd(to_key, to_ep.port_number),
                    )
                )
                logger.debug(f"  connection {from_key} -> {to_key}")

        for dests in self.connections.values():
            dests.sort(key=str)
        self.connection_list.sort(key=lambda c: (str(c.source), str(c.dest)))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def outputs_for(self, info: InstanceInfo, flow_entry: str) -> List[str]:
        """Output ports reachable from one handler, via the shared flow engine"""
        return self.flow.outputs_for(
            info.component_name, flow_entry, info.output_ports
        )

    def destinations(self, instance: str, out_port: str) -> List[PortKey]:
        """Input ports wired to one output port"""
        return self.connections.get(str(PortKey(instance, out_port)), [])

    def outward_hops(
        self, instance: str, flow_entry: str
    ) -> Iterator[Tuple[PortKey, PortKey, "InstanceInfo", SyncKind]]:
        """Every wired call out of one handler, and how the far end takes it

        Yields ``(source, dest, dest_info, kind)``. One handler can reach the
        same input port under more than one dispatch kind, so a port that is
        both sync and guarded is yielded once per kind.

        Every traversal in the package goes through here, so they cannot
        disagree about what "the calls out of a handler" means, and they all
        see hops in the same order.
        """
        info = self.instances.get(instance)
        if info is None:
            return
        for out_port in self.outputs_for(info, flow_entry):
            source = PortKey(instance, out_port)
            for dest in self.destinations(instance, out_port):
                dest_info = self.instances.get(dest.instance)
                if dest_info is None:
                    continue
                for kind in sorted(
                    dest_info.input_ports.get(dest.port, set()), key=str
                ):
                    yield source, dest, dest_info, kind

    def connected_inputs(self) -> Set[str]:
        """Every input port that something in the topology drives"""
        return {str(dest) for dests in self.connections.values() for dest in dests}

    @property
    def connection_count(self) -> int:
        return sum(len(v) for v in self.connections.values())

    # ------------------------------------------------------------------
    # Thread origins
    # ------------------------------------------------------------------

    def _compute_thread_origins(self) -> None:
        """Label every input port with the thread origins that can invoke it.

        An origin is a thread of control: an active or queued instance, whose
        handlers run off its own queue, or an external caller for an entry port
        nothing in the topology drives. Origins propagate along synchronous and
        guarded hops and stop at async hops, because crossing an async port
        hands the work to the target's own thread.

        Several analyses need this - which threads contend for a mutex, whether
        two threads reach one passive component, whether a handler is reachable
        at all - so it belongs to the graph rather than to any one of them.
        """
        connected = self.connected_inputs()
        origins: List[Tuple[str, PortKey, SyncKind]] = []

        for name, info in self.instances.items():
            if info.is_own_thread:
                for port_name, kinds in info.input_ports.items():
                    if SyncKind.ASYNC in kinds:
                        origins.append(
                            (
                                f"<thread:{name}>",
                                PortKey(name, port_name),
                                SyncKind.ASYNC,
                            )
                        )

        # An unconnected input port can still be driven by hand-written code -
        # a driver task, an ISR, main - so treat it as its own thread rather
        # than assuming it is unreachable.
        for name, info in self.instances.items():
            for port_name, kinds in info.input_ports.items():
                key = PortKey(name, port_name)
                if str(key) not in connected:
                    origins.extend(
                        (f"<external:{key}>", key, kind) for kind in kinds
                    )

        for label, start, kind in origins:
            self._propagate_origin(label, start, kind)

    def _propagate_origin(
        self, origin: str, start_port: PortKey, start_kind: SyncKind
    ) -> None:
        """Flood one thread origin forward across synchronous hops"""
        start_info = self.instances.get(start_port.instance)
        if start_info is None:
            return

        seen: Set[Tuple[str, str]] = set()
        queue: List[Tuple[str, str]] = [
            (start_port.instance, entry)
            for entry in start_info.flow_entries(start_port.port, start_kind)
        ]

        while queue:
            instance, flow_entry = queue.pop()
            if (instance, flow_entry) in seen:
                continue
            seen.add((instance, flow_entry))
            for _source, dest, dest_info, kind in self.outward_hops(
                instance, flow_entry
            ):
                if kind == SyncKind.ASYNC:
                    continue
                self.port_threads.setdefault(str(dest), set()).add(origin)
                queue.extend(
                    (dest.instance, nxt)
                    for nxt in dest_info.flow_entries(dest.port, kind)
                )

    def ensure_thread_origins(self) -> None:
        """Compute thread origins once, on first use"""
        if self._origins_computed:
            return
        self._origins_computed = True
        self._compute_thread_origins()

    def threads_reaching(self, port: PortKey) -> Set[str]:
        """Thread origins that can invoke one input port"""
        self.ensure_thread_origins()
        return set(self.port_threads.get(str(port), set())) or {UNKNOWN_THREAD}

    # ------------------------------------------------------------------
    # Chain traversal
    # ------------------------------------------------------------------

    def walk_chains(
        self,
        entry: PortKey,
        entry_kind: SyncKind,
        on_hop: Callable[[Hop], Any],
        initial_state: Any = None,
        state_key: Callable[[Any], Any] = lambda state: state,
        budget: Optional[List[int]] = None,
    ) -> bool:
        """Walk every call chain leaving one input port's handler.

        This is the one traversal both analyses share. It resolves each
        handler's real output ports through the flow map, follows the topology
        connections, and hands every resulting hop to ``on_hop``. The analysis
        supplies only the policy:

        * return ``STOP`` to stop descending past a hop, or
        * return the state to descend with (often the state unchanged).

        The deadlock analysis carries the held-lock stack as state and stops at
        async hops; the priority analysis carries nothing and stops at async
        hops after recording them. Neither re-implements the walk.

        :param entry: the input port whose handler starts the chains
        :param entry_kind: how that input port is dispatched, which selects the
            handlers behind a command recv port
        :param budget: single-element list used as a shared mutable traversal
            budget, so one budget can span many entry points
        :returns: whether traversal stopped early on the budget
        """
        info = self.instances.get(entry.instance)
        if info is None:
            return False
        if budget is None:
            budget = [DEFAULT_MAX_STATES]

        truncated = False
        for flow_entry in info.flow_entries(entry.port, entry_kind):
            label = (
                f"{entry} [{entry_kind} entry]"
                if flow_entry == entry.port
                else f"{entry} [{entry_kind} entry: {flow_entry}]"
            )
            truncated |= self._descend(
                entry=entry,
                entry_flow=flow_entry,
                instance=entry.instance,
                flow_entry=flow_entry,
                state=initial_state,
                path=[label],
                on_hop=on_hop,
                state_key=state_key,
                visited=set(),
                budget=budget,
            )
        return truncated

    def _descend(
        self,
        entry: PortKey,
        entry_flow: str,
        instance: str,
        flow_entry: str,
        state: Any,
        path: List[str],
        on_hop: Callable[[Hop], Any],
        state_key: Callable[[Any], Any],
        visited: Set[Tuple[str, str, Any]],
        budget: List[int],
    ) -> bool:
        """Depth-first descent through one component's outward calls"""
        if budget[0] <= 0:
            return True
        marker = (instance, flow_entry, state_key(state))
        if marker in visited:
            return False
        visited.add(marker)
        budget[0] -= 1

        truncated = False
        for source, dest, dest_info, kind in self.outward_hops(instance, flow_entry):
            hop = Hop(
                entry=entry,
                entry_flow=entry_flow,
                source=source,
                dest=dest,
                kind=kind,
                path=[*path, f"{source} -> {dest} [{kind}]"],
                state=state,
            )
            next_state = on_hop(hop)
            if next_state is STOP:
                continue
            for dest_flow in dest_info.flow_entries(dest.port, kind):
                truncated |= self._descend(
                    entry=entry,
                    entry_flow=entry_flow,
                    instance=dest.instance,
                    flow_entry=dest_flow,
                    state=next_state,
                    path=hop.path,
                    on_hop=on_hop,
                    state_key=state_key,
                    visited=visited,
                    budget=budget,
                )
        return truncated
