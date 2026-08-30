#!/usr/bin/env python3
"""
Port Flow Map - shared intra-component call flow for topology analyses

The FPP topology (via ``fpp-to-json``) describes *inter*-component flow: which
output port is wired to which input port, and how each input port is dispatched.
It says nothing about *intra*-component flow - which output ports a given input
handler actually invokes - because that lives in the C++ implementation.

``component_call_graph.py`` recovers that half with libclang and writes it out as
a flow map. This module loads that flow map and answers the one question the
topology analyses need:

    Given component C and the handler entered at input port P, which of C's
    output ports can be invoked before that handler returns?

Both the guarded-port deadlock analysis and the queue priority analysis are
driven by that question, so they share this engine and stay consistent with each
other.

Resolution is strict by default. If the flow map is missing, does not cover a
component, does not cover a handler, or marks a handler ``opaque`` because
libclang could not resolve one of its calls, the lookup raises
``UnresolvedFlowError`` rather than guessing.

The alternative - assuming an unresolved handler may call every output port - is
sound in the formal sense but useless in practice: on a real deployment it makes
almost every guarded component appear to reach almost every other, burying real
defects under false positives. Failing loudly says "the C++ analysis did not
run, so this result would be meaningless" instead of printing a meaningless
result. Callers that genuinely want the over-approximation must opt in
explicitly via ``PortFlowMap.permissive()``.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

FLOW_FORMAT_VERSION = 1


# F' implementation classes do not have to match the FPP component name. The
# common conventions append one of these suffixes, e.g. FPP Svc.CommandDispatcher
# is implemented by C++ Svc::CommandDispatcherImpl.
IMPL_CLASS_SUFFIXES = ("", "Impl", "ComponentImpl", "ComponentImp")


class UnresolvedFlowError(RuntimeError):
    """A handler's output ports could not be resolved from the C++.

    Carries the specific handler so the caller can report exactly which
    function needs attention, rather than failing with a generic message.
    """

    def __init__(self, component: str, entry: str, reason: str):
        self.component = component
        self.entry = entry
        self.reason = reason
        super().__init__(f"{component}.{entry}: {reason}")


class PortFlowMap:
    """Resolves component handlers to the output ports they can invoke"""

    def __init__(self, data: Optional[dict] = None, strict: bool = True):
        self.data = data or {}
        # C++-style component name -> handler entry -> record
        self.components: Dict[str, dict] = self.data.get("components", {})
        self.strict = strict
        self.stats_precise = 0
        self.stats_conservative = 0
        # Handlers that could not be resolved, collected for reporting
        self.unresolved: Dict[str, str] = {}

    @classmethod
    def permissive(cls, data: Optional[dict] = None) -> "PortFlowMap":
        """A flow map that assumes an unresolved handler calls every output.

        This opt-in mode is useful for exercising topology-level dispatch rules
        in isolation and for a deliberate worst-case sweep. It is not appropriate
        for reporting real findings, because unresolved handlers manufacture
        chains that the C++ may never take.
        """
        return cls(data, strict=False)

    @classmethod
    def load(cls, path: Path, strict: bool = True) -> "PortFlowMap":
        """Load a flow map produced by component_call_graph.py

        Raises:
            FileNotFoundError: If the flow map does not exist
            ValueError: If the flow map is malformed or an unsupported version
        """
        if not path.exists():
            raise FileNotFoundError(f"Flow map not found: {path}")
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Malformed flow map {path}: {e}") from e

        version = data.get("version")
        if version != FLOW_FORMAT_VERSION:
            raise ValueError(
                f"Unsupported flow map version {version!r} in {path}; "
                f"expected {FLOW_FORMAT_VERSION}"
            )
        return cls(data, strict=strict)

    @classmethod
    def empty(cls) -> "PortFlowMap":
        """An empty strict flow map; every lookup fails until one is loaded"""
        return cls()

    @property
    def is_empty(self) -> bool:
        return not self.components

    @staticmethod
    def _cpp_name(component_qualified_name: str) -> str:
        """Convert an FPP qualified name to the C++ spelling"""
        return component_qualified_name.replace(".", "::")

    def _candidate_names(self, component: str) -> List[str]:
        """C++ class names an FPP component might be implemented as"""
        base = self._cpp_name(component)
        return [f"{base}{suffix}" for suffix in IMPL_CLASS_SUFFIXES]

    def _component_record(self, component: str) -> Optional[dict]:
        """Find the flow map record for a component, trying impl naming"""
        for name in self._candidate_names(component):
            record = self.components.get(name)
            if record is not None:
                return record
        return None

    def _lookup(self, component: str, entry: str) -> Optional[dict]:
        """Find the record for one handler, if the flow map has it"""
        record = self._component_record(component)
        if record is None:
            return None
        return record.get("handlers", {}).get(entry)

    def has_component(self, component: str) -> bool:
        """Whether the flow map covers this component at all"""
        return self._component_record(component) is not None

    def outputs_for(
        self,
        component: str,
        entry: str,
        all_outputs: List[str],
    ) -> List[str]:
        """Output ports reachable from one handler.

        Falls back to ``all_outputs`` whenever the answer is not known to be
        complete: no flow map, component absent, handler absent, or the handler
        was marked opaque because libclang could not resolve one of its calls.

        :param component: FPP qualified component name, e.g. ``Svc.BufferManager``
        :param entry: input port name, or ``cmd:<MNEMONIC>`` for a command
        :param all_outputs: every output port the component declares
        """
        record = self._lookup(component, entry)
        if record is None or record.get("opaque", True):
            reason = self._unresolved_reason(component, record)
            self.unresolved[f"{component}.{entry}"] = reason
            if self.strict:
                raise UnresolvedFlowError(component, entry, reason)
            self.stats_conservative += 1
            return list(all_outputs)

        declared = set(all_outputs)
        # Intersect with the declared ports so a stale flow map cannot invent
        # ports that the topology does not have.
        resolved = [port for port in record.get("ports", []) if port in declared]
        self.stats_precise += 1
        return resolved

    def _unresolved_reason(self, component: str, record: Optional[dict]) -> str:
        """Explain precisely why a handler could not be resolved"""
        if self.is_empty:
            return "no flow map was supplied; run component_call_graph.py first"
        if not self.has_component(component):
            return (
                "component absent from the flow map; its source may not be in "
                "compile_commands.json"
            )
        if record is None:
            return "handler absent from the flow map; it may not be implemented in C++"
        return (
            "handler marked opaque: libclang could not resolve a call it makes "
            "(function pointer, delegate, or a parse error in that translation unit)"
        )

    def is_precise(self, component: str, entry: str) -> bool:
        """Whether this handler resolved to an exact output port set"""
        record = self._lookup(component, entry)
        return record is not None and not record.get("opaque", True)

    def facet(self, component: str, entry: str, name: str) -> List[str]:
        """One extra recorded fact about a handler.

        Facets are the C++ details beyond port usage: ``guarded_ports`` (ports
        the handler tests with isConnected before invoking), ``fields`` (non-port
        members it touches) and ``event_severities``. An absent facet is an
        empty list rather than an error, so a check that wants one degrades to
        finding nothing rather than failing the whole run.
        """
        record = self._lookup(component, entry)
        if record is None:
            return []
        return list(record.get(name, []))

    def summary(self) -> str:
        """One-line description of how much precision was available"""
        if self.is_empty:
            return (
                "No flow map supplied"
                if self.strict
                else "No flow map: assuming every handler may invoke every "
                "output port (permissive mode)"
            )
        total = self.stats_precise + self.stats_conservative
        if total == 0:
            return f"Flow map loaded: {len(self.components)} component(s)"
        pct = 100.0 * self.stats_precise / total
        if self.strict:
            return (
                f"Flow map: {self.stats_precise}/{total} handler lookups "
                f"resolved precisely from the C++ (strict mode)"
            )
        return (
            f"Flow map: {self.stats_precise}/{total} handler lookups resolved "
            f"precisely ({pct:.0f}%), {self.stats_conservative} fell back to "
            f"all-outputs (permissive mode)"
        )
