"""
End-to-end test of the hybrid FPP + C++ analysis

The topology alone allows a lock-order cycle, because wiring permits
flowThing's guarded handler to call outX. The C++ shows that handler only ever
calls outY. Together they prove there is no cycle - which neither half can
establish on its own.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import pytest

from fprime_topology_analysis.guarded_port_analyzer import FindingKind, GuardedPortAnalyzer
from fprime_topology_analysis.port_flow import PortFlowMap, UnresolvedFlowError


def test_topology_alone_reports_a_cycle(graph_builder):
    """Without the C++ half, the wiring looks like a lock-order cycle"""
    analyzer = GuardedPortAnalyzer(graph_builder("flow_precision"))
    analyzer.run()

    assert ("RegTest.flowThing", "RegTest.partner") in analyzer.lock_edges
    assert ("RegTest.partner", "RegTest.flowThing") in analyzer.lock_edges
    assert analyzer.findings


def test_flow_map_eliminates_the_false_positive(graph_builder, flow_map_builder):
    """With the C++ half, the edge and the cycle both disappear"""
    flow = PortFlowMap(
        flow_map_builder("FlowThingComponentBaseStub.cpp", "FlowThing.cpp")
    )
    analyzer = GuardedPortAnalyzer(graph_builder("flow_precision", flow))
    analyzer.run()

    # flowThing.gIn_handler never calls outX, so it never nests partner's mutex
    assert ("RegTest.flowThing", "RegTest.partner") not in analyzer.lock_edges
    # partner's own call back into flowThing is real and must be kept
    assert ("RegTest.partner", "RegTest.flowThing") in analyzer.lock_edges
    assert analyzer.findings == []


def test_unmapped_components_fail_rather_than_guess(graph_builder, flow_map_builder):
    """Strict mode refuses to analyze components the C++ pass never covered.

    The old behavior was to assume such a handler calls every output port. That
    is sound but manufactures chains the code never takes, so a result built on
    it is not trustworthy. Failing is the honest answer.
    """
    flow = PortFlowMap(
        flow_map_builder("FlowThingComponentBaseStub.cpp", "FlowThing.cpp")
    )
    analyzer = GuardedPortAnalyzer(graph_builder("synthetic_abba", flow))

    with pytest.raises(UnresolvedFlowError) as excinfo:
        analyzer.run()
    # The synthetic_abba components have no C++ in this flow map at all
    assert excinfo.value.component.startswith("T.")
    assert "absent from the flow map" in excinfo.value.reason


def test_permissive_mode_still_reports_real_cycles(graph_builder, flow_map_builder):
    """Opting into the over-approximation keeps the old behavior available"""
    flow = PortFlowMap.permissive(
        flow_map_builder("FlowThingComponentBaseStub.cpp", "FlowThing.cpp")
    )
    analyzer = GuardedPortAnalyzer(graph_builder("synthetic_abba", flow))
    analyzer.run()

    assert FindingKind.ABBA in {f.kind for f in analyzer.findings}
