"""
Regression tests for the C++ component call graph extractor

The extractor answers the question the FPP model cannot: which output ports does
a given handler actually invoke? These tests pin down transitive resolution
through private helpers and through generated helpers, and the soundness
fallback for calls libclang cannot resolve.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import pytest

from fprime_topology_analysis.component_call_graph import CallGraphExtractor
from fprime_topology_analysis.port_flow import PortFlowMap, UnresolvedFlowError


def handlers_of(flow_map, component):
    return flow_map["components"][component]["handlers"]


def test_libclang_darwin_attribute_cursor_kinds_are_supported(tmp_path):
    extractor = CallGraphExtractor(
        tmp_path / "compile_commands.json", system_includes=[]
    )

    cindex = extractor._load_clang()

    for value in range(420, 438):
        assert cindex.CursorKind.from_id(value).value == value
    assert cindex.CursorKind.from_id(437) == cindex.CursorKind.FLAG_ENUM


def test_handler_resolves_through_private_helpers(flow_map_builder):
    """gIn_handler reaches alphaOut through two levels of private helper"""
    flow_map = flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp")
    handlers = handlers_of(flow_map, "Svc::TestThing")

    assert "alphaOut" in handlers["gIn"]["ports"]
    assert not handlers["gIn"]["opaque"]


def test_handler_resolves_generated_telemetry_helper(flow_map_builder):
    """A generated tlmWrite_* helper resolves to the telemetry output port"""
    flow_map = flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp")
    handlers = handlers_of(flow_map, "Svc::TestThing")

    assert "tlmOut" in handlers["gIn"]["ports"]


def test_handler_excludes_ports_it_never_calls(flow_map_builder):
    """The whole point: a handler is not credited with unrelated output ports"""
    flow_map = flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp")
    handlers = handlers_of(flow_map, "Svc::TestThing")

    assert "betaOut" not in handlers["gIn"]["ports"]
    assert handlers["sIn"]["ports"] == ["betaOut"]


def test_command_handlers_are_keyed_separately(flow_map_builder):
    """Command handlers are keyed cmd:<MNEMONIC>, since kind is per command"""
    flow_map = flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp")
    handlers = handlers_of(flow_map, "Svc::TestThing")

    assert "cmd:NOOP" in handlers
    assert handlers["cmd:NOOP"]["ports"] == ["eventOut"]


# ----------------------------------------------------------------------
# The shared flow engine
# ----------------------------------------------------------------------


def test_flow_map_narrows_outputs(flow_map_builder):
    flow = PortFlowMap(flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp"))
    declared = ["alphaOut", "betaOut", "tlmOut", "eventOut"]

    assert set(flow.outputs_for("Svc.TestThing", "gIn", declared)) == {
        "alphaOut",
        "tlmOut",
    }
    assert flow.is_precise("Svc.TestThing", "gIn")


def test_unknown_handler_fails_in_strict_mode(flow_map_builder):
    """An unmapped handler is an error, not a silent over-approximation"""
    flow = PortFlowMap(flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp"))
    declared = ["alphaOut", "betaOut"]

    with pytest.raises(UnresolvedFlowError):
        flow.outputs_for("Svc.TestThing", "notAHandler", declared)
    with pytest.raises(UnresolvedFlowError):
        flow.outputs_for("Svc.NotAComponent", "gIn", declared)
    assert not flow.is_precise("Svc.TestThing", "notAHandler")


def test_unknown_handler_widens_in_permissive_mode(flow_map_builder):
    """Permissive mode widens unresolved handlers to every output port."""
    flow = PortFlowMap.permissive(
        flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp")
    )
    declared = ["alphaOut", "betaOut"]

    assert flow.outputs_for("Svc.TestThing", "notAHandler", declared) == declared
    assert flow.outputs_for("Svc.NotAComponent", "gIn", declared) == declared


def test_unresolved_reason_is_actionable(flow_map_builder):
    """The failure names why, so the user knows what to fix"""
    flow = PortFlowMap(flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp"))

    with pytest.raises(UnresolvedFlowError) as excinfo:
        flow.outputs_for("Svc.NotAComponent", "gIn", ["a"])
    assert "compile_commands" in excinfo.value.reason


def test_empty_flow_map_fails_in_strict_mode():
    """Running with no flow map at all is a hard error"""
    flow = PortFlowMap.empty()

    assert flow.is_empty
    with pytest.raises(UnresolvedFlowError) as excinfo:
        flow.outputs_for("Any.Component", "anyHandler", ["a", "b"])
    assert "no flow map" in excinfo.value.reason.lower()


def test_empty_permissive_flow_map_is_conservative():
    flow = PortFlowMap.permissive()
    declared = ["a", "b", "c"]

    assert flow.is_empty
    assert flow.outputs_for("Any.Component", "anyHandler", declared) == declared


def test_flow_map_cannot_invent_undeclared_ports(flow_map_builder):
    """A stale flow map must not add ports the topology does not declare"""
    flow = PortFlowMap(flow_map_builder("TestComponentBaseStub.cpp", "TestThing.cpp"))

    # alphaOut is resolved by the extractor but absent from the declared list
    assert flow.outputs_for("Svc.TestThing", "gIn", ["tlmOut"]) == ["tlmOut"]


def test_rejects_unsupported_version(tmp_path):
    import json

    path = tmp_path / "flow.json"
    path.write_text(json.dumps({"version": 99, "components": {}}))

    with pytest.raises(ValueError, match="Unsupported flow map version"):
        PortFlowMap.load(path)
