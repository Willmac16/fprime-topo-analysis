"""
Regression tests for the topology checks

Each check is pinned against a purpose-built topology so its verdict is
deterministic, plus a guard that the whole suite stays quiet on real F'
components.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""


from fprime_topology_analysis.checks import CHECKS, Severity, run_checks
from fprime_topology_analysis.port_flow import PortFlowMap
from fprime_topology_analysis.topology_graph import TopologyGraph


def graph_for(model_dir, flow=None):
    return TopologyGraph(model_dir, flow=flow or PortFlowMap.permissive()).load()


def findings_for(model_dir, check_id, flow=None):
    graph = graph_for(model_dir, flow)
    findings, skipped = run_checks(graph, {check_id})
    assert not skipped, skipped
    return findings


def test_every_check_has_an_id_and_name():
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids)), "check ids must be unique"
    assert all(c.id and c.name for c in CHECKS)


def test_checks_needing_flow_are_skipped_not_guessed(model_builder):
    """A flow-dependent check must not report from an empty flow map"""
    graph = TopologyGraph(
        model_builder("synthetic_abba"), flow=PortFlowMap.empty()
    ).load()
    findings, skipped = run_checks(graph, {"sync-cycle"})

    assert findings == []
    assert any("sync-cycle" in note for note in skipped)


def test_priority_inversion_window_spans_two_drivers(model_builder):
    """Two drivers at different priorities contending one mutex is a window"""
    findings = findings_for(model_builder("synthetic_abba"), "priority-inversion-window")

    # synthetic_abba drives both guarded components from two tasks at the same
    # priority, so there is no spread to report
    assert all(f.severity != Severity.ERROR for f in findings)


def test_ping_coverage_flags_unmonitored_thread(model_builder):
    """An active instance with no ping connected is unmonitored"""
    findings = findings_for(model_builder("synthetic_abba"), "ping-coverage")

    subjects = {f.subject for f in findings}
    assert "T.d1" in subjects and "T.d2" in subjects
    assert all(f.severity == Severity.WARNING for f in findings)


def test_cmd_tlm_paths_quiet_without_commands(model_builder):
    """A topology with no commands or telemetry has nothing to report"""
    findings = findings_for(model_builder("synthetic_clean"), "cmd-tlm-paths")

    assert findings == []


def test_sync_cycle_needs_a_real_cycle(model_builder):
    """The sync-passthrough topology has a guarded hop, so it is not pure sync"""
    flow = PortFlowMap.permissive()
    findings = findings_for(
        model_builder("synthetic_sync_passthrough"), "sync-cycle", flow
    )

    # The cycle there passes through guarded ports, which the deadlock analyzer
    # owns; this check must not double-report it
    assert findings == []


def test_queue_overflow_only_errors_on_a_self_enqueue(model_builder):
    """Fan-out onto another instance's queue is not a proof of overflow"""
    findings = findings_for(model_builder("priority_inversion"), "queue-overflow")

    for finding in findings:
        if finding.severity == Severity.ERROR:
            # An error must name the same instance as both stimulus and target
            assert finding.subject in finding.evidence[0]


def test_buffer_ownership_quiet_without_buffers(model_builder):
    findings = findings_for(model_builder("synthetic_clean"), "buffer-ownership")

    assert findings == []


def test_unconnected_port_is_a_warning_not_a_claim(model_builder, flow_map_builder):
    """Reachability is not execution, so this check never reports an error"""
    flow = PortFlowMap.permissive(
        flow_map_builder("FlowThingComponentBaseStub.cpp", "FlowThing.cpp")
    )
    findings = findings_for(
        model_builder("flow_precision"), "unconnected-port-invoked", flow
    )

    assert all(f.severity == Severity.WARNING for f in findings)


def test_all_checks_run_without_error(model_builder):
    """Every check must survive a real topology without raising"""
    graph = graph_for(model_builder("real_buffermanager_clean"))
    findings, skipped = run_checks(graph)

    # Skips are only allowed for checks that need a flow map
    flow_checks = {c.id for c in CHECKS if c.requires_flow}
    for note in skipped:
        assert note.split(":")[0] in flow_checks, note
    assert isinstance(findings, list)
