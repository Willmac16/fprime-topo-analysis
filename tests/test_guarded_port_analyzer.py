"""
Regression tests for the guarded port deadlock analyzer

Covers both synthetic topologies, which pin down each dispatch rule in
isolation, and topologies built from real F' components, which check that the
analyzer reads the shipped models correctly.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""


from fprime_topology_analysis.guarded_port_analyzer import (
    FindingKind,
    GuardedPortAnalyzer,
    Severity,
    SyncKind,
    load_suppressions,
)


def analyze(graph, **kwargs):
    """Run the analyzer over a loaded graph"""
    analyzer = GuardedPortAnalyzer(graph, **kwargs)
    analyzer.run()
    return analyzer


def kinds_of(analyzer):
    return {finding.kind for finding in analyzer.findings}


def cycles_of(analyzer, kind):
    return {
        tuple(sorted(finding.cycle))
        for finding in analyzer.findings
        if finding.kind == kind
    }


# ----------------------------------------------------------------------
# Synthetic topologies: one dispatch rule at a time
# ----------------------------------------------------------------------


def test_abba_between_two_guarded_components(graph_builder):
    """Two all-guarded components reaching into each other deadlock"""
    analyzer = analyze(graph_builder("synthetic_abba"))

    assert FindingKind.ABBA in kinds_of(analyzer)
    assert ("T.a", "T.b") in cycles_of(analyzer, FindingKind.ABBA)

    abba = next(f for f in analyzer.findings if f.kind == FindingKind.ABBA)
    assert abba.severity == Severity.ERROR
    # Both directions of the cycle must be reported, each with a witness path
    assert len(abba.edges) == 2
    assert all(edge.witness for edge in abba.edges)

    # The two drivers are distinct threads, which is what makes it an ABBA
    # rather than a single-threaded self-deadlock
    threads = set().union(*(edge.threads for edge in abba.edges))
    assert len({t for t in threads if t.startswith("<thread:")}) >= 2


def test_async_hop_breaks_the_lock_chain(graph_builder):
    """An async input port queues the message and releases the caller's lock"""
    analyzer = analyze(graph_builder("synthetic_async_break"))

    assert analyzer.findings == []
    assert analyzer.lock_edges == {}


def test_sync_passthrough_preserves_the_lock_chain(graph_builder):
    """A sync port takes no mutex but keeps the chain on the caller's thread"""
    analyzer = analyze(graph_builder("synthetic_sync_passthrough"))

    # The lock chain survives the sync hop: a locks c and c locks a, so the
    # cycle is detected as edges (all passive here, so no live ABBA is reported).
    assert ("T.a", "T.c") in analyzer.lock_edges
    assert ("T.c", "T.a") in analyzer.lock_edges

    # The sync passthrough runs under the caller's lock but owns no mutex, so
    # it must never appear as a node in the lock-order graph
    nodes = {edge.holder for edge in analyzer.lock_edges.values()}
    nodes |= {edge.acquired for edge in analyzer.lock_edges.values()}
    assert "T.p" not in nodes


def test_call_chains_trace_from_thread_origin_to_entry(graph_builder):
    """--call-chains shows the path from each driving thread's origin to the entry"""
    from fprime_topology_analysis.topology_graph import PortKey

    analyzer = analyze(graph_builder("synthetic_abba"), show_call_chains=True)

    # d1's own thread wakes and calls out into a.gIn.
    path = analyzer.graph.origin_call_path("<thread:T.d1>", PortKey("T.a", "gIn"))
    assert path == ["T.d1.wake [origin]", "T.d1.out -> T.a.gIn [guarded]"]

    # An unreached origin yields no path.
    assert analyzer.graph.origin_call_path("<unknown>", PortKey("T.a", "gIn")) is None

    # The rendered report exposes the chain on the finding edges.
    assert "reached by <thread:" in analyzer.format_report()


def test_call_chains_are_off_by_default(graph_builder):
    analyzer = analyze(graph_builder("synthetic_abba"))
    assert "reached by" not in analyzer.format_report()


def test_one_way_guarded_chain_is_clean(graph_builder):
    """Locks taken in a single consistent order are not a hazard"""
    analyzer = analyze(graph_builder("synthetic_clean"))

    assert analyzer.findings == []
    # The one-way call is still recorded as a lock ordering, just not a cycle
    assert ("T.a", "T.b") in analyzer.lock_edges


def test_report_summary_is_aligned(graph_builder):
    analyzer = analyze(graph_builder("synthetic_clean"))

    summary = analyzer.format_report()

    assert "Component instances:           3" in summary
    assert "Instances with guarded ports:  2" in summary
    assert "Lock-order edges:              1" in summary
    assert "C++ handlers resolved:         0/6 (6 conservative)" in summary
    assert "Intra-component flow:" not in summary
    assert "Findings:                      0" in summary


def test_report_summarizes_resolved_cpp_handlers(graph_builder):
    analyzer = analyze(graph_builder("synthetic_clean"))
    analyzer.graph.flow.stats_precise = 719
    analyzer.graph.flow.stats_conservative = 0

    summary = analyzer.format_report()

    assert "C++ handlers resolved:         719/719" in summary
    assert "strict mode" not in summary


def test_suppression_removes_a_lock_edge(graph_builder):
    """A recorded lock ordering can be suppressed once it is enforced"""
    analyzer = analyze(graph_builder("synthetic_abba"), suppressions={("T.a", "T.b")}
    )

    assert ("T.a", "T.b") not in analyzer.lock_edges
    assert not cycles_of(analyzer, FindingKind.ABBA)


def test_suppression_file_parsing(tmp_path):
    """Suppression files accept edges, self edges and comments"""
    path = tmp_path / "suppress.txt"
    path.write_text(
        "\n".join(
            [
                "# enforced by construction",
                "a.b -> c.d",
                "self.instance",
                "   ",
                "e.f -> g.h  # trailing comment",
            ]
        )
    )

    assert load_suppressions(path) == {
        ("a.b", "c.d"),
        ("self.instance", "self.instance"),
        ("e.f", "g.h"),
    }


# ----------------------------------------------------------------------
# Real F' components
# ----------------------------------------------------------------------


def test_real_tlmchan_guarded_ports_are_recognized(graph_builder):
    """Svc.TlmChan's shipped port kinds are read correctly from the model"""
    analyzer = analyze(graph_builder("real_tlmchan_cycle"))

    tlm_chan = analyzer.instances["RegTest.tlmChan"]
    assert tlm_chan.component_name == "Svc.TlmChan"

    # TlmRecv and TlmGet are guarded input ports in Svc/TlmChan/TlmChan.fpp
    assert tlm_chan.input_ports["TlmRecv"] == {SyncKind.GUARDED}
    assert tlm_chan.input_ports["TlmGet"] == {SyncKind.GUARDED}
    # Run and pingIn are async, and must not act as guarded entries
    assert tlm_chan.input_ports["Run"] == {SyncKind.ASYNC}
    assert set(tlm_chan.guarded_entries()) == {"TlmRecv", "TlmGet"}


def test_real_tlmchan_cycle_is_detected(graph_builder):
    """A guarded time provider that emits telemetry closes a lock-order cycle on
    TlmChan. Only tlmChan's own thread reaches it, so the cycle is detected as
    edges but is latent (not reported as a live ABBA)."""
    analyzer = analyze(graph_builder("real_tlmchan_cycle"))

    assert ("RegTest.tlmChan", "RegTest.timeKeeper") in analyzer.lock_edges
    assert ("RegTest.timeKeeper", "RegTest.tlmChan") in analyzer.lock_edges
    assert ("RegTest.timeKeeper", "RegTest.tlmChan") not in cycles_of(
        analyzer, FindingKind.ABBA
    )


def test_real_buffermanager_topology_is_clean(graph_builder):
    """A correctly wired real BufferManager produces no findings"""
    analyzer = analyze(graph_builder("real_buffermanager_clean"))

    buffer_manager = analyzer.instances["RegTest.bufferManager"]
    assert buffer_manager.component_name == "Svc.BufferManager"
    # All three BufferManager input ports are guarded in the shipped model
    assert set(buffer_manager.guarded_entries()) == {
        "bufferSendIn",
        "bufferGetCallee",
        "schedIn",
    }

    assert analyzer.findings == []


def test_real_event_manager_log_recv_is_sync(graph_builder):
    """Svc.EventManager.LogRecv is sync, so it continues the caller's chain

    This is a easy thing to get wrong by assuming every event path is queued.
    An event emitted inside a guarded handler runs EventManager's handler on
    the caller's thread with the caller's mutex still held.
    """
    analyzer = analyze(graph_builder("real_buffermanager_clean"))

    event_manager = analyzer.instances["RegTest.eventManager"]
    assert event_manager.component_name == "Svc.EventManager"
    assert event_manager.input_ports["LogRecv"] == {SyncKind.SYNC}
    assert not event_manager.guarded_entries()
