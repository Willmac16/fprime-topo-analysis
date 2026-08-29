"""
Regression tests for report rendering

Both cases here are bugs that a passing analysis still shipped: a renderer that
crashed only on the flag nobody exercised, and a report whose evidence lines
came out in a different order every run, which makes a checked-in baseline
impossible to diff.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

from fprime_topology_analysis.async_queue_analyzer import analyze, render_mermaid
from fprime_topology_analysis.checks import run_checks


def test_mermaid_diagram_renders(graph_builder):
    """--diagram-output has to produce a diagram, not a NameError"""
    rows = analyze(graph_builder("priority_inversion"), {})

    diagram = render_mermaid(rows)

    assert diagram.startswith("flowchart LR")
    # Instance names are sanitized into mermaid-safe node ids
    assert "T_urgent" in diagram
    assert "T.urgent" in diagram


def test_connection_order_is_stable(graph_builder):
    """Two graphs built from one model agree on destination order

    The model returns connections in an order that varies between runs, so the
    graph sorts them. Without that, findings are identical but their evidence
    shuffles, and no two runs of the tool produce the same file.
    """
    first = graph_builder("real_tlmchan_cycle")
    second = graph_builder("real_tlmchan_cycle")

    assert first.connections.keys() == second.connections.keys()
    for source, dests in first.connections.items():
        assert [str(d) for d in dests] == [str(d) for d in second.connections[source]]
        assert [str(d) for d in dests] == sorted(str(d) for d in dests)


def test_findings_are_reported_in_a_stable_order(graph_builder):
    """The same graph checked twice reports identical evidence, line for line"""
    graph = graph_builder("real_tlmchan_cycle")

    first, _ = run_checks(graph, None)
    second, _ = run_checks(graph, None)

    assert [(f.check, f.subject, f.evidence) for f in first] == [
        (f.check, f.subject, f.evidence) for f in second
    ]
