"""
Regression tests for report rendering

Both cases here are bugs that a passing analysis still shipped: a renderer that
crashed only on the flag nobody exercised, and a report whose evidence lines
came out in a different order every run, which makes a checked-in baseline
impossible to diff.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

from fprime_topology_analysis.async_queue_analyzer import (
    InboundAsyncPortGroup,
    InboundProducer,
    QueueGroup,
    analyze,
    filter_drop_ports,
    render_markdown,
    render_mermaid,
)
from fprime_topology_analysis.checks import run_checks


def test_mermaid_diagram_renders(graph_builder):
    """--diagram-output has to produce a diagram, not a NameError"""
    rows = analyze(graph_builder("priority_inversion"), {})

    diagram = render_mermaid(rows)

    assert diagram.startswith("flowchart LR")
    # Instance names are sanitized into mermaid-safe node ids
    assert "T_urgent" in diagram
    assert "T.urgent" in diagram


def test_queue_report_explains_colors_and_shares_drain_count_rows():
    producers = [
        InboundProducer(
            source="active",
            thread_kind="active",
            thread_priority=20,
        ),
        InboundProducer(
            source="passive",
            thread_kind="passive",
            emit_context="sync input handler recv",
        ),
    ]
    row = QueueGroup(
        destination="queue",
        queue_size=10,
        drain_thread_kind="active",
        drain_thread_priority=10,
        drain_drain_source=None,
        drain_context="",
        inbound_ports=[InboundAsyncPortGroup(producers=producers)],
        inbound=[],
        data_types=[],
        total_production_hz=None,
        consumer_rate_hz=None,
        queue_fill_time_s=None,
    )

    report = render_markdown([row], include_rates=False)

    assert "🟠 caller-thread priority is unresolved" in report
    lines = report.splitlines()
    destination = next(index for index, line in enumerate(lines) if "| queue |" in line)
    assert "| 10 | active | 10 |" in lines[destination]
    active = next(line for line in lines if "| active | active |" in line)
    passive = next(line for line in lines if "| passive | passive" in line)
    assert "|  |  | 🔴 1 |" in active
    assert "|  |  | 🟠 1 |" in passive
    assert "<br" not in report


def test_drop_port_filter_removes_groups_and_empty_queues():
    keep = InboundAsyncPortGroup(
        destination_port="keep",
        data_type="Keep",
        overflow_behavior="assert",
        producers=[InboundProducer(source="keep.out")],
        total_production_hz=2.0,
    )
    drop = InboundAsyncPortGroup(
        destination_port="discard",
        data_type="Drop",
        overflow_behavior="drop",
        producers=[InboundProducer(source="drop.out")],
        total_production_hz=10.0,
    )
    base = {
        "queue_size": 10,
        "drain_thread_kind": "active",
        "drain_thread_priority": 10,
        "drain_drain_source": None,
        "drain_context": "",
        "data_types": ["Drop", "Keep"],
        "total_production_hz": 12.0,
        "consumer_rate_hz": 1.0,
        "queue_fill_time_s": 1.0,
    }
    mixed = QueueGroup(
        destination="mixed",
        inbound_ports=[keep, drop],
        inbound=["drop.out", "keep.out"],
        **base,
    )
    only_drop = QueueGroup(
        destination="onlyDrop",
        inbound_ports=[drop],
        inbound=["drop.out"],
        **base,
    )

    filtered = filter_drop_ports([mixed, only_drop])

    assert [row.destination for row in filtered] == ["mixed"]
    assert [group.destination_port for group in filtered[0].inbound_ports] == ["keep"]
    assert filtered[0].inbound == ["keep.out"]
    assert filtered[0].data_types == ["Keep"]
    assert filtered[0].total_production_hz == 2.0


def test_fw_cmd_queue_behavior_is_per_command(graph_builder):
    graph = graph_builder("command_queue_behavior")
    command_target = graph.instances["T.target"]
    assert command_target.command_priorities == {"DISCARD": 9, "KEEP": 3}
    assert command_target.command_queue_full == {
        "DISCARD": "drop",
        "KEEP": "assert",
    }

    rows = analyze(graph, {})

    assert len(rows) == 1
    groups = {group.destination_port: group for group in rows[0].inbound_ports}
    assert groups["cmdIn:DISCARD"].overflow_behavior == "drop"
    assert groups["cmdIn:KEEP"].overflow_behavior == "assert"

    report = render_markdown(rows, include_rates=False)
    assert report.count("T.source.cmdOut") == 1
    assert "T.CommandTarget" in report
    keep_line = next(line for line in report.splitlines() if "cmdIn:KEEP" in line)
    assert "T.source.cmdOut" not in keep_line
    assert "passive" not in keep_line
    assert "^" not in report

    filtered = filter_drop_ports(rows)

    assert [group.destination_port for group in filtered[0].inbound_ports] == [
        "cmdIn:KEEP"
    ]


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
