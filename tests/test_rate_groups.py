"""Tests for deployment-derived rate-group frequencies."""

import json

from fprime_topology_analysis.async_queue_analyzer import analyze
from fprime_topology_analysis.rate_groups import infer_rate_groups


def test_rate_group_frequency_and_producer_rate_are_inferred(
    graph_builder, tmp_path
):
    graph = graph_builder("rate_group_frequency")
    source = tmp_path / "Topology.cpp"
    source.write_text(
        """
        Svc::RateGroupDriver::DividerSet dividers{{{4, 0}}};
        void configureTopology() { driver.configure(dividers); }
        void start() { startRateGroups(Fw::TimeInterval(0, 500000)); }
        """
    )
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["c++", "-c", str(source)],
                }
            ]
        )
    )

    rates = infer_rate_groups(graph, database, tmp_path)

    assert rates.rate_groups == {"T.rateGroup": 0.5}
    assert rates.production_rate_hz["T.driver.CycleOut[0]"] == 0.5
    assert rates.production_rate_hz["T.rateGroup.RateGroupMemberOut[0]"] == 0.5
    assert rates.production_rate_hz["T.producer.workOut"] == 0.5
    assert "T.consumer.onward" not in rates.production_rate_hz

    queues = {row.destination: row for row in analyze(graph, rates.as_rate_model())}
    assert queues["T.rateGroup"].total_production_hz == 0.5
    assert queues["T.consumer"].total_production_hz == 0.5
