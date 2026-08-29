"""
Regression tests for self re-queue priority drops

Producer-versus-consumer thread priority is classified per connection by
classify_priority_relation. These tests cover the case it cannot see: a chain
that returns to the queue it started on at a lower priority.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

from fprime_topology_analysis.async_queue_analyzer import find_requeue_drops
from fprime_topology_analysis.port_flow import PortFlowMap
from fprime_topology_analysis.topology_graph import TopologyGraph


def graph_for(model_dir):
    return TopologyGraph(model_dir, flow=PortFlowMap.permissive()).load()


def test_same_queue_priority_drop_is_found(model_builder):
    """urgent.hiIn arrives at priority 9 and is re-queued onto loIn at 1"""
    drops = find_requeue_drops(graph_for(model_builder("priority_inversion")))

    assert len(drops) == 1
    drop = drops[0]
    assert drop.instance == "T.urgent"
    assert (drop.from_port, drop.to_port) == ("hiIn", "loIn")
    assert (drop.from_priority, drop.to_priority) == (9, 1)
    assert drop.witness


def test_priority_increase_is_not_a_drop(model_builder):
    """Re-queuing upward, or onto another component, is not reported here"""
    drops = find_requeue_drops(graph_for(model_builder("priority_inversion")))

    # sluggish and peer are separate queues; their priorities are not
    # comparable to urgent's and are handled by the producer classification
    assert all(d.instance == "T.urgent" for d in drops)


def test_no_drops_without_a_self_loop(model_builder):
    drops = find_requeue_drops(graph_for(model_builder("synthetic_async_break")))

    assert drops == []
