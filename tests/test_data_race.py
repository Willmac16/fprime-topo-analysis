"""
Regression tests for member data race detection

The check answers "which threads reach this member, and does any of them write
it without holding the component mutex". These tests pin the three ways an
access pattern is safe, so the check does not drift into reporting them.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

from fprime_topology_analysis.checks import DataRace, MemberAccess, Severity
from fprime_topology_analysis.port_flow import PortFlowMap
from fprime_topology_analysis.topology_graph import SyncKind, TopologyGraph


def test_shared_reads_are_not_a_race():
    """Two threads reading one member is safe"""
    accesses = [
        MemberAccess("a", SyncKind.SYNC, frozenset({"<thread:x>"}), False),
        MemberAccess("b", SyncKind.SYNC, frozenset({"<thread:y>"}), False),
    ]
    assert DataRace().classify("inst", "C::m_v", accesses) is None


def test_one_thread_is_not_a_race():
    """A member only one thread touches cannot race, even when written"""
    accesses = [
        MemberAccess("a", SyncKind.SYNC, frozenset({"<thread:x>"}), True),
        MemberAccess("b", SyncKind.SYNC, frozenset({"<thread:x>"}), False),
    ]
    assert DataRace().classify("inst", "C::m_v", accesses) is None


def test_all_guarded_is_not_a_race():
    """The component mutex serializes guarded handlers with each other"""
    accesses = [
        MemberAccess("a", SyncKind.GUARDED, frozenset({"<thread:x>"}), True),
        MemberAccess("b", SyncKind.GUARDED, frozenset({"<thread:y>"}), True),
    ]
    assert DataRace().classify("inst", "C::m_v", accesses) is None


def test_all_async_is_not_a_race():
    """Async handlers are serialized by the instance's own queue"""
    accesses = [
        MemberAccess("a", SyncKind.ASYNC, frozenset({"<thread:inst>"}), True),
        MemberAccess("b", SyncKind.ASYNC, frozenset({"<thread:inst>"}), True),
    ]
    assert DataRace().classify("inst", "C::m_v", accesses) is None


def test_write_from_two_threads_is_a_race():
    """An async handler and a sync handler on different threads both writing"""
    accesses = [
        MemberAccess("cmd", SyncKind.ASYNC, frozenset({"<thread:inst>"}), True),
        MemberAccess("sched", SyncKind.SYNC, frozenset({"<thread:driver>"}), True),
    ]
    finding = DataRace().classify("inst", "C::m_injectError", accesses)

    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert finding.subject == "inst.m_injectError"
    # The evidence must name the threads, which is the question being answered
    assert any("thread:driver" in line for line in finding.evidence)
    assert any("thread:inst" in line for line in finding.evidence)


def test_guarded_write_with_unguarded_read_is_informational():
    """A guarded writer and an unguarded reader is weaker than a write race"""
    accesses = [
        MemberAccess("reg", SyncKind.GUARDED, frozenset({"<thread:x>"}), True),
        MemberAccess("run", SyncKind.ASYNC, frozenset({"<thread:y>"}), False),
    ]
    finding = DataRace().classify("inst", "C::m_table", accesses)

    assert finding is not None
    assert finding.severity == Severity.INFO


def test_real_ref_race_is_found(model_builder):
    """The check runs end to end and names threads for each access"""
    graph = TopologyGraph(
        model_builder("real_buffermanager_clean"), flow=PortFlowMap.permissive()
    ).load()
    findings = DataRace().run(graph)

    for finding in findings:
        assert finding.evidence[0].startswith("threads reaching this member")
