"""
Tests for the shared entry-point plumbing

The three analyzers agree on how to find a topology, load a flow map, and
refuse when they cannot. These are the paths a user hits when something is
wrong, which is exactly when the tool has to say something useful.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import pytest

from fprime_topology_analysis import cli
from fprime_topology_analysis.async_queue_analyzer import main as queue_main
from fprime_topology_analysis.guarded_port_analyzer import main as guarded_main
from fprime_topology_analysis.topology_checks import main as checks_main

ENTRY_POINTS = [queue_main, guarded_main, checks_main]


def run(main, argv, monkeypatch):
    monkeypatch.setattr("sys.argv", ["analyzer", *argv])
    return main()


@pytest.mark.parametrize("main", ENTRY_POINTS)
def test_missing_topology_path_is_reported(main, monkeypatch, tmp_path, caplog):
    """A path that does not exist is a message, not a traceback"""
    flow = tmp_path / "flow.json"
    flow.write_text('{"version": 1, "components": {}}')

    code = run(main, ["--topology-path", str(tmp_path / "nope"), "--flow-map", str(flow)], monkeypatch)

    assert code == 1
    assert "Topology path not found" in caplog.text


@pytest.mark.parametrize("main", ENTRY_POINTS)
def test_missing_flow_map_file_is_reported(main, monkeypatch, tmp_path, caplog):
    code = run(
        main,
        ["--topology-path", str(tmp_path), "--flow-map", str(tmp_path / "nope.json")],
        monkeypatch,
    )

    assert code == 1
    assert "Flow map not found" in caplog.text


@pytest.mark.parametrize("main", [queue_main, guarded_main])
def test_no_flow_map_refuses_rather_than_guessing(main, monkeypatch, tmp_path, caplog):
    """Without the C++ half these analyses would be meaningless, so they stop"""
    code = run(main, ["--topology-path", str(tmp_path)], monkeypatch)

    assert code == 1
    assert "No --flow-map given" in caplog.text
    assert "--permissive" in caplog.text


def test_checks_without_a_flow_map_skips_rather_than_refusing(
    model_builder, monkeypatch, capsys
):
    """The checks CLI can still run the analyses that need no call flow"""
    code = run(
        checks_main,
        ["--topology-path", str(model_builder("synthetic_clean")), "--fail-on", "never"],
        monkeypatch,
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out
    assert "needs the C++ flow map" in out


def test_unknown_check_id_is_rejected(model_builder, monkeypatch, caplog):
    code = run(
        checks_main,
        ["--topology-path", str(model_builder("synthetic_clean")), "--checks", "nope"],
        monkeypatch,
    )

    assert code == 1
    assert "Unknown check(s): nope" in caplog.text


def test_list_checks_needs_no_topology(monkeypatch, capsys):
    assert run(checks_main, ["--list-checks"], monkeypatch) == 0

    out = capsys.readouterr().out
    assert "data-race" in out
    assert "(needs flow map)" in out


def test_write_or_print_creates_the_output_directory(tmp_path):
    target = tmp_path / "nested" / "report.txt"

    cli.write_or_print("hello", target)

    assert target.read_text() == "hello"
