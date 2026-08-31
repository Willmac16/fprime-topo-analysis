"""
Regression tests for the C++ component call graph extractor

The extractor answers the question the FPP model cannot: which output ports does
a given handler actually invoke? These tests pin down transitive resolution
through private helpers and through generated helpers, and the soundness
fallback for calls libclang cannot resolve.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from fprime_topology_analysis.component_call_graph import (
    CallGraphExtractor,
    MethodInfo,
    _UnitResult,
    detect_host_libclang,
)
from fprime_topology_analysis.port_flow import PortFlowMap, UnresolvedFlowError


def handlers_of(flow_map, component):
    return flow_map["components"][component]["handlers"]


def test_extract_args_tolerates_gcc_only_warning_flags():
    # A GCC compile database (e.g. monarch) carries -W flags clang rejects, and
    # -Werror would turn "unknown warning option" into a hard parse failure.
    extractor = CallGraphExtractor(
        Path("compile_commands.json"), system_includes=[], jobs=1
    )
    entry = {
        "file": "Foo.cpp",
        "arguments": [
            "g++",
            "-Werror",
            "-Werror=maybe-uninitialized",
            "-Wno-stringop-overflow",
            "-std=c++17",
            "-c",
            "Foo.cpp",
        ],
    }

    args = extractor._extract_args(entry)

    assert "-Werror" not in args
    assert "-Werror=maybe-uninitialized" not in args
    assert "-std=c++17" in args
    assert "-Wno-stringop-overflow" in args
    assert args[-1] == "-Wno-unknown-warning-option"
    assert "g++" not in args and "-c" not in args and "Foo.cpp" not in args


def test_spawned_os_task_resolves_ports_through_virtual_override(flow_map_builder):
    """A driver spawns a read task in a mixin base (Os::Task), and its recv is
    reachable only through the concrete component's sendBuffer/getBuffer
    override - libclang sees only the abstract base at the call site."""
    flow = flow_map_builder("DriverTask.cpp")

    tasks = {
        task["name"]: set(task["ports"])
        for task in flow["components"]["RegTest::DriverTask"]["tasks"]
    }
    assert "recv" in tasks["readTask"]
    assert "allocate" in tasks["readTask"]


def test_detect_system_includes_prepends_clang_resource_dir(monkeypatch):
    # Clang's builtins must precede a GCC database's private headers, whose
    # intrinsics use __builtin_ia32_* that clang cannot compile.
    from fprime_topology_analysis import component_call_graph as ccg

    monkeypatch.setattr(ccg, "_clang_resource_include", lambda: "/opt/clang/include")

    flags = ccg.detect_system_includes()

    assert flags[:2] == ["-isystem", "/opt/clang/include"]


def test_detect_host_libclang_from_selected_xcode(monkeypatch, tmp_path):
    compiler = tmp_path / "Toolchain" / "usr" / "bin" / "clang"
    library = tmp_path / "Toolchain" / "usr" / "lib" / "libclang.dylib"
    library.parent.mkdir(parents=True)
    library.touch()
    monkeypatch.setattr("sys.platform", "darwin")
    def xcrun(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=f"{compiler}\n", stderr="")

    monkeypatch.setattr("subprocess.run", xcrun)

    assert detect_host_libclang() == Path(library)


def test_parallel_parse_uses_at_most_one_worker_per_unit(monkeypatch, tmp_path):
    import json

    sources = []
    for index in range(3):
        source = tmp_path / f"Source{index}.cpp"
        source.write_text("")
        sources.append(source)
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["c++", "-c", str(source)],
                }
                for source in sources
            ]
        )
    )
    extractor = CallGraphExtractor(
        database, system_includes=[], jobs=8
    )
    selected_workers = []

    def fake_parallel_results(units, workers):
        selected_workers.append(workers)
        for _ in units:
            yield _UnitResult({}, {}, {}, 1, [], set(), 0, [], set(), set())

    monkeypatch.setattr(extractor, "_parallel_results", fake_parallel_results)

    extractor.run()

    assert selected_workers == [3]
    assert extractor.parsed_files == 3


def test_flow_cache_reuses_unchanged_units_and_invalidates_dependencies(tmp_path):
    source = tmp_path / "Thing.cpp"
    header = tmp_path / "Thing.hpp"
    source.write_text('#include "Thing.hpp"\n')
    header.write_text("struct Thing {};\n")
    database = tmp_path / "compile_commands.json"
    database.write_text("[]")
    extractor = CallGraphExtractor(
        database,
        system_includes=[],
        jobs=1,
        unit_cache_dir=tmp_path / "cache" / "units",
    )
    args = ["-std=c++17"]
    method = MethodInfo("Thing", "run", ports={"out"})
    result = _UnitResult(
        {method.key: method},
        {"Thing": "Demo.Thing"},
        {},
        1,
        [],
        set(),
        0,
        [],
        set(),
        {str(source), str(header)},
    )

    extractor._write_cached_unit(source, args, result)
    cached = extractor._read_cached_unit(source, args)

    assert cached is not None
    assert cached.methods[method.key].ports == {"out"}

    extractor.dependencies = {str(source), str(header)}
    flow = {"version": 1, "components": {}}
    extractor._write_cached_flow(flow)
    assert extractor._read_cached_flow() == flow

    header.write_text("struct Thing { int changed; };\n")

    assert extractor._read_cached_unit(source, args) is None
    assert extractor._read_cached_flow() is None


def test_unit_cache_reuses_missing_generated_header_until_it_appears(tmp_path):
    source = tmp_path / "Thing.cpp"
    source.write_text('#include "ThingComponentAc.hpp"\n')
    database = tmp_path / "compile_commands.json"
    database.write_text("[]")
    extractor = CallGraphExtractor(
        database,
        system_includes=[],
        jobs=1,
        unit_cache_dir=tmp_path / "cache" / "units",
    )
    args = ["-I", str(tmp_path)]
    result = _UnitResult(
        {},
        {},
        {},
        0,
        [],
        set(),
        0,
        [str(source)],
        {"ThingComponentAc.hpp"},
        {str(source)},
    )

    extractor._write_cached_unit(source, args, result)

    assert extractor._read_cached_unit(source, args) is not None

    (tmp_path / "ThingComponentAc.hpp").write_text("// generated\n")

    assert extractor._read_cached_unit(source, args) is None


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
