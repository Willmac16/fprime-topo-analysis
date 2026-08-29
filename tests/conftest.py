"""
Shared fixtures for the topology analysis tests

Building an FPP model means running the FPP tool chain over the dependency
closure of a topology, which takes a few seconds. Models are therefore built
once per session and cached by topology name.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import sys
from pathlib import Path

import pytest

TEST_DIR = Path(__file__).resolve().parent

# The analyzers are an installed package; only the test helpers need the path
sys.path.insert(0, str(TEST_DIR))

from fpp_model import build_model, find_fprime_root, fpp_tools_available  # noqa: E402

TOPOLOGY_DIR = TEST_DIR / "topologies"


@pytest.fixture(scope="session")
def fprime_root() -> Path:
    return find_fprime_root()


@pytest.fixture(scope="session")
def model_builder(tmp_path_factory, fprime_root):
    """Build and cache an FPP model per topology name"""
    if not fpp_tools_available():
        pytest.skip("FPP tool chain not available on PATH")

    cache = {}
    base = tmp_path_factory.mktemp("fpp-models")

    def build(topology_name: str) -> Path:
        if topology_name not in cache:
            source = TOPOLOGY_DIR / f"{topology_name}.fpp"
            if not source.exists():
                raise FileNotFoundError(f"No such test topology: {source}")
            cache[topology_name] = build_model(
                [source], base / topology_name, fprime_root
            )
        return cache[topology_name]

    return build


def _libclang_available() -> bool:
    try:
        import clang.cindex

        clang.cindex.Index.create()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def flow_map_builder(tmp_path_factory):
    """Run the C++ call graph extractor over a fixture and return the flow map"""
    if not _libclang_available():
        pytest.skip("clang Python bindings not available")

    import json

    from fprime_topology_analysis.component_call_graph import CallGraphExtractor

    cpp_dir = TEST_DIR / "cpp"
    cache = {}
    base = tmp_path_factory.mktemp("flow-maps")

    def build(*sources: str):
        key = tuple(sorted(sources))
        if key not in cache:
            work = base / "_".join(s.replace(".cpp", "") for s in key)
            work.mkdir(parents=True, exist_ok=True)
            database = work / "compile_commands.json"
            database.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(cpp_dir),
                            "file": str(cpp_dir / source),
                            "arguments": [
                                "c++",
                                "-std=c++11",
                                "-I",
                                str(cpp_dir),
                                "-c",
                                str(cpp_dir / source),
                                "-o",
                                str(work / f"{source}.o"),
                            ],
                        }
                        for source in key
                    ]
                )
            )
            cache[key] = CallGraphExtractor(compile_commands=database).run()
        return cache[key]

    return build


@pytest.fixture
def graph_builder(model_builder):
    """Build a loaded TopologyGraph for a test topology

    The analyses are policy over a graph, so tests build one the same way the
    CLIs do rather than each constructing a model of their own.
    """
    from fprime_topology_analysis.port_flow import PortFlowMap
    from fprime_topology_analysis.topology_graph import TopologyGraph

    def build(topology_name: str, flow=None):
        return TopologyGraph(
            model_builder(topology_name), flow=flow or PortFlowMap.permissive()
        ).load()

    return build
