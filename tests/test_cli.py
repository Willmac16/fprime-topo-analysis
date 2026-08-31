"""Tests for source-oriented analyzer command-line behavior."""

import shutil
from argparse import Namespace
from pathlib import Path

import pytest

from fprime_topology_analysis import cli
from fprime_topology_analysis.async_queue_analyzer import main as queue_main
from fprime_topology_analysis.guarded_port_analyzer import main as guarded_main
from fprime_topology_analysis.topology_checks import main as checks_main

ENTRY_POINTS = [queue_main, guarded_main, checks_main]


def run(main, argv, monkeypatch):
    monkeypatch.setattr("sys.argv", ["analyzer", *argv])
    return main()


def source_project(tmp_path: Path, model: Path | None = None, *, cpp: bool = False):
    """Create one source deployment and optionally install generated inputs."""
    project = tmp_path / "Project"
    deployment = project / "DemoDeployment"
    top = deployment / "Top"
    top.mkdir(parents=True)
    (project / "settings.ini").write_text("[fprime]\n")
    (deployment / "CMakeLists.txt").write_text("project(DemoDeployment)\n")
    (top / "topology.fpp").write_text("deployment topology Test {}\n")

    if model is not None:
        generated = project / "generated" / "DemoDeployment" / "Top"
        generated.mkdir(parents=True)
        for filename in cli.MODEL_FILES:
            shutil.copy(model / filename, generated / filename)
        build_root = project / "generated"
        (build_root / "CMakeCache.txt").write_text("FPRIME_PROJECT_ROOT:PATH=x\n")
        if cpp:
            (build_root / cli.COMPILE_COMMANDS).write_text("[]")

    return project, deployment


def install_project_fprime_util(project: Path) -> Path:
    executable = project / ".venv" / "bin" / "fprime-util"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    cmake = executable.parent / "cmake"
    cmake.write_text("#!/bin/sh\n")
    cmake.chmod(0o755)
    return executable


@pytest.mark.parametrize("main", ENTRY_POINTS)
def test_missing_source_path_is_reported(main, monkeypatch, tmp_path, caplog):
    code = run(main, [str(tmp_path / "missing")], monkeypatch)

    assert code == 1
    assert "Project or deployment path not found" in caplog.text


@pytest.mark.parametrize("main", ENTRY_POINTS)
def test_directory_without_a_deployment_is_reported(main, monkeypatch, tmp_path, caplog):
    code = run(main, [str(tmp_path)], monkeypatch)

    assert code == 1
    assert "No deployment topology was found" in caplog.text
    assert "source directory" in caplog.text


@pytest.mark.parametrize("main", ENTRY_POINTS)
def test_help_uses_only_source_context_inputs(main, monkeypatch, capsys):
    with pytest.raises(SystemExit) as raised:
        run(main, ["--help"], monkeypatch)

    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    assert "PROJECT_OR_DEPLOYMENT" in help_text
    assert "--topology-path" not in help_text
    assert "--flow-map" not in help_text
    assert "--compile-commands" not in help_text
    assert "--dot" not in help_text
    assert "-j JOBS" in help_text
    if main is queue_main:
        assert "--hide-drop-ports" in help_text


@pytest.mark.parametrize("main", [queue_main, guarded_main])
def test_missing_generated_inputs_reports_project_venv_action(
    main, monkeypatch, tmp_path, caplog
):
    _, deployment = source_project(tmp_path)

    code = run(main, [str(deployment)], monkeypatch)

    assert code == 1
    assert "virtual environment was not found" in caplog.text
    assert str(deployment) in caplog.text
    assert "compile_commands.json" not in caplog.text


def test_checks_without_cpp_analysis_skips_dependent_checks(
    model_builder, monkeypatch, tmp_path, capsys
):
    _, deployment = source_project(tmp_path, model_builder("synthetic_clean"))
    monkeypatch.setattr(cli, "_prepare_analysis", lambda _source: None)

    code = run(checks_main, [str(deployment), "--fail-on", "never"], monkeypatch)

    assert code == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out
    assert "needs C++ call-flow analysis" in out


def test_unknown_check_id_is_rejected(monkeypatch, tmp_path, caplog):
    code = run(checks_main, [str(tmp_path), "--checks", "nope"], monkeypatch)

    assert code == 1
    assert "Unknown check(s): nope" in caplog.text


def test_list_checks_needs_no_source_path(monkeypatch, capsys):
    assert run(checks_main, ["--list-checks"], monkeypatch) == 0

    out = capsys.readouterr().out
    assert "data-race" in out
    assert "(needs C++ analysis)" in out


def test_source_deployment_builds_a_graph(model_builder, monkeypatch, tmp_path, capsys):
    _, deployment = source_project(tmp_path, model_builder("synthetic_clean"))
    monkeypatch.setattr(cli, "_prepare_analysis", lambda _source: None)

    code = run(
        checks_main,
        [str(deployment), "--permissive", "--fail-on", "never"],
        monkeypatch,
    )

    assert code == 0
    assert "Topology Checks" in capsys.readouterr().out


def test_project_with_several_deployments_requests_a_source_choice(tmp_path):
    project, _ = source_project(tmp_path)
    second = project / "OtherDeployment"
    (second / "Top").mkdir(parents=True)
    (second / "CMakeLists.txt").write_text("project(OtherDeployment)\n")
    (second / "Top" / "topology.fpp").write_text("deployment topology Other {}\n")

    with pytest.raises(cli.CliError, match="Several deployments were found") as raised:
        cli.resolve_deployment_source(Namespace(path=project))

    message = str(raised.value)
    assert str(project / "DemoDeployment") in message
    assert str(second) in message


def test_deployment_flag_selects_plain_topology_form(tmp_path):
    project = tmp_path / "Project"
    top = project / "DemoDeployment" / "Top"
    top.mkdir(parents=True)
    (project / "settings.ini").write_text("[fprime]\n")
    (project / "DemoDeployment" / "CMakeLists.txt").write_text("project(Demo)\n")
    # Older FPP (< 3.3.0): plain `topology`, no `deployment` keyword.
    (top / "topology.fpp").write_text("module topologies {\n  topology Legacy {}\n}\n")

    with pytest.raises(cli.CliError, match="No deployment topology was found"):
        cli.resolve_deployment_source(Namespace(path=project, deployment=None))

    source = cli.resolve_deployment_source(Namespace(path=project, deployment="Legacy"))
    assert source.topology_name == "Legacy"
    assert source.topology_file == top / "topology.fpp"


def test_deployment_flag_disambiguates_several_deployments(tmp_path):
    project, _ = source_project(tmp_path)
    second = project / "OtherDeployment"
    (second / "Top").mkdir(parents=True)
    (second / "CMakeLists.txt").write_text("project(OtherDeployment)\n")
    (second / "Top" / "topology.fpp").write_text("deployment topology Other {}\n")

    source = cli.resolve_deployment_source(Namespace(path=project, deployment="Other"))
    assert source.topology_name == "Other"


def test_unknown_deployment_name_is_reported(tmp_path):
    project, _ = source_project(tmp_path)
    with pytest.raises(cli.CliError, match="No topology named 'Nope'"):
        cli.resolve_deployment_source(Namespace(path=project, deployment="Nope"))


def test_complete_deployment_lists_matching_topology_names(tmp_path):
    project, _ = source_project(tmp_path)  # declares `deployment topology Test`

    assert "Test" in cli._complete_deployment(parsed_args=Namespace(path=project))
    assert cli._complete_deployment(
        prefix="Te", parsed_args=Namespace(path=project)
    ) == ["Test"]


def test_cpp_call_flow_is_derived_from_selected_deployment(
    model_builder, monkeypatch, tmp_path
):
    _, deployment = source_project(
        tmp_path, model_builder("synthetic_clean"), cpp=True
    )
    database = tmp_path / "Project" / "generated" / cli.COMPILE_COMMANDS

    runs = 0

    class FakeExtractor:
        def __init__(self, **kwargs):
            assert kwargs["compile_commands"] == database
            assert kwargs["jobs"] == 3

        def run(self):
            nonlocal runs
            runs += 1
            return {"version": 1, "components": {"Svc::Thing": {"handlers": {}}}}

    monkeypatch.setattr(
        "fprime_topology_analysis.component_call_graph.CallGraphExtractor",
        FakeExtractor,
    )
    monkeypatch.setattr(cli, "_prepare_analysis", lambda _source: None)
    args = Namespace(path=deployment, permissive=False, jobs=3)

    assert "Svc::Thing" in cli.load_flow(args).components
    assert runs == 1


def test_preparation_runs_from_deployment_source(monkeypatch, tmp_path):
    project, deployment = source_project(tmp_path)
    source = cli.resolve_deployment_source(Namespace(path=deployment))
    executable = install_project_fprime_util(project)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli._prepare_analysis(source)

    assert all(command[0] == executable for command, _ in calls)
    assert [command[1] for command, _ in calls] == ["info", "generate", "build"]
    assert all(kwargs["cwd"] == deployment for _, kwargs in calls)
    assert all(kwargs["env"]["VIRTUAL_ENV"] == str(project / ".venv") for _, kwargs in calls)
    assert all(
        kwargs["env"]["PATH"].split(cli.os.pathsep)[0] == str(executable.parent)
        for _, kwargs in calls
    )


def test_deployment_venv_takes_precedence(monkeypatch, tmp_path):
    project, deployment = source_project(tmp_path)
    install_project_fprime_util(project)
    deployment_executable = install_project_fprime_util(deployment)
    source = cli.resolve_deployment_source(Namespace(path=deployment))
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli._prepare_analysis(source)

    assert all(command[0] == deployment_executable for command, _ in calls)
    assert all(
        kwargs["env"]["VIRTUAL_ENV"] == str(deployment / ".venv")
        for _, kwargs in calls
    )


def test_enclosing_venv_is_used_for_nested_project(monkeypatch, tmp_path):
    checkout = tmp_path / "fprime"
    project, deployment = source_project(checkout)
    executable = install_project_fprime_util(checkout)
    source = cli.resolve_deployment_source(Namespace(path=deployment))
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli._prepare_analysis(source)

    assert project == checkout / "Project"
    assert all(command[0] == executable for command, _ in calls)
    assert all(
        kwargs["env"]["VIRTUAL_ENV"] == str(checkout / ".venv")
        for _, kwargs in calls
    )


def test_existing_release_cache_is_reconfigured(monkeypatch, tmp_path):
    project, deployment = source_project(tmp_path)
    executable = install_project_fprime_util(project)
    build_cache = project / "build"
    build_cache.mkdir()
    (build_cache / "CMakeCache.txt").write_text(
        f"CMAKE_HOME_DIRECTORY:INTERNAL={project}\n"
    )
    source = cli.resolve_deployment_source(Namespace(path=deployment))
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1] == "info":
            return Namespace(
                returncode=0,
                stdout=f"Release build cache: {build_cache}\n",
                stderr="",
            )
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli._prepare_analysis(source)

    assert [command[1] for command, _ in calls] == ["info", "-S", "build"]
    cmake_command = calls[1][0]
    assert cmake_command[0] == executable.parent / "cmake"
    assert cmake_command[2] == project
    assert cmake_command[4] == build_cache
    assert "-DFPRIME_ENABLE_JSON_MODEL_GENERATION=ON" in cmake_command
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in cmake_command


def test_configured_release_cache_runs_incremental_build(monkeypatch, tmp_path):
    project, deployment = source_project(tmp_path)
    executable = install_project_fprime_util(project)
    build_cache = project / "build"
    build_cache.mkdir()
    (build_cache / "CMakeCache.txt").write_text(
        f"CMAKE_HOME_DIRECTORY:INTERNAL={project}\n"
        "FPRIME_ENABLE_JSON_MODEL_GENERATION:BOOL=ON\n"
        "CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON\n"
    )
    source = cli.resolve_deployment_source(Namespace(path=deployment))
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1] == "info":
            return Namespace(
                returncode=0,
                stdout=f"Release build cache: {build_cache}\n",
                stderr="",
            )
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli._prepare_analysis(source)

    assert [command[1] for command, _ in calls] == ["info", "build"]
    assert all(command[0] == executable for command, _ in calls)


def test_existing_artifacts_are_built_before_resolution(
    model_builder, monkeypatch, tmp_path
):
    _, deployment = source_project(
        tmp_path, model_builder("synthetic_clean"), cpp=True
    )
    calls = []

    monkeypatch.setattr(cli, "_prepare_analysis", calls.append)

    artifacts = cli.resolve_analysis_artifacts(Namespace(path=deployment))

    assert calls == [cli.resolve_deployment_source(Namespace(path=deployment))]
    assert artifacts.compile_commands is not None


def test_preparation_failure_includes_tool_output(monkeypatch, tmp_path):
    project, deployment = source_project(tmp_path)
    install_project_fprime_util(project)
    source = cli.resolve_deployment_source(Namespace(path=deployment))

    def fake_run(command, **kwargs):
        if command[1] == "generate":
            return Namespace(
                returncode=1,
                stdout="",
                stderr="specific generation failure\n",
            )
        return Namespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    with pytest.raises(cli.CliError, match="specific generation failure"):
        cli._prepare_analysis(source)


def test_write_or_print_creates_the_output_directory(tmp_path):
    target = tmp_path / "nested" / "report.txt"

    cli.write_or_print("hello", target)

    assert target.read_text() == "hello"
