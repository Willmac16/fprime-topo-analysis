#!/usr/bin/env python3
"""Shared source-project discovery and reporting for the analyzer CLIs.

The public commands start from an F Prime project or deployment source
directory. This module identifies the deployment, prepares the generated FPP
model and C++ compilation information when necessary, and builds the shared
``TopologyGraph`` used by every analysis.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import argparse
import logging
import os
import re
import subprocess
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .port_flow import PortFlowMap, UnresolvedFlowError
from .topology_graph import Severity, TopologyGraph

logger = logging.getLogger(__name__)

MODEL_FILES = ("fpp-ast.json", "fpp-loc-map.json", "fpp-analysis.json")
COMPILE_COMMANDS = "compile_commands.json"
DEPLOYMENT_RE = re.compile(r"\bdeployment\s+topology\s+([A-Za-z_][A-Za-z0-9_]*)")
RELEASE_BUILD_CACHE_RE = re.compile(
    r"^\s*Release build cache:\s*(?P<path>.+?)\s*$", re.MULTILINE
)
IGNORED_SOURCE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "node_modules",
}


class CliError(Exception):
    """A condition the user has to fix, reported without a traceback."""


@dataclass(frozen=True)
class AnalysisArtifacts:
    """Generated inputs selected for one source deployment."""

    project_root: Path
    deployment_dir: Path
    topology_name: str
    topology_path: Path
    compile_commands: Optional[Path]


@dataclass(frozen=True)
class DeploymentSource:
    """A deployment topology declaration and its owning source directory."""

    project_root: Path
    deployment_dir: Path
    topology_file: Path
    topology_name: str


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def add_topology_args(parser: argparse.ArgumentParser) -> None:
    """Add the source-context options shared by every analyzer."""
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        metavar="PROJECT_OR_DEPLOYMENT",
        help="F Prime project or deployment source directory (default: current directory)",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=_positive_int,
        help="Maximum C++ parsing workers (default: all logical CPU cores)",
    )
    parser.add_argument(
        "--permissive",
        action="store_true",
        help=(
            "Assume a C++ handler that cannot be resolved may call every output "
            "port. This is conservative but can produce many false positives"
        ),
    )
    parser.add_argument("--verbose", "-v", action="store_true")


def add_report_args(parser: argparse.ArgumentParser) -> None:
    """Add the flags every analyzer uses to emit its report."""
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the text report to this file instead of stdout",
    )
    parser.add_argument("--json", type=Path, help="Write findings as JSON to this file")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["never"],
        default="error",
        help="Exit non-zero when a finding at or above this severity is found",
    )


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def _input_path(args) -> Path:
    return (getattr(args, "path", None) or Path.cwd()).expanduser().resolve()


def _is_project_marker(path: Path) -> bool:
    settings = path / "settings.ini"
    return settings.is_file() or (path / "project.cmake").is_file()


def _project_root(path: Path) -> Path:
    """Find the enclosing project while still accepting a deployment alone."""
    for candidate in (path, *path.parents):
        if _is_project_marker(candidate):
            return candidate
    return path


def _walk_files(root: Path, suffix: str) -> Iterable[Path]:
    """Walk source files without descending into generated or tool directories."""
    try:
        listed = subprocess.run(
            (
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                f"*{suffix}",
            ),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        listed = None
    if listed is not None and listed.returncode == 0:
        yield from (
            root / name for name in listed.stdout.split("\0") if name
        )
        return

    for directory, names, files in os.walk(root):
        names[:] = [
            name
            for name in names
            if name not in IGNORED_SOURCE_DIRS
            and not name.startswith("build-")
            and not name.startswith("cmake-build-")
        ]
        base = Path(directory)
        yield from (base / name for name in files if name.endswith(suffix))


def _deployment_directory(topology_file: Path, boundary: Path) -> Path:
    """Return the nearest CMake project that owns a topology declaration."""
    for candidate in (topology_file.parent, *topology_file.parents):
        try:
            candidate.relative_to(boundary)
        except ValueError:
            break
        cmake = candidate / "CMakeLists.txt"
        if cmake.is_file():
            try:
                text = cmake.read_text(errors="replace")
            except OSError:
                continue
            if re.search(r"\bproject\s*\(", text, re.IGNORECASE):
                return candidate
        if candidate == boundary:
            break
    if topology_file.parent.name.lower() == "top":
        return topology_file.parent.parent
    return topology_file.parent


def _deployment_declarations(root: Path, project_root: Path) -> list[DeploymentSource]:
    declarations: list[DeploymentSource] = []
    for source in _walk_files(root, ".fpp"):
        try:
            text = source.read_text(errors="replace")
        except OSError:
            continue
        text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        declarations.extend(
            (
                DeploymentSource(
                    project_root=project_root,
                    deployment_dir=_deployment_directory(source, project_root),
                    topology_file=source,
                    topology_name=match.group(1),
                )
                for match in DEPLOYMENT_RE.finditer(text)
            )
        )
    return declarations


def resolve_deployment_source(args) -> DeploymentSource:
    """Resolve the public source path to one deployment topology."""
    selected = _input_path(args)
    if not selected.exists():
        raise CliError(f"Project or deployment path not found: {selected}")
    if not selected.is_dir():
        raise CliError(f"Project or deployment path is not a directory: {selected}")

    project_root = _project_root(selected)
    declarations = _deployment_declarations(selected, project_root)
    if not declarations and project_root != selected:
        declarations = _deployment_declarations(project_root, project_root)

    if not declarations:
        raise CliError(
            f"No deployment topology was found under {selected}. "
            "Run this command from an F Prime project or deployment source directory."
        )

    unique = {
        (item.topology_file, item.topology_name): item for item in declarations
    }
    declarations = sorted(
        unique.values(), key=lambda item: (item.deployment_dir, item.topology_name)
    )
    if len(declarations) > 1:
        source_dirs = sorted({item.deployment_dir for item in declarations})
        rendered = "\n  ".join(str(path) for path in source_dirs[:10])
        suffix = f"\n  ... and {len(source_dirs) - 10} more" if len(source_dirs) > 10 else ""
        raise CliError(
            "Several deployments were found. Run the command from one of these "
            f"source directories:\n  {rendered}{suffix}"
        )
    return declarations[0]


def _is_model_dir(path: Path) -> bool:
    return path.is_dir() and all((path / name).is_file() for name in MODEL_FILES)


def _path_has_suffix(path: Path, suffix: Path) -> bool:
    if not suffix.parts:
        return True
    return len(path.parts) >= len(suffix.parts) and path.parts[-len(suffix.parts) :] == suffix.parts


def _build_root_for(model: Path, project_root: Path) -> Optional[Path]:
    """Find the generated tree that contains a model directory."""
    for candidate in (model, *model.parents):
        if (candidate / "CMakeCache.txt").is_file() or (
            candidate / COMPILE_COMMANDS
        ).is_file():
            return candidate
        if candidate == project_root:
            break
    return None


def _model_candidates(source: DeploymentSource) -> list[tuple[Path, Optional[Path]]]:
    """Locate generated models matching a source topology without exposing them."""
    try:
        relative_top = source.topology_file.parent.relative_to(source.project_root)
    except ValueError:
        relative_top = Path(source.topology_file.parent.name)

    candidates: list[tuple[Path, Optional[Path]]] = []
    for analysis in source.project_root.rglob("fpp-analysis.json"):
        model = analysis.parent
        if not _is_model_dir(model) or not _path_has_suffix(model, relative_top):
            continue
        build_root = _build_root_for(model, source.project_root)
        compile_commands = None
        if build_root is not None and (build_root / COMPILE_COMMANDS).is_file():
            compile_commands = build_root / COMPILE_COMMANDS
        candidates.append((model, compile_commands))

    return sorted(
        candidates,
        key=lambda item: (
            item[1] is not None,
            max((item[0] / name).stat().st_mtime for name in MODEL_FILES),
        ),
        reverse=True,
    )


def _available_artifacts(source: DeploymentSource) -> Optional[AnalysisArtifacts]:
    candidates = _model_candidates(source)
    if not candidates:
        return None
    model, compile_commands = candidates[0]
    return AnalysisArtifacts(
        project_root=source.project_root,
        deployment_dir=source.deployment_dir,
        topology_name=source.topology_name,
        topology_path=model,
        compile_commands=compile_commands,
    )


def _project_venv(source: DeploymentSource) -> tuple[Path, Path]:
    """Return the selected source tree's virtual environment and fprime-util."""
    for root in (source.deployment_dir, *source.deployment_dir.parents):
        venv = root / ".venv"
        executables = (
            venv / "bin" / "fprime-util",
            venv / "Scripts" / "fprime-util.exe",
            venv / "Scripts" / "fprime-util",
        )
        for executable in executables:
            if executable.is_file():
                return venv, executable

    raise CliError(
        f"The F Prime virtual environment was not found near {source.deployment_dir}. "
        "Create .venv in the deployment, project, or an enclosing directory and "
        "install its F Prime dependencies."
    )


def _prepare_command(
    command: tuple[object, ...],
    source: DeploymentSource,
    environment: dict[str, str],
) -> subprocess.CompletedProcess:
    """Run one preparation command and preserve useful failure output."""
    try:
        result = subprocess.run(
            command,
            cwd=source.deployment_dir,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise CliError(
            f"Could not prepare analysis data for {source.deployment_dir}: {error}"
        ) from error
    if result.returncode != 0:
        output = "\n".join(
            line
            for line in (
                getattr(result, "stdout", "") + "\n" + getattr(result, "stderr", "")
            ).splitlines()
            if line.strip()
        )
        detail = "\n".join(output.splitlines()[-12:])
        label = " ".join(str(part) for part in command[:2])
        suffix = f"\n{detail}" if detail else ""
        raise CliError(
            f"Could not prepare analysis data for {source.deployment_dir}: "
            f"{label} failed.{suffix}"
        )
    return result


def _release_build_cache(
    executable: Path,
    source: DeploymentSource,
    environment: dict[str, str],
) -> Optional[Path]:
    """Ask fprime-util for the release cache selected by this source context."""
    result = _prepare_command((executable, "info"), source, environment)
    output = getattr(result, "stdout", "") + "\n" + getattr(result, "stderr", "")
    match = RELEASE_BUILD_CACHE_RE.search(output)
    if match is None:
        return None
    cache = Path(match.group("path")).expanduser().resolve()
    return cache if (cache / "CMakeCache.txt").is_file() else None


def _cmake_home(build_cache: Path, fallback: Path) -> Path:
    """Read the source directory recorded by an existing CMake cache."""
    try:
        cache = (build_cache / "CMakeCache.txt").read_text(errors="replace")
    except OSError:
        return fallback
    match = re.search(r"^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$", cache, re.MULTILINE)
    return Path(match.group(1)).resolve() if match else fallback


def _analysis_options_enabled(build_cache: Path) -> bool:
    """Return whether an existing cache emits both analysis inputs."""
    try:
        cache = (build_cache / "CMakeCache.txt").read_text(errors="replace")
    except OSError:
        return False
    enabled = {"1", "ON", "TRUE", "YES", "Y"}
    values = dict(
        re.findall(
            r"^(FPRIME_ENABLE_JSON_MODEL_GENERATION|CMAKE_EXPORT_COMPILE_COMMANDS)"
            r":[^=]+=(\S+)\s*$",
            cache,
            re.MULTILINE,
        )
    )
    return all(values.get(option, "").upper() in enabled for option in (
        "FPRIME_ENABLE_JSON_MODEL_GENERATION",
        "CMAKE_EXPORT_COMPILE_COMMANDS",
    ))


def _prepare_analysis(source: DeploymentSource) -> None:
    venv, executable = _project_venv(source)
    environment = os.environ.copy()
    scripts = executable.parent
    environment["VIRTUAL_ENV"] = str(venv)
    environment["PATH"] = os.pathsep.join(
        (str(scripts), environment.get("PATH", ""))
    )
    environment.pop("PYTHONHOME", None)

    logger.info(f"Checking analysis inputs for {source.deployment_dir}")
    build_cache = _release_build_cache(executable, source, environment)
    if build_cache is None:
        _prepare_command(
            (
                executable,
                "generate",
                "-DFPRIME_ENABLE_JSON_MODEL_GENERATION=ON",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ),
            source,
            environment,
        )
    elif not _analysis_options_enabled(build_cache):
        cmake = executable.parent / ("cmake.exe" if os.name == "nt" else "cmake")
        if not cmake.is_file():
            raise CliError(
                f"The F Prime virtual environment at {venv} does not provide cmake."
            )
        _prepare_command(
            (
                cmake,
                "-S",
                _cmake_home(build_cache, source.project_root),
                "-B",
                build_cache,
                "-DFPRIME_ENABLE_JSON_MODEL_GENERATION=ON",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ),
            source,
            environment,
        )
    _prepare_command((executable, "build"), source, environment)


def resolve_analysis_artifacts(args, *, require_cpp: bool = True) -> AnalysisArtifacts:
    """Resolve or prepare generated inputs for the selected source deployment."""
    cached = getattr(args, "analysis_artifacts", None)
    if cached is not None and (cached.compile_commands is not None or not require_cpp):
        return cached

    source = resolve_deployment_source(args)
    _prepare_analysis(source)
    artifacts = _available_artifacts(source)

    if artifacts is None:
        raise CliError(
            f"The analysis model for {source.deployment_dir} could not be prepared. "
            "Run fprime-util build in that deployment source directory and try again."
        )
    if require_cpp and artifacts.compile_commands is None:
        raise CliError(
            f"C++ analysis data for {source.deployment_dir} could not be prepared. "
            "Run fprime-util generate and fprime-util build there, then try again."
        )

    args.analysis_artifacts = artifacts
    return artifacts


def load_flow(args, *, allow_empty: bool = False) -> PortFlowMap:
    """Derive intra-component call flow for the selected deployment."""
    if args.permissive:
        return PortFlowMap.permissive()

    artifacts = resolve_analysis_artifacts(args, require_cpp=not allow_empty)
    if artifacts.compile_commands is None:
        return PortFlowMap.empty()

    logger.info("Analyzing component C++ call flow")
    try:
        from .component_call_graph import CallGraphExtractor

        data = CallGraphExtractor(
            compile_commands=artifacts.compile_commands,
            exclude_pattern=r"/(?:test|tests)/",
            jobs=getattr(args, "jobs", None),
            unit_cache_dir=(
                artifacts.compile_commands.parent
                / ".fprime-topology-analysis"
                / "units"
            ),
        ).run()
    except (RuntimeError, FileNotFoundError, ValueError) as error:
        if allow_empty:
            logger.warning(f"C++ call-flow analysis could not be completed: {error}")
            return PortFlowMap.empty()
        raise CliError(
            f"Could not analyze component C++ call flow for "
            f"{artifacts.deployment_dir}: {error}"
        ) from None
    return PortFlowMap(data)


def load_graph(args, flow: PortFlowMap) -> TopologyGraph:
    """Build the topology graph for the selected source deployment."""
    artifacts = resolve_analysis_artifacts(args, require_cpp=False)
    try:
        return TopologyGraph(
            artifacts.topology_path,
            flow=flow,
            topology_name=artifacts.topology_name,
        ).load()
    except (FileNotFoundError, ValueError):
        raise CliError(
            f"Could not load the deployment topology for {artifacts.deployment_dir}. "
            "Rebuild that deployment and try again."
        ) from None


def report_error(error: CliError, verbose: bool = False) -> int:
    """Print a CliError the way every analyzer prints it, and give an exit code."""
    logger.error(str(error))
    if verbose:
        traceback.print_exc()
    return 1


def report_unresolved(error: UnresolvedFlowError) -> int:
    """Explain a strict-mode resolution failure and give an exit code."""
    logger.error(
        f"Could not resolve intra-component call flow for {error.component}."
        f"{error.entry}: {error.reason}"
    )
    logger.error(
        "Refusing to guess. Fix the C++ analysis, or pass --permissive to assume "
        "unresolved handlers call every output port."
    )
    return 1


def write_or_print(text: str, path: Optional[Path]) -> None:
    """Write a report to ``path``, creating its directory, or print it."""
    if path is None:
        print(text)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    logger.debug(f"Wrote {path}")
