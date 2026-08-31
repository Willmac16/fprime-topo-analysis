#!/usr/bin/env python3
"""
Component Call Graph Extractor - libclang Implementation

Extracts, for every F' component implementation, the set of output ports each
input-port (or command) handler can actually invoke.

The FPP topology says which output port is wired to which input port, and which
input ports take the guarded mutex. It does not say which output ports a given
handler calls - that lives in the C++ implementation, behind ordinary member
calls. Without it, any topology-level analysis has to assume every handler may
call every output port, which is sound but very imprecise.

This tool closes that gap. For each translation unit in ``compile_commands.json``
it builds a call graph over member functions, then computes, for each handler,
the transitive closure of the functions it calls and the output ports those
functions invoke:

    bufferSendIn_handler
      -> BufferManager::returnBuffer            (private helper)
        -> BufferManagerComponentBase::bufferDeallocate_out
          -> m_bufferDeallocate_OutputPort      (port invocation)

An output port invocation is recognized two ways: a reference to the generated
``m_<port>_OutputPort`` member, and a call to a generated ``<port>_out`` method.
Telemetry, event, parameter and time helpers resolve through the same closure
once the generated ``*ComponentAc.cpp`` is parsed, since those helpers are just
member functions that touch the corresponding special port member.

Soundness: a handler that makes a call libclang cannot resolve (a call through a
function pointer or a delegate) is marked ``opaque``. Consumers must fall back to
the conservative "may call any output port" assumption for opaque handlers
rather than trusting a partial answer.

Copyright 2026, by the California Institute of Technology.
ALL RIGHTS RESERVED. United States Government Sponsorship acknowledged.
"""

import glob
import hashlib
import json
import logging
import multiprocessing
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from tqdm import tqdm

logger = logging.getLogger(__name__)

FLOW_FORMAT_VERSION = 1
UNIT_CACHE_VERSION = 1

# Generated naming conventions used to recognize port invocations
OUTPUT_PORT_MEMBER_RE = re.compile(r"^m_(?P<port>\w+)_OutputPort$")
OUTPUT_INVOKER_RE = re.compile(r"^(?P<port>\w+)_out$")
# Guard a handler uses before invoking an optional output port. Calling an
# unconnected output port asserts, so a guarded call is not a defect.
IS_CONNECTED_RE = re.compile(r"^isConnected_(?P<port>\w+)_OutputPort$")
# Generated event helpers, which name the severity they log at
EVENT_HELPER_RE = re.compile(r"^log_(?P<severity>[A-Z_]+?)_(?P<event>\w+)$")

# Handler naming conventions used to recognize entry points. An internal port's
# handler is generated as <port>_internalInterfaceHandler, not <port>_handler.
PORT_HANDLER_RE = re.compile(r"^(?P<port>\w+)_handler$")
INTERNAL_HANDLER_RE = re.compile(r"^(?P<port>\w+)_internalInterfaceHandler$")
CMD_HANDLER_RE = re.compile(r"^(?P<cmd>\w+)_cmdHandler$")

# Generated base classes are named <Component>ComponentBase
COMPONENT_BASE_SUFFIX = "ComponentBase"

# Compilers used to probe for default system include paths, in order
SYSTEM_INCLUDE_PROBES = (("g++", "c++"), ("clang++", "c++"), ("cc", "c"))

# A compilation database describes the whole project, but a deployment build
# only autocodes the modules that deployment actually links. Sources for the
# rest are listed and never generated, and implementation files that include
# their missing generated header fail the same way. Neither is a defect in the
# extraction, so they are counted separately from real failures.
MISSING_AUTOCODE_RE = re.compile(r"'([\w/.-]*Ac\.hpp)' file not found")

# A member of one of these types is a lock. A component that protects its own
# state with an explicit mutex, rather than relying on guarded ports, is still
# synchronized, and a race check that does not know this reports every such
# member.
LOCK_TYPE_MARKERS = ("Mutex", "ScopeLock", "Semaphore", "SpinLock")

# Assignment forms that make the left hand side a write
ASSIGN_TOKEN = "="
INCREMENT_TOKENS = {"++", "--"}

# A GCC compile database carries warning flags libclang does not recognize
# (e.g. -Wno-stringop-overflow, -Wno-maybe-uninitialized), and -Werror turns the
# resulting "unknown warning option" into a hard parse error. Analysis ignores
# warnings, so drop -Werror* and tell clang to shrug off the flags it can't parse.
CLANG_UNKNOWN_WARNING_TOLERANCE = "-Wno-unknown-warning-option"


def detect_host_libclang() -> Optional[Path]:
    """Find the libclang supplied by the selected macOS developer toolchain."""
    if sys.platform != "darwin":
        return None
    try:
        result = subprocess.run(
            ("xcrun", "--find", "clang"),
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    compiler = Path(result.stdout.strip())
    library = compiler.parent.parent / "lib" / "libclang.dylib"
    return library if library.is_file() else None


def _clang_resource_include() -> Optional[str]:
    """Clang's own builtin-header dir (stddef.h and the SSE/AVX intrinsics).

    A GCC compilation database points -isystem at GCC's private compiler headers,
    whose intrinsics (xmmintrin.h, ...) use __builtin_ia32_* builtins that clang
    does not implement - on monarch that produced ~9.7k parse errors. Searching
    clang's resource headers first makes clang use its own compatible versions.
    """
    for binary in ("clang", "clang++"):
        try:
            result = subprocess.run(
                [binary, "-print-resource-dir"], capture_output=True, text=True
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            include = Path(result.stdout.strip()) / "include"
            if (include / "stddef.h").is_file():
                return str(include)
    # No clang driver on PATH: take the newest resource dir a system LLVM ships.
    candidates = [
        path
        for pattern in (
            "/usr/lib/clang/*/include",
            "/usr/lib/llvm-*/lib/clang/*/include",
        )
        for path in glob.glob(pattern)
        if (Path(path) / "stddef.h").is_file()
    ]
    return max(candidates, default=None)


def detect_system_includes() -> List[str]:
    """Find the host compiler's default include paths as -isystem flags.

    A compilation database records only the flags the build passes explicitly.
    The compiler's own default include paths are implicit, and libclang - which
    is not the build's compiler - does not know them. Without this, every
    translation unit fails on <stddef.h> and resolution silently degrades.
    """
    # Clang's resource headers go first so its intrinsics/stddef win over a GCC
    # database's private compiler include dir, which clang cannot compile.
    resource = _clang_resource_include()
    prefix = ["-isystem", resource] if resource else []
    for compiler, language in SYSTEM_INCLUDE_PROBES:
        try:
            result = subprocess.run(
                [compiler, "-E", "-v", "-x", language, "/dev/null"],
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue

        paths: List[str] = []
        collecting = False
        for line in result.stderr.splitlines():
            if line.startswith("#include <...>"):
                collecting = True
                continue
            if line.startswith("End of search list"):
                break
            if collecting:
                candidate = Path(line.strip())
                if candidate.is_dir():
                    paths.append(str(candidate))
        if paths:
            logger.debug(f"System includes from {compiler}: {paths}")
            return prefix + [flag for path in paths for flag in ("-isystem", path)]

    logger.warning(
        "Could not detect system include paths; parses may fail on standard headers"
    )
    return prefix


@dataclass
class MethodInfo:
    """One member function definition and what it reaches directly"""

    cls: str
    name: str
    # (class, method) pairs called directly from this body
    calls: Set[Tuple[str, str]] = field(default_factory=set)
    # Output port names invoked directly from this body
    ports: Set[str] = field(default_factory=set)
    # Output ports this body tests with isConnected_<port>_OutputPort
    guarded_ports: Set[str] = field(default_factory=set)
    # Non-port member fields this body reads and writes. Recorded as
    # Owner::field so fields belonging to other classes - a Fw::Buffer's
    # members, a std container's internals - can be filtered out later.
    fields_read: Set[str] = field(default_factory=set)
    fields_written: Set[str] = field(default_factory=set)
    # Event severities emitted directly, e.g. WARNING_HI
    event_severities: Set[str] = field(default_factory=set)
    # Lock-typed members this body touches, i.e. explicit synchronization
    locks_touched: Set[str] = field(default_factory=set)
    # True when this body contains a call libclang could not resolve
    opaque: bool = False

    @property
    def key(self) -> Tuple[str, str]:
        return (self.cls, self.name)


@dataclass
class _UnitResult:
    methods: Dict[Tuple[str, str], MethodInfo]
    class_component: Dict[str, str]
    parsed_files: int
    failed_files: List[str]
    files_with_errors: Set[str]
    diagnostic_count: int
    not_generated: List[str]
    missing_autocode: Set[str]
    dependencies: Set[str]


_WORKER_CINDEX = None
_WORKER_INDEX = None


def _initialize_parse_worker(libclang_path: Optional[str]) -> None:
    """Give each process its own libclang index."""
    global _WORKER_CINDEX, _WORKER_INDEX
    extractor = CallGraphExtractor(
        Path("compile_commands.json"),
        libclang_path=libclang_path,
        system_includes=[],
        jobs=1,
    )
    _WORKER_CINDEX, _WORKER_INDEX = extractor.create_parser()
    logger.disabled = True


def _parse_unit_worker(unit: Tuple[Path, List[str]]) -> _UnitResult:
    """Parse one unit without sharing mutable extractor state."""
    source, args = unit
    extractor = CallGraphExtractor(
        Path("compile_commands.json"), system_includes=[], jobs=1
    )
    extractor.parse_unit_with(source, args, _WORKER_CINDEX, _WORKER_INDEX)
    return _extract_unit_result(extractor)


def _extract_unit_result(extractor: "CallGraphExtractor") -> _UnitResult:
    """Detach the serializable state produced by one translation unit."""
    return _UnitResult(
        methods=extractor.methods,
        class_component=extractor.class_component,
        parsed_files=extractor.parsed_files,
        failed_files=extractor.failed_files,
        files_with_errors=extractor.files_with_errors,
        diagnostic_count=extractor.diagnostic_count,
        not_generated=extractor.not_generated,
        missing_autocode=extractor.missing_autocode,
        dependencies=extractor.dependencies,
    )


class CallGraphExtractor:
    """Builds a member-function call graph and resolves handler port usage"""

    def __init__(
        self,
        compile_commands: Path,
        include_pattern: Optional[str] = None,
        exclude_pattern: Optional[str] = None,
        libclang_path: Optional[str] = None,
        system_includes: Optional[List[str]] = None,
        jobs: Optional[int] = None,
        unit_cache_dir: Optional[Path] = None,
    ):
        self.compile_commands = compile_commands
        self.system_includes = (
            system_includes if system_includes is not None else detect_system_includes()
        )
        self.include_re = re.compile(include_pattern) if include_pattern else None
        self.exclude_re = re.compile(exclude_pattern) if exclude_pattern else None
        self.libclang_path = libclang_path
        self.jobs = max(1, jobs if jobs is not None else (os.cpu_count() or 1))
        self.unit_cache_dir = unit_cache_dir
        self.cache_version = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

        self.methods: Dict[Tuple[str, str], MethodInfo] = {}
        # Implementation class -> FPP component it implements, by inheritance
        self.class_component: Dict[str, str] = {}
        self.parsed_files = 0
        self.failed_files: List[str] = []
        self.files_with_errors: Set[str] = set()
        self.diagnostic_count = 0
        # Sources listed in the database but never generated, and sources that
        # include a generated header that was never produced
        self.not_generated: List[str] = []
        self.missing_autocode: Set[str] = set()
        self.dependencies: Set[str] = set()
        self._source_cache: Dict[str, str] = {}

    def _merge_unit_result(self, result: _UnitResult) -> None:
        """Merge one worker result in compilation-database order."""
        self.methods.update(result.methods)
        self.class_component.update(result.class_component)
        self.parsed_files += result.parsed_files
        self.failed_files.extend(result.failed_files)
        self.files_with_errors.update(result.files_with_errors)
        self.diagnostic_count += result.diagnostic_count
        self.not_generated.extend(result.not_generated)
        self.missing_autocode.update(result.missing_autocode)
        self.dependencies.update(result.dependencies)

    def create_parser(self):
        """Create the libclang objects owned by one parsing process."""
        cindex = self._load_clang()
        return cindex, cindex.Index.create()

    def parse_unit_with(self, source: Path, args: List[str], cindex, index) -> None:
        """Parse one unit using parser objects owned by the current process."""
        self._cindex = cindex
        self._index = index
        self.parse_unit(source, args)

    def _unit_cache_file(self, source: Path) -> Optional[Path]:
        if self.unit_cache_dir is None:
            return None
        name = hashlib.sha256(str(source.resolve()).encode()).hexdigest()
        return self.unit_cache_dir / f"{name}.json"

    @staticmethod
    def _method_to_data(method: MethodInfo) -> dict:
        return {
            "cls": method.cls,
            "name": method.name,
            "calls": [list(call) for call in sorted(method.calls)],
            "ports": sorted(method.ports),
            "guarded_ports": sorted(method.guarded_ports),
            "fields_read": sorted(method.fields_read),
            "fields_written": sorted(method.fields_written),
            "event_severities": sorted(method.event_severities),
            "locks_touched": sorted(method.locks_touched),
            "opaque": method.opaque,
        }

    @staticmethod
    def _method_from_data(data: dict) -> MethodInfo:
        return MethodInfo(
            cls=data["cls"],
            name=data["name"],
            calls={tuple(call) for call in data["calls"]},
            ports=set(data["ports"]),
            guarded_ports=set(data["guarded_ports"]),
            fields_read=set(data["fields_read"]),
            fields_written=set(data["fields_written"]),
            event_severities=set(data["event_severities"]),
            locks_touched=set(data["locks_touched"]),
            opaque=data["opaque"],
        )

    def _result_to_data(self, result: _UnitResult) -> dict:
        return {
            "methods": [
                self._method_to_data(method)
                for _, method in sorted(result.methods.items())
            ],
            "class_component": result.class_component,
            "parsed_files": result.parsed_files,
            "failed_files": result.failed_files,
            "files_with_errors": sorted(result.files_with_errors),
            "diagnostic_count": result.diagnostic_count,
            "not_generated": result.not_generated,
            "missing_autocode": sorted(result.missing_autocode),
            "dependencies": sorted(result.dependencies),
        }

    def _result_from_data(self, data: dict) -> _UnitResult:
        methods = [self._method_from_data(method) for method in data["methods"]]
        return _UnitResult(
            methods={method.key: method for method in methods},
            class_component=dict(data["class_component"]),
            parsed_files=data["parsed_files"],
            failed_files=list(data["failed_files"]),
            files_with_errors=set(data["files_with_errors"]),
            diagnostic_count=data["diagnostic_count"],
            not_generated=list(data["not_generated"]),
            missing_autocode=set(data["missing_autocode"]),
            dependencies=set(data["dependencies"]),
        )

    @staticmethod
    def _dependency_stamps(paths: Set[str]) -> Optional[dict]:
        stamps = {}
        for path_text in sorted(paths):
            try:
                stat = Path(path_text).stat()
            except OSError:
                return None
            stamps[path_text] = [stat.st_mtime_ns, stat.st_size]
        return stamps

    def _missing_header_available(self, args: List[str], headers: Set[str]) -> bool:
        include_dirs: List[Path] = []
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in {"-I", "-isystem", "-iquote"} and index + 1 < len(args):
                include_dirs.append(Path(args[index + 1]))
                index += 2
                continue
            for prefix in ("-I", "-isystem", "-iquote"):
                if arg.startswith(prefix) and len(arg) > len(prefix):
                    include_dirs.append(Path(arg[len(prefix) :]))
                    break
            index += 1
        return any(
            (directory / header).is_file()
            for directory in include_dirs
            for header in headers
        )

    def _read_cached_unit(
        self, source: Path, args: List[str]
    ) -> Optional[_UnitResult]:
        cache_file = self._unit_cache_file(source)
        if cache_file is None:
            return None
        try:
            payload = json.loads(cache_file.read_text())
            if (
                payload["version"] != UNIT_CACHE_VERSION
                or payload["extractor"] != self.cache_version
                or payload["args"] != args
            ):
                return None
            dependencies = payload["dependencies"]
            for path_text, expected in dependencies.items():
                stat = Path(path_text).stat()
                if [stat.st_mtime_ns, stat.st_size] != expected:
                    return None
            result = self._result_from_data(payload["result"])
            if result.missing_autocode and self._missing_header_available(
                args, result.missing_autocode
            ):
                return None
            return result
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _write_cached_unit(
        self, source: Path, args: List[str], result: _UnitResult
    ) -> None:
        cache_file = self._unit_cache_file(source)
        if (
            cache_file is None
            or (result.parsed_files != 1 and not result.not_generated)
            or result.failed_files
            or result.diagnostic_count
        ):
            return
        dependencies = self._dependency_stamps(result.dependencies)
        if not dependencies:
            return
        temporary: Optional[Path] = None
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": UNIT_CACHE_VERSION,
                "extractor": self.cache_version,
                "args": args,
                "dependencies": dependencies,
                "result": self._result_to_data(result),
            }
            with tempfile.NamedTemporaryFile(
                "w", dir=cache_file.parent, prefix="unit-", delete=False
            ) as stream:
                json.dump(payload, stream)
                temporary = Path(stream.name)
            temporary.replace(cache_file)
        except OSError:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _flow_cache_file(self) -> Optional[Path]:
        if self.unit_cache_dir is None:
            return None
        return self.unit_cache_dir.parent / "flow.json"

    def _read_cached_flow(self) -> Optional[dict]:
        cache_file = self._flow_cache_file()
        if cache_file is None:
            return None
        try:
            payload = json.loads(cache_file.read_text())
            if (
                payload["version"] != UNIT_CACHE_VERSION
                or payload["extractor"] != self.cache_version
                or payload["compile_commands"]
                != hashlib.sha256(self.compile_commands.read_bytes()).hexdigest()
            ):
                return None
            for path_text, expected in payload["dependencies"].items():
                stat = Path(path_text).stat()
                if [stat.st_mtime_ns, stat.st_size] != expected:
                    return None
            data = payload["data"]
            return data if isinstance(data, dict) else None
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _write_cached_flow(self, data: dict) -> None:
        cache_file = self._flow_cache_file()
        dependencies = self._dependency_stamps(self.dependencies)
        if cache_file is None or not dependencies or self.diagnostic_count:
            return
        temporary: Optional[Path] = None
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": UNIT_CACHE_VERSION,
                "extractor": self.cache_version,
                "compile_commands": hashlib.sha256(
                    self.compile_commands.read_bytes()
                ).hexdigest(),
                "dependencies": dependencies,
                "data": data,
            }
            with tempfile.NamedTemporaryFile(
                "w", dir=cache_file.parent, prefix="flow-", delete=False
            ) as stream:
                json.dump(payload, stream)
                temporary = Path(stream.name)
            temporary.replace(cache_file)
        except OSError:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _parallel_results(self, units: List[Tuple[Path, List[str]]], workers: int):
        """Yield unit results in source order while parsing across processes."""
        methods = multiprocessing.get_all_start_methods()
        context = multiprocessing.get_context("fork" if "fork" in methods else "spawn")
        selected_libclang = self.libclang_path
        if selected_libclang is None:
            detected = detect_host_libclang()
            selected_libclang = str(detected) if detected is not None else None
        with ProcessPoolExecutor(
            max_workers=workers,
            mp_context=context,
            initializer=_initialize_parse_worker,
            initargs=(selected_libclang,),
        ) as executor:
            yield from executor.map(_parse_unit_worker, units, chunksize=1)

    # ------------------------------------------------------------------
    # libclang setup
    # ------------------------------------------------------------------

    def _load_clang(self):
        """Import clang.cindex, configuring the library path if given

        Raises:
            RuntimeError: If the clang Python bindings are unavailable
        """
        try:
            import clang.cindex as cindex
        except ImportError as e:
            raise RuntimeError(
                "The clang Python bindings are required. Install libclang in "
                "the active environment."
            ) from e

        libclang_path = Path(self.libclang_path) if self.libclang_path else detect_host_libclang()
        if libclang_path is not None and not cindex.Config.loaded:
            path = libclang_path
            if path.is_dir():
                cindex.Config.set_library_path(str(path))
            else:
                cindex.Config.set_library_file(str(path))

        # Darwin headers expose the standard Objective-C attribute cursor range.
        # Some Python libclang packages omit these IDs, causing Cursor.kind to
        # raise before the walker can ignore the attributes.
        missing_attribute_kinds = {
            420: "NS_RETURNS_RETAINED",
            421: "NS_RETURNS_NOT_RETAINED",
            422: "NS_RETURNS_AUTORELEASED",
            423: "NS_CONSUMES_SELF",
            424: "NS_CONSUMED",
            425: "OBJC_EXCEPTION",
            426: "OBJC_NSOBJECT",
            427: "OBJC_INDEPENDENT_CLASS",
            428: "OBJC_PRECISE_LIFETIME",
            429: "OBJC_RETURNS_INNER_POINTER",
            430: "OBJC_REQUIRES_SUPER",
            431: "OBJC_ROOT_CLASS",
            432: "OBJC_SUBCLASSING_RESTRICTED",
            433: "OBJC_EXPLICIT_PROTOCOL_IMPL",
            434: "OBJC_DESIGNATED_INITIALIZER",
            435: "OBJC_RUNTIME_VISIBLE",
            436: "OBJC_BOXABLE",
            437: "FLAG_ENUM",
        }
        registered_values = {
            cursor_kind.value for cursor_kind in cindex.CursorKind.get_all_kinds()
        }
        for value, name in missing_attribute_kinds.items():
            if value not in registered_values:
                setattr(cindex.CursorKind, name, cindex.CursorKind(value))
        return cindex

    # ------------------------------------------------------------------
    # Compilation database
    # ------------------------------------------------------------------

    def load_translation_units(self) -> List[Tuple[Path, List[str]]]:
        """Read compile_commands.json into (file, args) tuples

        Raises:
            FileNotFoundError: If the compilation database is missing
            ValueError: If the compilation database is malformed
        """
        if not self.compile_commands.exists():
            raise FileNotFoundError(
                f"Compilation database not found: {self.compile_commands}"
            )

        try:
            entries = json.loads(self.compile_commands.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Malformed compilation database: {e}") from e

        units = []
        for entry in entries:
            source = entry.get("file")
            if not source:
                continue
            if self.include_re and not self.include_re.search(source):
                continue
            if self.exclude_re and self.exclude_re.search(source):
                continue

            if not Path(source).exists():
                # Generated for a module this build did not need
                self.not_generated.append(source)
                continue

            args = self._extract_args(entry) + self.system_includes
            units.append((Path(source), args))

        return units

    def _extract_args(self, entry: dict) -> List[str]:
        """Get compiler arguments for one entry, dropping output/compile flags"""
        if "arguments" in entry:
            raw = list(entry["arguments"])
        else:
            import shlex

            raw = shlex.split(entry.get("command", ""))

        args: List[str] = []
        skip_next = False
        for i, arg in enumerate(raw):
            if skip_next:
                skip_next = False
                continue
            # Drop the compiler binary itself
            if i == 0:
                continue
            if arg in ("-c", "-o"):
                skip_next = arg == "-o"
                continue
            if arg == entry.get("file"):
                continue
            # Warnings-as-errors would fail the parse on flags clang lacks.
            if arg == "-Werror" or arg.startswith("-Werror="):
                continue
            args.append(arg)
        args.append(CLANG_UNKNOWN_WARNING_TOLERANCE)
        return args

    # ------------------------------------------------------------------
    # AST walking
    # ------------------------------------------------------------------

    def _qualified_class_name(self, cursor) -> Optional[str]:
        """Fully qualified name of a class/struct cursor, e.g. Svc::BufferManager"""
        cindex = self._cindex
        parts: List[str] = []
        node = cursor
        while node is not None and node.kind != cindex.CursorKind.TRANSLATION_UNIT:
            if node.spelling and node.kind in (
                cindex.CursorKind.CLASS_DECL,
                cindex.CursorKind.STRUCT_DECL,
                cindex.CursorKind.CLASS_TEMPLATE,
                cindex.CursorKind.NAMESPACE,
            ):
                parts.append(node.spelling)
            node = node.semantic_parent
        if not parts:
            return None
        return "::".join(reversed(parts))

    def _method_key(self, decl) -> Optional[Tuple[str, str]]:
        """Map a method declaration to a (class, method) key"""
        parent = decl.semantic_parent
        if parent is None:
            return None
        cls = self._qualified_class_name(parent)
        if cls is None:
            return None
        return (cls, decl.spelling)

    def parse_unit(self, source: Path, args: List[str]) -> None:
        """Parse one translation unit and fold its methods into the graph"""
        cindex = self._cindex
        index = self._index
        self.dependencies.add(str(source.resolve()))

        try:
            tu = index.parse(
                str(source),
                args=args,
                options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
        except cindex.TranslationUnitLoadError as e:
            logger.debug(f"  Failed to parse {source}: {e}")
            self.failed_files.append(str(source))
            return

        with suppress(Exception):
            self.dependencies.update(
                inclusion.include.name
                for inclusion in tu.get_includes()
                if inclusion.include is not None and inclusion.include.name
            )

        errors = [
            d for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error
        ]
        if errors:
            missing = {
                match.group(1)
                for match in (
                    MISSING_AUTOCODE_RE.search(d.spelling or "") for d in errors
                )
                if match
            }
            if missing:
                # The module was not built, so its generated header does not
                # exist. Not an extraction failure.
                self.missing_autocode |= missing
                self.not_generated.append(str(source))
                logger.debug(
                    f"  {source}: skipped, generated header not built "
                    f"({min(missing)})"
                )
                return
            self.diagnostic_count += len(errors)
            self.files_with_errors.add(str(source))
            logger.debug(
                f"  {source}: {len(errors)} parse error(s); "
                f"first: {errors[0].spelling}"
            )

        self.parsed_files += 1
        self._walk_methods(tu.cursor)

    def _record_component_bases(self, node) -> None:
        """Map a class to the FPP component it implements, via its base class.

        An F' implementation class may be named anything: FPP
        ``Svc.PassiveTextLogger`` is implemented by ``Svc::ConsoleTextLoggerImpl``.
        What is reliable is that it derives from the generated
        ``<Component>ComponentBase``, so the base class names the component even
        when the derived class does not.
        """
        cindex = self._cindex
        cls = self._qualified_class_name(node)
        if cls is None:
            return
        for child in node.get_children():
            if child.kind != cindex.CursorKind.CXX_BASE_SPECIFIER:
                continue
            base = child.referenced or child
            base_name = self._qualified_class_name(base) or base.spelling
            if base_name and base_name.endswith(COMPONENT_BASE_SUFFIX):
                self.class_component[cls] = base_name[: -len(COMPONENT_BASE_SUFFIX)]
                return

    def _walk_methods(self, cursor) -> None:
        """Find every method definition in the TU and record what it reaches"""
        cindex = self._cindex
        for node in cursor.walk_preorder():
            if node.kind == cindex.CursorKind.CLASS_DECL and node.is_definition():
                self._record_component_bases(node)
            if node.kind not in (
                cindex.CursorKind.CXX_METHOD,
                cindex.CursorKind.CONSTRUCTOR,
                cindex.CursorKind.FUNCTION_TEMPLATE,
            ):
                continue
            if not node.is_definition():
                continue
            key = self._method_key(node)
            if key is None:
                continue

            info = self.methods.get(key)
            if info is None:
                info = MethodInfo(cls=key[0], name=key[1])
                self.methods[key] = info

            self._scan_body(node, info)

    # Comparison operators that also contain '=' but assign nothing
    NON_ASSIGN_OPERATORS = ("==", "!=", "<=", ">=")

    def _source_text(self, path: str) -> str:
        """File contents, cached per translation unit.

        Slicing the source between two cursor extents is far cheaper than
        libclang tokenization, and the operator of a binary expression is
        exactly the text between its two operands.
        """
        if path not in self._source_cache:
            try:
                self._source_cache[path] = Path(path).read_text(errors="ignore")
            except OSError:
                self._source_cache[path] = ""
        return self._source_cache[path]

    def _is_assignment(self, cursor, children) -> bool:
        """Whether a binary expression assigns to its left operand"""
        if len(children) < 2:
            return False
        location = cursor.location
        if location is None or location.file is None:
            return False
        source = self._source_text(location.file.name)
        if not source:
            return False
        between = source[
            children[0].extent.end.offset : children[1].extent.start.offset
        ]
        if any(op in between for op in self.NON_ASSIGN_OPERATORS):
            return False
        return ASSIGN_TOKEN in between

    def _is_increment(self, cursor) -> bool:
        """Whether a unary expression increments or decrements its operand"""
        location = cursor.location
        if location is None or location.file is None:
            return False
        source = self._source_text(location.file.name)
        if not source:
            return False
        text = source[cursor.extent.start.offset : cursor.extent.end.offset]
        return any(token in text for token in INCREMENT_TOKENS)

    def _writes_first_operand(self, node, children) -> bool:
        """Whether this expression mutates whatever its first child names"""
        cindex = self._cindex
        if node.kind == cindex.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            return True
        if node.kind == cindex.CursorKind.BINARY_OPERATOR:
            return self._is_assignment(node, children)
        if node.kind == cindex.CursorKind.UNARY_OPERATOR:
            return self._is_increment(node)
        if node.kind == cindex.CursorKind.CALL_EXPR:
            # A non-const method called on a member mutates that member
            referenced = node.referenced
            return (
                referenced is not None
                and referenced.kind == cindex.CursorKind.CXX_METHOD
                and not referenced.is_const_method()
            )
        return False

    def _scan_member_ref(self, node, info: MethodInfo) -> Optional[str]:
        """Record an output port or a lock touched here; name any other member

        :returns: the qualified member name when this is an ordinary field,
            which the caller classifies as a read or a write by its offset.
        """
        spelling = node.spelling or ""
        port = OUTPUT_PORT_MEMBER_RE.match(spelling)
        if port:
            info.ports.add(port.group("port"))
            return None

        # A non-port member. Two threads touching the same field with no mutex,
        # at least one writing, is a data race, so record what each handler
        # reads and writes.
        referenced = node.referenced
        if referenced is None or referenced.kind != self._cindex.CursorKind.FIELD_DECL:
            return None
        owner = self._qualified_class_name(referenced.semantic_parent)
        if not owner:
            return None

        qualified = f"{owner}::{spelling}"
        type_name = ""
        with suppress(AttributeError, ValueError):
            type_name = referenced.type.spelling or ""
        if any(marker in type_name for marker in LOCK_TYPE_MARKERS):
            info.locks_touched.add(qualified)
            return None
        return qualified

    def _scan_call(self, node, info: MethodInfo) -> None:
        """Record the callee, and anything its generated name reveals"""
        cindex = self._cindex
        referenced = node.referenced
        if referenced is None:
            # libclang emits CALL_EXPR nodes for implicit work too: constructor
            # calls, conversions and operators. Those carry no spelling and no
            # referenced declaration, and they cannot invoke a port, so they are
            # not a loss of information. Only a *named* call we failed to
            # resolve means the handler is no longer fully enumerated.
            if node.spelling:
                info.opaque = True
                logger.debug(
                    f"    opaque: unresolved call {node.spelling!r} in "
                    f"{info.cls}::{info.name}"
                )
            return
        if referenced.kind not in (
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.FUNCTION_TEMPLATE,
            cindex.CursorKind.CONSTRUCTOR,
        ):
            return
        callee = self._method_key(referenced)
        if callee is None:
            return
        info.calls.add(callee)

        # Generated helpers name what they act on. A <port>_out invoker keeps
        # resolution working even when the generated *ComponentAc.cpp is not
        # part of the compilation database.
        name = referenced.spelling or ""
        for pattern, group, target in (
            (OUTPUT_INVOKER_RE, "port", info.ports),
            (IS_CONNECTED_RE, "port", info.guarded_ports),
            (EVENT_HELPER_RE, "severity", info.event_severities),
        ):
            match = pattern.match(name)
            if match:
                target.add(match.group(group))

    def _scan_body(self, method_cursor, info: MethodInfo) -> None:
        """Record calls, port references and member accesses in one body.

        A single pass. Assignment left-hand sides are recorded as source
        ranges, and a member reference is a write when it falls inside one, so
        neither subtree re-walks nor tokenization are needed.
        """
        cindex = self._cindex
        write_ranges: List[Tuple[int, int]] = []
        member_refs: List[Tuple[int, str]] = []

        for node in method_cursor.walk_preorder():
            children = list(node.get_children())
            if children and self._writes_first_operand(node, children):
                target = children[0].extent
                write_ranges.append((target.start.offset, target.end.offset))

            if node.kind == cindex.CursorKind.MEMBER_REF_EXPR:
                member = self._scan_member_ref(node, info)
                if member:
                    member_refs.append((node.extent.start.offset, member))
            elif node.kind == cindex.CursorKind.CALL_EXPR:
                self._scan_call(node, info)

        for offset, member in member_refs:
            if any(start <= offset < end for start, end in write_ranges):
                info.fields_written.add(member)
            else:
                info.fields_read.add(member)

    def _resolve(self, key: Tuple[str, str]):
        """Transitively resolve one handler to what it reaches.

        Returns:
            (output port names, opaque, functions visited, extra recorded facts)
        """
        ports: Set[str] = set()
        guarded: Set[str] = set()
        reads: Set[str] = set()
        writes: Set[str] = set()
        locks: Set[str] = set()
        severities: Set[str] = set()
        opaque = False
        seen: Set[Tuple[str, str]] = set()
        stack = [key]

        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)

            info = self.methods.get(current)
            if info is None:
                # Not defined in any parsed TU. Its name may still identify a
                # port invoker, which _scan_body already recorded at the call
                # site, so treat it as a leaf rather than as opaque.
                continue

            ports |= info.ports
            guarded |= info.guarded_ports
            reads |= info.fields_read
            writes |= info.fields_written
            locks |= info.locks_touched
            severities |= info.event_severities
            opaque = opaque or info.opaque
            stack.extend(info.calls - seen)

        # A field is a write wherever it is written, so reads are the rest
        extra = {
            "guarded_ports": sorted(guarded),
            "fields_written": sorted(writes),
            "fields_read": sorted(reads - writes),
            "locks_taken": sorted(locks),
            "event_severities": sorted(severities),
        }
        return ports, opaque, len(seen), extra

    def build_flow_map(self) -> dict:
        """Resolve every handler in the graph into the output ports it reaches"""
        components: Dict[str, dict] = {}

        for cls, name in sorted(self.methods):

            internal_match = INTERNAL_HANDLER_RE.match(name)
            # Check the internal form first: it also matches PORT_HANDLER_RE,
            # which would otherwise name the port "<port>_internalInterface".
            port_match = None if internal_match else PORT_HANDLER_RE.match(name)
            cmd_match = CMD_HANDLER_RE.match(name)
            if not port_match and not cmd_match and not internal_match:
                continue

            # Attribute the handler to the component it implements. Inheritance
            # is authoritative; the class name is only a fallback for a class
            # whose base was not in any parsed translation unit.
            if cls.endswith(COMPONENT_BASE_SUFFIX):
                component = cls[: -len(COMPONENT_BASE_SUFFIX)]
            else:
                component = self.class_component.get(cls, cls)

            if internal_match:
                entry = internal_match.group("port")
            elif port_match:
                entry = port_match.group("port")
            else:
                entry = f"cmd:{cmd_match.group('cmd')}"

            ports, opaque, visited, extra = self._resolve((cls, name))

            # Keep only fields belonging to this component's own classes. A
            # handler that touches a Fw::Buffer's members, or a std container's
            # internals, is not sharing this component's state.
            owned = {cls, f"{component}{COMPONENT_BASE_SUFFIX}"}
            for facet in ("fields_read", "fields_written", "locks_taken"):
                extra[facet] = [
                    name
                    for name in extra[facet]
                    if name.rsplit("::", 1)[0] in owned
                ]

            comp_entry = components.setdefault(
                component, {"class": cls, "handlers": {}}
            )
            existing = comp_entry["handlers"].get(entry)
            if existing is None:
                comp_entry["handlers"][entry] = {
                    "ports": sorted(ports),
                    "opaque": opaque,
                    "functions_visited": visited,
                    **extra,
                }
            else:
                # A handler defined in both the base and the implementation:
                # union the results and stay conservative about opacity.
                existing["ports"] = sorted(set(existing["ports"]) | ports)
                existing["opaque"] = existing["opaque"] or opaque
                existing["functions_visited"] += visited
                for facet, values in extra.items():
                    existing[facet] = sorted(set(existing.get(facet, [])) | set(values))

            logger.debug(
                f"  {component}.{entry} -> {sorted(ports)}"
                f"{' (opaque)' if opaque else ''}"
            )

        return {
            "version": FLOW_FORMAT_VERSION,
            "implemented_by": dict(sorted(self.class_component.items())),
            "compile_commands": str(self.compile_commands),
            "parsed_files": self.parsed_files,
            "failed_files": self.failed_files,
            "not_generated": sorted(self.not_generated),
            "components": components,
        }

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Parse every selected translation unit and produce the flow map"""
        units = self.load_translation_units()
        cached_flow = self._read_cached_flow()
        if cached_flow is not None:
            logger.info(
                f"Using cached C++ flow map ({len(units)} translation unit(s) unchanged)"
            )
            return cached_flow

        unit_results: List[Optional[_UnitResult]] = [None] * len(units)
        pending: List[Tuple[int, Tuple[Path, List[str]]]] = []
        for index, (source, args) in enumerate(units):
            cached_unit = self._read_cached_unit(source, args)
            if cached_unit is None:
                pending.append((index, (source, args)))
            else:
                unit_results[index] = cached_unit

        workers = min(self.jobs, len(pending)) if pending else 1
        logger.info(
            f"Parsing {len(pending)} changed translation unit(s) with "
            f"{workers} worker(s) ({len(units) - len(pending)} cached)"
        )

        with tqdm(
            total=len(pending),
            desc="Parsing C++",
            unit="unit",
            # Match the old bar: only on a real terminal, and never while
            # --verbose logging is sharing stderr (tqdm would shred the log).
            disable=not pending
            or not sys.stderr.isatty()
            or logger.isEnabledFor(logging.DEBUG),
            file=sys.stderr,
        ) as progress:
            if pending and workers == 1:
                cindex, clang_index = self.create_parser()
                for index, (source, args) in pending:
                    logger.debug(f"Parsing {source}")
                    unit_extractor = CallGraphExtractor(
                        self.compile_commands,
                        libclang_path=self.libclang_path,
                        system_includes=[],
                        jobs=1,
                    )
                    unit_extractor.parse_unit_with(
                        source, args, cindex, clang_index
                    )
                    result = _extract_unit_result(unit_extractor)
                    unit_results[index] = result
                    self._write_cached_unit(source, args, result)
                    progress.update(1)
            elif pending:
                pending_units = [unit for _, unit in pending]
                for (index, (source, args)), result in zip(
                    pending,
                    self._parallel_results(pending_units, workers),
                    strict=True,
                ):
                    unit_results[index] = result
                    self._write_cached_unit(source, args, result)
                    progress.update(1)

        for result in unit_results:
            if result is None:
                raise RuntimeError("C++ parsing did not produce a unit result")
            self._merge_unit_result(result)

        logger.info(
            f"Parsed {self.parsed_files} file(s), "
            f"{len(self.methods)} method definition(s)"
        )
        if self.not_generated:
            logger.info(
                f"Skipped {len(self.not_generated)} translation unit(s) not "
                f"produced by this deployment"
                + (
                    f" ({len(self.missing_autocode)} generated header(s) unavailable)"
                    if self.missing_autocode
                    else ""
                )
            )
        if self.failed_files:
            logger.warning(f"{len(self.failed_files)} file(s) failed to parse")
        if self.diagnostic_count:
            logger.warning(
                f"{self.diagnostic_count} parse error(s) across "
                f"{len(self.files_with_errors)} file(s); the flow map may be "
                f"incomplete. Check include paths in the compilation database."
            )
            for path in sorted(self.files_with_errors)[:5]:
                logger.warning(f"  {path}")

        data = self.build_flow_map()
        self._write_cached_flow(data)
        return data
