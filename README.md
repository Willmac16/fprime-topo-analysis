# F´ Topology Analysis

Standalone package, intended to be extracted into its own repository.
Depends on an fprime checkout only as an *input*, never as a host.


Static analyses over an F´ topology, for concurrency defects that no single
source of truth can see on its own.

## Why the analysis is hybrid

An F´ concurrency bug lives across two artifacts:

| Question | Answered by |
| --- | --- |
| Which output port is wired to which input port? | the FPP topology (`fpp-to-json`) |
| Does that input port lock a mutex, or queue a message? | the FPP topology |
| Which output ports does *this handler* actually call? | the C++ implementation |

Neither half is sufficient. A C++-only tool cannot resolve a port call, because
`someOut_out()` dispatches through a port object wired at topology-init time —
the far end exists only in the FPP model. An FPP-only tool has to assume every
handler may call every output port, which is sound but reports chains the code
never takes.

So the topology supplies the inter-component edges, `libclang` supplies the
intra-component ones, and the analyses run over the join.

```
                 ┌─ inter-component edges ─┐                            guarded_port_analyzer.py
fpp-to-json ─────┤  + sync/guarded/async   ├──►  topology_graph.py  ──►  async_queue_analyzer.py
                 └─ tagging per input port ┘     (the tagged graph,      checks.py (12 checks)
                                             ▲    thread origins, and    (policy only)
component_call_graph.py ──► port_flow.py ────┘    the one traversal)
   (libclang: which output ports
    a handler actually calls)
```

The layering is deliberate:

1. **`component_call_graph.py` + `port_flow.py`** — the C++ port connection
   engine. Resolves each handler to the output ports it really invokes.
2. **`topology_graph.py`** — builds the whole topology as one graph, with every
   input port tagged sync / guarded / async (and commands tagged per mnemonic),
   and owns the single chain traversal that walks it.
3. **The analyzers** — each is *only* a policy over that traversal. Every hop is
   handed to a callback that returns either the state to descend with or `STOP`.
   The deadlock analysis carries the held-lock stack and stops at async hops;
   the priority analysis carries nothing and records async hops before stopping.
   Neither re-implements the walk, so they cannot drift apart about what "async"
   means. A new analysis is a new callback, not a new traversal.

## Tools

### `guarded_port_analyzer.py` — ABBA deadlock detection

Every component instance owns exactly one guarded-port mutex
(`m_guardedPortMutex`). The generated `*_handlerBase` for a guarded input port
locks it, calls the handler, and unlocks it afterwards, so **every port the
handler invokes is invoked with that mutex held**. A synchronous call out of a
guarded handler that lands on another guarded port therefore nests two mutexes.

The tool walks every guarded entry point, carrying a lock stack, and records
each nested acquisition as a lock-order edge — the same relation a runtime
checker like lockdep learns. Cycles in that graph are reported:

| Finding | Meaning |
| --- | --- |
| `SELF_DEADLOCK` | One chain re-enters a mutex it already holds. `Os::Mutex` is not recursive, so this hangs unconditionally. |
| `ABBA` | A lock-order cycle whose edges two different threads can drive, one taking A-then-B while the other takes B-then-A. |
| `ABBA_SINGLE_THREAD` | A lock-order cycle only one thread can reach. It cannot interleave today, but becomes a real ABBA once a second caller is connected. |

Dispatch rules that drive the walk:

* **guarded** input — takes the target's mutex, chain continues on this thread
* **sync** input — takes no mutex, chain continues on this thread
* **async** input — message is queued and the caller's locks are released, so
  the chain **ends**

Commands are resolved per mnemonic, since `sync`/`guarded`/`async` is declared
per command rather than on the `command recv` port.

```bash
python3 guarded_port_analyzer.py \
    --topology-path build-fprime-automatic-native/MyDeployment/Top \
    --flow-map flow.json \
    --dot locks.dot --fail-on error
```

### `async_queue_analyzer.py` — queue pressure and drain context

The single queue analyzer, ported from the original `fprime_async_analyzer`.
For every component queue it reports which producers feed it, on which threads,
at what priorities, and — given a rate model — how fast it would fill. Markdown,
JSON and Mermaid output.

Priority inversion is reported two ways, which cover different things:

* **Producer above consumer** — a producer thread at a higher priority than the
  queue's drain thread. Classified per connection by
  `classify_priority_relation`, which also accounts for passive callers and the
  emit context.
* **Self re-queue drop** — a chain that returns to the queue it started on at a
  lower port priority, so the rest of an urgent chain waits behind everything
  queued above it. The per-connection classification cannot see this, because
  it spans a chain rather than one connection.

`tools/parity_check.py` runs the original and this one over the same topology
and classifies every difference as equivalent, a connection the original
missed, a name it mangled, or a regression.

What the port changed is where each half of the input comes from. The topology
used to come from parsing `fpp-to-json -s` output as raw dicts, which meant
re-implementing connection pattern expansion, topology closure and port kind
resolution; it now comes from `TopologyGraph`, so FPP itself resolves patterns,
port aliases and imported subtopologies. Which handler emits on a producer port
used to come from regex scanning `.cpp` files — matching definitions by pattern,
finding bodies by counting braces, matching calls by name with no receiver type;
it now comes from the libclang flow map, which resolves calls through the real
AST and follows them transitively. The analysis, the priority classification and
the report vocabulary are unchanged, with one deliberate addition: a guarded
input handler is reported as such and treated like a sync handler for priority
purposes, because a guarded port also runs on the caller's thread. The regex
layer could not distinguish it.

### `checks.py` + `topology_checks.py` — the check registry

Twelve analyses over the same graph, each a policy returning uniform findings.
`fprime-topology-checks --list-checks` names them. A check declares whether it
needs the flow map and is skipped with a note rather than reporting on guesses.

| Check | Finds |
| --- | --- |
| `priority-inversion-window` | Spread of task priorities contending one mutex |
| `unconnected-port-invoked` | A handler that can reach an unconnected output port |
| `sync-cycle` | A cycle of sync ports — unbounded recursion, not deadlock |
| `ping-coverage` | Unmonitored threads, and pings that prove nothing |
| `data-race` | Members reached by two threads with an unsynchronized writer |
| `buffer-ownership` | Cross-pool buffer returns and leak sinks |
| `stack-depth` | Deepest synchronous chain per thread |
| `rate-group` | Members whose sync closure contends a mutex |
| `fatal-path` | A FATAL report that can be queued or dropped |
| `queue-overflow` | Fan-out onto a queue; error only for a provable self-enqueue |
| `cmd-tlm-paths` | Unwired command, time, event and telemetry ports |
| `cpu-affinity` | Mutexes contended across pinned CPUs |

### Data race detection

`data-race` answers "which threads reach this member, and does any of them
write it unsynchronized". It needs three facts the extractor now records per
handler: which members it **reads**, which it **writes**, and which **lock**
members it takes.

Four access patterns are safe and are not reported:

* only one thread reaches the member;
* every access is a read;
* every accessor is a guarded port, serialized by the component mutex;
* every accessor takes a common lock member — a component that protects its own
  state with an explicit `Os::Mutex` is synchronized just as well, and without
  this the check reports every member such a component owns.

What remains is split by shape. Two unsynchronized writers on different threads
is a warning: the writes interleave and one can be lost. A single writer with
readers elsewhere is informational: a reader can see a stale or partial value,
but the writes cannot lose each other.

The evidence lists every accessing handler, its dispatch kind, whether it reads
or writes, and the threads that reach it — so the answer is auditable rather
than a verdict.

### `component_call_graph.py` — C++ handler → output port resolution

Builds a member-function call graph from `compile_commands.json` and computes,
for each handler, the transitive closure of what it calls and which output ports
those functions invoke:

```
bufferSendIn_handler
  -> BufferManager::returnBuffer                    (private helper)
    -> BufferManagerComponentBase::bufferDeallocate_out
      -> m_bufferDeallocate_OutputPort              (port invocation)
```

A port invocation is recognized from the generated `m_<port>_OutputPort` member
and from `<port>_out` invoker names, so telemetry, event, parameter and time
helpers resolve through the same closure without special-casing.

```bash
pip install libclang
python3 component_call_graph.py \
    --compile-commands build/compile_commands.json \
    --exclude '/test/' --output flow.json
```

**Strictness.** A handler containing a call libclang cannot resolve (through a
function pointer or a delegate) is marked `opaque`. Any unresolved handler —
opaque, absent, or a component missing from the flow map — is a **hard error**.
The analyses refuse to run rather than assume the handler calls every output
port.

That assumption is sound in the formal sense, but on a real deployment it makes
nearly every guarded component appear to reach nearly every other, so real
defects drown. Refusing to guess is the honest answer: it says the C++ analysis
did not cover this code, rather than printing a result built on a guess.

`--permissive` opts into the over-approximation deliberately. It is useful for a
worst-case sweep, not for reporting findings.

Note the consequence: **the flow map must cover every component in the
topology.** A deployment analysis needs the whole deployment compiled into
`compile_commands.json`.

A compilation database describes the whole project, while a deployment build
only autocodes the modules that deployment links. Sources for the rest are
listed and never generated, and implementation files that include their missing
generated header fail the same way. The extractor recognizes both and reports
them as skipped rather than as failures — they are components the deployment
does not instantiate. If one of them *is* instantiated, it will simply be absent
from the flow map, and strict mode names it.

### `port_flow.py` — the shared engine

Loads the flow map and answers one question for both analyses: *given component
C entered at handler P, which output ports can be invoked?* Sharing it means the
deadlock analysis and the priority analysis cannot disagree about what a handler
can reach, or about what "async" means.

### `topology_graph.py` — the tagged graph

One graph per topology, with every port tagged sync, guarded, or async, and
every traversal in the package going through `outward_hops` so no two analyses
can disagree about what "the calls out of a handler" means, or see them in a
different order.

### `cli.py` — shared entry-point plumbing

Every analyzer takes the same route to a graph: a directory of `fpp-to-json`
output, a flow map, one `TopologyGraph`, then findings and an exit code. That
half lives here so the three CLIs cannot drift apart on the flags a user has to
remember, on what happens when a flow map is missing, or on what an unresolved
handler is allowed to mean.

### Related: `priority_buffer_analyzer.py` (lives in fprime, not here)

fprime's own `cmake/autocoder/scripts/priority_buffer_analyzer.py` generates
`PriorityBufferSizes.hpp` for `Os::Generic::PriorityMemQueue`. It is
intra-component by construction — it sizes each priority level from the
component's own async ports and commands — so it needs no flow map and stays
where it is. See `Os/Generic/docs/sdd.md`.

## Blocking sends

A `queue full block` port blocks the sender inside the enqueue until the
receiver drains, so it is not really a thread boundary. Every analysis here
still treats it as an ordinary async hop — the chain ends and the caller's locks
are considered released. The graph warns when it sees one, so a topology relying
on blocking sends is not silently analyzed under an assumption that does not
hold for it. A circular wait through two blocking sends is therefore **not**
detected.

## What is deliberately not modeled

* **`m_paramLock`.** The generated code releases the parameter mutex before
  every output port call, so it is a leaf lock and cannot join a cross-component
  cycle. (It *is* held across calls into a user-supplied external-parameter
  delegate, which is C++ the topology does not describe.)
* **User-written threads and callbacks.** Only F´ port calls are followed.
* **Runtime guards.** A handler that calls a port only under a condition the
  analysis cannot evaluate is treated as though it always does. This is why
  `unconnected-port-invoked` reports a warning rather than a claim: a
  data-condition guard — a flag only set when a feature is wired — is a common
  and legitimate reason for a reachable path never to be taken.
* **Run-time port routing.** A dispatcher's port array reaches every component,
  but one opcode routes to exactly one of them. Counts through a wide port array
  are upper bounds, which is why `queue-overflow` excludes them from its error
  tier.

## Suppressions

Both analyzers accept a suppression file for orderings enforced outside the
topology. Each entry hides a real edge, so keep them commented:

```
# fileUplink always takes bufferManager before tlmChan; enforced by review
myDeployment.fileUplink -> myDeployment.tlmChan
```

## Tests

```bash
pip install -e '.[test]'
FPRIME_ROOT=/path/to/fprime python3 -m pytest
```

`FPRIME_ROOT` is optional when an `fprime/` submodule is present.

The suite covers synthetic topologies that pin down one dispatch rule at a
time, topologies built from **real F´ components** (`Svc.TlmChan`,
`Svc.BufferManager`, `Svc.EventManager`), the C++ extractor, an end-to-end case
where the flow map removes a false positive the topology alone reports, and
report rendering — including that two runs over one topology produce the same
bytes, which is what makes a checked-in baseline diffable — and the CLI paths a
user hits when something is wrong. Tests skip themselves when the FPP tool chain
or `libclang` is unavailable.

Lint settings live in `pyproject.toml`; the package is kept clean against them,
so `ruff check .` should pass before a push.
