# dlfreeze

Bundle a 64-bit Linux ELF program into one executable.  Dynamically linked
targets include their ELF interpreter and shared-library dependency graph;
fully static targets are preserved as a one-entry extraction artifact.

`dlfreeze` prefers its experimental in-process loader by default and retains
extraction through an ELF interpreter as a compatibility fallback. Use `-x`
to force extraction instead. Dynamic libraries and data discovered only at
runtime must be traced for self-containment; otherwise loading may fail or
fall back to files on the host.

The implementation is application-agnostic. It does not select behavior from
an executable name or contain Python-, Ruby-, Zig-, or OpenSSL-specific loader
paths. Those programs appear in the tests only as broad compatibility probes;
the strict direct-loader contract is exercised by generic C fixtures.

## Support scope

| Area | Supported contract |
|---|---|
| Architecture | Little-endian ELF64 x86_64 and AArch64; source and target must match |
| Default direct preference | Emits direct-loader metadata for target-validated musl 1.2.2–1.2.6 and admitted glibc 2.34–2.44 shapes with an SSP-disabled static bootstrap capability; static musl and static glibc are the tested bootstrap implementations. Other targets and unvalidated startup entry points retain extraction only when the manifest permits it |
| Forced extraction (`-x`) | Bundles the interpreter and libraries without direct metadata; may use a byte-identical installed interpreter, otherwise invokes the bundled copy when that loader family has a validated command-line ABI |
| Dependency-free alternate loaders | An unrecognized `PT_INTERP` is admitted only when both it and the main executable have no `DT_NEEDED` entries. It runs through the kernel and the original byte-identical interpreter pathname; dlfreeze never guesses how to invoke it as a command-line launcher |
| Fully static targets | ELF images with neither `PT_INTERP` nor `DT_NEEDED` are bundled without a libc-specific runtime contract and executed through the kernel extraction path |
| `dlopen()` dependencies | Capture with `-t` by exercising relevant paths; uncaptured libraries may use an explicit host-disk fallback |
| Runtime data | Capture selected paths with `-t -f`; captured-file artifacts are direct-only and never use extraction fallback |

Direct loading is the preferred path, but depends on private libc details and
should be treated as experimental even on the tested runtimes. Extraction is
the compatibility path and can be selected explicitly with `-x`.
Glibc releases older than 2.34 remain recognizable for dependency resolution
and extraction compatibility, but are not direct-loaded because their private
rtld/GLRO and x86 CPU-feature layouts predate the validated direct contract.
AArch64 payloads are aligned for kernels with pages up to 64 KiB, and direct
mode preserves `AT_PAGESZ`; native non-4-KiB testing is still recommended.
Portability means running the captured program/runtime on another compatible
Linux host of the same architecture, not emulating a different CPU or kernel.
The bundled code's instruction-set and syscall requirements still apply.
Capture optional library and data paths that the program will need: a host-disk
fallback is not a guarantee that a foreign host's libraries are ABI-compatible
with the bundled runtime. Cross-host CI replays the same generic direct
artifact, including constructor-time cold binding, after removing its source
library and data files.
The direct loader enforces segment permissions and GNU RELRO, validates and
uses both GNU and SysV dynamic symbol hashes, and resolves GNU symbol versions.
Its admitted-target regression suite covers preinit/init/fini, `atexit`,
signal, and glibc `fork()` lifecycle behavior; this is not a claim of private
ABI compatibility beyond the admitted target shapes. Separate `dlmopen()`
namespaces and runtime unloading on
`dlclose()` are not implemented, so mapped objects remain resident. Glibc
thread teardown reclaims loader-owned dynamic TLS with that target glibc's
generation-appropriate allocator ABI; loader-owned late musl TLS storage
currently remains resident until process exit. A loader-owned recursive lock
serializes runtime graph/TLS publication with concurrent `dlopen()`, `dlsym()`,
`dlclose()`, `dladdr()`, `dladdr1()`, `dlinfo()`, `dl_iterate_phdr()`, and
unwind metadata readers; standard `fork()` handlers preserve a coherent
child-side snapshot. A child created by a raw fork syscall while an outer
loader operation owns that lock must unwind the inherited operation before
re-entering the loader; an earlier nested re-entry fails closed because raw
syscalls bypass the registered atfork repair contract.
Constructors run after graph/TLS publication. They reserve ordinary loader
operations while releasing the physical namespace lock for lazy symbol
binding, including first calls and IFUNC result publication from other
threads. Nested constructors and surviving fork callback stacks retain that
reservation. This does not make arbitrary cross-thread constructor cycles
safe: a constructor must still avoid waiting for another thread to finish a
competing `dlopen()` or other ordinary loader operation.
Loader-owned errno, finalization, pthread-key, atfork, allocation, and VFS
fallthrough services bind directly to complete, executable function definitions
in the structurally selected target libc. Executable or preload interposers
therefore affect ordinary application lookup, not the loader's private state.
Direct mode publishes only the static-TLS extent assigned to startup objects;
it does not advertise glibc's optional compatibility surplus. Traced
initial-exec closures are promoted into that startup extent, while a later load
which needs a new static offset is refused. The modern DTV `to_free`
interpretation remains private policy rather than public ABI, so direct
admission bounds it to the tested glibc 2.34–2.44 generations; a later
generation is refused until its target contract is validated.
Direct metadata is bounded to 512 ELF objects (including dormant traced
objects) and is rejected before loading when that explicit resource contract
would be exceeded.
The direct loader exposes one coherent namespace for the objects it maps. It
does not add the kernel vDSO to that namespace, so the vDSO is absent from
`link_map`, `dl_iterate_phdr()`, `dladdr()`, and `_dl_find_object()` even though
the unchanged kernel `AT_SYSINFO_EHDR` entry remains available to libc.
Accordingly, an explicit bare-name `dlopen()` of `linux-vdso.so.1` or
`linux-gate.so.1` fails with `dlerror()` instead of returning an unrelated
global handle. A slash-containing ELF path with either basename remains an
ordinary file-backed `dlopen()` target. The loader's `dlinfo()` implementation
supports `RTLD_DI_LMID`, `RTLD_DI_LINKMAP`,
`RTLD_DI_TLS_MODID`, `RTLD_DI_TLS_DATA`, and `RTLD_DI_PHDR`; other requests fail
with `dlerror()` rather than consuming a private loader handle as a native
`link_map`. A target that reaches glibc's separate private
`RTLD_DI_SERINFO` hook is terminated with status 127 because its opaque output
ABI cannot be completed safely.
Public loader and VFS replacement entry addresses are provider-virtualized for
`dladdr()` and `dladdr1()`: an exact public entry pointer reports the target
libc provider identity and a coherent synthetic symbol address. Only the exact
entry pointer has that semantic identity; other bootstrap PCs report the
introspection-only direct-loader ELF object which owns their unwind metadata
and remains outside target symbol lookup.
The direct loader honors `RTLD_LOCAL`, `RTLD_GLOBAL` promotion, and
`RTLD_NOLOAD` visibility checks. Musl's `RTLD_LAZY` contract is eager, so it is
replayed directly. On GNU runtimes, admitted startup PLT imports and runtime
`RTLD_LAZY` loads use the direct loader's architecture-specific lazy resolver.
This preserves first-call binding and GNU IFUNC timing and once-state for both
filesystem-loaded objects and traced dormant objects. A later `RTLD_NOW` open
preflights the complete remaining lazy closure before changing it; a failed
promotion leaves the existing lazy handle usable, and `RTLD_NOW` takes
precedence when both binding bits are supplied. Nonstandard PLT/GOT protocols
fail closed. A NOW promotion which races an in-flight lazy IFUNC on another
thread also fails coherently instead of waiting while holding the loader lock.
A failed traced loader call still selects extraction because it supplies no
successful object identity to replay. A runtime-only early refusal can use the
explicit supervised fallback described below; ordinary direct execution
refuses it before target code runs.
`RTLD_NODELETE` is implicit. Unknown mode bits and `RTLD_DEEPBIND` fail closed.
Glibc also has a separate private module-loader interface used by facilities
such as external gconv converters and NSS backends. Direct mode does not create
per-module private `link_map` or symbol-lookup structures, nor use synthetic
maps as public loader handles. It does allocate one zero-filled synthetic
base-namespace lifetime token: admitted target startup must prove its
namespace-head access, and the target's TLS-destructor paths must independently
identify the counter they update in that token. On exact admitted glibc
2.34–2.44 layouts direct mode installs glibc's complete static-loader hook ABI,
whose handles are explicitly opaque, and routes those internal operations
through the same loader as public `dlopen()`. Every hook-pointer offset is
release- and layout-specific.
Admission validates the target's full 13-slot hook contract: exported public
consumers must load the exact `_rtld_global_ro` slot and hidden libc entry points
must dispatch through the corresponding internal members. Release and object
size alone are not accepted as layout evidence; an unvalidated layout is
refused.
The same rule applies to the other synthetic rtld state: size/release tuples
only nominate candidate offsets. The embedded target must independently prove
each written field through its relocations, exported consumers, or public
`libthread_db` descriptors. The zero-filled lifetime token and the explicitly
bounded DTV word interpretation above are narrow private-policy exceptions;
distribution names and host-libc layouts are not runtime selectors.
Detected pre-2.34 layouts have no equivalent complete hook and remain on the
extraction compatibility path. The remaining GLIBC_PRIVATE exception
entries are error-only guards: they preserve the target calling convention
but terminate without reading or writing glibc's opaque `dl_exception` record
or invoking a callback outside the real interpreter's exception region.
Glibc-internal opens bypass the preload tracer, so their libraries are not
made self-contained by `-t`; an uncaptured module can still use the documented
host-disk fallback below.
Glibc's tunable IDs and value widths are likewise private. For an empty
tunables environment, direct mode obtains compiled scalar defaults through
the exact target interpreter's ABI-compatible accessors against a separately
mapped interpreter data image; it does not guess IDs or write a fixed-width
value. The isolated image admits only bounded self-contained accessor control
flow and explicitly validates every relocation; an unfamiliar accessor or
relocation selects native extraction. Runtime admission also requires the
embedded libc's stable release identity to match the admitted interpreter.
A supported x86-64 glibc target also has to prove its private CPU-feature
object from the exact interpreter: the exported accessor, its initialization
wrapper, the initializer's field writes, and the control-flow roots of its
generic CPU-kind value must all agree. In a bounded copy-on-write clone, the
loader runs that exact target wrapper and initializer, validates their result,
then publishes the complete target-computed scalar CPU object, cache values,
HWCAP state, and ISA level only if the parent mapping remained unchanged. An
unfamiliar compiler shape, layout, or initializer result is refused rather
than guessed. This private libc ABI remains one reason that direct loading is
experimental.
A nonempty `GLIBC_TUNABLES` selects native extraction because reproducing the
interpreter's parsing, security, and CPU policy would require its private
initialization machinery. Glibc gmon profiling (including GCC `-pg`) also
selects native extraction when possible: its cleanup path walks the native
loader's hidden `link_map` namespace, which is intentionally not fabricated
by the direct loader. A DSO whose version metadata binds that lifecycle to
`libc.so.6`, found by an uncaptured runtime `dlopen()`, is rejected before
relocation or constructors. Likewise, `dlsym()`/`dlvsym()` refuses
`__monstartup` or `_mcleanup` only when ordinary ELF lookup actually selects
the embedded libc definition. A program or plugin may provide unrelated
same-named functions, and those retain normal interposition semantics;
ordinary weak `__gmon_start__` references are also unaffected.
Direct admission likewise refuses nonempty `LD_PRELOAD` and `LD_AUDIT`, a
nonempty glibc system preload file, and glibc loader-control variables that
would change binding, diagnostics, profiling, CPU selection, or loader policy
(including `LD_BIND_NOW`, `LD_DYNAMIC_WEAK`, `LD_HWCAP_MASK`, `LD_PROFILE`,
and `LD_DEBUG`). Public `dlopen()` does not expand dynamic string tokens: a
requested filename containing `$` fails with `dlerror()` instead of being
interpreted or silently treated as a literal path. If a native traced run
successfully uses `dlopen()` mode bits that direct mode cannot replay (such as
`RTLD_DEEPBIND`), tracing fails closed instead of publishing a divergent
artifact.
For an uncaptured bare-name `dlopen()` on a GNU-family runtime, host-disk
search follows caller/loader `DT_RPATH` ancestry, `LD_LIBRARY_PATH`, the
caller's `DT_RUNPATH`, and the target interpreter's validated compiled cache
path. The cache and system-preload path are derived from unique absolute
strings in the structurally admitted interpreter, so custom glibc
`SYSCONFDIR` builds do not silently inherit the bootstrap host's `/etc`. The
loader does not
guess Debian, Fedora, or generic `/lib*` directories. It accepts bounded
legacy, old/new compatibility, and version-1.1 caches, reproduces the target
glibc release's GNU ABI-tag behavior (kernel-minimum checks through glibc 2.35,
and the later releases' intentional omission), and supports the built-in
x86-64 v2/v3/v4 hwcaps names. A missing or malformed cache, a cache miss which
would require glibc's private compiled default-directory table, and a
`DF_1_NODEFLIB` cache result whose system-directory status cannot be proven
fail closed. Trace such loads with `-t` when portability or self-containment
matters.
Pack-time GNU `DT_NEEDED` resolution uses the same RPATH/environment/RUNPATH
ordering and reads the binary cache directly; it never invokes `ldconfig` or
parses its localized output. It accepts bounded legacy, compatibility, and
version-1.1 cache images, selects an exact-architecture generic entry, applies
the target glibc release's GNU ABI-tag semantics, and validates the resulting
ELF. A malformed or missing cache, a validated cache miss, and an
unclassifiable `DF_1_NODEFLIB` request fail closed. This deliberately avoids
copying glibc's evolving CPU/tunable policy or inferring its private compiled
default-directory table.
Direct mode retains the kernel-created main-thread stack rather than
fabricating a second mapping after constructors have run. It validates the
original `argc`/`argv`/`envp` relationship, rewrites the existing required
auxiliary-vector slots in place before target libc initialization, and restores
that same initial stack pointer at the executable entry. Constructors,
`getauxval()`, `pthread_getattr_np()`, and `main` therefore observe one stack
and one target-image auxiliary vector with the kernel's original guard and
`RLIMIT_STACK` semantics. GNU direct mode reports `AT_BASE` as zero because it
does not map the native ELF interpreter; that observable value is part of the
experimental direct-mode contract.
Target ELF objects are prelinked into deterministic virtual-address slots and
reserved at runtime with `MAP_FIXED_NOREPLACE`. Address collisions therefore
fail closed, but the target executable and DSOs do not receive normal
per-execution ASLR. Do not treat direct-mode artifacts as hardened executables.
Prelinked objects retain extraction-safe relocation bytes: RELR is replayed at
runtime, while only explicit-addend, file-backed RELA relative results may be
persisted. Direct artifacts enter the loader in the original process by
default, preserving the caller-assigned PID and process-associated state which
survives `execve()` but not `fork()`, including POSIX record-lock ownership.
Setting `DLFREEZE_SUPERVISED_FALLBACK=1` explicitly opts a clean,
extraction-representable artifact into a speculative child attempt: an early
loader refusal may then retry through extraction. This changes process identity
and leaves inherited POSIX record locks owned by the supervisor rather than the
application child. `DLFREEZE_NO_FORK=1` overrides that opt-in and also disables
the bootstrap's disposable startup page-transfer proof; direct mode then uses
its portable anonymous-copy path without making either optional bootstrap
`clone`/`wait4` boundary. This setting does not suppress a process-isolated
probe which a validated target runtime itself requires: GNU x86-64 direct
startup currently computes the target `ld.so` CPU-feature state in a contained
clone before invoking target code. Inherited seccomp policies must therefore
allow that required target-runtime probe or return an ordinary error; a policy
which kills or traps it cannot be recovered in-process. The supervisor never
retries after target resolvers or other target code can run.
Captured-DATA manifests and exact pathful or otherwise unreproducible
dynamic-load identities remain direct-only and ignore the supervisor opt-in.

For sufficiently large startup images, the existing disposable page-transfer
probe also checks an optional fork-detection page. When the kernel and
authenticated procfs confirm `MADV_WIPEONFORK` support, the runtime loader lock
uses the target's architectural thread pointer for ownership, avoiding a
`gettid` syscall on ordinary loader and VFS operations. This adds no probe
process. Small images, unavailable capabilities, and `DLFREEZE_NO_FORK=1`
retain kernel-TID ownership; the optimization is not required for direct
loading.

Captured files are served by the direct loader's in-process VFS. Consequently,
`-f` requires `-t`, is incompatible with forced extraction (`-x`), and packing
fails if the target runtime cannot be loaded directly. The bootstrap never
converts a captured-file artifact into an extraction-mode run. Serving a
captured regular file with genuine read-only or `O_PATH` descriptor semantics
normally reopens its sealed memfd through `/proc/self/fd`. When memfd, sealing,
or that procfs reopen is unavailable for a recognized capability reason, the
loader instead creates a collision-resistant file in its immutable startup
temporary-directory set, reopens and validates an independent descriptor, and
unlinks the name while its private construction descriptor is still open.
Executable backing is accepted only after an actual executable mapping probe;
descriptor or integrity mismatches still fail closed. Captured regular files
retain their validated mtime and ctime, and libc `stat`, `fstat`, and
`fstatat(..., AT_EMPTY_PATH)` observe the same immutable metadata across
loader-interposed descriptor duplication and close operations. As with the
other captured-file hooks, raw syscalls and `statx` are outside this
interposition contract. An ordinary child program
started with `exec` does not
inherit this VFS: dlfreeze does not materialize captured compiler/linker inputs
under `/tmp` or inject paths into `LIBRARY_PATH`. Likewise, `/proc/self/exe` is
not rewritten to the freeze-time source path; `readlink()` observes the identity
reported by the kernel for the currently executing artifact.

Tracing is implemented by a target-ABI-compatible `LD_PRELOAD` helper and
observes the libc interfaces that it interposes. Each trace stream is claimed
by one process image. Fork descendants inherit that claim and write
PID-tagged records; a fork-and-exec descendant is deliberately excluded
because neither the direct namespace nor the captured-file VFS survives
`exec`. A same-PID `exec` invalidates the trace, and collection refuses a
stream still owned by a live descendant instead of racing an append.
If a loader callback reaches an interposer before libc has published
`environ`, the helper reads the inherited trace contract from
`/proc/self/environ` with raw syscalls. Failure to read that initial contract
makes the trace incomplete rather than silently dropping the early operation.
Successful dynamic-load and captured-file records bind the observed path to
its device, inode, type, size, mtime, and ctime, which are revalidated before
packing. There is no portable way for the helper to obtain the loader's
private file descriptor, so a narrow race remains between the loader's open
and the helper's post-return pathname snapshot. Later changes fail closed.
Trace-descriptor mutations through `close`, `dup`, `dup2`, `dup3`,
`close_range`, and `closefrom` are bracketed by begin/commit records. The
helper rehomes its private descriptors before calling a downstream interposer
and never holds its descriptor lock across that call. A destructive range is
forwarded exactly once when a private descriptor can be moved outside it. For
the common range that covers every non-stdio descriptor, no such number
exists; `close_range` is then issued as raw segments around the private
descriptors, and `closefrom` is implemented equivalently. This preserves
traceability but is observable to seccomp policies or lower interposers that
distinguish the original range from its segments. `CLOSE_RANGE_UNSHARE`
cannot share one process-global trace publication across the resulting fd
tables and therefore makes the trace unusable while retaining the native
call. A failed segment likewise invalidates the trace because earlier
segments may already have changed the descriptor table.
The helper cannot observe raw syscalls which bypass an interposed libc entry
point, including `openat`, `openat2`, `statx`, and descriptor mutations.
Likewise, `fcntl(F_DUPFD*)` is not interposed, so code which deliberately
discovers and duplicates a private trace descriptor can escape the descriptor
transaction protocol. A program can also remove the preload/trace environment
or access a path outside the exercised run. Treat these cases as coverage
limitations rather than an implicit promise of self-containment; closing them
requires a ptrace-, seccomp-, or audit-level tracer.
The captured-file VFS serves a followed symlink's contents under the traced
request path; it does not reproduce the symlink object for `lstat()` or
`readlink()`. Synthetic captured-directory descriptors are intended for
enumeration and relative lookups. Their identity is propagated through
`dup()`, `dup2()`, `dup3()`, and `fcntl(F_DUPFD*)`; `fchdir()` and descriptor
metadata are not yet virtualized and can expose host working-directory or
descriptor behavior. Avoid those operations in captured-directory workloads.
Extraction uses a securely admitted private directory below `TMPDIR`, with an
equally checked `/tmp` fallback; the selected path must permit both file
creation and execution. The directory remains available while the supervised
target is running and is removed afterward, so extraction mode is not intended
for targets that daemonize descendants which outlive the target.
When no byte-identical system interpreter is available, invoking the bundled
interpreter is necessarily observable through `argv[0]` and `/proc/self/exe`.
That fallback is limited to recognized loader families. An unrecognized,
dependency-free interpreter has no generic command-line ABI, so its artifact
fails closed if the original `PT_INTERP` pathname is missing, non-executable,
or no longer byte-identical. The runtime compares stable file revisions, but
Linux resolves the literal interpreter pathname again during `execve()`; a
writer able to replace that pathname retains the same final pathname race as
an ordinary execution of the original program.
Artifacts fail closed when the kernel reports `AT_SECURE` (for example after a
set-user-ID or set-group-ID transition). Extraction depends on loader
environment controls that secure execution ignores, and the direct loader does
not claim the native runtime's privileged-execution contract.

## Quick start

```bash
make
```

Freeze `ls`:

```bash
./build/dlfreeze -o ls.frozen /bin/ls
./ls.frozen -la /etc
```

Freeze an application while tracing runtime-loaded libraries and selected
resource files:

```bash
./build/dlfreeze -t -f '/usr/share/myapp/*' -o myapp.frozen -- myapp --self-test
./myapp.frozen --self-test
```

Interactive targets inherit dlfreeze's controlling terminal during tracing.
Exercise the interactive path, then exit it normally so packing can finish.
For example, this captures the Python standard-library files and extension
modules used to start a REPL, without any Python-specific loader behavior:

```bash
stdlib=$(python3 -I -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
./build/dlfreeze -t -f "$stdlib/*" -o python-repl.frozen -- python3 -I -q
# A trace-time prompt appears here. Exit it after exercising desired paths.
./python-repl.frozen -I -q
```

## How it works

1. **Dependency resolution** — For interpreter-bearing targets, a BFS walk over `DT_NEEDED` entries applies ABI validation, content-based target-libc identification, bounded GNU legacy/compatibility/version-1.1 cache lookup, exact musl prefix/path-file replacement semantics, and target-specific `$ORIGIN`/`DT_RPATH`/`DT_RUNPATH` ordering. A fully static target has an empty closure. An unknown interpreter is extraction-only and admitted solely when both it and the main executable have empty `DT_NEEDED` closures, so no unknown search policy is inferred. No distribution library directories are guessed; missing or incompatible required libraries, cache misses that require private GNU defaults, and other unknown loader search ABIs are fatal.
2. **Dynamic-load tracing** (`-t`) — Runs the program under an `LD_PRELOAD` shim that records successful and failed `dlopen()`/`dlmopen()` calls, including their modes and resolved object identities.
3. **Packing** — Concatenates the statically-linked bootstrap stub, every collected object (page-aligned), a string table, a manifest, and a 64-byte footer (`DLFREEZ` magic) into a single ELF.
4. **Runtime — direct load (default)** — For admitted glibc 2.34–2.44 and target-validated musl 1.2.2–1.2.6 shapes, the bootstrap invokes an in-process ELF loader in the original process; it maps segments, resolves relocations, builds runtime state, and serves captured DATA. An extraction-representable manifest uses early runtime fallback only when `DLFREEZE_SUPERVISED_FALLBACK=1` explicitly enables the speculative supervisor, and never retries after target code runs.
5. **Runtime — extraction compatibility** (`-x`, a fully static target, or an unsupported default target) — The bootstrap extracts files to a private tmpdir. It executes a static target directly, uses normal kernel `PT_INTERP` startup when the installed interpreter is byte-identical, and otherwise invokes a recognized bundled interpreter. A dependency-free unknown interpreter requires the byte-identical original path and is never invoked through a guessed loader CLI. Captured DATA and path identities which extraction cannot reproduce remain direct-only.

The bootstrap and direct loader are copied into each frozen executable when it
is packed. Rebuilding `dlfreeze` does not update existing artifacts; regenerate
an artifact to pick up loader fixes and startup-performance improvements.

The artifact format exposes a generic mapped-payload ABI for post-link tools:
the payload lives in a `PT_LOAD` segment, and a `DLFRZLDR` descriptor in
`.data` lets the bootstrap find it in memory when the footer is no longer at
EOF. UPX is one tested consumer of that ABI; the runtime does not select a
code path by compressor name.

## Usage

```
dlfreeze [options] [--] <executable> [args...]

Options:
  -o <path>   Output file  (default: <name>.frozen)
  -d          Prefer direct-load mode (the default)
  -x          Force extraction mode instead of direct loading
  -t          Trace runtime loading by running the program (TTY preserved)
  -f <glob>   Embed data files matching glob (requires -t, repeatable)
  -v          Verbose
  -h          Help
```

When `-t` is used, `[args...]` are passed to the traced run so the program
exercises the code paths that trigger `dlopen()` and resource access. The
traced process remains in the foreground terminal process group, so prompts,
line editing, Ctrl-C, and shell stop/continue job control retain their normal
semantics.

## Building

Requires Linux, a compiler capable of producing static executables, and
`readelf` or `llvm-readelf` to verify the bootstrap's final GNU properties.
`musl-gcc` remains preferred for a smaller bootstrap, while a static system
glibc compiler is supported as well. Automatic `musl-gcc` selection requires
its target architecture to match `CC`; cross builds can set `STATIC_CC`
explicitly. After target TLS is installed, the
direct loader uses raw architecture syscalls and loader-owned memory/string
primitives, and publishes exposed errno results through the target libc rather
than re-entering bootstrap TLS.

```bash
make            # also builds native- and static-bootstrap-ABI preload helpers
make test       # runs the suite; direct cases are strict (no hidden extraction fallback)
make bench      # startup benchmarks (requires perf)
make clean
```

The CI-like Docker matrix can be run locally without modifying the worktree;
it copies the source from a read-only mount into each container. It can also
target one environment while iterating on a failure:

```bash
tests/local-cross-matrix.sh --arch amd64 --env ubuntu-20.04
tests/local-cross-matrix.sh --arch arm64 --env alpine-3.20
```

The manual GitHub Actions workflow accepts the same architecture/environment
filter and can additionally run one exact test-function range. Setting both
selectors to the same function is useful for reproducing a CI-only failure
without launching the complete suite:

```bash
gh workflow run cross-platform.yml \
  -f architecture=arm64 \
  -f environment=ubuntu-24.04 \
  -f test_start_at=test_direct_dlopen_embedded_static_tls \
  -f test_stop_after=test_direct_dlopen_embedded_static_tls
```

Partial shards report their own pass/skip/fail result without requiring an
unrelated aggregate direct-artifact count; direct-load tests still verify
their individual artifacts strictly. An explicitly selected first-to-last
range remains a full suite and retains the aggregate direct-coverage check.

The benchmark harness can opt into larger traced runtime workloads when they
are installed:

```bash
BENCH_CASES=python-imports make bench
BENCH_CASES=python-numpy make bench
```

## Disclaimer

The majority of code for this project was written by LLMs. Although I've read through the code to make sure there's nothing obviously stupid, do not use this project in a production or security-sensitive environment without vetting it yourself.

## License

This project is licensed under the [GNU Lesser General Public License version 3](LICENSE).
