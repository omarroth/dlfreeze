# dlfreeze

Bundle a dynamically linked 64-bit Linux program, its ELF interpreter, and its
shared-library dependency graph into one executable.

`dlfreeze` provides two runtime strategies: extraction through an ELF
interpreter (the default) and an experimental in-process loader (`-d`). Dynamic
libraries and data discovered only at runtime must be traced for
self-containment; otherwise loading may fail or fall back to files on the host.

The implementation is application-agnostic. It does not select behavior from
an executable name or contain Python-, Ruby-, Zig-, or OpenSSL-specific loader
paths. Those programs appear in the tests only as broad compatibility probes;
the strict direct-loader contract is exercised by generic C fixtures.

## Support scope

| Area | Supported contract |
|---|---|
| Architecture | ELF64 x86_64 and AArch64; source and target must match |
| Default extraction | Bundles the interpreter and libraries when no runtime DATA is captured; may use a byte-identical installed interpreter, otherwise invokes the bundled copy |
| Direct load (`-d`) | Target-validated musl 1.2.2–1.2.6 and admitted glibc 2.34–2.44 shapes with an SSP-disabled static bootstrap capability; static musl and static glibc are the tested bootstrap implementations. Other targets and unvalidated startup entry points use extraction only when the artifact has no captured DATA |
| `dlopen()` dependencies | Capture with `-t` by exercising relevant paths; uncaptured libraries may use an explicit host-disk fallback |
| Runtime data | Capture selected paths with `-d -t -f`; captured-file artifacts are direct-only and never use extraction fallback |

Extraction is the compatibility path. Direct loading depends on private libc
details and should be treated as experimental even on the tested runtimes.
Glibc releases older than 2.34 remain recognizable for dependency resolution
and extraction compatibility, but are not direct-loaded because their private
rtld/GLRO and x86 CPU-feature layouts predate the validated direct contract.
AArch64 payloads are aligned for kernels with pages up to 64 KiB, and direct
mode preserves `AT_PAGESZ`; native non-4-KiB testing is still recommended.
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
child-side snapshot.
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
The direct loader honors `RTLD_LOCAL`, `RTLD_GLOBAL` promotion, and
`RTLD_NOLOAD` visibility checks. It accepts `RTLD_LAZY` for compatibility
(including together with `RTLD_NOW`, which takes precedence) but resolves
relocations eagerly; `RTLD_NODELETE` is therefore implicit. Unknown mode bits
and `RTLD_DEEPBIND` fail closed.
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
generic CPU-kind value must all agree. The loader publishes a conservative
generic feature state and derives cache thresholds and separately exposed ISA
levels from the executing machine's CPUID/XCR0 state. An unfamiliar compiler
shape or layout is refused rather than guessed. This private libc ABI remains
one reason that direct loading is experimental.
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
legacy, old/new compatibility, and version-1.1 caches, checks any GNU ABI-tag
kernel minimum against a raw `uname(2)` result, and supports the built-in
x86-64 v2/v3/v4 hwcaps names. A missing or malformed cache, a cache miss which would
require glibc's private compiled default-directory table, and a
`DF_1_NODEFLIB` cache result whose system-directory status cannot be proven
fail closed. Trace such loads with `-t` when portability or self-containment
matters.
Pack-time GNU `DT_NEEDED` resolution uses the same RPATH/environment/RUNPATH
ordering and reads the binary cache directly; it never invokes `ldconfig` or
parses its localized output. It accepts bounded legacy, compatibility, and
version-1.1 cache images, selects an exact-architecture generic entry, checks
any GNU ABI-tag kernel minimum against `uname(2)`, and validates the resulting
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
`RLIMIT_STACK` semantics.
Target ELF objects are prelinked into deterministic virtual-address slots and
reserved at runtime with `MAP_FIXED_NOREPLACE`. Address collisions therefore
fail closed, but the target executable and DSOs do not receive normal
per-execution ASLR. Do not treat direct-mode artifacts as hardened executables.
Prelinked artifacts, captured-DATA manifests, and exact pathful dynamic-load
manifests cannot use extraction fallback, so their direct loader enters in the
original process and preserves the caller-assigned PID. A clean
runtime-relocation artifact remains supervised until application handoff so an
early loader refusal can still select extraction; after handoff it is never
retried.

Captured files are served by the direct loader's in-process VFS. Consequently,
`-f` requires both `-t` and `-d`, and packing fails if the target runtime cannot
be loaded directly. The bootstrap never converts a captured-file artifact into
an extraction-mode run. Serving a captured regular file with genuine
read-only or `O_PATH` descriptor semantics requires reopening its sealed memfd
through `/proc/self/fd`; the open fails closed if procfs is unavailable rather
than exposing the writable construction descriptor. An ordinary child program
started with `exec` does not
inherit this VFS: dlfreeze does not materialize captured compiler/linker inputs
under `/tmp` or inject paths into `LIBRARY_PATH`. Likewise, `/proc/self/exe` is
not rewritten to the freeze-time source path; `readlink()` observes the identity
reported by the kernel for the currently executing artifact.

Tracing is implemented by a target-ABI-compatible `LD_PRELOAD` helper and
observes the libc interfaces that it interposes. It cannot observe a program
that bypasses libc with raw `openat`, `openat2`, or `statx` system calls, and it
captures only paths exercised by the traced run. Treat either case as an input
coverage limitation rather than an implicit promise of self-containment.
An exec'd program can also deliberately remove the preload/trace environment,
and a daemonized descendant can outlive the supervised trace and race trace
collection; neither case can be made complete without a ptrace-, seccomp-, or
audit-level tracer.
The captured-file VFS serves a followed symlink's contents under the traced
request path; it does not reproduce the symlink object for `lstat()` or
`readlink()`. Synthetic captured-directory descriptors are intended for
enumeration and relative lookups. Descriptor duplication, `fchdir()`, and
descriptor metadata are not yet virtualized and can expose host descriptor or
working-directory behavior; avoid those operations in captured-directory
workloads.
Extraction uses a private directory under `/tmp`; that path must permit both
file creation and execution. The directory remains available while the
supervised target is running and is removed afterward, so extraction mode is
not intended for targets that daemonize descendants which outlive the target.
When no byte-identical system interpreter is available, invoking the bundled
interpreter is necessarily observable through `argv[0]` and `/proc/self/exe`.
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
./build/dlfreeze -d -t -f '/usr/share/myapp/*' -o myapp.frozen -- myapp --self-test
./myapp.frozen --self-test
```

Interactive targets inherit dlfreeze's controlling terminal during tracing.
Exercise the interactive path, then exit it normally so packing can finish.
For example, this captures the Python standard-library files and extension
modules used to start a REPL, without any Python-specific loader behavior:

```bash
stdlib=$(python3 -I -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
./build/dlfreeze -d -t -f "$stdlib/*" -o python-repl.frozen -- python3 -I -q
# A trace-time prompt appears here. Exit it after exercising desired paths.
./python-repl.frozen -I -q
```

## How it works

1. **Dependency resolution** — BFS walk over `DT_NEEDED` entries, with ABI validation, content-based target-libc identification, bounded GNU legacy/compatibility/version-1.1 cache lookup, exact musl prefix/path-file replacement semantics, and target-specific `$ORIGIN`/`DT_RPATH`/`DT_RUNPATH` ordering. No distribution library directories are guessed; missing or incompatible required libraries, cache misses that require private GNU defaults, and unknown loader search ABIs are fatal.
2. **dlopen tracing** (`-t`) — Runs the program under an `LD_PRELOAD` shim that intercepts `dlopen()` and records the resolved paths.
3. **Packing** — Concatenates the statically-linked bootstrap stub, every collected object (page-aligned), a string table, a manifest, and a 64-byte footer (`DLFREEZ` magic) into a single ELF.
4. **Runtime — extraction mode (default)** — For artifacts without captured DATA, the bootstrap extracts files to a tmpdir. It uses normal kernel `PT_INTERP` startup when the installed interpreter is byte-identical, otherwise it invokes the bundled interpreter.
5. **Runtime — direct-load mode** (`-d`) — For admitted glibc 2.34–2.44 and target-validated musl 1.2.2–1.2.6 shapes, the bootstrap invokes an in-process ELF loader that maps segments, resolves relocations, builds runtime state, and serves captured DATA. Unsupported runtimes use extraction only when no DATA was captured.

Frozen binaries are compatible with UPX and should mostly work with other packing tools: the payload lives in a `PT_LOAD` segment so compressors preserve it, and a `DLFRZLDR` sentinel in `.data` lets the bootstrap find the payload in virtual memory if the footer is no longer at EOF.

## Usage

```
dlfreeze [options] [--] <executable> [args...]

Options:
  -o <path>   Output file  (default: <name>.frozen)
  -d          Request experimental direct-load mode (required with -f)
  -t          Trace runtime loading by running the program (TTY preserved)
  -f <glob>   Embed data files matching glob (requires -d -t, repeatable)
  -v          Verbose
  -h          Help
```

When `-t` is used, `[args...]` are passed to the traced run so the program
exercises the code paths that trigger `dlopen()` and resource access. The
traced process remains in the foreground terminal process group, so prompts,
line editing, Ctrl-C, and shell stop/continue job control retain their normal
semantics.

## Building

Requires Linux and a compiler capable of producing static executables.
`musl-gcc` remains preferred for a smaller bootstrap, while a static system
glibc compiler is supported as well. Automatic `musl-gcc` selection requires
its target architecture to match `CC`; cross builds can set `STATIC_CC`
explicitly. After target TLS is installed, the
direct loader uses raw architecture syscalls and loader-owned memory/string
primitives, and publishes exposed errno results through the target libc rather
than re-entering bootstrap TLS.

```bash
make            # also builds native and alternate-libc preload helpers
make test       # runs the suite; -d cases are strict (no hidden extraction fallback)
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
