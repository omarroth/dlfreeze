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

Direct loading grows its relocation-definition cache on demand for large
dependency graphs, up to 524,288 cached requester/symbol bindings. Small
programs keep the initial fixed-size table; total cache storage is bounded to
less than 48 MiB even at maximum growth. Allocation failure falls back to
normal symbol lookup; cache growth does not change symbol-version, scope,
IFUNC, or writable-metadata semantics.

## Disclaimer

The majority of code for this project was written by LLMs. Although I've read through the code to make sure there's nothing obviously stupid, do not use this project in a production or security-sensitive environment without vetting it yourself.

## License

This project is licensed under the [GNU Lesser General Public License version 3](LICENSE).
