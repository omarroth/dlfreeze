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
the strict direct-loader contract is exercised by generic C fixtures. CI also
rejects application identities in production sources so compatibility fixes
must be expressed as ELF, libc, kernel, or traced-resource semantics.

## Quick start

On x86-64 or arm64 Linux, you can download the matching binary archive from
[GitHub Releases](https://github.com/omarroth/dlfreeze/releases) instead of
building from source. See [Installing and repackaging](#installing-and-repackaging)
for the archive layout.

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

To exercise separate command-line modes and merge their observed libraries,
files, missing-path results, and directory views into one artifact, create one
record per invocation and merge them when packing:

```bash
./build/dlfreeze -t -f '/usr/share/myapp/*' --record trace-a -- myapp --mode-a
./build/dlfreeze -t -f '/usr/share/myapp/*' --record trace-b -- myapp --mode-b
./build/dlfreeze --merge trace-a --merge trace-b -o myapp.frozen -- myapp
```

`--record` is record-only and does not produce a frozen executable. Each
record retains dlfreeze's descriptor-bound file observations and complete
`dlopen` transactions; it is intentionally not a wrapper around `strace`.
The executable, shared libraries, and regular resources must still be the
recorded revisions when `--merge` runs. Conflicting observations and changed
inputs fail closed. The resulting frozen executable remains self-contained;
the recording directories are build inputs only and are not a runtime cache.

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
2. **Dynamic-load and resource tracing** (`-t`) — Runs the program under an `LD_PRELOAD` shim that records successful and failed `dlopen()`/`dlmopen()` calls, including their modes and resolved object identities. With `-f`, parent-owned ptrace observation augments the shim at libc's syscall boundary so private, directly-bound opens are captured without application- or pathname-specific rules. Restricted kernels which deny ptrace retain the preload path and report the incomplete low-level coverage under `-v`.
3. **Packing** — Concatenates the statically-linked bootstrap stub, every collected object (page-aligned), a string table, a manifest, and a 64-byte footer (`DLFREEZ` magic) into a single ELF.
4. **Runtime — direct load (default)** — For admitted glibc 2.34–2.44 and target-validated musl 1.2.2–1.2.6 shapes, the bootstrap invokes an in-process ELF loader in the original process; it maps segments, resolves relocations, builds runtime state, and serves captured DATA. Validated libc open entry points, including directly-bound private aliases, are routed through the same manifest VFS before target constructors run. An extraction-representable manifest uses early runtime fallback only when `DLFREEZE_SUPERVISED_FALLBACK=1` explicitly enables the speculative supervisor, and never retries after target code runs.
5. **Runtime — extraction compatibility** (`-x`, a fully static target, or an unsupported default target) — The bootstrap extracts files to a private tmpdir. It executes a static target directly, uses normal kernel `PT_INTERP` startup when the installed interpreter is byte-identical, and otherwise invokes a recognized bundled interpreter. A dependency-free unknown interpreter requires the byte-identical original path and is never invoked through a guessed loader CLI. Captured DATA and path identities which extraction cannot reproduce remain direct-only.

The bootstrap and direct loader are copied into each frozen executable when it
is packed. Rebuilding `dlfreeze` does not update existing artifacts; regenerate
an artifact to pick up loader fixes and startup-performance improvements.

The artifact format exposes a generic mapped-payload ABI for post-link tools:
the payload lives in a `PT_LOAD` segment, and a `DLFRZLDR` descriptor in
`.data` lets the bootstrap find it in memory when the footer is no longer at
EOF. UPX is one tested consumer of that ABI; the runtime does not select a
code path by compressor name.

Direct loading supports the ELF `GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS`
contract used by newer toolchains. Protected data and function identities are
preserved; incompatible executable COPY relocations and legacy PLT-address
references are rejected before target resolvers run. Unknown needed-property
bits still require native-loader semantics. This does not relax the separate
trace admission policy for failed dynamic-loader calls.

## Usage

```
dlfreeze [options] [--] <executable> [args...]

Options:
  -o <path>   Output file  (default: <name>.frozen)
  -d          Prefer direct-load mode (the default)
  -x          Force extraction mode instead of direct loading
  -t          Trace runtime loading by running the program (TTY preserved)
  -f <glob>   Embed data files matching glob (requires -t, repeatable)
  --record <dir>  Trace one invocation into a reusable record directory
  --merge <dir>   Merge a trace record when packing (repeatable)
  -v          Verbose
  -h          Help
```

When `-t` is used, `[args...]` are passed to the traced run so the program
exercises the code paths that trigger `dlopen()` and resource access. The
traced process remains in the foreground terminal process group, so prompts,
line editing, Ctrl-C, and shell stop/continue job control retain their normal
semantics. A selected directory which the program enumerates retains its
selected immediate member names and `d_type` values. Unopened members remain
metadata-only directory entries; their contents are embedded only if the
trace opens or otherwise captures them. Shell quoting already protects `*`,
so use `-f '/usr/*'`, not `-f '/usr/\*'` (the latter matches a literal
asterisk).

Tracing belongs to one executable image. A command runner that replaces
itself with another program, such as `uvx`, cannot be frozen by naming the
runner: dlfreeze rejects the incomplete first-image trace. Prepare a stable
environment first, then name its final ELF interpreter or executable and
pass the script or module arguments directly. Trace-time arguments and
environment variables are not baked into the artifact; provide them again
when running it. This rule also applies to shell launchers and other wrappers.

`--record <dir>` requires `-t` and cannot be combined with `-o` or
`--merge`. `--merge <dir>` is repeatable and consumes completed records
without rerunning their commands; it cannot be combined with `-t` or `-f`.
All records in one merge must describe the exact executable revision being
packed. Regular source files are revision-checked again during the merge,
while recorded negative lookups must still be absent.

Direct tracing can retain verified missing absolute library roots as frozen
negative lookups. On supported x86_64 GNU libc layouts, a read-only witness
checks the unconsumed native loader error without calling `dlerror()`.
Replay preserves `errno` and thread-local, consume-once errors, formatting
messages through the embedded libc in the current locale. Unknown layouts,
denied inspection, missing dependencies, and other failure classes keep the
native-loader fallback; this is not an application-specific plugin rule.
Caller-scoped witnesses also retain bare-name misses and `RTLD_NOLOAD`
probes which return NULL without setting a loader error. Replay checks loaded
objects first, including captured inode aliases, then preserves the observed
probe result, `errno`, and consume-once diagnostic. Probe metadata is not a
captured filesystem path. Importing or packing a recording rechecks its caller
revision and search result; unknown failure classes still require native
semantics. New recordings use dlopen trace V10; completed V8/V9 recordings
remain readable.

A captured regular file and a dormant library can share their original ELF
payload when their exact source revisions match. Startup/prelinked sources
are excluded, so file reads never expose pre-applied relocation bytes.

## Installing and repackaging

GitHub CI builds `dlfreeze-linux-x86_64.tar.gz` and
`dlfreeze-linux-aarch64.tar.gz` with matching `.tar.gz.sha256` files. The
archives use paths relative to the installation root, without an extra
directory to strip:

```text
usr/bin/dlfreeze
usr/lib/dlfreeze/dlfreeze-bootstrap
usr/lib/dlfreeze/dlfreeze-preload.so
usr/lib/dlfreeze/dlfreeze-preload-static.so
usr/share/doc/dlfreeze/
```

Verify and unpack into a staging root for your package manager:

```bash
archive=dlfreeze-linux-x86_64.tar.gz  # use aarch64 on arm64
sha256sum -c "$archive.sha256"
mkdir -p pkgroot
tar -xzf "$archive" -C pkgroot
./pkgroot/usr/bin/dlfreeze -h
```

Keep `bin` and `lib/dlfreeze` under the same prefix. Only the CLI belongs
on `PATH`; it locates the private files relative to its executable.
Packaged CLI and bootstrap binaries are statically linked with musl.
The tracing helpers use the target program's libc: the GNU helper
requires glibc symbol versions up to 2.34, and the musl helper uses the
musl ABI. A static CLI does not make tracing or direct loading available
for every target libc; those modes still validate the target's runtime.
Frozen executables do not need the package installed to run.

For source-based packaging, use `make DESTDIR="$PWD/pkgroot" install`
(default `PREFIX=/usr`; override it for a different prefix). To build the
standard archive and checksum, run `make package` with GNU tar, gzip, and
a matching `strip` (set `STRIP` for a cross build). This always stages a
`/usr` tree under `DIST` (default `dist`), regardless of the install prefix.
Archive metadata is normalized; set `SOURCE_DATE_EPOCH` to choose its
timestamp. To reproduce the release ABI, use the compiler, libc baseline,
and flags in [the package workflow](.github/workflows/ci.yml).

The workflow exposes both archives as CI artifacts on ordinary runs. A
pushed `v*` tag publishes both verified archives and checksums once the
test and packaging jobs succeed. The annotation on that tag becomes the
GitHub release notes. To preserve Markdown headings that Git would otherwise
treat as comments, create the tag with `--cleanup=verbatim`:

```bash
git tag -a v1.2.3 --cleanup=verbatim -F release-notes.md
git push origin v1.2.3
```

Use `-s` instead of `-a` for a signed tag; the signature is not included in
the published notes. A lightweight tag uses the tagged commit's message.

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

The benchmark harness can opt into additional startup workloads when they
are installed:

```bash
BENCH_CASES=python-imports make bench
BENCH_CASES=python-numpy make bench
BENCH_RUNS=5 BENCH_CASES=kmail make bench
```

The `kmail` case compares `kmail --version` with an untraced frozen artifact;
it measures a large shared-library startup graph, not full GUI functionality
or a fully captured runtime-plugin/data environment. Native and frozen runs
inherit the same caller environment, including any display configuration.
The summary's `artifact_mode` column distinguishes direct-load artifacts from
extraction fallbacks; a successful freeze alone does not imply direct loading.

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
