# dlfreeze

Bundle a dynamically linked 64-bit Linux program, its ELF interpreter, and its
shared-library dependency graph into one executable.

`dlfreeze` provides two runtime strategies: extraction through an ELF
interpreter (the default) and an experimental in-process loader (`-d`). Dynamic
libraries and data discovered only at runtime must be traced for
self-containment; otherwise loading may fail or fall back to files on the host.

## Support scope

| Area | Supported contract |
|---|---|
| Architecture | ELF64 x86_64 and AArch64; source and target must match |
| Default extraction | Bundles the interpreter and libraries; may use a byte-identical installed interpreter, otherwise invokes the bundled copy |
| Direct load (`-d`) | musl and recognized modern glibc runtimes; unsupported runtimes or unvalidated startup entry points are packaged in extraction mode |
| `dlopen()` dependencies | Capture with `-t` by exercising relevant paths; uncaptured libraries may use an explicit host-disk fallback |
| Runtime data | Capture selected paths with `-t -f`; uncaptured files may still come from the target host |

Extraction is the compatibility path. Direct loading depends on private libc
details and should be treated as experimental even on the tested runtimes.
AArch64 payloads are aligned for kernels with pages up to 64 KiB, and direct
mode preserves `AT_PAGESZ`; native non-4-KiB testing is still recommended.
The direct loader enforces segment permissions and GNU RELRO, validates and
uses both GNU and SysV dynamic symbol hashes, resolves GNU symbol versions,
and preserves normal preinit/init/fini, `atexit`, signal, and glibc `fork()`
lifecycle behavior. Separate `dlmopen()` namespaces and runtime unloading on
`dlclose()` are not implemented; objects remain resident until process exit.

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

1. **Dependency resolution** — BFS walk over `DT_NEEDED` entries, with ABI validation, ldconfig cache lookup, musl path-file lookup, and `$ORIGIN`/`DT_RPATH`/`DT_RUNPATH` expansion. Missing or incompatible required libraries are fatal.
2. **dlopen tracing** (`-t`) — Runs the program under an `LD_PRELOAD` shim that intercepts `dlopen()` and records the resolved paths.
3. **Packing** — Concatenates the statically-linked bootstrap stub, every collected object (page-aligned), a string table, a manifest, and a 64-byte footer (`DLFREEZ` magic) into a single ELF.
4. **Runtime — extraction mode (default)** — The bootstrap extracts files to a tmpdir. It uses normal kernel `PT_INTERP` startup when the installed interpreter is byte-identical, otherwise it invokes the bundled interpreter.
5. **Runtime — direct-load mode** (`-d`) — For recognized glibc/musl targets, the bootstrap invokes an in-process ELF loader that maps segments, resolves relocations, and builds runtime state. Unsupported runtimes are packaged directly for extraction instead.

Frozen binaries are compatible with UPX and should mostly work with other packing tools: the payload lives in a `PT_LOAD` segment so compressors preserve it, and a `DLFRZLDR` sentinel in `.data` lets the bootstrap find the payload in virtual memory if the footer is no longer at EOF.

## Usage

```
dlfreeze [options] [--] <executable> [args...]

Options:
  -o <path>   Output file  (default: <name>.frozen)
  -d          Request experimental direct-load mode
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

Requires Linux and a C compiler. `musl-gcc` is preferred for smaller static binaries but the build falls back to the system `gcc`.

```bash
make            # builds build/dlfreeze, build/dlfreeze-bootstrap, build/dlfreeze-preload.so
make test       # runs the suite; -d cases are strict (no hidden extraction fallback)
make bench      # startup benchmarks (requires perf)
make clean
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
