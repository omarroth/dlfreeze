# dlfreeze

Turn any dynamically linked Linux program into a single, self-contained executable.

`dlfreeze` resolves a program's full shared-library dependency tree, bundles everything — binary, runtime linker, libraries, and optional data files — into one portable file, and provides two runtime strategies: extraction to a tmpdir (default) or a fast in-process loader that maps objects directly from the frozen binary's memory (direct-load mode).

## Quick start

```bash
make
```

Freeze `ls`:

```bash
./build/dlfreeze -o ls.frozen /bin/ls
./ls.frozen -la /etc
```

Freeze Python with traced `dlopen()` dependencies and data files:

```bash
./build/dlfreeze -d -t -f '/usr/lib/python3*' -o python3.frozen -- python3 -c 'import sqlite3'
./python3.frozen -c 'import sqlite3; print(sqlite3.sqlite_version)'
```

## How it works

1. **Dependency resolution** — BFS walk over `DT_NEEDED` entries, with ldconfig cache lookup, `$ORIGIN`/`DT_RPATH`/`DT_RUNPATH` expansion, and automatic inclusion of glibc NSS libraries.
2. **dlopen tracing** (`-t`) — Runs the program under an `LD_PRELOAD` shim that intercepts `dlopen()` and records the resolved paths.
3. **Packing** — Concatenates the statically-linked bootstrap stub, every collected object (page-aligned), a string table, a manifest, and a 64-byte footer (`DLFREEZ` magic) into a single ELF.
4. **Runtime — extraction mode (default)** — The bootstrap reads `/proc/self/exe`, extracts files to a tmpdir, and execs the program through the bundled `ld.so`.
5. **Runtime — direct-load mode** (`-d`) — The bootstrap invokes an in-process ELF loader that maps segments from the payload, resolves relocations, sets up TLS, and jumps to `_start`.

Frozen binaries are compatible with UPX and should mostly work with other packing tools: the payload lives in a `PT_LOAD` segment so compressors preserve it, and a `DLFRZLDR` sentinel in `.data` lets the bootstrap find the payload in virtual memory if the footer is no longer at EOF.

## Usage

```
dlfreeze [options] [--] <executable> [args...]

Options:
  -o <path>   Output file  (default: <name>.frozen)
  -d          Direct-load mode (in-process loader, no tmpdir)
  -t          Trace dlopen calls by running the program
  -f <glob>   Embed data files matching glob (requires -t, repeatable)
  -v          Verbose
  -h          Help
```

When `-t` is used, `[args...]` are passed to the traced run so the program exercises the code paths that trigger `dlopen()`.

## Building

Requires Linux and a C compiler. `musl-gcc` is preferred for smaller static binaries but the build falls back to the system `gcc`.

```bash
make            # builds build/dlfreeze, build/dlfreeze-bootstrap, build/dlfreeze-preload.so
make test       # runs the test suite
make bench      # startup benchmarks (requires perf)
make clean
```

## Disclaimer

The majority of code for this project was written by LLMs. Although I've read through the code to make sure there's nothing obviously stupid, do not use this project in a production or security-sensitive environment without vetting it yourself.

## License

This project is licensed under the [GNU Lesser General Public License version 3](LICENSE).
