#!/usr/bin/env bash
# Verify the archive itself, then exercise its installed tools on a native
# glibc or musl host. Use "elf" for read-only cross-architecture verification.
set -euo pipefail
export LC_ALL=C

archive=$(realpath "${1:?usage: release-package-gate.sh ARCHIVE ARCH glibc|glibc-direct|musl|elf}")
arch=${2:?missing package architecture}
runtime=${3:?missing runtime}
case "$arch" in
    x86_64) machine='Advanced Micro Devices X86-64'; min_alignment=4096 ;;
    aarch64) machine=AArch64; min_alignment=65536 ;;
    *) echo "unknown package architecture: $arch" >&2; exit 1 ;;
esac
case "$runtime" in glibc|glibc-direct|musl|elf) ;; *) exit 1 ;; esac

die() { echo "release package: $*" >&2; exit 1; }
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
(
    cd "$(dirname "$archive")"
    sha256sum -c "$(basename "$archive").sha256"
)
tar -tzf "$archive" > "$root/members"
awk '
    /^usr\/(bin\/dlfreeze|lib\/dlfreeze\/dlfreeze-bootstrap|lib\/dlfreeze\/dlfreeze-preload(-static)?\.so|share\/doc\/dlfreeze\/(README\.md|LICENSE(\.musl)?))$/ { next }
    /^usr\/(bin\/|lib\/(dlfreeze\/)?|share\/(doc\/(dlfreeze\/)?)?)?$/ { next }
    { print "Unexpected archive member: " $0 > "/dev/stderr"; bad = 1 }
    END { exit bad }
' "$root/members"
tar -xzf "$archive" -C "$root"

tool="$root/usr/bin/dlfreeze"
lib="$root/usr/lib/dlfreeze"
bootstrap="$lib/dlfreeze-bootstrap"
gnu_helper="$lib/dlfreeze-preload.so"
musl_helper="$lib/dlfreeze-preload-static.so"
doc="$root/usr/share/doc/dlfreeze"
for f in "$tool" "$bootstrap" "$gnu_helper" "$musl_helper"; do
    [ -f "$f" ] && [ ! -L "$f" ] || die "missing regular file: $f"
    header=$(readelf -hW "$f")
    grep -Eq 'Class:[[:space:]]+ELF64' <<< "$header" || die "not ELF64: $f"
    grep -Eq "Machine:[[:space:]]+$machine$" <<< "$header" || die "incorrect architecture: $f"
    segments=$(readelf -lW "$f")
    mapfile -t load_alignments < <(awk '$1 == "LOAD" {print $NF}' <<< "$segments")
    [ "${#load_alignments[@]}" -ne 0 ] || die "no PT_LOAD segments: $f"
    for alignment in "${load_alignments[@]}"; do
        if ! [[ "$alignment" =~ ^0x[0-9a-fA-F]+$ ]] || (( alignment < min_alignment )); then
            die "load segment does not support $min_alignment-byte pages: $f"
        fi
    done
    if [ "$arch" = x86_64 ]; then
        notes=$(readelf -nW "$f")
        if grep -Eq 'x86 ISA needed:.*x86-64-v[234]' <<< "$notes"; then
            die "requires a non-baseline x86-64 ISA: $f"
        fi
    fi
done
for f in "$tool" "$bootstrap"; do
    [ -x "$f" ] || die "not executable: $f"
    segments=$(readelf -lW "$f")
    if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<< "$segments"; then
        die "not statically linked: $f"
    fi
done
for f in "$doc/README.md" "$doc/LICENSE"; do
    [ -s "$f" ] || die "missing documentation: $f"
done

needed() {
    readelf -dW "$1" | sed -n '/(NEEDED)/s/.*\[\([^]]*\)\].*/\1/p'
}
# AArch64 glibc exports the stack-protector guard from the interpreter.
# Accept that already-loaded provider, but no extra runtime libraries.
gnu_needed=$(needed "$gnu_helper" | sort)
case "$arch:$gnu_needed" in
    x86_64:libc.so.6|aarch64:libc.so.6|aarch64:$'ld-linux-aarch64.so.1\nlibc.so.6') ;;
    *) die "unexpected glibc helper dependencies: $gnu_needed" ;;
esac
musl_needed=$(needed "$musl_helper")
case "$musl_needed" in
    libc.so|libc.musl-"$arch".so.1) ;;
    *) die "unexpected musl helper dependencies: $musl_needed" ;;
esac
versions=$(readelf -VW "$gnu_helper" | awk '/Name: GLIBC_/ {print $3}')
[ -n "$versions" ] || die "missing glibc symbol version requirements"
while IFS= read -r version; do
    if ! [[ "$version" =~ ^GLIBC_2\.([0-9]+)(\.[0-9]+)?$ ]] ||
       (( BASH_REMATCH[1] > 34 )); then
        die "glibc helper exceeds the GLIBC_2.34 baseline: $version"
    fi
done <<< "$versions"
if [ "$runtime" = elf ]; then
    echo "PASS: $arch release archive layout and ELF portability"
    exit 0
fi

cd "$root"
plugin=libdlfreeze-release-probe.so
trace_library_path=
case "$runtime" in
    # Exercise the portable extraction path separately from direct loading.
    # An exact bare name is representable in extraction mode.
    glibc)
        helper=$gnu_helper; request=$plugin; freeze_mode=-x; replay=extraction
        # The interposer is the native dlopen caller, so the executable's
        # RUNPATH alone does not supply this lookup. Scope the search path to
        # the trace; replay must find the packed library without it.
        trace_library_path=$root
        ;;
    # Also prove the archive can replay a request that requires direct
    # loading. An absolute request must never pass via extraction.
    glibc-direct) helper=$gnu_helper; request="$root/$plugin"; freeze_mode=-d; replay=direct ;;
    musl) helper=$musl_helper; request="$root/$plugin"; freeze_mode=-d; replay=direct ;;
esac
${CC:-cc} -Wall -Wextra -Werror -fPIC -shared -o "$plugin" -x c - <<'C'
int release_probe(void) { return 42; }
C
${CC:-cc} -Wall -Wextra -Werror -o probe -x c - -ldl <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 3;
    }
    int (*probe)(void) = (int (*)(void))dlsym(handle, "release_probe");
    if (!probe || probe() != 42)
        return 4;
    puts("release trace ok");
    return 0;
}
C
ln -s "$tool" ./freeze
if ! LD_LIBRARY_PATH="$trace_library_path" \
        ./freeze -v "$freeze_mode" -t -o ./probe.frozen -- ./probe "$request" > freeze.log 2>&1; then
    cat freeze.log >&2
    die "$runtime trace failed"
fi
grep -Fxq "bootstrap : $bootstrap" freeze.log || die "wrong bootstrap used"
grep -Fxq "trace helper: $helper" freeze.log || die "wrong $runtime preload helper used"
meta_offset=$(od -An -tu8 -j "$(($(wc -c < probe.frozen) - 24))" -N8 probe.frozen | tr -d '[:space:]')
case "$replay:$meta_offset" in
    extraction:0|direct:[1-9]*) ;;
    *) die "expected $replay metadata, got offset $meta_offset" ;;
esac
rm ./probe "./$plugin"
rm -rf ./usr
[ "$(./probe.frozen "$request")" = 'release trace ok' ] ||
    die "$replay artifact did not replay without package or source files"
echo "PASS: $arch release archive froze and replayed a $runtime dlopen workload ($replay)"
