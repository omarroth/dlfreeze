#!/usr/bin/env bash
set -eu

BUILD=${1:-build}
CC=${CC:-gcc}
runner=()
if [ -n "${RUNNER:-}" ]; then
    read -r -a runner <<<"$RUNNER"
fi

run_target() {
    "${runner[@]}" "$@"
}

case "$($CC -dumpmachine 2>/dev/null || true)" in
    x86_64*|amd64*|aarch64*|arm64*) ;;
    *)
        echo "SKIP: preload early-IFUNC trace (unsupported architecture)"
        exit 77
        ;;
esac

helper="$BUILD/dlfreeze-preload.so"
if [ ! -r "$helper" ] || ! command -v readelf >/dev/null 2>&1; then
    echo "SKIP: preload early-IFUNC trace (missing helper/readelf)"
    exit 77
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/dlfreeze-preload-early-ifunc.XXXXXX")
trap 'rm -rf "$root"' EXIT
library="$root/libdlfreeze-preload-early-ifunc-late.so"
provider="$root/libdlfreeze-preload-early-ifunc-provider.so"
program="$root/main"
dltrace="$root/dlopen.trace"
filetrace="$root/file.trace"

if ! "$CC" -Wall -Wextra -Werror -shared -fPIC \
        -Wl,-soname,libdlfreeze-preload-early-ifunc-late.so \
        -o "$library" tests/direct_startup_ifunc_library.c ||
   ! "$CC" -Wall -Wextra -Werror -shared -fPIC -fno-stack-protector \
        -Wl,-z,now \
        -Wl,-soname,libdlfreeze-preload-early-ifunc-provider.so \
        -DSTARTUP_IFUNC_LATE_PATH="\"$library\"" \
        -o "$provider" tests/direct_startup_ifunc_provider.c -ldl ||
   ! "$CC" -Wall -Wextra -Werror -fno-stack-protector -rdynamic \
        -Wl,-z,now -Wl,-rpath,"$root" -L"$root" \
        -DSTARTUP_IFUNC_LATE_PATH="\"$library\"" \
        -o "$program" tests/direct_startup_ifunc_main.c \
        -l:libdlfreeze-preload-early-ifunc-provider.so -ldl; then
    echo "SKIP: preload early-IFUNC trace (toolchain lacks GNU IFUNC)"
    exit 77
fi
if ! readelf -rW "$program" | grep -q 'IRELATIVE' ||
   ! readelf -sW "$provider" | grep -Eq \
        'IFUNC.*direct_startup_symbolic_ifunc_probe'; then
    echo "SKIP: preload early-IFUNC trace (resolver relocations not emitted)"
    exit 77
fi

native_output=$(run_target "$program") || {
    echo "SKIP: preload early-IFUNC trace (native runtime rejects resolver)"
    exit 77
}
if [ "$native_output" != "startup-ifunc-native-load-ok" ]; then
    echo "FAIL: preload early-IFUNC native output: $native_output"
    exit 1
fi

# The first dlopen calls happen from startup resolvers, before any constructor
# (including the trace helper's constructor) can run.  Pass the streams exactly
# as the collector does: inherited O_APPEND descriptors plus immutable file
# identities, with no pathname fallback.  This also keeps the gate independent
# of direct-loader availability in cross/qemu jobs.
: >"$dltrace"
: >"$filetrace"
exec {dltrace_fd}>>"$dltrace"
exec {filetrace_fd}>>"$filetrace"
read -r dltrace_device dltrace_inode < <(stat -Lc '%d %i' "$dltrace")
read -r filetrace_device filetrace_inode < <(stat -Lc '%d %i' "$filetrace")
printf -v dltrace_identity '%016x:%016x:%016x:%016x' \
    "$dltrace_device" "$dltrace_inode" 32768 0
printf -v filetrace_identity '%016x:%016x:%016x:%016x' \
    "$filetrace_device" "$filetrace_inode" 32768 0

traced_output=""
traced_rc=0
traced_output=$( \
    LD_PRELOAD="$helper" \
    DLFREEZE_TRACE_FD="$dltrace_fd" \
    DLFREEZE_FILE_TRACE_FD="$filetrace_fd" \
    DLFREEZE_TRACE_IDENTITY="$dltrace_identity" \
    DLFREEZE_FILE_TRACE_IDENTITY="$filetrace_identity" \
    run_target "$program" 2>"$root/traced.err") || traced_rc=$?
exec {dltrace_fd}>&-
exec {filetrace_fd}>&-

late_hex=$(printf '%s' "$library" | od -An -tx1 | tr -d ' \n')
if [ "$traced_rc" -ne 0 ] ||
   [ "$traced_output" != "startup-ifunc-native-load-ok" ] ||
   [ "$(sed -n '1p' "$dltrace")" != '#DLFREEZE_DLOPEN_TRACE_V8' ] ||
   [ "$(sed -n '1p' "$filetrace")" != '#DLFREEZE_PRELOAD_TRACE_V9' ] ||
   [ "$(grep -Ec '^O [0-9a-f]{16}$' "$dltrace")" -ne 1 ] ||
   [ "$(grep -Ec '^A [0-9a-f]{16} [0-9a-f]{16}$' "$dltrace")" -ne 1 ] ||
   [ "$(grep -Ec '^K [0-9a-f]{16} [0-9a-f]{16} [0-9a-f]{16}$' "$dltrace")" -lt 1 ] ||
   [ "$(grep -Ec '^Q [0-9a-f]{16} [0-9a-f]{16}$' "$dltrace")" -ne 2 ] ||
   [ "$(grep -Ec "^P [0-9a-f]{16} [0-9a-f]{16} [0-9a-f]{16} 00000002 $late_hex $late_hex $late_hex( [0-9a-f]{16}){8}$" "$dltrace")" -ne 3 ] ||
   [ "$(grep -Ec "^F [0-9a-f]{16} $late_hex $late_hex( [0-9a-f]{16}){8}$" "$filetrace")" -ne 3 ] ||
   grep -q '^! ' "$dltrace" || grep -q '^! ' "$filetrace"; then
    echo "FAIL: preload early-IFUNC calls were not completely traced"
    echo "exit=$traced_rc output=$traced_output"
    sed -n '1,80p' "$root/traced.err"
    sed -n '1,120p' "$dltrace"
    sed -n '1,120p' "$filetrace"
    exit 1
fi

echo "PASS: preload tracing starts before target IFUNC dlopen"
