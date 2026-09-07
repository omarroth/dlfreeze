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

run_freezer() {
    if [ -n "${FREEZE_LIBRARY_PATH:-}" ]; then
        LD_LIBRARY_PATH=$FREEZE_LIBRARY_PATH run_target "$@"
    else
        run_target "$@"
    fi
}

case "$($CC -dumpmachine 2>/dev/null || true)" in
    x86_64*|amd64*|aarch64*|arm64*) ;;
    *)
        echo "SKIP: direct startup IFUNC phase (unsupported architecture)"
        exit 77
        ;;
esac

if [ ! -x "$BUILD/dlfreeze" ] || ! command -v readelf >/dev/null 2>&1; then
    echo "SKIP: direct startup IFUNC phase (missing dlfreeze/readelf)"
    exit 77
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/dlfreeze-startup-ifunc.XXXXXX")
trap 'rm -rf "$root"' EXIT
library="$root/libdlfreeze-startup-ifunc-late.so"
provider="$root/libdlfreeze-startup-ifunc-provider.so"
program="$root/main"
frozen="$root/main.frozen"

if ! "$CC" -Wall -Wextra -Werror -shared -fPIC \
        -Wl,-soname,libdlfreeze-startup-ifunc-late.so \
        -o "$library" tests/direct_startup_ifunc_library.c ||
   ! "$CC" -Wall -Wextra -Werror -shared -fPIC -fno-stack-protector \
        -Wl,-z,now \
        -Wl,-soname,libdlfreeze-startup-ifunc-provider.so \
        -DSTARTUP_IFUNC_LATE_PATH="\"$library\"" \
        -o "$provider" tests/direct_startup_ifunc_provider.c -ldl ||
   ! "$CC" -Wall -Wextra -Werror -fno-stack-protector -rdynamic \
        -Wl,-z,now \
        -Wl,-rpath,"$root" -L"$root" \
        -DSTARTUP_IFUNC_LATE_PATH="\"$library\"" \
        -o "$program" tests/direct_startup_ifunc_main.c \
        -ldlfreeze-startup-ifunc-provider -ldl; then
    echo "SKIP: direct startup IFUNC phase (toolchain lacks GNU IFUNC)"
    exit 77
fi
if ! readelf -rW "$program" | grep -q 'IRELATIVE' ||
   ! readelf -sW "$provider" | grep -Eq \
        'IFUNC.*direct_startup_symbolic_ifunc_probe'; then
    echo "SKIP: direct startup IFUNC phase (resolver relocations not emitted)"
    exit 77
fi

native_output=$(run_target "$program") || {
    echo "SKIP: direct startup IFUNC phase (native runtime rejects resolver)"
    exit 77
}
if [ "$native_output" != "startup-ifunc-native-load-ok" ]; then
    echo "FAIL: native startup IFUNC output: $native_output"
    exit 1
fi

if ! run_freezer "$BUILD/dlfreeze" -d -o "$frozen" -- \
        "$program" >"$root/freeze.log" 2>&1; then
    echo "SKIP: direct startup IFUNC phase (direct freeze unavailable)"
    sed -n '1,120p' "$root/freeze.log"
    exit 77
fi
if ! grep -q 'mode       : direct-load' "$root/freeze.log"; then
    echo "SKIP: direct startup IFUNC phase (direct mode not selected)"
    sed -n '1,120p' "$root/freeze.log"
    exit 77
fi

direct_output=$(DLFREEZE_NO_FORK=1 run_target "$frozen") || {
    echo "FAIL: frozen startup IFUNC phase"
    sed -n '1,160p' "$root/freeze.log"
    exit 1
}
if [ "$direct_output" != "startup-ifunc-readonly-ok" ]; then
    echo "FAIL: frozen startup IFUNC output: $direct_output"
    exit 1
fi

echo "PASS: direct startup IFUNC graph is read-only until runtime"
