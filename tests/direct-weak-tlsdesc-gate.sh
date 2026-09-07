#!/usr/bin/env bash
set -eu

BUILD=${1:-build}
CC=${CC:-gcc}

case "$($CC -dumpmachine 2>/dev/null || true)" in
    x86_64*|amd64*) tls_flags=(-mtls-dialect=gnu2) ;;
    aarch64*|arm64*) tls_flags=() ;;
    *)
        echo "SKIP: direct undefined-weak TLSDESC (unsupported architecture)"
        exit 77
        ;;
esac

if [ ! -x "$BUILD/dlfreeze" ] || ! command -v readelf >/dev/null 2>&1; then
    echo "SKIP: direct undefined-weak TLSDESC (missing dlfreeze/readelf)"
    exit 77
fi

root=$(mktemp -d "${TMPDIR:-/tmp}/dlfreeze-weak-tlsdesc.XXXXXX")
trap 'rm -rf "$root"' EXIT
library="$root/libdlfreeze-weak-tlsdesc.so"
program="$root/main"
frozen="$root/main.frozen"

if ! "$CC" -Wall -Wextra -Werror -shared -fPIC "${tls_flags[@]}" \
        -Wl,-soname,libdlfreeze-weak-tlsdesc.so \
        -o "$library" tests/direct_weak_tlsdesc_library.c ||
   ! readelf -rW "$library" | grep -q 'TLSDESC' ||
   ! "$CC" -Wall -Wextra -Werror -o "$program" \
        tests/direct_weak_tlsdesc_main.c -ldl; then
    echo "SKIP: direct undefined-weak TLSDESC (toolchain lacks TLSDESC)"
    exit 77
fi

native_output=$("$program" "$library" 2>&1) || {
    echo "SKIP: direct undefined-weak TLSDESC (native runtime rejects control)"
    exit 77
}
if [ "$native_output" != "weak-tlsdesc-null-ok" ]; then
    echo "FAIL: native undefined-weak TLSDESC output: $native_output"
    exit 1
fi

if ! "$BUILD/dlfreeze" -d -t -o "$frozen" -- \
        "$program" "$library" >"$root/freeze.log" 2>&1; then
    echo "SKIP: direct undefined-weak TLSDESC (direct freeze unavailable)"
    exit 77
fi
if ! grep -q 'mode       : direct-load' "$root/freeze.log"; then
    echo "SKIP: direct undefined-weak TLSDESC (direct mode not selected)"
    exit 77
fi

mv "$library" "$library.saved"
direct_output=$("$frozen" "$library") || {
    echo "FAIL: frozen undefined-weak TLSDESC"
    exit 1
}
if [ "$direct_output" != "weak-tlsdesc-null-ok" ]; then
    echo "FAIL: frozen undefined-weak TLSDESC output: $direct_output"
    exit 1
fi

echo "PASS: direct undefined-weak TLSDESC resolves to NULL"
