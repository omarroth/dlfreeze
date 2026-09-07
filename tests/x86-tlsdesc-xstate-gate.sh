#!/usr/bin/env bash
set -eu

CC=${CC:-gcc}

case "$($CC -dumpmachine 2>/dev/null || true)" in
    x86_64*|amd64*) ;;
    *)
        echo "SKIP: x86 TLSDESC XSAVE gate (unsupported architecture)"
        exit 77
        ;;
esac

root=$(mktemp -d "${TMPDIR:-/tmp}/dlfreeze-x86-tlsdesc-xstate.XXXXXX")
trap 'rm -rf "$root"' EXIT
gate="$root/x86_tlsdesc_xstate_gate"

if ! "$CC" -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -Iinclude \
        -ffunction-sections -fdata-sections -fno-stack-protector \
        -Wl,--gc-sections -o "$gate" \
        tests/x86_tlsdesc_xstate_gate.c -ldl -pthread; then
    echo "FAIL: cannot build x86 TLSDESC XSAVE gate"
    exit 1
fi

"$gate"
