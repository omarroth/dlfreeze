#!/usr/bin/env bash
set -euo pipefail

build=${1:-build}
root=$(mktemp -d "${TMPDIR:-/tmp}/dlfreeze-descriptor-gate.XXXXXX")
trap 'rm -rf "$root"' EXIT

helper=$(realpath "$build/dlfreeze-preload.so")
mock="$root/libdescriptor-downstream.so"
target="$root/descriptor-target"
dltrace="$root/dlopen.trace"
filetrace="$root/file.trace"
input="$root/input.txt"

run_with_timeout() {
    local timeout_help

    if ! command -v timeout >/dev/null 2>&1; then
        "$@"
        return
    fi
    timeout_help=$(timeout --help 2>&1 || true)
    if grep -F -- '--kill-after' <<<"$timeout_help" >/dev/null; then
        timeout --kill-after=2 20 "$@"
    elif grep -Eq '(^|[[:space:]])-k([[:space:],]|$)' \
            <<<"$timeout_help"; then
        timeout -k 2 20 "$@"
    else
        timeout 20 "$@"
    fi
}

gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -shared -fPIC \
    -o "$mock" tests/preload_descriptor_downstream.c -ldl -pthread
gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE \
    -o "$target" tests/preload_descriptor_transactions.c -ldl
printf '%s\n' descriptor-input >"$input"

output=$(run_with_timeout env \
    LD_PRELOAD="$helper:$mock" \
    DLFREEZE_TRACE_FILE="$dltrace" \
    DLFREEZE_FILE_TRACE_FILE="$filetrace" \
    DLFREEZE_DESCRIPTOR_TEST_INPUT="$input" \
    "$target" callbacks "$filetrace")
test "$output" = descriptor-transactions-ok

test "$(sed -n '1p' "$dltrace")" = '#DLFREEZE_DLOPEN_TRACE_V8'
test "$(sed -n '1p' "$filetrace")" = '#DLFREEZE_PRELOAD_TRACE_V9'
for trace in "$dltrace" "$filetrace"; do
    ! grep -q '^! ' "$trace"
    awk '
        $1 == "V" && NF == 3 {
            key = $2 SUBSEP $3
            if (pending[key]++) exit 1
            begins++
            next
        }
        $1 == "W" && NF == 3 {
            key = $2 SUBSEP $3
            if (pending[key] != 1) exit 1
            delete pending[key]
            commits++
            next
        }
        END {
            for (key in pending) exit 1
            if (begins < 10 || begins != commits) exit 1
        }
    ' "$trace"
done

# glibc closefrom falls back when close_range is denied with errors other than
# ENOSYS.  Compare the native control before requiring the helper to preserve
# that behavior.
native_rc=0
native_output=$(run_with_timeout "$target" closefrom-eperm) || \
    native_rc=$?
if [[ $native_rc == 77 ]]; then
    printf '%s\n' 'descriptor gate: closefrom EPERM case unavailable'
elif [[ $native_rc != 0 || $native_output != descriptor-closefrom-eperm-ok ]]; then
    printf 'native closefrom EPERM control failed: exit=%d output=%s\n' \
        "$native_rc" "$native_output" >&2
    exit 1
else
    traced="$root/closefrom-eperm.file.trace"
    traced_output=$(run_with_timeout env \
        LD_PRELOAD="$helper" \
        DLFREEZE_FILE_TRACE_FILE="$traced" \
        "$target" closefrom-eperm)
    test "$traced_output" = descriptor-closefrom-eperm-ok
fi

segment_dltrace="$root/segment-failure.dlopen.trace"
segment_filetrace="$root/segment-failure.file.trace"
segment_rc=0
segment_output=$(run_with_timeout env \
    LD_PRELOAD="$helper" \
    DLFREEZE_TRACE_FILE="$segment_dltrace" \
    DLFREEZE_FILE_TRACE_FILE="$segment_filetrace" \
    "$target" segmented-eperm) || segment_rc=$?
if [[ $segment_rc == 77 ]]; then
    printf '%s\n' 'descriptor gate: segmented EPERM case unavailable'
else
    test "$segment_rc" -eq 0
    test "$segment_output" = descriptor-segmented-eperm-ok
    for trace in "$segment_dltrace" "$segment_filetrace"; do
        test "$(grep -Ec '^! [0-9a-f]{16} segmented-close-range-did-not-complete$' \
            "$trace")" -eq 1
    done
fi

printf '%s\n' 'descriptor transaction gate: PASS'
