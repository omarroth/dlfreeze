#!/usr/bin/env bash
# dlfreeze test suite
# shellcheck disable=SC2016 # command snippets and $ORIGIN are intentionally literal
set -euo pipefail

BUILD="${1:-build}"
DLFREEZE="$BUILD/dlfreeze"

mkdir -p "$BUILD"

PASS=0 FAIL=0 SKIP=0 DIRECT_ARTIFACTS=0
RED=$'\033[31m' GRN=$'\033[32m' YLW=$'\033[33m' RST=$'\033[0m'
pass() { echo "${GRN}PASS${RST}: $1"; ((PASS++)) || true; }
fail() { echo "${RED}FAIL${RST}: $1 — $2"; ((FAIL++)) || true; }
skip() { echo "${YLW}SKIP${RST}: $1 — $2"; ((SKIP++)) || true; }

TEST_RUN_TIMEOUT="${TEST_RUN_TIMEOUT:-30}"
TEST_FREEZE_TIMEOUT="${TEST_FREEZE_TIMEOUT:-180}"
TEST_TIMEOUT_KILL_AFTER="${TEST_TIMEOUT_KILL_AFTER:-5}"
TEST_CC_RETRIES="${TEST_CC_RETRIES:-2}"
TEST_REAL_GCC="${TEST_REAL_GCC:-$(command -v gcc || true)}"

# A -d regression must exercise the in-process loader itself.  Individual
# fallback tests explicitly unset this variable when they need the wrapper.
export DLFREEZE_NO_FORK="${DLFREEZE_NO_FORK:-1}"

gcc() {
    local attempt=0 tmp rc

    if [ -z "$TEST_REAL_GCC" ]; then
        echo "gcc: command not found" >&2
        return 127
    fi

    while :; do
        tmp=$(mktemp)
        set +e
        "$TEST_REAL_GCC" "$@" 2>"$tmp"
        rc=$?
        set -e

        if [ "$rc" -eq 0 ]; then
            cat "$tmp" >&2
            rm -f "$tmp"
            return 0
        fi

        if [ "$attempt" -lt "$TEST_CC_RETRIES" ] &&
           grep -Eqi 'internal compiler error|segmentation fault signal terminated program (cc1|collect2)|fatal error: killed signal terminated program (cc1|collect2)' "$tmp"; then
            attempt=$((attempt + 1))
            echo "warning: gcc crashed while compiling test fixture; retrying ($attempt/$TEST_CC_RETRIES)" >&2
            cat "$tmp" >&2
            rm -f "$tmp"
            continue
        fi

        cat "$tmp" >&2
        rm -f "$tmp"
        return "$rc"
    done
}

run_with_timeout_seconds() {
    local limit="$1"
    shift

    if command -v timeout &>/dev/null; then
        if timeout --help 2>&1 | grep -- '--kill-after' >/dev/null; then
            timeout --kill-after="$TEST_TIMEOUT_KILL_AFTER" "$limit" "$@"
        else
            timeout "$limit" "$@"
        fi
    else
        "$@"
    fi
}

run_with_timeout() {
    run_with_timeout_seconds "$TEST_RUN_TIMEOUT" "$@"
}

run_freeze() {
    run_with_timeout_seconds "$TEST_FREEZE_TIMEOUT" "$@"
}

capture_output() {
    local __var="$1" __tmp __rc
    shift

    __tmp=$(mktemp)
    set +e
    run_with_timeout "$@" >"$__tmp" 2>&1
    __rc=$?
    set -e
    printf -v "$__var" '%s' "$(cat "$__tmp")"
    rm -f "$__tmp"
    return "$__rc"
}

capture_output_in_dir() {
    local __var="$1" __dir="$2" __tmp __rc
    shift 2

    __tmp=$(mktemp)
    set +e
    (cd "$__dir" && run_with_timeout "$@") >"$__tmp" 2>&1
    __rc=$?
    set -e
    printf -v "$__var" '%s' "$(cat "$__tmp")"
    rm -f "$__tmp"
    return "$__rc"
}

# Compiler command names do not identify their target libc: gcc and musl-gcc
# may name the same musl-targeting compiler, while a glibc host may provide a
# separate musl-gcc.  Use the target headers when a test needs to distinguish
# GNU dynamic-linker semantics from musl semantics.
compiler_targets_glibc() {
    local cc="${1:-$TEST_REAL_GCC}"

    printf '#include <features.h>\n' |
        "$cc" -dM -E - 2>/dev/null |
        grep '^#define __GLIBC__ ' >/dev/null
}

# GNU ld can reserve unused DT_NULL slots but has no option for emitting both
# DT_RPATH and DT_RUNPATH.  Turn the first reserved terminator into an empty
# DT_RUNPATH while leaving the following terminator intact.  The supported
# test targets (x86_64 and aarch64) are both little-endian ELF64.
elf64_inject_empty_runpath() {
    local file="$1" section dynamic_offset dynamic_size first_null tag_offset

    if ! LC_ALL=C readelf -h "$file" 2>/dev/null |
            grep 'Class:[[:space:]]*ELF64' >/dev/null ||
       ! LC_ALL=C readelf -h "$file" 2>/dev/null |
            grep "Data:[[:space:]]*2's complement, little endian" >/dev/null; then
        return 1
    fi
    section=$(LC_ALL=C readelf -SW "$file" 2>/dev/null |
        awk '$2 == ".dynamic" { print $5, $6; exit }')
    read -r dynamic_offset dynamic_size <<<"$section"
    if [[ ! "$dynamic_offset" =~ ^[0-9A-Fa-f]+$ ]] ||
       [[ ! "$dynamic_size" =~ ^[0-9A-Fa-f]+$ ]]; then
        return 1
    fi
    dynamic_offset=$((16#$dynamic_offset))
    dynamic_size=$((16#$dynamic_size))
    first_null=$(od -An -v -j "$dynamic_offset" -N "$dynamic_size" \
        -w16 -t x8 "$file" 2>/dev/null |
        awk '$1 == "0000000000000000" {
                 if (!seen) { first = NR - 1; seen = 1 }
                 else { print first; exit }
             }')
    if [[ ! "$first_null" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    tag_offset=$((dynamic_offset + first_null * 16))
    printf '\035\0\0\0\0\0\0\0' |
        dd of="$file" bs=1 seek="$tag_offset" count=8 conv=notrunc \
            2>/dev/null
}

# Change only e_machine while retaining a structurally valid native ELF64
# image.  This models a search-directory ABI mismatch without requiring a
# cross compiler on every CI runner.
elf64_set_foreign_machine() {
    local file="$1"

    case "$(uname -m)" in
        x86_64)
            printf '\267\000' | dd of="$file" bs=1 seek=18 count=2 \
                conv=notrunc status=none
            ;;
        aarch64)
            printf '\076\000' | dd of="$file" bs=1 seek=18 count=2 \
                conv=notrunc status=none
            ;;
        *)
            return 1
            ;;
    esac
}

path_is_elf() {
    local path="$1"
    command -v file &>/dev/null &&
        file -b "$path" 2>/dev/null | grep 'ELF' >/dev/null
}

resolve_ruby_elf() {
    local path candidate

    if ! command -v ruby &>/dev/null; then
        return 1
    fi
    path=$(readlink -f "$(command -v ruby)")
    if path_is_elf "$path"; then
        printf '%s\n' "$path"
        return 0
    fi

    for candidate in ruby-mri ruby3.4 ruby3.3 ruby3.2 ruby3.1 ruby3.0 ruby2.7; do
        if command -v "$candidate" &>/dev/null; then
            path=$(readlink -f "$(command -v "$candidate")")
            if path_is_elf "$path"; then
                printf '%s\n' "$path"
                return 0
            fi
        fi
    done

    return 1
}

capture_output_split() {
    local __stdout_var="$1" __stderr_var="$2" __out __err __rc
    shift 2

    __out=$(mktemp)
    __err=$(mktemp)
    set +e
    run_with_timeout "$@" >"$__out" 2>"$__err"
    __rc=$?
    set -e
    printf -v "$__stdout_var" '%s' "$(cat "$__out")"
    printf -v "$__stderr_var" '%s' "$(cat "$__err")"
    rm -f "$__out" "$__err"
    return "$__rc"
}

test_libc_semantics_gate() {
    echo "--- libc semantics bounds gate ---"
    local helper="$BUILD/libc_semantics_gate"

    if gcc -O2 -g -Wall -Wextra -Werror -Iinclude \
            -o "$helper" tests/libc_semantics_gate.c && "$helper"; then
        pass "libc SONAME and used-only static-TLS semantics gate"
    else
        fail "libc SONAME and used-only static-TLS semantics gate" \
            "compile failed, semantics differed, or a short name overread"
    fi
    rm -f "$helper"
}

test_bootstrap_secure_gate() {
    echo "--- bootstrap secure-environment gate ---"
    local helper="$BUILD/bootstrap_secure_gate"

    if gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/bootstrap_secure_gate.c &&
       run_with_timeout_seconds 8 "$helper"; then
        pass "bootstrap secure policy and bounded manifest admission"
    else
        fail "bootstrap secure-environment gate" \
            "compile failed, policy differed, or alias admission timed out"
    fi
    rm -f "$helper"
}

test_packer_alias_gate() {
    echo "--- packer alias ownership complexity gate ---"
    local helper="$BUILD/packer_alias_gate"

    if gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/packer_alias_gate.c src/elf_parser.c &&
       run_with_timeout_seconds 8 "$helper"; then
        pass "packer stable reads and high-cardinality alias grouping"
    else
        fail "packer alias ownership complexity gate" \
            "compile failed, truncate handling/ownership differed, or timed out"
    fi
    rm -f "$helper"
}

test_packer_elf_alignment_gate() {
    echo "--- packer ELF alignment and transaction gate ---"
    local helper="$BUILD/packer_elf_alignment_gate"

    if gcc -std=c11 -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/packer_elf_alignment_gate.c &&
       run_with_timeout_seconds 8 "$helper"; then
        pass "packer unaligned ELF tables and failed-mutation transaction"
    else
        fail "packer ELF alignment and transaction gate" \
            "compile failed, malformed bounds were admitted, or mutation leaked"
    fi
    rm -f "$helper"
}

test_glibc_gnu_hash_shift_gate() {
    echo "--- GNU hash bloom-shift bounds gate ---"
    local helper="$BUILD/glibc_gnu_hash_gate"
    local sanitized="$BUILD/glibc_gnu_hash_gate.ubsan"
    local sanitizer_log="$BUILD/glibc_gnu_hash_gate.ubsan-build.log"
    local actual rc=0

    rm -f "$helper" "$sanitized" "$sanitizer_log"
    if gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$helper" tests/glibc_gnu_hash_gate.c && "$helper"; then
        pass "GNU hash bloom-shift admission boundary"
    else
        fail "GNU hash bloom-shift admission boundary" \
            "compile failed, shift 31 was rejected, or shift >= 32 was admitted"
        rm -f "$helper" "$sanitized" "$sanitizer_log"
        return
    fi

    # The ordinary control above catches fail-open admission even when a
    # sanitizer runtime is unavailable.  Where UBSan can be linked, rerun the
    # same malformed mutations so an out-of-range hash shift is also proven
    # free of C undefined behavior.
    if "$TEST_REAL_GCC" -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
            -fsanitize=undefined -fno-sanitize-recover=undefined -Iinclude \
            -o "$sanitized" tests/glibc_gnu_hash_gate.c \
            2>"$sanitizer_log"; then
        actual=""; rc=0
        capture_output actual env \
            UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
            "$sanitized" || rc=$?
        if [ "$rc" -eq 0 ]; then
            pass "GNU hash malformed-shift UBSan gate"
        else
            fail "GNU hash malformed-shift UBSan gate" \
                "exit=$rc output=$actual"
        fi
    else
        skip "GNU hash malformed-shift UBSan gate" \
            "compiler cannot link the undefined-behavior sanitizer"
    fi
    rm -f "$helper" "$sanitized" "$sanitizer_log"
}

strip_dlfreeze_warnings() {
    grep -v '^dlfreeze: warning:' || true
}

# Distinguish a target toolchain/runtime pair which implements GNU IFUNC from
# a broken test fixture.  Linkability alone is insufficient: for example,
# some musl-gcc/binutils combinations can emit AArch64 IRELATIVE relocations
# which their runtime loader rejects.  Exercise a local IFUNC relocation and
# call through it before enabling the real fixture.
compiler_supports_gnu_ifunc() {
    local root="$1"
    local src="$root/.dlfreeze-ifunc-probe.c"
    local lib="$root/.dlfreeze-ifunc-probe.so"
    local runner_src="$root/.dlfreeze-ifunc-probe-main.c"
    local runner="$root/.dlfreeze-ifunc-probe-main"

    cat > "$src" <<'C'
static int probe_impl(void) { return 0; }
static void *probe_resolver(void) { return (void *)probe_impl; }
static int dlfreeze_ifunc_probe(void)
    __attribute__((ifunc("probe_resolver")));
static int (*probe_pointer)(void) = dlfreeze_ifunc_probe;
int dlfreeze_ifunc_call(void) { return probe_pointer(); }
C
    cat > "$runner_src" <<'C'
#include <dlfcn.h>
typedef int (*probe_fn)(void);
int main(int argc, char **argv)
{
    void *handle;
    probe_fn probe;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    probe = (probe_fn)dlsym(handle, "dlfreeze_ifunc_call");
    if (!probe)
        return 4;
    return probe();
}
C
    if gcc -shared -fPIC -o "$lib" "$src" >/dev/null 2>&1 &&
       gcc -o "$runner" "$runner_src" -ldl >/dev/null 2>&1 &&
       (ulimit -c 0; run_with_timeout "$runner" "$lib" >/dev/null 2>&1); then
        rm -f "$src" "$lib" "$runner_src" "$runner"
        return 0
    fi
    rm -f "$src" "$lib" "$runner_src" "$runner"
    return 1
}

# Probe linker/compiler options with trivial inputs before using them in a
# fixture.  An unsupported option is a legitimate skip; once these probes
# succeed, failures in the real fixture are regressions and must be reported.
linker_supports_hash_style() {
    local root="$1" style="$2" tag dynamic
    local src="$root/.dlfreeze-hash-${style}-probe.c"
    local lib="$root/.dlfreeze-hash-${style}-probe.so"

    case "$style" in
        gnu) tag=GNU_HASH ;;
        sysv) tag=HASH ;;
        *) return 1 ;;
    esac

    cat > "$src" <<'C'
int dlfreeze_hash_style_probe(void) { return 0; }
C
    if ! gcc -shared -fPIC "-Wl,--hash-style=$style" -o "$lib" "$src" \
            >/dev/null 2>&1; then
        rm -f "$src" "$lib"
        return 1
    fi
    if command -v readelf >/dev/null 2>&1; then
        dynamic=$(LC_ALL=C readelf -d "$lib" 2>/dev/null || true)
        if ! grep -qF "($tag)" <<<"$dynamic"; then
            rm -f "$src" "$lib"
            return 1
        fi
    fi

    rm -f "$src" "$lib"
    return 0
}

compiler_supports_non_pie() {
    local root="$1"
    local src="$root/.dlfreeze-non-pie-probe.c"
    local bin="$root/.dlfreeze-non-pie-probe"

    cat > "$src" <<'C'
int main(void) { return 0; }
C
    if gcc -fno-pie -no-pie -o "$bin" "$src" >/dev/null 2>&1; then
        rm -f "$src" "$bin"
        return 0
    fi
    rm -f "$src" "$bin"
    return 1
}

# A successful `dlfreeze -d` may still intentionally produce an extraction-
# mode image when the embedded runtime is unsupported.  DLFREEZE_NO_FORK only
# disables fallback after direct metadata has been found, so it cannot make
# such an image a strict direct-load test.  Captured DATA instead fails
# admission when the runtime is unsupported; report that as an unsupported
# test target.  Keep the packer log and raw footer checks together so direct
# regressions cannot silently pass via extraction.
DIRECT_FREEZE_REASON=""
DIRECT_META_OFF=""
freeze_require_direct_with() {
    local freezer="$1" label="$2" log="$3" output="$4"
    local runtime_warning size footer_magic meta_off payload_end
    local direct_confirmed=0
    shift 4

    DIRECT_FREEZE_REASON=""
    DIRECT_META_OFF=""
    if ! run_freeze "$freezer" -d -o "$output" "$@" >"$log" 2>&1; then
        runtime_warning=$(grep -Em1 \
            '^dlfreeze: (captured files require a supported direct-load runtime|pathful traced dlopen entries require a supported direct-load mode|pathful DT_NEEDED entries require a supported direct-load mode)$' \
            "$log" || true)
        if [ -n "$runtime_warning" ]; then
            DIRECT_FREEZE_REASON=${runtime_warning#dlfreeze: }
            return 77
        fi
        fail "$label" "dlfreeze failed"
        return 1
    fi

    if grep -Eq \
        '^[[:space:]]*mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)[[:space:]]*$' \
        "$log"; then
        direct_confirmed=1
    fi
    runtime_warning=$(grep -Em1 \
        'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
        "$log" || true)
    if [ -n "$runtime_warning" ]; then
        if [ "$direct_confirmed" -eq 1 ]; then
            fail "$label" "packer reported contradictory direct-load modes"
            return 1
        fi
        DIRECT_FREEZE_REASON=${runtime_warning#dlfreeze: warning: }
        return 77
    fi
    if [ "$direct_confirmed" -ne 1 ]; then
        fail "$label" "packer did not confirm direct-load mode"
        return 1
    fi

    size=$(stat -c %s "$output" 2>/dev/null || true)
    if [[ ! "$size" =~ ^[0-9]+$ ]] || [ "$size" -lt 64 ]; then
        fail "$label" "direct-load output has no complete footer"
        return 1
    fi
    footer_magic=$(od -An -tx1 -j $((size - 64)) -N8 "$output" \
        2>/dev/null | tr -d '[:space:]')
    if [ "$footer_magic" != 444c465245455a00 ]; then
        fail "$label" "direct-load output has invalid footer magic"
        return 1
    fi
    meta_off=$(od -An -tu8 -j $((size - 24)) -N8 "$output" \
        2>/dev/null | tr -d '[:space:]')
    if [[ ! "$meta_off" =~ ^[0-9]+$ ]] || [ "$meta_off" = 0 ]; then
        fail "$label" "direct-load output has no metadata"
        return 1
    fi
    payload_end=$((size - 64))
    # Equal-length, digit-only decimal strings have numeric lexical order.
    # shellcheck disable=SC2071
    if [ "${#meta_off}" -gt "${#payload_end}" ] ||
       { [ "${#meta_off}" -eq "${#payload_end}" ] &&
         [[ "$meta_off" > "$payload_end" || "$meta_off" = "$payload_end" ]]; }; then
        fail "$label" "direct-load metadata offset lies outside payload"
        return 1
    fi

    DIRECT_META_OFF=$meta_off
    DIRECT_ARTIFACTS=$((DIRECT_ARTIFACTS + 1))
    return 0
}

freeze_require_direct() {
    freeze_require_direct_with "$DLFREEZE" "$@"
}

# ===================================================================
# Helper: freeze, run, compare
# ===================================================================
freeze_and_compare() {
    local label="$1" binary="$2" output="$3"
    shift 3  # remaining args are passed to both runs

    if ! run_freeze "$DLFREEZE" -v -o "$output" "$binary"; then
        fail "$label" "dlfreeze failed"; return 1
    fi
    if [ ! -x "$output" ]; then
        fail "$label" "output not executable"; return 1
    fi

    local expect actual rc_e=0 rc_a=0
    capture_output expect "$binary" "$@" || rc_e=$?
    capture_output actual "$output" "$@" || rc_a=$?

    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "$label"
    else
        fail "$label" "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi
}

# ===================================================================
# Test 1: simple hello-world program
# ===================================================================
test_hello() {
    echo "--- hello ---"
    local src="$BUILD/hello.c" bin="$BUILD/hello" out="$BUILD/hello.frozen"
    cat > "$src" <<'C'
#include <stdio.h>
#include <math.h>
int main(int argc, char **argv) {
    printf("Hello, World!\n");
    printf("argc=%d\n", argc);
    for (int i = 1; i < argc; i++) printf("  argv[%d]=%s\n", i, argv[i]);
    printf("sqrt(2)=%.6f\n", sqrt(2.0));
    return 0;
}
C
    gcc -o "$bin" "$src" -lm

    # compare (ignore argv[0] line by using args 1+)
    if ! run_freeze "$DLFREEZE" -v -o "$out" "$bin"; then fail "hello" "dlfreeze failed"; return; fi

    local expect actual rc_e=0 rc_a=0
    capture_output expect "$bin" foo bar || rc_e=$?
    capture_output actual "$out" foo bar || rc_a=$?
    expect=$(printf '%s\n' "$expect" | tail -n +2)
    actual=$(printf '%s\n' "$actual" | tail -n +2)
    if [ "$expect" = "$actual" ]; then pass "hello"; else
        fail "hello" "output differs"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi
    rm -f "$src" "$bin" "$out"
}

# Repeatable options are limited by argv/resources, not an unrelated parser
# array.  Omit the executable deliberately so this remains a pure option gate.
test_file_pattern_option_scaling() {
    echo "--- repeatable file-pattern option scaling ---"
    local -a arguments=(-d -t)
    local actual="" rc=0 i

    for ((i = 0; i < 80; i++)); do
        arguments+=(-f "/dlfreeze-option-scaling-$i/*")
    done
    capture_output actual "$DLFREEZE" "${arguments[@]}" || rc=$?
    if [ "$rc" -eq 1 ] &&
       [[ "$actual" == *"no executable specified"* ]] &&
       [[ "$actual" != *"too many -f patterns"* ]]; then
        pass "repeatable file patterns scale with argv"
    else
        fail "repeatable file-pattern option scaling" \
            "exit=$rc output=$actual"
    fi
}

# ===================================================================
# Test 1b: musl dynamic executable in direct-load mode
# ===================================================================
test_musl_hello_direct() {
    echo "--- musl hello direct-load ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-hello-direct" "musl-gcc not installed"
        return
    fi

    local src="$BUILD/hello_musl.c" bin="$BUILD/hello_musl"
    local out="$BUILD/hello_musl.frozen" log="$BUILD/hello_musl.log"
    rm -f "$log"
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) {
    puts("hello musl");
    return 0;
}
C

    if ! musl-gcc "$src" -o "$bin"; then
        fail "musl-hello-direct" "musl-gcc failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-hello-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-hello-direct" "native musl fixture is not runnable (exit $rc_e)"
        [ -z "$expect" ] || printf '  output: %s\n' "$expect"
        rm -f "$src" "$bin" "$out"
        return
    fi

    freeze_require_direct "musl-hello-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-hello-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "musl hello direct-load"
    else
        fail "musl hello direct-load" \
            "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    actual=""; rc_a=0
    capture_output actual env DLFREEZE_NO_FORK=1 \
        GLIBC_TUNABLES=glibc.malloc.perturb=17 "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "musl direct-load ignores GNU-only tunables"
    else
        fail "musl GNU-only tunables isolation" \
            "output or exit code differs (exit $rc_e vs $rc_a)"
    fi

    # musl folds historical libpthread/libm/librt/etc. SONAMEs into its
    # combined dynamic-linker/libc object.  Exercise that libc ABI rule with
    # a normal ELF mutation, independent of any application behavior.
    if ! command -v patchelf >/dev/null 2>&1; then
        skip "musl reserved SONAME direct-load" "patchelf not installed"
    elif ! LC_ALL=C readelf -d "$bin" 2>/dev/null |
            grep -F 'Shared library: [libc.so]' >/dev/null; then
        skip "musl reserved SONAME direct-load" \
            "fixture does not contain the canonical musl libc dependency"
    else
        local alias_bin="$BUILD/hello_musl_reserved"
        local alias_out="$BUILD/hello_musl_reserved.frozen"
        local alias_log="$BUILD/hello_musl_reserved.log"
        local alias_expect="" alias_actual="" alias_rc_e=0 alias_rc_a=0
        local alias_freeze_rc=0

        if ! cp "$bin" "$alias_bin" ||
           ! patchelf --replace-needed libc.so libpthread.so.0 \
                "$alias_bin"; then
            fail "musl reserved SONAME direct-load" \
                "could not create ELF fixture"
        else
            capture_output alias_expect "$alias_bin" || alias_rc_e=$?
            if [ "$alias_rc_e" -ne 0 ]; then
                fail "native musl reserved SONAME control" \
                    "exit=$alias_rc_e output=$alias_expect"
            else
                freeze_require_direct "musl-reserved-soname-direct" \
                    "$alias_log" "$alias_out" "$alias_bin" ||
                    alias_freeze_rc=$?
                if [ "$alias_freeze_rc" -eq 77 ]; then
                    skip "musl reserved SONAME direct-load" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$alias_freeze_rc" -eq 0 ]; then
                    capture_output alias_actual "$alias_out" ||
                        alias_rc_a=$?
                    if [ "$alias_rc_a" -eq "$alias_rc_e" ] &&
                       [ "$alias_actual" = "$alias_expect" ]; then
                        pass "musl reserved SONAME maps to libc provider"
                    else
                        fail "musl reserved SONAME direct-load" \
                            "exit=$alias_rc_a output=$alias_actual"
                    fi
                fi
            fi
        fi
        rm -f "$alias_bin" "$alias_out" "$alias_log"
    fi

    rm -f "$src" "$bin" "$out" "$log"
}

# GNU tunables are a private ld.so/libc contract which changes across glibc
# releases.  Direct mode supplies target defaults but must not silently ignore
# an explicit request; clean artifacts can fall back to their native loader.
test_glibc_tunable_environment_direct() {
    echo "--- glibc tunable environment direct-load policy ---"
    local src="$BUILD/glibc_tunable_environment.c"
    local bin="$BUILD/glibc_tunable_environment"
    local out="$BUILD/glibc_tunable_environment.frozen"
    local log="$BUILD/glibc_tunable_environment.log"
    local actual="" rc=0 freeze_rc=0 policy_env
    local label="glibc tunable environment direct-load policy"

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "host compiler does not target glibc"
        return
    fi
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("glibc-tunable-target-ran"); return 0; }
C
    if ! "$TEST_REAL_GCC" -o "$bin" "$src"; then
        fail "$label" "fixture compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 GLIBC_TUNABLES= \
        "$out" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = "glibc-tunable-target-ran" ]; then
        pass "glibc direct-load accepts an empty tunables value"
    else
        fail "$label" "empty value exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 \
        GLIBC_TUNABLES=glibc.malloc.perturb=17 "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"refusing direct load: nonempty GLIBC_TUNABLES is unsupported"* ]] &&
       [[ "$actual" != *"glibc-tunable-target-ran"* ]]; then
        pass "glibc direct-load refuses unimplemented tunables"
    else
        fail "$label" "nonempty value exit=$rc output=$actual"
    fi

    for policy_env in LD_BIND_NOW LD_DYNAMIC_WEAK LD_HWCAP_MASK; do
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$policy_env=dlfreeze-policy-test" "$out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"refusing direct load: nonempty $policy_env is unsupported"* ]] &&
           [[ "$actual" != *"glibc-tunable-target-ran"* ]]; then
            pass "glibc direct-load refuses semantic $policy_env"
        else
            fail "$label" "$policy_env exit=$rc output=$actual"
        fi
    done

    rm -f "$src" "$bin" "$out" "$log"
}

# The direct loader delegates tunable value width/default selection to an
# isolated image of the exact target interpreter.  Compare several scalar
# defaults which libc consumes after startup.  IDs are derived from that
# interpreter's own ordered table, never copied into the test.
test_glibc_tunable_defaults_direct() {
    echo "--- glibc compiled tunable defaults direct-load ---"
    local src="$BUILD/glibc_tunable_defaults.c"
    local bin="$BUILD/glibc_tunable_defaults"
    local out="$BUILD/glibc_tunable_defaults.frozen"
    local log="$BUILD/glibc_tunable_defaults.log"
    local interp list ids="" name id
    local expect="" actual="" rc_e=0 rc_a=0 freeze_rc=0
    local label="glibc compiled tunable defaults direct-load"

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "host compiler does not target glibc"
        return
    fi
    if ! command -v readelf >/dev/null 2>&1; then
        skip "$label" "readelf is unavailable"
        return
    fi
    interp=$(LC_ALL=C readelf -l /bin/true 2>/dev/null |
        sed -n 's@.*interpreter: \(.*\)]@\1@p' | head -n1)
    if [ -z "$interp" ] || [ ! -x "$interp" ]; then
        skip "$label" "target interpreter path is unavailable"
        return
    fi
    list=$("$interp" --list-tunables 2>/dev/null || true)
    for name in glibc.malloc.top_pad glibc.pthread.mutex_spin_count \
                glibc.pthread.stack_cache_size \
                glibc.rtld.optional_static_tls; do
        id=$(awk -v target="$name:" '$1 == target { print NR - 1; exit }' \
            <<<"$list")
        if [[ ! "$id" =~ ^[0-9]+$ ]]; then
            skip "$label" "interpreter does not expose an ordered $name entry"
            return
        fi
        ids+=" $id"
    done

    cat > "$src" <<'C'
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum tunable_id {
    TUNABLE_ID_ZERO = 0,
    TUNABLE_ID_FORCE_WIDTH = 0x7fffffff
};
union tunable_value {
    intmax_t numval;
    struct {
        const char *str;
        size_t len;
    } strval;
};
typedef void (*tunable_callback_t)(union tunable_value *);
extern void __tunable_get_val(enum tunable_id, void *, tunable_callback_t);

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        char *end = NULL;
        uint64_t value = UINT64_C(0xfeedfacecafebeef);
        long parsed;
        enum tunable_id id;

        errno = 0;
        parsed = strtol(argv[i], &end, 10);
        if (errno || !end || *end || parsed < 0 || parsed > 0x7fffffffL)
            return 2;
        id = (enum tunable_id)parsed;
        __tunable_get_val(id, &value, NULL);
        printf("%d:%016llx\n", (int)id, (unsigned long long)value);
    }
    return 0;
}
C
    # Link against the exact PT_INTERP object so GLIBC_PRIVATE provider
    # admission is exercised as well as the delegated accessor itself.
    if ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror -o "$bin" "$src" \
            "$interp"; then
        skip "$label" "compiler cannot link the target private accessor probe"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    # shellcheck disable=SC2086 # IDs are validated decimal words.
    capture_output expect "$bin" $ids || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "$label" "native private accessor probe exited $rc_e"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    # shellcheck disable=SC2086 # IDs are validated decimal words.
    capture_output actual "$out" $ids || rc_a=$?
    if [ "$rc_a" -eq "$rc_e" ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a expected=$rc_e output=$actual expected=$expect"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# GCC's gmon cleanup enters a hidden glibc dl_iterate_phdr implementation
# which requires the native rtld link_map namespace.  Verify that ordinary
# -pg inputs select extraction before pre-linking, and that an uncaptured DSO
# importing the same ABI is rejected transactionally by runtime dlopen.
test_glibc_gmon_loader_policy() {
    echo "--- glibc gmon native-loader policy ---"
    local src="$BUILD/glibc_gmon_profile.c"
    local bin="$BUILD/glibc_gmon_profile"
    local out="$BUILD/glibc_gmon_profile.frozen"
    local log="$BUILD/glibc_gmon_profile.log"
    local native_dir="$BUILD/glibc_gmon_native"
    local frozen_dir="$BUILD/glibc_gmon_frozen"
    local expect="" actual="" rc_e=0 rc_a=0 meta_off size
    local label="glibc gmon native-loader policy"
    local dso_src="$BUILD/glibc_gmon_dlopen_lib.c"
    local dso="$BUILD/libglibc_gmon_dlopen.so"
    local runner_src="$BUILD/glibc_gmon_dlopen.c"
    local runner="$BUILD/glibc_gmon_dlopen"
    local runner_out="$BUILD/glibc_gmon_dlopen.frozen"
    local runner_log="$BUILD/glibc_gmon_dlopen.log"
    local lookup_src="$BUILD/glibc_gmon_lookup.c"
    local lookup="$BUILD/glibc_gmon_lookup"
    local lookup_out="$BUILD/glibc_gmon_lookup.frozen"
    local lookup_log="$BUILD/glibc_gmon_lookup.log"
    local custom_root="$BUILD/glibc_gmon_custom_provider"
    local custom_provider_src="$custom_root/provider.c"
    local custom_provider_map="$custom_root/provider.map"
    local custom_provider="$custom_root/libcustom_gmon.so"
    local custom_main_src="$custom_root/main.c"
    local custom_main="$custom_root/main"
    local custom_main_out="$custom_root/main.frozen"
    local custom_main_log="$custom_root/main.log"
    local custom_dso_src="$custom_root/consumer.c"
    local custom_dso="$custom_root/libcustom_gmon_consumer.so"
    local custom_runner_src="$custom_root/runner.c"
    local custom_runner="$custom_root/runner"
    local custom_runner_out="$custom_root/runner.frozen"
    local custom_runner_log="$custom_root/runner.log"
    local freeze_rc=0

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "host compiler does not target glibc"
        return
    fi
    cat > "$src" <<'C'
int main(void) { return 23; }
C
    if ! "$TEST_REAL_GCC" -pg -o "$bin" "$src"; then
        skip "$label" "compiler does not support dynamic -pg fixtures"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    mkdir -p "$native_dir" "$frozen_dir"
    capture_output_in_dir expect "$native_dir" "$(readlink -f "$bin")" ||
        rc_e=$?
    if [ "$rc_e" -ne 23 ] || [ ! -s "$native_dir/gmon.out" ] ||
       [ "$(stat -c %s "$native_dir/gmon.out")" -le 20 ]; then
        skip "$label" "native -pg runtime did not produce a complete gmon.out"
        rm -f "$src" "$bin" "$out" "$log" "$native_dir/gmon.out"
        rmdir "$native_dir" "$frozen_dir" 2>/dev/null || true
        return
    fi

    if ! run_freeze "$DLFREEZE" -d -o "$out" "$bin" >"$log" 2>&1; then
        fail "$label" "dlfreeze failed"
    elif ! grep -Fq "requires glibc's native gmon loader ABI" "$log" &&
         ! grep -Eq \
             '^dlfreeze: warning: direct-load is unavailable for runtime [^;[:cntrl:]]+; creating an extraction-mode binary$' \
             "$log"; then
        fail "$label" \
            "packer reported neither the gmon policy nor an extraction-only runtime"
    elif grep -Eq '^[[:space:]]*mode[[:space:]]*:[[:space:]]*direct-load' \
            "$log"; then
        fail "$label" "profiled input was still packaged for direct loading"
    else
        size=$(stat -c %s "$out" 2>/dev/null || true)
        meta_off=""
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
            meta_off=$(od -An -tu8 -j $((size - 24)) -N8 "$out" \
                2>/dev/null | tr -d '[:space:]')
        fi
        capture_output_in_dir actual "$frozen_dir" "$(readlink -f "$out")" ||
            rc_a=$?
        if [ "$meta_off" = 0 ] && [ "$rc_a" -eq "$rc_e" ] &&
           [ "$actual" = "$expect" ] && [ -s "$frozen_dir/gmon.out" ] &&
           [ "$(stat -c %s "$frozen_dir/gmon.out")" -gt 20 ]; then
            pass "glibc gmon input uses native extraction loader"
        else
            fail "$label" "meta=$meta_off exit=$rc_a output=$actual"
        fi
    fi

    cat > "$dso_src" <<'C'
extern void _mcleanup(void);
void dlfreeze_gmon_cleanup_reference(void) { _mcleanup(); }
C
    cat > "$runner_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    const char *error;
    void *handle;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle)
        return 3;
    error = dlerror();
    if (!error || !strstr(error, "gmon profiling requires the native loader"))
        return 4;
    puts("gmon-dso-refused");
    return 0;
}
C
    if ! "$TEST_REAL_GCC" -shared -fPIC -o "$dso" "$dso_src" ||
       ! "$TEST_REAL_GCC" -o "$runner" "$runner_src" -ldl; then
        fail "glibc gmon dlopen gate" "fixture compile failed"
    else
        freeze_require_direct "glibc gmon dlopen gate" "$runner_log" \
            "$runner_out" "$runner" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "glibc gmon dlopen gate" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc_a=0
            capture_output actual "$runner_out" "$(readlink -f "$dso")" ||
                rc_a=$?
            if [ "$rc_a" -eq 0 ] && [ "$actual" = "gmon-dso-refused" ]; then
                pass "glibc gmon dlopen import fails before activation"
            else
                fail "glibc gmon dlopen gate" "exit=$rc_a output=$actual"
            fi
        fi
    fi

    # These names are not reserved ABI capabilities.  A custom DSO may
    # export them, and an import versioned to that DSO must keep ordinary ELF
    # semantics at startup and during transactional dlopen.
    mkdir -p "$custom_root"
    cat > "$custom_provider_src" <<'C'
#include <stdint.h>
#include <stdio.h>
void _mcleanup(void) { puts("custom-gmon-provider"); }
void __monstartup(uintptr_t low, uintptr_t high)
{
    (void)low;
    (void)high;
}
C
    cat > "$custom_provider_map" <<'MAP'
CUSTOM_GMON_1 {
    global: _mcleanup; __monstartup;
    local: *;
};
MAP
    cat > "$custom_main_src" <<'C'
extern void _mcleanup(void);
int main(void) { _mcleanup(); return 0; }
C
    cat > "$custom_dso_src" <<'C'
extern void _mcleanup(void);
void call_custom_gmon_provider(void) { _mcleanup(); }
C
    cat > "$custom_runner_src" <<'C'
#include <dlfcn.h>
typedef void (*call_fn)(void);
int main(int argc, char **argv)
{
    call_fn call;
    void *handle;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    *(void **)(&call) = dlsym(handle, "call_custom_gmon_provider");
    if (!call || dlerror())
        return 4;
    call();
    return 0;
}
C
    if ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror -shared -fPIC \
            -Wl,-soname,libcustom_gmon.so \
            -Wl,--version-script,"$custom_provider_map" \
            -o "$custom_provider" "$custom_provider_src" ||
       ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror \
            -Wl,-rpath,'$ORIGIN' -o "$custom_main" "$custom_main_src" \
            -L"$custom_root" -Wl,--no-as-needed -lcustom_gmon ||
       ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror -shared -fPIC \
            -Wl,-soname,libcustom_gmon_consumer.so -Wl,-rpath,'$ORIGIN' \
            -o "$custom_dso" "$custom_dso_src" -L"$custom_root" \
            -Wl,--no-as-needed -lcustom_gmon ||
       ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror \
            -o "$custom_runner" "$custom_runner_src" -ldl; then
        fail "custom gmon provider semantics" "fixture compile failed"
    else
        actual=""; rc_a=0; freeze_rc=0
        capture_output actual "$custom_main" || rc_a=$?
        if [ "$rc_a" -ne 0 ] || [ "$actual" != "custom-gmon-provider" ]; then
            fail "custom gmon startup provider" \
                "native exit=$rc_a output=$actual"
        else
            freeze_require_direct "custom gmon startup provider" \
                "$custom_main_log" "$custom_main_out" "$custom_main" ||
                freeze_rc=$?
            if [ "$freeze_rc" -eq 77 ]; then
                skip "custom gmon startup provider" "$DIRECT_FREEZE_REASON"
            elif [ "$freeze_rc" -eq 0 ]; then
                actual=""; rc_a=0
                capture_output actual "$custom_main_out" || rc_a=$?
                if [ "$rc_a" -eq 0 ] &&
                   [ "$actual" = "custom-gmon-provider" ]; then
                    pass "custom gmon startup provider remains direct"
                else
                    fail "custom gmon startup provider" \
                        "exit=$rc_a output=$actual"
                fi
            fi
        fi

        actual=""; rc_a=0; freeze_rc=0
        capture_output actual "$custom_runner" \
            "$(readlink -f "$custom_dso")" || rc_a=$?
        if [ "$rc_a" -ne 0 ] || [ "$actual" != "custom-gmon-provider" ]; then
            fail "custom gmon dlopen provider" \
                "native exit=$rc_a output=$actual"
        else
            freeze_require_direct "custom gmon dlopen provider" \
                "$custom_runner_log" "$custom_runner_out" \
                "$custom_runner" || freeze_rc=$?
            if [ "$freeze_rc" -eq 77 ]; then
                skip "custom gmon dlopen provider" "$DIRECT_FREEZE_REASON"
            elif [ "$freeze_rc" -eq 0 ]; then
                actual=""; rc_a=0
                capture_output actual "$custom_runner_out" \
                    "$(readlink -f "$custom_dso")" || rc_a=$?
                actual=$(printf '%s\n' "$actual" |
                    strip_dlfreeze_warnings)
                if [ "$rc_a" -eq 0 ] &&
                   [ "$actual" = "custom-gmon-provider" ]; then
                    pass "custom gmon dlopen provider remains selectable"
                else
                    fail "custom gmon dlopen provider" \
                        "exit=$rc_a output=$actual"
                fi
            fi
        fi
    fi

    cat > "$lookup_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__aarch64__)
#define GMON_BASE_VERSION "GLIBC_2.17"
#elif defined(__x86_64__)
#define GMON_BASE_VERSION "GLIBC_2.2.5"
#else
#error unsupported gmon test architecture
#endif

static void invoke_if_present(const char *name, void *address)
{
    if (strcmp(name, "__monstartup") == 0)
        ((void (*)(uintptr_t, uintptr_t))address)(0, 0);
    else
        ((void (*)(void))address)();
}

static int check_name(const char *name)
{
    const char *error;
    void *address;

    (void)dlerror();
    address = dlsym(RTLD_DEFAULT, name);
    if (address) {
        invoke_if_present(name, address);
        return 1;
    }
    error = dlerror();
    if (!error || !strstr(error, "gmon profiling requires the native loader"))
        return 2;

    (void)dlerror();
    address = dlvsym(RTLD_DEFAULT, name, GMON_BASE_VERSION);
    if (address) {
        invoke_if_present(name, address);
        return 3;
    }
    error = dlerror();
    if (!error || !strstr(error, "gmon profiling requires the native loader"))
        return 4;
    return 0;
}

int main(void)
{
    if (check_name("__monstartup") != 0 || check_name("_mcleanup") != 0)
        return 5;
    puts("gmon-symbol-lookups-refused");
    return 0;
}
C
    freeze_rc=0
    if ! "$TEST_REAL_GCC" -O2 -Wall -Wextra -Werror -o "$lookup" \
            "$lookup_src" -ldl; then
        fail "glibc gmon API lookup gate" "fixture compile failed"
    else
        freeze_require_direct "glibc gmon API lookup gate" "$lookup_log" \
            "$lookup_out" "$lookup" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "glibc gmon API lookup gate" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc_a=0
            capture_output actual "$lookup_out" || rc_a=$?
            if [ "$rc_a" -eq 0 ] &&
               [ "$actual" = "gmon-symbol-lookups-refused" ]; then
                pass "glibc gmon dlsym/dlvsym lifecycle gate"
            else
                fail "glibc gmon API lookup gate" \
                    "exit=$rc_a output=$actual"
            fi
        fi
    fi

    rm -f "$src" "$bin" "$out" "$log" "$native_dir/gmon.out" \
        "$frozen_dir/gmon.out" "$dso_src" "$dso" "$runner_src" "$runner" \
        "$runner_out" "$runner_log" "$lookup_src" "$lookup" \
        "$lookup_out" "$lookup_log"
    rm -rf "$custom_root"
    rmdir "$native_dir" "$frozen_dir" 2>/dev/null || true
}

# ===================================================================
# Test 1c: musl direct-load preserves main executable constructors
# ===================================================================
test_musl_ctor_direct() {
    echo "--- musl ctor direct-load ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-ctor-direct" "musl-gcc not installed"
        return
    fi

    local src="$BUILD/ctor_musl.c" bin="$BUILD/ctor_musl"
    local out="$BUILD/ctor_musl.frozen" log="$BUILD/ctor_musl.log"
    rm -f "$log"
    cat > "$src" <<'C'
#include <stdio.h>

static int ctor_ran;

__attribute__((constructor)) static void init(void) {
    ctor_ran = 7;
    puts("ctor");
}

int main(void) {
    printf("main:%d\n", ctor_ran);
    return ctor_ran != 7;
}
C

    if ! musl-gcc "$src" -o "$bin"; then
        fail "musl-ctor-direct" "musl-gcc failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-ctor-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-ctor-direct" "native musl fixture is not runnable (exit $rc_e)"
        [ -z "$expect" ] || printf '  output: %s\n' "$expect"
        rm -f "$src" "$bin" "$out"
        return
    fi

    freeze_require_direct "musl-ctor-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-ctor-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl ctor direct-load"
    else
        fail "musl ctor direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1d: musl direct-load fixes COPY-relocated stderr/stdout aliases
# ===================================================================
test_musl_copy_reloc_direct() {
    echo "--- musl copy-reloc direct-load ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-copy-reloc-direct" "musl-gcc not installed"
        return
    fi

    local src="$BUILD/copy_reloc_musl.c" bin="$BUILD/copy_reloc_musl"
    local out="$BUILD/copy_reloc_musl.frozen" log="$BUILD/copy_reloc_musl.log"
    rm -f "$log"
    cat > "$src" <<'C'
#include <stdio.h>

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    fputs("copy-reloc-ok\n", stderr);
    return 0;
}
C

    if ! musl-gcc "$src" -o "$bin"; then
        fail "musl-copy-reloc-direct" "musl-gcc failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-copy-reloc-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! readelf -W -r "$bin" |
            grep 'R_X86_64_COPY.*stderr' >/dev/null; then
        skip "musl-copy-reloc-direct" "musl-gcc did not emit stderr COPY relocation"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-copy-reloc-direct" "native musl fixture is not runnable (exit $rc_e)"
        [ -z "$expect" ] || printf '  output: %s\n' "$expect"
        rm -f "$src" "$bin" "$out"
        return
    fi

    freeze_require_direct "musl-copy-reloc-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-copy-reloc-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl copy-reloc direct-load"
    else
        fail "musl copy-reloc direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1e: musl direct-load seeds thread locale for multibyte APIs
# ===================================================================
test_musl_multibyte_direct() {
    echo "--- musl multibyte direct-load ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-multibyte-direct" "musl-gcc not installed"
        return
    fi

    local src="$BUILD/multibyte_musl.c" bin="$BUILD/multibyte_musl"
    local out="$BUILD/multibyte_musl.frozen" log="$BUILD/multibyte_musl.log"
    rm -f "$log"
    cat > "$src" <<'C'
#include <stdio.h>
#include <wchar.h>

int main(void) {
    wchar_t out[8] = {0};
    const char *src = "abc";
    size_t n = mbsrtowcs(out, &src, 8, NULL);
    printf("%zu %u %u %u\n", n,
           (unsigned)out[0], (unsigned)out[1], (unsigned)out[2]);
    return !(n == 3 && src == NULL && out[0] == L'a' && out[1] == L'b' && out[2] == L'c');
}
C

    if ! musl-gcc "$src" -o "$bin"; then
        fail "musl-multibyte-direct" "musl-gcc failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-multibyte-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-multibyte-direct" "native musl fixture is not runnable (exit $rc_e)"
        [ -z "$expect" ] || printf '  output: %s\n' "$expect"
        rm -f "$src" "$bin" "$out"
        return
    fi

    freeze_require_direct "musl-multibyte-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-multibyte-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl multibyte direct-load"
    else
        fail "musl multibyte direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1f: musl direct-load populates DTV for shared-library TLS modules
# ===================================================================
test_musl_shared_tls_direct() {
    echo "--- musl shared-tls direct-load ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-shared-tls-direct" "musl-gcc not installed"
        return
    fi

    local src_lib="$BUILD/tlsdep_musl.c" src_main="$BUILD/tlsmain_musl.c"
    local lib="$BUILD/libtlsdep_musl.so" bin="$BUILD/tlsmain_musl"
    local out="$BUILD/tlsmain_musl.frozen" log="$BUILD/tlsmain_musl.log"
    rm -f "$log"
    cat > "$src_lib" <<'C'
__thread int tls_value = 41;

int get_tls_value(void) {
    return ++tls_value;
}
C
    cat > "$src_main" <<'C'
#include <stdio.h>

int get_tls_value(void);

int main(void) {
    printf("%d\n", get_tls_value());
    return 0;
}
C

    if ! musl-gcc -shared -fPIC -Wl,-soname,libtlsdep_musl.so -o "$lib" "$src_lib"; then
        fail "musl-shared-tls-direct" "musl-gcc failed building shared library"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    if ! readelf -W -l "$lib" | grep 'TLS' >/dev/null; then
        skip "musl-shared-tls-direct" "musl-gcc did not emit PT_TLS for the shared library"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    if ! musl-gcc -Wl,-rpath,'$ORIGIN' -L"$BUILD" -o "$bin" "$src_main" -ltlsdep_musl; then
        fail "musl-shared-tls-direct" "musl-gcc failed building main executable"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-shared-tls-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-shared-tls-direct" "native musl fixture is not runnable (exit $rc_e)"
        [ -z "$expect" ] || printf '  output: %s\n' "$expect"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    freeze_require_direct "musl-shared-tls-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-shared-tls-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl shared-tls direct-load"
    else
        fail "musl shared-tls direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1g: target-derived musl pthread/TLS/locale startup contract
# ===================================================================
test_musl_target_contract_direct() {
    echo "--- musl target-derived startup contract ---"
    if ! command -v musl-gcc &>/dev/null; then
        skip "musl-target-contract-direct" "musl-gcc not installed"
        return
    fi

    local bin="$BUILD/musl_target_contract"
    local out="$BUILD/musl_target_contract.frozen"
    local log="$BUILD/musl_target_contract.log"
    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    rm -f "$bin" "$out" "$log"

    if ! musl-gcc -O2 -pthread tests/musl_target_contract.c -o "$bin"; then
        fail "musl-target-contract-direct" "musl-gcc failed"
        rm -f "$bin" "$out" "$log"
        return
    fi
    if ! file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl-target-contract-direct" \
            "musl-gcc did not produce a dynamic musl executable"
        rm -f "$bin" "$out" "$log"
        return
    fi

    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        skip "musl-target-contract-direct" \
            "native musl fixture is not runnable (exit $rc_e)"
        rm -f "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "musl-target-contract-direct" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl-target-contract-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$bin" "$out" "$log"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl target-derived pthread/TLS/locale contract"
    else
        fail "musl target-derived pthread/TLS/locale contract" \
            "strict direct output or exit differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi
    rm -f "$bin" "$out" "$log"
}

# ===================================================================
# Runtime-family classification follows validated interpreter contents, not
# the installed PT_INTERP basename.  The layout-gate tests below separately
# cover content which is genuinely unknown or stale.
# ===================================================================
test_renamed_runtime_identity() {
    echo "--- renamed runtime content identity ---"
    if ! command -v readelf &>/dev/null; then
        skip "renamed runtime content identity" "readelf not installed"
        return
    fi

    local src="$BUILD/renamed_runtime.c" probe="$BUILD/renamed_runtime_probe"
    local bin="$BUILD/renamed_runtime" out="$BUILD/renamed_runtime.frozen"
    local log="$BUILD/renamed_runtime.log"
    local custom="$BUILD/custom-runtime" interp interp_dir actual
    local alias="$BUILD/custom-runtime-hardlink"
    local trace="$BUILD/custom-runtime-hardlink.trace"
    local gate="$BUILD/dep_interpreter_trace_gate"
    local gate_log="$BUILD/dep_interpreter_trace_gate.log"
    local alias_abs alias_hex
    local cc=gcc rc=0 freeze_rc=0
    local label="renamed runtime content identity"
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("renamed runtime direct ok"); return 0; }
C
    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
        # Deliberately collide with glibc's libc SONAME.  Interpreter
        # pathname basenames are not ELF runtime identities and must not make
        # the glibc-linked trace helper outrank the musl helper.
        custom="$BUILD/libc.so.6"
    fi
    if ! "$cc" -o "$probe" "$src"; then
        fail "$label" "probe compile failed"
        rm -f "$src" "$probe"
        return
    fi
    interp=$(LC_ALL=C readelf -W -l "$probe" 2>/dev/null |
        sed -n 's@.*Requesting program interpreter: \([^]]*\).*@\1@p')
    if [ -z "$interp" ] || [ ! -r "$interp" ]; then
        skip "$label" "could not locate target interpreter"
        rm -f "$src" "$probe"
        return
    fi
    interp_dir=$(dirname "$(readlink -f "$interp")")
    if ! cp -L "$interp" "$custom" ||
       ! "$cc" -Wl,--dynamic-linker="$(realpath "$custom")" \
            -Wl,-rpath="$interp_dir" -o "$bin" "$src"; then
        fail "$label" "renamed-interpreter fixture compile failed"
        rm -f "$src" "$probe" "$bin" "$custom"
        return
    fi

    # An already-mapped interpreter is identified by its file ID, not its
    # PT_INTERP pathname.  A traced hardlink spelling must therefore be
    # ignored rather than becoming a dlopen alias (or, for musl, mutating the
    # startup libc entry into a traced object).
    rm -f "$alias" "$trace" "$gate" "$gate_log"
    if ! ln "$custom" "$alias" ||
       ! gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_interpreter_trace_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "traced interpreter hardlink identity" \
            "fixture or resolver gate compile failed"
    else
        alias_abs=$(realpath "$alias")
        alias_hex=$(printf '%s' "$alias_abs" | od -An -tx1 | tr -d ' \n')
        printf '#DLFREEZE_DLOPEN_TRACE_V4\nP %s %s %s\n' \
            "$alias_hex" "$alias_hex" "$alias_hex" >"$trace"
        if "$gate" "$bin" "$trace" "$alias_abs" >"$gate_log" 2>&1; then
            pass "traced interpreter hardlink identity"
        else
            fail "traced interpreter hardlink identity" \
                "resolver packaged an already-mapped file identity"
        fi
    fi

    freeze_require_direct "$label" "$log" "$out" -v -t -- "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$probe" "$bin" "$out" "$custom" "$log" \
            "$alias" "$trace" "$gate" "$gate_log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$probe" "$bin" "$out" "$custom" "$log" \
            "$alias" "$trace" "$gate" "$gate_log"
        return
    fi

    # On a glibc-targeting host the ordinary helper is glibc-linked and the
    # separately built static-musl helper must win.  On a musl-native host
    # both helper builds have the target runtime identity, so the stable
    # candidate order legitimately selects the ordinary helper.
    if [ "$cc" = musl-gcc ] && compiler_targets_glibc &&
       ! grep -Eq 'trace helper: .*dlfreeze-preload-static\.so$' "$log"; then
        fail "$label" \
            "colliding interpreter basename selected the wrong trace helper"
        rm -f "$src" "$probe" "$bin" "$out" "$custom" "$log" \
            "$alias" "$trace" "$gate" "$gate_log"
        return
    fi

    # The source pathname must play no role after its bytes are embedded.
    rm -f "$custom"
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "renamed runtime direct ok" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc output=$actual"
    fi
    rm -f "$src" "$probe" "$bin" "$out" "$custom" "$log" \
        "$alias" "$trace" "$gate" "$gate_log"
}

# ===================================================================
# The direct loader must not import bootstrap memory/string/syscall helpers.
# This object-level gate catches both explicit calls and calls synthesized by
# compiler lowering (for example, a struct copy becoming memcpy at -O2).
# ===================================================================
test_loader_post_tls_import_gate() {
    echo "--- direct loader post-TLS import gate ---"

    local -a compilers=("$TEST_REAL_GCC")
    local cc object label imports

    if command -v musl-gcc >/dev/null 2>&1 &&
       [ "$(command -v musl-gcc)" != "$(command -v "$TEST_REAL_GCC")" ]; then
        compilers+=(musl-gcc)
    fi
    if ! command -v nm >/dev/null 2>&1; then
        skip "direct loader bootstrap-neutral imports" "nm not installed"
        return
    fi

    for cc in "${compilers[@]}"; do
        label="direct loader bootstrap-neutral imports ($cc)"
        object="$BUILD/loader-post-tls-$(basename "$cc").o"
        if ! "$cc" -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
                -fno-stack-protector -ffunction-sections -fdata-sections \
                -c src/loader.c -o "$object"; then
            fail "$label" "loader object compile failed"
            rm -f "$object"
            continue
        fi
        imports=$(nm -u "$object" 2>/dev/null | awk '{print $NF}' | \
            grep -E '^(memcpy|memmove|memset|memchr|memcmp|bcmp|bzero|strlen|strnlen|strcmp|strncmp|strchr|strrchr|strstr|strcpy|strncpy|strcat|strncat|syscall|__errno_location|__atomic_.*|__aarch64_(swp|cas).*)$' || true)
        if [ -n "$imports" ]; then
            fail "$label" "forbidden imports: $(tr '\n' ' ' <<<"$imports")"
        else
            pass "$label"
        fi
        rm -f "$object"
    done
}

# ===================================================================
# Once direct mode installs target TLS, loader syscalls and errno propagation
# must not re-enter the bootstrap libc.  Build the same bootstrap with static
# glibc to prove this is a capability contract rather than a musl identity
# heuristic.  Environments without a static glibc toolchain skip this probe.
# ===================================================================
test_direct_bootstrap_libc_independence() {
    echo "--- direct bootstrap libc independence ---"

    local build_abs root src plugin_src bin plugin data out log bootstrap_log
    local actual musl_bin musl_plugin musl_data musl_out musl_log
    local rc=0 freeze_rc=0
    local label="direct static-glibc bootstrap to glibc target"
    local musl_label="direct static-glibc bootstrap to musl target"

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "compiler does not target glibc"
        return
    fi

    build_abs=$(cd "$BUILD" && pwd -P)
    root=$(mktemp -d "$build_abs/bootstrap-libc.XXXXXX")
    src="$root/main.c"
    plugin_src="$root/plugin.c"
    bin="$root/main"
    plugin="$root/libbootstrap_probe.so"
    data="$root/data"
    out="$root/main.frozen"
    log="$root/freeze.log"
    bootstrap_log="$root/bootstrap.log"

    cat > "$plugin_src" <<'C'
__thread int bootstrap_probe_tls = 72;
int bootstrap_probe(void) { return ++bootstrap_probe_tls; }
C
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*probe_fn)(void);
static const char *data_path;

static void finalizer(void) { puts("bootstrap-neutral-atexit-ok"); }

static void *thread_main(void *unused) {
    char byte = 0;
    int fd;

    (void)unused;
    errno = 0;
    if (open("/definitely/not/present/dlfreeze-bootstrap", O_RDONLY) >= 0 ||
        errno != ENOENT)
        return (void *)1;
    errno = EDOM;
    fd = open(data_path, O_RDONLY);
    if (fd < 0)
        return (void *)2;
    if (errno != EDOM)
        return (void *)3;
    if (read(fd, &byte, 1) != 1 || byte != 'x')
        return (void *)4;
    if (close(fd) != 0)
        return (void *)5;
    errno = 0;
    fd = open(data_path, O_WRONLY);
    if (fd >= 0)
        close(fd);                 /* native tracing run */
    else if (errno != EROFS)
        return (void *)6;          /* frozen VFS run */
    return NULL;
}

int main(int argc, char **argv) {
    pthread_t thread;
    void *thread_result = NULL;
    void *handle;
    probe_fn probe;
    int thread_error;

    if (argc != 3 || atexit(finalizer) != 0)
        return 2;
    data_path = argv[1];
    thread_error = pthread_create(&thread, NULL, thread_main, NULL);
    if (thread_error != 0)
        return 3;
    thread_error = pthread_join(thread, &thread_result);
    if (thread_error != 0)
        return 4;
    if (thread_result)
        return 10 + (int)(unsigned long)thread_result;
    handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 20;
    probe = (probe_fn)dlsym(handle, "bootstrap_probe");
    if (!probe || probe() != 73 || dlclose(handle) != 0)
        return 21;
    puts("bootstrap-neutral-ok");
    return 0;
}
C
    printf x > "$data"

    if ! "$TEST_REAL_GCC" -Wall -Wextra -Werror -O2 -D_GNU_SOURCE \
            -Iinclude -fno-stack-protector -ffunction-sections \
            -fdata-sections -static -Wl,--gc-sections \
            -Wl,-Ttext-segment=0x40000000 \
            -o "$root/dlfreeze-bootstrap" src/bootstrap.c src/loader.c \
            >"$bootstrap_log" 2>&1; then
        skip "$label" "static glibc bootstrap is unavailable"
        rm -rf "$root"
        return
    fi
    if ! cp "$DLFREEZE" "$root/dlfreeze" ||
       ! cp "$BUILD/dlfreeze-preload.so" "$root/dlfreeze-preload.so" ||
       ! cp "$BUILD/dlfreeze-preload-static.so" \
              "$root/dlfreeze-preload-static.so" ||
       ! gcc -shared -fPIC -Wl,-soname,libbootstrap_probe.so \
              -o "$plugin" "$plugin_src" ||
       ! gcc -O2 -pthread -o "$bin" "$src" -ldl; then
        fail "$label" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct_with "$root/dlfreeze" "$label" "$log" "$out" \
        -t -f "$data" -- "$bin" "$data" "$plugin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        mv "$data" "${data}.source"
        mv "$plugin" "${plugin}.source"
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" \
            "$data" "$plugin" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] &&
           [ "$actual" = \
               $'bootstrap-neutral-ok\nbootstrap-neutral-atexit-ok' ]; then
            pass "$label"
        else
            fail "$label" "exit=$rc output=$actual"
        fi
    fi

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "$musl_label" "musl-gcc not installed"
        rm -rf "$root"
        return
    fi
    musl_bin="$root/main-musl"
    musl_plugin="$root/libbootstrap_probe_musl.so"
    musl_data="$root/data-musl"
    musl_out="$root/main-musl.frozen"
    musl_log="$root/freeze-musl.log"
    printf x > "$musl_data"
    if ! musl-gcc -shared -fPIC \
            -Wl,-soname,libbootstrap_probe_musl.so \
            -o "$musl_plugin" "$plugin_src" ||
       ! musl-gcc -O2 -pthread -o "$musl_bin" "$src" -ldl; then
        fail "$musl_label" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    freeze_rc=0
    freeze_require_direct_with "$root/dlfreeze" "$musl_label" \
        "$musl_log" "$musl_out" -t -f "$musl_data" -- \
        "$musl_bin" "$musl_data" "$musl_plugin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$musl_label" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        mv "$musl_data" "${musl_data}.source"
        mv "$musl_plugin" "${musl_plugin}.source"
        actual=""
        rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$musl_out" \
            "$musl_data" "$musl_plugin" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] &&
           [ "$actual" = \
               $'bootstrap-neutral-ok\nbootstrap-neutral-atexit-ok' ]; then
            pass "$musl_label"
        else
            fail "$musl_label" "exit=$rc output=$actual"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 1g: glibc direct-load exposes a valid __libc_stack_end
# ===================================================================
test_glibc_stack_end_direct() {
    echo "--- glibc stack-end direct-load ---"

    if ! command -v file &>/dev/null; then
        skip "glibc-stack-end-direct" "file(1) not installed"
        return
    fi

    local src="$BUILD/libc_stack_end.c" bin="$BUILD/libc_stack_end"
    local out="$BUILD/libc_stack_end.frozen" log="$BUILD/libc_stack_end.log"
    rm -f "$log"
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argc;

    void **slot = (void **)dlsym(RTLD_DEFAULT, "__libc_stack_end");
    void *expected = (void *)(argv - 1);

    if (!slot || *slot != expected) {
        fprintf(stderr,
                "__libc_stack_end mismatch slot=%p value=%p expected=%p\n",
                (void *)slot, slot ? *slot : NULL, expected);
        return 1;
    }

    puts("stack-end-ok");
    return 0;
}
C

    if ! gcc -o "$bin" "$src" -ldl; then
        fail "glibc-stack-end-direct" "gcc failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep 'interpreter .*ld-linux' >/dev/null; then
        skip "glibc-stack-end-direct" "gcc did not produce a dynamic glibc executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    capture_output expect "$bin" || rc_e=$?

    freeze_require_direct "glibc-stack-end-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "glibc-stack-end-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "glibc stack-end direct-load"
    else
        fail "glibc stack-end direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1ga: constructors and the executable entry share one main stack
# ===================================================================
test_direct_constructor_stack_identity() {
    echo "--- direct constructor/main stack identity ---"
    local src="$BUILD/constructor_stack_identity.c"
    local bin="$BUILD/constructor_stack_identity"
    local out="$BUILD/constructor_stack_identity.frozen"
    local log="$BUILD/constructor_stack_identity.log"
    local musl_bin="$BUILD/constructor_stack_identity.musl"
    local musl_out="$BUILD/constructor_stack_identity.musl.frozen"
    local musl_log="$BUILD/constructor_stack_identity.musl.log"
    local expect actual freeze_rc=0 rc_e=0 rc=0

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static uintptr_t constructor_sp;
static uintptr_t constructor_base;
static size_t constructor_size;
static int constructor_status;

static int current_stack(uintptr_t *base, size_t *size)
{
    pthread_attr_t attr;
    void *address = NULL;

    if (pthread_getattr_np(pthread_self(), &attr) != 0)
        return -1;
    if (pthread_attr_getstack(&attr, &address, size) != 0) {
        pthread_attr_destroy(&attr);
        return -1;
    }
    pthread_attr_destroy(&attr);
    *base = (uintptr_t)address;
    return 0;
}

__attribute__((constructor))
static void remember_constructor_stack(void)
{
    volatile unsigned char marker = 0;

    constructor_sp = (uintptr_t)&marker;
    constructor_status = current_stack(&constructor_base, &constructor_size);
}

int main(void)
{
    volatile unsigned char marker = 0;
    uintptr_t main_sp = (uintptr_t)&marker;
    uintptr_t main_base = 0;
    size_t main_size = 0;

    if (constructor_status != 0 ||
        current_stack(&main_base, &main_size) != 0 ||
        constructor_size == 0 || main_size == 0 ||
        constructor_base > UINTPTR_MAX - constructor_size ||
        main_base > UINTPTR_MAX - main_size)
        return 2;
    if (constructor_sp < constructor_base ||
        constructor_sp >= constructor_base + constructor_size ||
        main_sp < main_base || main_sp >= main_base + main_size)
        return 3;
    if (constructor_base != main_base || constructor_size != main_size)
        return 4;
    puts("constructor-stack-ok");
    return 0;
}
C

    if ! gcc -Wall -Wextra -Werror -o "$bin" "$src" -pthread; then
        fail "direct constructor/main stack identity" "fixture compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "constructor-stack-ok" ]; then
        fail "native constructor/main stack identity" \
            "exit=$rc_e output=$expect"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "direct constructor/main stack identity" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct constructor/main stack identity" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "direct constructor/main stack identity"
        else
            fail "direct constructor/main stack identity" \
                "exit=$rc expected=$expect actual=$actual"
        fi
    fi
    if command -v musl-gcc >/dev/null 2>&1; then
        expect=""; actual=""; freeze_rc=0; rc_e=0; rc=0
        if ! musl-gcc -Wall -Wextra -Werror -o "$musl_bin" "$src" \
                -pthread; then
            fail "musl direct constructor/main stack identity" \
                "fixture compile failed"
        else
            capture_output expect "$musl_bin" || rc_e=$?
            if [ "$rc_e" -ne 0 ] ||
               [ "$expect" != "constructor-stack-ok" ]; then
                fail "native musl constructor/main stack identity" \
                    "exit=$rc_e output=$expect"
            else
                freeze_require_direct \
                    "musl direct constructor/main stack identity" \
                    "$musl_log" "$musl_out" "$musl_bin" || freeze_rc=$?
                if [ "$freeze_rc" -eq 77 ]; then
                    skip "musl direct constructor/main stack identity" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$freeze_rc" -eq 0 ]; then
                    capture_output actual "$musl_out" || rc=$?
                    actual=$(printf '%s\n' "$actual" | \
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
                        pass "musl direct constructor/main stack identity"
                    else
                        fail "musl direct constructor/main stack identity" \
                            "exit=$rc expected=$expect actual=$actual"
                    fi
                fi
            fi
        fi
    fi
    rm -f "$src" "$bin" "$out" "$log" \
        "$musl_bin" "$musl_out" "$musl_log"
}

# ===================================================================
# Test 1gb: constructors and main observe the target image's one auxv
# ===================================================================
test_direct_target_auxv_identity() {
    echo "--- direct target auxiliary-vector identity ---"
    local src="$BUILD/target_auxv_identity.c"
    local bin="$BUILD/target_auxv_identity"
    local out="$BUILD/target_auxv_identity.frozen"
    local log="$BUILD/target_auxv_identity.log"
    local musl_bin="$BUILD/target_auxv_identity.musl"
    local musl_out="$BUILD/target_auxv_identity.musl.frozen"
    local musl_log="$BUILD/target_auxv_identity.musl.log"
    local expect actual freeze_rc=0 rc_e=0 rc=0

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>

extern void _start(void);

static uintptr_t constructor_phdr;
static uintptr_t constructor_phnum;
static uintptr_t constructor_phent;
static uintptr_t constructor_entry;

__attribute__((constructor))
static void remember_constructor_auxv(void)
{
    constructor_phdr = getauxval(AT_PHDR);
    constructor_phnum = getauxval(AT_PHNUM);
    constructor_phent = getauxval(AT_PHENT);
    constructor_entry = getauxval(AT_ENTRY);
}

struct phdr_match {
    uintptr_t phdr;
    uintptr_t phnum;
    int matches;
};

static int match_main_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    struct phdr_match *match = data;
    (void)size;

    if ((uintptr_t)info->dlpi_phdr == match->phdr &&
        (uintptr_t)info->dlpi_phnum == match->phnum)
        match->matches++;
    return 0;
}

int main(void)
{
    struct phdr_match match = {
        .phdr = getauxval(AT_PHDR),
        .phnum = getauxval(AT_PHNUM),
        .matches = 0,
    };
    uintptr_t phent = getauxval(AT_PHENT);
    uintptr_t entry = getauxval(AT_ENTRY);

    if (!match.phdr || !match.phnum || phent != sizeof(Elf64_Phdr) ||
        entry != (uintptr_t)&_start)
        return 2;
    if (constructor_phdr != match.phdr ||
        constructor_phnum != match.phnum ||
        constructor_phent != phent || constructor_entry != entry)
        return 3;
    if (dl_iterate_phdr(match_main_phdr, &match) < 0 || match.matches != 1)
        return 4;
    puts("target-auxv-ok");
    return 0;
}
C

    if ! gcc -Wall -Wextra -Werror -o "$bin" "$src" -ldl; then
        fail "direct target auxiliary-vector identity" \
            "fixture compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "target-auxv-ok" ]; then
        fail "native target auxiliary-vector identity" \
            "exit=$rc_e output=$expect"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "direct target auxiliary-vector identity" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct target auxiliary-vector identity" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "direct target auxiliary-vector identity"
        else
            fail "direct target auxiliary-vector identity" \
                "exit=$rc expected=$expect actual=$actual"
        fi
    fi

    if command -v musl-gcc >/dev/null 2>&1; then
        expect=""; actual=""; freeze_rc=0; rc_e=0; rc=0
        if ! musl-gcc -Wall -Wextra -Werror -o "$musl_bin" "$src" \
                -ldl; then
            fail "musl direct target auxiliary-vector identity" \
                "fixture compile failed"
        else
            capture_output expect "$musl_bin" || rc_e=$?
            if [ "$rc_e" -ne 0 ] || [ "$expect" != "target-auxv-ok" ]; then
                fail "native musl target auxiliary-vector identity" \
                    "exit=$rc_e output=$expect"
            else
                freeze_require_direct \
                    "musl direct target auxiliary-vector identity" \
                    "$musl_log" "$musl_out" "$musl_bin" || freeze_rc=$?
                if [ "$freeze_rc" -eq 77 ]; then
                    skip "musl direct target auxiliary-vector identity" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$freeze_rc" -eq 0 ]; then
                    capture_output actual "$musl_out" || rc=$?
                    actual=$(printf '%s\n' "$actual" | \
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
                        pass "musl direct target auxiliary-vector identity"
                    else
                        fail "musl direct target auxiliary-vector identity" \
                            "exit=$rc expected=$expect actual=$actual"
                    fi
                fi
            fi
        fi
    fi
    rm -f "$src" "$bin" "$out" "$log" \
        "$musl_bin" "$musl_out" "$musl_log"
}

# ===================================================================
# Test 1h: unbridged glibc private exceptions fail closed without touching
# opaque caller storage; ordinary startup remains on validated service paths
# ===================================================================
test_glibc_private_exception_direct() {
    echo "--- glibc private exception ABI direct-load ---"
    local helper="$BUILD/glibc_exception_gate"
    local src="$BUILD/glibc_private_exception.c"
    local bin="$BUILD/glibc_private_exception"
    local out="$BUILD/glibc_private_exception.frozen"
    local log="$BUILD/glibc_private_exception.log"
    local libc ldd_output imports expect actual
    local rc_e=0 rc_a=0 freeze_rc=0
    local label="glibc private exception ABI direct-load"

    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -fno-stack-protector \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/glibc_exception_gate.c -ldl -pthread; then
        fail "glibc private exception fail-closed contract" \
            "helper compile failed"
        rm -f "$helper"
        return
    elif "$helper"; then
        pass "glibc private exception fail-closed contract"
    else
        fail "glibc private exception fail-closed contract" \
            "an opaque record was touched or callback was invoked"
        rm -f "$helper"
        return
    fi
    rm -f "$helper"

    if ! command -v readelf >/dev/null 2>&1; then
        skip "$label" "readelf not installed"
        return
    fi
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("glibc-private-exception-ok"); return 0; }
C
    if ! gcc -o "$bin" "$src"; then
        fail "$label" "fixture compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    ldd_output=$(ldd "$bin" 2>/dev/null || true)
    libc=$(awk '$1 ~ /^libc\.so/ && $2 == "=>" { print $3; exit }' \
        <<<"$ldd_output")
    if [ -z "$libc" ] || [ ! -r "$libc" ]; then
        skip "$label" "fixture does not use a discoverable glibc libc"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    imports=$(readelf -W --dyn-syms "$libc" 2>/dev/null || true)
    if ! grep -Eq \
        'UND _dl_(exception_create|exception_create_format|exception_free|fatal_printf|signal_error|signal_exception|catch_exception)@GLIBC_PRIVATE' \
        <<<"$imports"; then
        skip "$label" "target libc does not import private exception hooks"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output expect "$bin" || rc_e=$?
    freeze_require_direct "$label" "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ] &&
           [ "$actual" = "$expect" ] &&
           [ "$actual" = "glibc-private-exception-ok" ]; then
            pass "$label"
        else
            fail "$label" "exit=$rc_a expected=$expect actual=$actual"
        fi
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 1i: glibc-private module loading is either supported or fails closed
# ===================================================================
test_glibc_internal_module_loading_direct() {
    echo "--- glibc internal module loading direct-load ---"
    local bin="$BUILD/glibc_internal_loading"
    local out="$BUILD/glibc_internal_loading.frozen"
    local log="$BUILD/glibc_internal_loading.log"
    local libc_banner glibc_minor native_iconv native_nss native_fallback
    local native_error actual
    local native_iconv_rc=0 native_nss_rc=0 native_fallback_rc=0
    local native_error_rc=0 rc=0 freeze_rc=0 require_bridge=0

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc' <<<"$libc_banner"; then
        skip "glibc internal iconv module direct-load" \
            "fixture requires glibc"
        skip "glibc internal NSS module direct-load" \
            "fixture requires glibc"
        skip "glibc internal NSS fallback direct-load" \
            "fixture requires glibc"
        skip "glibc internal dlfcn error isolation" \
            "fixture requires glibc"
        return
    fi
    glibc_minor=$(getconf GNU_LIBC_VERSION 2>/dev/null |
        awk -F. 'NF == 2 { print $2; exit }')
    if [[ "$glibc_minor" =~ ^[0-9]+$ ]] &&
       [ "$glibc_minor" -ge 34 ]; then
        require_bridge=1
    fi
    if ! gcc -O2 -Wall -Wextra -Werror -o "$bin" \
            tests/direct_glibc_internal_loading.c -ldl; then
        fail "glibc internal module loading direct-load" \
            "fixture compile failed"
        return
    fi

    capture_output native_iconv "$bin" iconv || native_iconv_rc=$?
    capture_output native_nss "$bin" nss-module || native_nss_rc=$?
    capture_output native_fallback "$bin" nss-fallback || \
        native_fallback_rc=$?
    capture_output native_error "$bin" error-isolation || \
        native_error_rc=$?
    if [ "$native_fallback_rc" -ne 0 ] || \
       [ "$native_fallback" != "nss=root:0" ]; then
        fail "glibc internal NSS fallback direct-load" \
            "native control exit=$native_fallback_rc output=$native_fallback"
        rm -f "$bin" "$out" "$log"
        return
    fi
    if [ "$native_error_rc" -ne 0 ] ||
       [ "$native_error" != "dlerror=preserved" ]; then
        fail "glibc internal dlfcn error isolation" \
            "native control exit=$native_error_rc output=$native_error"
        rm -f "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "glibc internal module loading direct-load" \
        "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "glibc internal iconv module direct-load" \
            "$DIRECT_FREEZE_REASON"
        skip "glibc internal NSS module direct-load" \
            "$DIRECT_FREEZE_REASON"
        skip "glibc internal NSS fallback direct-load" \
            "$DIRECT_FREEZE_REASON"
        skip "glibc internal dlfcn error isolation" \
            "$DIRECT_FREEZE_REASON"
        rm -f "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$bin" "$out" "$log"
        return
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" iconv || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$native_iconv_rc" -eq 77 ]; then
        skip "glibc internal iconv module direct-load" \
            "native gconv module is unavailable"
    elif [ "$native_iconv_rc" -ne 0 ]; then
        fail "glibc internal iconv module direct-load" \
            "native control exit=$native_iconv_rc output=$native_iconv"
    elif [ "$rc" -eq 0 ] && [ "$actual" = "$native_iconv" ]; then
        pass "glibc internal iconv module direct-load"
    elif [ "$require_bridge" -eq 0 ] && [ "$rc" -eq 77 ] &&
         [ "$actual" = "iconv=unavailable" ]; then
        pass "glibc internal iconv module direct-load"
    else
        fail "glibc internal iconv module direct-load" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" nss-module || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$native_nss_rc" -eq 77 ]; then
        skip "glibc internal NSS module direct-load" \
            "native compat NSS module is unavailable"
    elif [ "$native_nss_rc" -ne 0 ]; then
        fail "glibc internal NSS module direct-load" \
            "native control exit=$native_nss_rc output=$native_nss"
    elif [ "$rc" -eq 0 ] && [ "$actual" = "$native_nss" ]; then
        pass "glibc internal NSS module direct-load"
    elif [ "$require_bridge" -eq 0 ] && [ "$rc" -eq 77 ] &&
         [ "$actual" = "nss=unavailable" ]; then
        pass "glibc internal NSS module direct-load"
    else
        fail "glibc internal NSS module direct-load" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" nss-fallback || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_fallback" ]; then
        pass "glibc internal NSS fallback direct-load"
    else
        fail "glibc internal NSS fallback direct-load" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 \
        "$out" error-isolation || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_error" ]; then
        pass "glibc internal dlfcn error isolation"
    else
        fail "glibc internal dlfcn error isolation" \
            "exit=$rc output=$actual"
    fi
    rm -f "$bin" "$out" "$log"
}

# ===================================================================
# Test 2: exit code preservation
# ===================================================================
test_exit_code() {
    echo "--- exit-code ---"
    local src="$BUILD/ec.c" bin="$BUILD/ec" out="$BUILD/ec.frozen"
    cat > "$src" <<'C'
#include <stdlib.h>
int main(int ac, char **av) { return ac > 1 ? atoi(av[1]) : 42; }
C
    gcc -o "$bin" "$src"
    if ! run_freeze "$DLFREEZE" -o "$out" "$bin"; then fail "exit-code" "dlfreeze failed"; return; fi

    local e0 a0 e42 a42 ed ad
    run_with_timeout "$bin"   0  || e0=$?;  e0=${e0:-0}
    run_with_timeout "$out"   0  || a0=$?;  a0=${a0:-0}
    run_with_timeout "$bin"   42 || e42=$?; e42=${e42:-0}
    run_with_timeout "$out"   42 || a42=$?; a42=${a42:-0}
    run_with_timeout "$bin"      || ed=$?;  ed=${ed:-0}
    run_with_timeout "$out"      || ad=$?;  ad=${ad:-0}

    if [[ "$e0" == "$a0" && "$e42" == "$a42" && "$ed" == "$ad" ]]; then
        pass "exit-code"
    else
        fail "exit-code" "expected $e0/$e42/$ed got $a0/$a42/$ad"
    fi
    rm -f "$src" "$bin" "$out"
}

# ===================================================================
# Test 2a: the bootstrap reserves and requires an UPX payload mapping
# ===================================================================
test_upx_payload_mapping() {
    echo "--- UPX payload mapping ---"
    local src="$BUILD/upx_payload.c" bin="$BUILD/upx_payload"
    local out="$BUILD/upx_payload.frozen" packed="$BUILD/upx_payload.upx"
    local log="$BUILD/upx_payload.log" expect actual rc_e=0 rc_a=0
    local bad_dir="$BUILD/upx-no-note" bad_out="$BUILD/upx_no_note.frozen"
    local bad_sentinel="pre-existing-output-must-survive"
    local decoy_dir="$BUILD/upx-decoy-loader-info"
    local decoy_gate="$decoy_dir/payload_phdr_gate"
    local decoy_out="$BUILD/upx_decoy.frozen"
    local decoy_packed="$BUILD/upx_decoy.upx"
    local order_dir="$BUILD/upx-payload-phdr-order"
    local order_gate="$order_dir/payload_phdr_gate"
    local order_out="$BUILD/upx_ordered.frozen"
    local order_packed="$BUILD/upx_ordered.upx"

    cat > "$src" <<'C'
#include <stdio.h>
int main(int argc, char **argv) {
    printf("upx-payload:%s\n", argc > 1 ? argv[1] : "missing");
    return argc > 1 ? 0 : 9;
}
C
    if ! gcc -o "$bin" "$src"; then
        fail "UPX payload mapping" "fixture compile failed"
        rm -f "$src" "$bin"
        return
    fi

    rm -f "$out" "$packed" "$log"
    if ! run_freeze "$DLFREEZE" -o "$out" "$bin" >"$log" 2>&1; then
        fail "UPX payload mapping" "dlfreeze failed"
    elif ! command -v upx >/dev/null 2>&1; then
        skip "UPX payload mapping" "upx not installed"
    elif ! upx --best -q -o "$packed" "$out" >/dev/null 2>&1; then
        fail "UPX payload mapping" "UPX rejected frozen artifact"
    else
        capture_output expect "$bin" marker || rc_e=$?
        capture_output actual "$packed" marker || rc_a=$?
        if [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ] &&
           [ "$actual" = "$expect" ] && [ "$actual" = "upx-payload:marker" ]; then
            pass "UPX payload mapping"
        else
            fail "UPX payload mapping" \
                "output or exit code differs (exit $rc_e vs $rc_a)"
        fi
    fi

    # A linker may place the explicitly reserved PT_NOTE before every
    # PT_LOAD.  Once that slot becomes the high-address payload PT_LOAD, the
    # load subsequence must be reordered by virtual address.  Otherwise the
    # ELF violates the PT_LOAD ordering contract and compressors commonly
    # reject it because its first load no longer contains the file header.
    rm -rf "$order_dir"
    rm -f "$order_out" "$order_packed"
    mkdir -p "$order_dir"
    if ! gcc -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
            -o "$order_gate" tests/payload_phdr_gate.c; then
        fail "payload PT_LOAD linker-order independence" \
            "could not compile program-header fixture"
    elif ! cp "$DLFREEZE" "$order_dir/dlfreeze" ||
         ! cp "$BUILD/dlfreeze-bootstrap" "$order_dir/dlfreeze-bootstrap" ||
         ! "$order_gate" --note-before-load \
             "$order_dir/dlfreeze-bootstrap"; then
        fail "payload PT_LOAD linker-order independence" \
            "could not place the reserved note before the first load"
    elif ! run_freeze "$order_dir/dlfreeze" -o "$order_out" "$bin" \
            >"$order_dir/pack.log" 2>&1; then
        fail "payload PT_LOAD linker-order independence" \
            "packer rejected the alternate valid header order"
    elif ! "$order_gate" --verify-load-order "$order_out"; then
        fail "payload PT_LOAD linker-order independence" \
            "packer emitted a non-canonical PT_LOAD sequence"
    else
        pass "payload PT_LOAD linker-order independence"
        if ! command -v upx >/dev/null 2>&1; then
            skip "ordered payload PT_LOAD survives compression" \
                "upx not installed"
        elif ! upx -1 -q -o "$order_packed" "$order_out" \
                >/dev/null 2>&1; then
            fail "ordered payload PT_LOAD survives compression" \
                "UPX rejected the canonical artifact"
        else
            actual=""; rc_a=0
            capture_output actual "$order_packed" ordered || rc_a=$?
            if [ "$rc_a" -eq 0 ] &&
               [ "$actual" = "upx-payload:ordered" ]; then
                pass "ordered payload PT_LOAD survives compression"
            else
                fail "ordered payload PT_LOAD survives compression" \
                    "exit=$rc_a output=$actual"
            fi
        fi
    fi

    if ! command -v objcopy >/dev/null 2>&1; then
        skip "missing reserved payload note is fatal" "objcopy not installed"
    else
        rm -rf "$bad_dir"
        rm -f "$bad_out"
        mkdir -p "$bad_dir"
        cp "$DLFREEZE" "$bad_dir/dlfreeze"
        cp "$BUILD/dlfreeze-bootstrap" "$bad_dir/dlfreeze-bootstrap"
        printf '%s\n' "$bad_sentinel" >"$bad_out"
        if ! objcopy --remove-section=.note.dlfreeze.payload \
                "$bad_dir/dlfreeze-bootstrap" >/dev/null 2>&1; then
            skip "missing reserved payload note is fatal" \
                "objcopy cannot remove the reservation"
        elif run_freeze "$bad_dir/dlfreeze" -o "$bad_out" "$bin" \
                >"$bad_dir/pack.log" 2>&1; then
            fail "missing reserved payload note is fatal" \
                "packer accepted a bootstrap without its reservation"
        elif [ "$(cat "$bad_out" 2>/dev/null)" = "$bad_sentinel" ] &&
             grep -q 'reserved payload PT_NOTE is missing' \
                "$bad_dir/pack.log"; then
            pass "late pack failure preserves existing output"
        else
            fail "late pack failure preserves existing output" \
                "packer failed for an unrelated reason or changed the output"
        fi
    fi

    # A hard-link alias is the dangerous case for an eager fopen(..., "wb"):
    # truncating the output also destroys the input before packing can fail.
    local alias_dir="$BUILD/packer-output-alias"
    local alias_input="$alias_dir/input" alias_out="$alias_dir/output"
    local alias_log="$alias_dir/pack.log" before_hash after_hash
    rm -rf "$alias_dir"
    mkdir -p "$alias_dir"
    if ! cp "$bin" "$alias_input" || ! ln "$alias_input" "$alias_out"; then
        fail "packer output alias rejection" "could not create hard-link fixture"
    else
        before_hash=$(sha256sum "$alias_input" | awk '{print $1}')
        if run_freeze "$DLFREEZE" -o "$alias_out" "$alias_input" \
                >"$alias_log" 2>&1; then
            fail "packer output alias rejection" "aliased output was accepted"
        else
            after_hash=$(sha256sum "$alias_input" | awk '{print $1}')
            if [ "$after_hash" = "$before_hash" ] &&
               [ "$alias_input" -ef "$alias_out" ] &&
               grep -q 'aliases input' "$alias_log"; then
                pass "packer output alias rejection preserves input"
            else
                fail "packer output alias rejection" \
                    "input/output inode or contents changed"
            fi
        fi
    fi

    # A bytewise scan of the entire bootstrap can patch a marker-shaped decoy
    # in read-only data and leave the live .data descriptor zero.  Replace an
    # existing diagnostic in place, before the live descriptor, so the test
    # never changes alloc-section offsets.  The unpacked artifact exercises
    # the ordinary footer path; UPX necessarily uses the in-memory descriptor.
    if ! command -v upx >/dev/null 2>&1; then
        skip "UPX live loader descriptor selection" \
            "upx not installed"
    else
        rm -rf "$decoy_dir"
        rm -f "$decoy_out" "$decoy_packed"
        mkdir -p "$decoy_dir"
        if ! gcc -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
                -o "$decoy_gate" tests/payload_phdr_gate.c ||
           ! cp "$DLFREEZE" "$decoy_dir/dlfreeze" ||
           ! cp "$BUILD/dlfreeze-bootstrap" \
                "$decoy_dir/dlfreeze-bootstrap" ||
           ! "$decoy_gate" --insert-readonly-decoy \
                "$decoy_dir/dlfreeze-bootstrap"; then
            fail "UPX live loader descriptor selection" \
                "could not construct a fixed-size read-only decoy"
        else
            rc_a=0
            run_with_timeout "$decoy_dir/dlfreeze-bootstrap" \
                >/dev/null 2>&1 || rc_a=$?
            if [ "$rc_a" -ne 127 ]; then
                fail "UPX live loader descriptor selection" \
                    "decoy construction corrupted the bootstrap (exit=$rc_a)"
            elif ! run_freeze "$decoy_dir/dlfreeze" -o "$decoy_out" "$bin" \
                >"$decoy_dir/pack.log" 2>&1; then
                fail "UPX live loader descriptor selection" \
                    "packer rejected a harmless read-only decoy"
            else
                actual=""; rc_a=0
                capture_output actual "$decoy_out" decoy || rc_a=$?
                if [ "$rc_a" -ne 0 ] ||
                   [ "$actual" != "upx-payload:decoy" ]; then
                    fail "UPX live loader descriptor selection" \
                        "uncompressed exit=$rc_a output=$actual"
                elif ! upx --best -q -o "$decoy_packed" "$decoy_out" \
                        >/dev/null 2>&1; then
                    fail "UPX live loader descriptor selection" \
                        "UPX rejected the decoy artifact"
                else
                    actual=""; rc_a=0
                    capture_output actual "$decoy_packed" decoy || rc_a=$?
                    if [ "$rc_a" -eq 0 ] &&
                       [ "$actual" = "upx-payload:decoy" ]; then
                        pass "UPX selects the live writable loader descriptor"
                    else
                        fail "UPX live loader descriptor selection" \
                            "compressed exit=$rc_a output=$actual"
                    fi
                fi
            fi
        fi
    fi

    rm -rf "$bad_dir"
    rm -rf "$decoy_dir"
    rm -rf "$alias_dir"
    rm -rf "$order_dir"
    rm -f "$src" "$bin" "$out" "$packed" "$log" "$bad_out" \
          "$decoy_out" "$decoy_packed" "$order_out" "$order_packed"
}

# ===================================================================
# Test 2aa: captured files are direct-only and never extract/fallback
# ===================================================================
test_captured_files_require_direct() {
    echo "--- captured files require direct mode ---"
    local root="$BUILD/captured-direct-root" src="$BUILD/captured_direct.c"
    local bin="$root/program" resource="$root/libcaptured-input.so"
    local sibling="$root/host-only.txt"
    local no_direct_out="$BUILD/captured_no_direct.frozen"
    local no_direct_log="$BUILD/captured_no_direct.log"
    local out="$BUILD/captured_direct.frozen" log="$BUILD/captured_direct.log"
    local fallback="$BUILD/captured_fallback.frozen"
    local root_abs size actual rc=0 freeze_rc=0
    local pid_marker frozen_pid frozen_rc=0

    rm -rf "$root"
    rm -f "$no_direct_out" "$no_direct_log" "$out" "$log" "$fallback"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    bin="$root_abs/program"
    resource="$root_abs/libcaptured-input.so"
    cat > "$src" <<'C'
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char line[64];
    FILE *file;

    if (argc < 2 || argc > 4)
        return 2;
    file = fopen(argv[1], "r");
    if (!file)
        return 3;
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return 4;
    }
    fclose(file);
    fputs(line, stdout);
    if (argc >= 3) {
        file = fopen(argv[2], "r");
        if (!file)
            return 5;
        if (!fgets(line, sizeof(line), file)) {
            fclose(file);
            return 6;
        }
        fclose(file);
        fputs(line, stdout);
    }
    if (argc == 4) {
        file = fopen(argv[3], "w");
        if (!file)
            return 7;
        if (fprintf(file, "%ld\n", (long)getpid()) < 0 ||
            fclose(file) != 0)
            return 8;
    }
    return 0;
}
C
    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -o "$bin" "$src"; then
            fail "captured files require direct mode" \
                "musl fixture compile failed"
            rm -rf "$root"
            rm -f "$src"
            return
        fi
    elif ! gcc -o "$bin" "$src"; then
        fail "captured files require direct mode" "fixture compile failed"
        rm -rf "$root"
        rm -f "$src"
        return
    fi
    printf 'resource-ok\n' > "$resource"

    if run_freeze "$DLFREEZE" -t -f "$root_abs/*" \
            -o "$no_direct_out" -- "$bin" "$resource" \
            >"$no_direct_log" 2>&1; then
        fail "captured files require direct mode" \
            "packer accepted captured DATA without -d"
    elif [ -e "$no_direct_out" ]; then
        fail "captured files require direct mode" \
            "rejected pack left an output artifact"
    elif grep -Fq 'captured files require direct-load mode (-d)' \
            "$no_direct_log"; then
        pass "captured files require direct mode"
    else
        fail "captured files require direct mode" \
            "packer failed for an unrelated reason"
    fi

    freeze_require_direct "captured-file direct artifact" "$log" "$out" \
        -t -f "$root_abs/*" -- "$bin" "$resource" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "captured-file direct artifact" "$DIRECT_FREEZE_REASON"
        skip "captured-file artifact refuses extraction" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        rm -f "$src" "$no_direct_out" "$no_direct_log" "$out" "$log" \
            "$fallback"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        rm -f "$src" "$no_direct_out" "$no_direct_log" "$out" "$log" \
            "$fallback"
        return
    fi

    mv "$resource" "${resource}.host"
    rc=0
    capture_output actual "$out" "$resource" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = "resource-ok" ]; then
        pass "captured-file direct artifact"
    else
        fail "captured-file direct artifact" \
            "embedded resource unavailable (exit=$rc output=$actual)"
    fi

    # Capturing one identity is not evidence that its whole parent directory
    # was enumerated.  An uncaptured sibling created after freezing must keep
    # ordinary host-filesystem semantics.
    printf 'host-sibling-ok\n' > "$sibling"
    rc=0
    capture_output actual "$out" "$resource" "$sibling" || rc=$?
    if [ "$rc" -eq 0 ] &&
       [ "$actual" = $'resource-ok\nhost-sibling-ok' ]; then
        pass "uncaptured sibling host fallthrough"
    else
        fail "uncaptured sibling host fallthrough" \
            "exit=$rc output=$actual"
    fi

    # DATA makes this artifact structurally direct-only.  With no extraction
    # fallback to preserve, direct startup must retain the PID assigned by the
    # caller instead of inserting an otherwise observable supervisor process.
    pid_marker="$root/frozen.pid"
    rm -f "$pid_marker"
    env -u DLFREEZE_NO_FORK "$out" "$resource" "$sibling" \
        "$pid_marker" >/dev/null 2>&1 &
    frozen_pid=$!
    wait "$frozen_pid" || frozen_rc=$?
    actual=$(cat "$pid_marker" 2>/dev/null || true)
    if [ "$frozen_rc" -eq 0 ] && [ "$actual" = "$frozen_pid" ]; then
        pass "captured-file direct process identity"
    else
        fail "captured-file direct process identity" \
            "launcher_pid=$frozen_pid target_pid=$actual exit=$frozen_rc"
    fi
    rm -f "$sibling"

    # Removing the complete direct-metadata tuple simulates an artifact for
    # which direct startup is unavailable.  DATA semantics cannot be
    # reproduced by extracting under a temporary prefix, so the bootstrap
    # must fail closed.  The footer stores meta/fixup offset/count together;
    # leaving only the fixup fields behind is intentionally non-canonical.
    cp "$out" "$fallback"
    size=$(stat -c %s "$fallback")
    dd if=/dev/zero of="$fallback" bs=1 seek=$((size - 24)) count=24 \
        conv=notrunc status=none
    rc=0
    capture_output actual env -u DLFREEZE_NO_FORK "$fallback" \
        "$resource" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"refusing extraction fallback for a captured-file artifact"* ]] &&
       [[ "$actual" != *"resource-ok"* ]]; then
        pass "captured-file artifact refuses extraction"
    else
        fail "captured-file artifact refuses extraction" \
            "exit=$rc output=$actual"
    fi
    mv "${resource}.host" "$resource"

    rm -rf "$root"
    rm -f "$src" "$no_direct_out" "$no_direct_log" "$out" "$log" \
        "$fallback"
}

# A clean pack-time prelink failure leaves original ELF bytes and direct
# metadata behind for the loader's runtime-relocation path.  Exercise both
# halves of the VFS stdio/directory contract there: fdopen must wrap a
# captured fopen memfd, while an uncaptured opendir must enter the target
# libc instead of returning an empty synthetic stream.
test_runtime_relocation_vfs_fallthrough() {
    echo "--- runtime-relocation VFS libc fallthrough ---"
    local root="$BUILD/runtime-reloc-vfs" src="$BUILD/runtime_reloc_vfs.c"
    local bin out log captured host_dir actual expect rc=0 freeze_rc=0
    local preload_src preload_so clean_out clean_log
    local limit_probe_src limit_probe
    local cc forced=0 saw_prelinked=0 limit
    local limits=(512 768 1024 1536 2048 3072 4096 6144 8192 12288)
    local label="runtime-relocation VFS libc fallthrough"

    rm -rf "$root"
    mkdir -p "$root/host-dir"
    root=$(realpath "$root")
    bin="$root/program"
    out="$root/program.frozen"
    log="$root/freeze.log"
    captured="$root/captured.txt"
    host_dir="$root/host-dir"
    preload_src="$root/preload.c"
    preload_so="$root/preload.so"
    limit_probe_src="$root/limit-probe.c"
    limit_probe="$root/limit-probe"
    clean_out="$root/program.clean.frozen"
    clean_log="$root/clean-freeze.log"
    printf 'captured-runtime-reloc\n' >"$captured"
    printf 'host-entry\n' >"$host_dir/uncaptured-entry"

    cat >"$src" <<'C'
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char line[64];
    FILE *stream;
    DIR *directory;
    struct dirent *entry;
    int found = 0;

    if (argc != 3)
        return 2;
    stream = fopen(argv[1], "r");
    if (!stream || !fgets(line, sizeof(line), stream) ||
        fclose(stream) != 0)
        return 3;
    line[strcspn(line, "\r\n")] = '\0';

    directory = opendir(argv[2]);
    if (!directory)
        return 4;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "uncaptured-entry") == 0)
            found = 1;
    }
    if (closedir(directory) != 0 || !found)
        return 5;
    printf("%s|host-dir-ok\n", line);
    return 0;
}
C

    cat >"$preload_src" <<'C'
#include <unistd.h>

__attribute__((constructor))
static void preload_started(void) {
    static const char message[] = "policy-preload-ran\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
}

unsigned int la_version(unsigned int version) {
    return version;
}
C

    cat >"$limit_probe_src" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/resource.h>

int main(void) {
    const size_t mapping_size = 64U * 1024U * 1024U;
    struct rlimit limit = { 512U * 1024U, 512U * 1024U };
    void *mapping;

    if (setrlimit(RLIMIT_DATA, &limit) != 0)
        return 77;
    errno = 0;
    mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return errno == ENOMEM ? 0 : 77;
    (void)munmap(mapping, mapping_size);
    return 77;
}
C

    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    else
        cc=gcc
    fi
    if ! "$cc" -fPIE -pie -o "$bin" "$src" ||
       ! "$cc" -shared -fPIC -o "$preload_so" "$preload_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$limit_probe" \
            "$limit_probe_src"; then
        fail "$label" "fixture compile failed"
        rm -rf "$root"
        rm -f "$src"
        return
    fi

    rc=0
    run_with_timeout "$limit_probe" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        skip "$label" \
            "RLIMIT_DATA does not constrain anonymous mappings"
        rm -rf "$root"
        rm -f "$src"
        return
    fi
    rc=0
    capture_output expect "$bin" "$captured" "$host_dir" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [ "$expect" != "captured-runtime-reloc|host-dir-ok" ]; then
        fail "$label" "native control exit=$rc output=$expect"
        rm -rf "$root"
        rm -f "$src"
        return
    fi

    # RLIMIT_DATA covers the prelink child's anonymous fixed mappings on
    # Linux.  Packing/tracing mainly maps executable files and has a smaller
    # data working set, while prelink additionally allocates every object's
    # image plus guard pages.  Probe a bounded set of limits so this stays
    # portable across libc/architectures.
    for limit in "${limits[@]}"; do
        rm -f "$out" "$log"
        set +e
        (
            ulimit -d "$limit" || exit 125
            run_freeze "$DLFREEZE" -d -t -f "$captured" -o "$out" -- \
                "$bin" "$captured" "$host_dir"
        ) >"$log" 2>&1
        freeze_rc=$?
        set -e
        if [ "$freeze_rc" -eq 0 ] &&
           grep -Eq 'pre-linked[[:space:]]*:[[:space:]]*yes' "$log" &&
           grep -Eq \
               'mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)' \
               "$log"; then
            saw_prelinked=1
        fi
        if [ "$freeze_rc" -eq 0 ] &&
           grep -Fq 'dlfreeze: pre-linker failed' "$log" &&
           grep -Eq 'pre-linked[[:space:]]*:[[:space:]]*no' "$log" &&
           grep -Eq \
               'mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)' \
               "$log"; then
            forced=1
            break
        fi
    done

    if [ "$forced" -eq 0 ]; then
        if grep -Eq \
               'direct-load is unavailable for runtime .*creating an extraction-mode binary|captured files require a supported direct-load runtime' \
               "$log" 2>/dev/null; then
            skip "$label" "target runtime does not support direct load"
        elif [ "$saw_prelinked" -eq 1 ]; then
            # RLIMIT_DATA is only a best-effort way to exercise this fallback
            # path: some libc/kernel combinations keep the prelinker's fixed
            # file mappings outside the constrained accounting.  A verified
            # prelinked artifact proves setup itself worked; do not turn an
            # unavailable fault-injection mechanism into a product failure.
            skip "$label" \
                "RLIMIT_DATA could not force runtime relocation"
        else
            fail "$label" "could not produce a clean non-prelinked artifact"
            tail -n 40 "$log" || true
        fi
        rm -rf "$root"
        rm -f "$src"
        return
    fi

    mv "$captured" "$captured.host"
    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" \
        "$captured" "$host_dir" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 LD_PRELOAD= LD_AUDIT= \
        "$out" "$captured" "$host_dir" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct loader accepts empty preload/audit values"
    else
        fail "direct loader accepts empty preload/audit values" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK \
        LD_PRELOAD=/dlfreeze-test-nonempty-preload LD_AUDIT= \
        "$out" "$captured" "$host_dir" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"refusing direct load: nonempty LD_PRELOAD is unsupported"* ]] &&
       [[ "$actual" == *"refusing extraction fallback for a captured-file artifact"* ]] &&
       [[ "$actual" != *"$expect"* ]]; then
        pass "LD_PRELOAD direct-only refusal"
    else
        fail "LD_PRELOAD direct-only refusal" "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK LD_PRELOAD= \
        LD_AUDIT=/dlfreeze-test-nonempty-audit \
        "$out" "$captured" "$host_dir" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"refusing direct load: nonempty LD_AUDIT is unsupported"* ]] &&
       [[ "$actual" == *"refusing extraction fallback for a captured-file artifact"* ]] &&
       [[ "$actual" != *"$expect"* ]]; then
        pass "LD_AUDIT direct-only refusal"
    else
        fail "LD_AUDIT direct-only refusal" "exit=$rc output=$actual"
    fi

    # Reuse the admitted RLIMIT_DATA value to produce the same original ELF
    # payload without captured DATA.  The early direct refusal must remain a
    # clean failure so the bootstrap can delegate these variables to the
    # native interpreter through extraction.
    set +e
    (
        ulimit -d "$limit" || exit 125
        run_freeze "$DLFREEZE" -d -o "$clean_out" -- "$bin"
    ) >"$clean_log" 2>&1
    freeze_rc=$?
    set -e
    if [ "$freeze_rc" -ne 0 ] ||
       ! grep -Fq 'dlfreeze: pre-linker failed' "$clean_log" ||
       ! grep -Eq 'pre-linked[[:space:]]*:[[:space:]]*no' "$clean_log" ||
       ! grep -Eq \
           'mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)' \
           "$clean_log"; then
        fail "direct loader environment extraction fallback" \
            "could not produce a clean runtime-relocation artifact"
        tail -n 40 "$clean_log" || true
        rm -rf "$root"
        rm -f "$src"
        return
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK LD_AUDIT= \
        LD_PRELOAD="$preload_so" "$clean_out" \
        "$captured.host" "$host_dir" || rc=$?
    if [ "$rc" -eq 0 ] &&
       [[ "$actual" == *"refusing direct load: nonempty LD_PRELOAD is unsupported"* ]] &&
       [[ "$actual" == *"policy-preload-ran"* ]] &&
       [[ "$actual" == *"$expect"* ]]; then
        pass "LD_PRELOAD extraction fallback"
    else
        fail "LD_PRELOAD extraction fallback" "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK LD_PRELOAD= \
        LD_AUDIT="$preload_so" "$clean_out" \
        "$captured.host" "$host_dir" || rc=$?
    if [ "$rc" -eq 0 ] &&
       [[ "$actual" == *"refusing direct load: nonempty LD_AUDIT is unsupported"* ]] &&
       [[ "$actual" == *"$expect"* ]]; then
        pass "LD_AUDIT extraction fallback"
    else
        fail "LD_AUDIT extraction fallback" "exit=$rc output=$actual"
    fi

    rm -rf "$root"
    rm -f "$src"
}

# File-trace V4 keeps the absolute spelling derived from cwd separate from
# the canonical source copied into the artifact.  Exercise every path-only
# VFS entry point after all traced files, symlinks, and directories disappear.
test_captured_file_request_identity_direct() {
    echo "--- captured-file request identity direct-load ---"
    local build_abs root src bin out log bad_manifest actual
    local size footer manifest count entry_flags special_index="" i
    local freeze_rc=0 rc=0

    build_abs=$(cd "$BUILD" && pwd -P)
    root="$build_abs/captured_request_identity_root"
    src="$build_abs/captured_request_identity.c"
    bin="$build_abs/captured_request_identity"
    out="$build_abs/captured_request_identity.frozen"
    log="$build_abs/captured_request_identity.log"
    bad_manifest="$build_abs/captured_request_identity_bad.frozen"

    rm -rf "$root"
    rm -f "$src" "$bin" "$out" "$log" "$bad_manifest"
    mkdir -p "$root/nested" "$root/captured-dir"
    printf 'relative\n' > "$root/relative.txt"
    printf 'dotted\n' > "$root/dotted.txt"
    printf 'shared\n' > "$root/shared-source.txt"
    ln -s shared-source.txt "$root/alias-one.txt"
    ln -s shared-source.txt "$root/alias-two.txt"

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_open(const char *path, char *out, size_t out_size) {
    int fd = open(path, O_RDONLY);
    ssize_t length;

    if (fd < 0)
        return -1;
    length = read(fd, out, out_size - 1);
    if (length <= 0 || close(fd) < 0)
        return -1;
    out[length] = '\0';
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

static int read_fopen(const char *path, char *out, size_t out_size) {
    FILE *stream = fopen(path, "r");

    if (!stream)
        return -1;
    if (!fgets(out, (int)out_size, stream) || fclose(stream) != 0)
        return -1;
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    char relative[32], dotted[32], alias_one[32], alias_two[32];
    char resolved[PATH_MAX];
    size_t root_length;
    struct stat sb;
    DIR *directory;

    if (argc != 2 || chdir(argv[1]) != 0)
        return 2;
    if (read_open("relative.txt", relative, sizeof(relative)) != 0 ||
        read_fopen("./nested/../dotted.txt", dotted, sizeof(dotted)) != 0 ||
        read_open("alias-one.txt", alias_one, sizeof(alias_one)) != 0 ||
        read_fopen("alias-two.txt", alias_two, sizeof(alias_two)) != 0)
        return 3;
    if (stat("alias-one.txt", &sb) != 0 || sb.st_size == 0 ||
        access("alias-two.txt", R_OK) != 0)
        return 4;
    directory = opendir("captured-dir");
    if (!directory || closedir(directory) != 0)
        return 5;
    root_length = strlen(argv[1]);
    if (!realpath("alias-one.txt", resolved) ||
        strncmp(resolved, argv[1], root_length) != 0 ||
        resolved[root_length] != '/')
        return 6;
    printf("%s|%s|%s|%s|identity-ok\n",
           relative, dotted, alias_one, alias_two);
    return 0;
}
C

    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -o "$bin" "$src"; then
            fail "captured-file request identity" \
                "musl fixture compile failed"
            rm -rf "$root"
            rm -f "$src" "$bin" "$out" "$log"
            return
        fi
    elif ! gcc -o "$bin" "$src"; then
        fail "captured-file request identity" "fixture compile failed"
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$bin" "$root" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [ "$actual" != "relative|dotted|shared|shared|identity-ok" ]; then
        fail "captured-file request identity" \
            "native fixture exit=$rc output=$actual"
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "captured-file request identity" "$log" "$out" \
        -t -f "$root/*" -- "$bin" "$root" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "captured-file request identity" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log" "$bad_manifest"
        return
    fi

    # Directory entries carry no bytes.  A non-zero range is ambiguous
    # metadata and must be rejected before VFS setup.
    size=$(stat -c %s "$out")
    footer=$((size - 64))
    count=$(od -An -tu4 -j $((footer + 12)) -N4 "$out" |
        tr -d '[:space:]')
    manifest=$(od -An -tu8 -j $((footer + 16)) -N8 "$out" |
        tr -d '[:space:]')
    if [[ "$count" =~ ^[0-9]+$ && "$manifest" =~ ^[0-9]+$ ]]; then
        for ((i = 0; i < count; i++)); do
            entry_flags=$(od -An -tu4 \
                -j $((manifest + i * 32 + 16)) -N4 "$out" |
                tr -d '[:space:]')
            if [[ "$entry_flags" =~ ^[0-9]+$ ]] &&
               [ $((entry_flags & 0x4000)) -ne 0 ]; then
                special_index=$i
                break
            fi
        done
    fi
    if [ -z "$special_index" ]; then
        fail "canonical directory VFS manifest" \
            "fixture produced no explicit directory entry"
    else
        cp "$out" "$bad_manifest"
        printf '\001\000\000\000\000\000\000\000' |
            dd of="$bad_manifest" bs=1 \
                seek=$((manifest + special_index * 32)) \
                conv=notrunc status=none
        actual=""; rc=0
        capture_output actual "$bad_manifest" "$root" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid manifest"* ]]; then
            pass "canonical directory VFS manifest"
        else
            fail "canonical directory VFS manifest" \
                "exit=$rc output=$actual"
        fi
    fi

    rm -rf "$root"
    mkdir -p "$root"
    # A destination-host symlink with the captured spelling must not change
    # realpath() for the immutable VFS entry or redirect later lookups.
    ln -s /etc/passwd "$root/alias-one.txt"
    actual=""; rc=0
    capture_output actual "$out" "$root" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] &&
       [ "$actual" = "relative|dotted|shared|shared|identity-ok" ]; then
        pass "relative, dotted, and symlink captured identities"
    else
        fail "captured-file request identity" "exit=$rc output=$actual"
    fi

    rm -rf "$root"
    rm -f "$src" "$bin" "$out" "$log" "$bad_manifest"
}

# Directory identity is a manifest kind, not a synthetic child pathname.
# A real file named .dir must therefore remain visible and readable after the
# traced filesystem tree has disappeared.
test_vfs_explicit_directory_kind() {
    echo "--- explicit VFS directory kind and literal .dir child ---"
    local root="$BUILD/vfs-directory-kind"
    local data src bin out log actual expected="directory-kind-ok"
    local rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root/data"
    root=$(realpath "$root")
    data="$root/data"
    src="$root/main.c"
    bin="$root/program"
    out="$BUILD/vfs-directory-kind.frozen"
    log="$BUILD/vfs-directory-kind.log"
    rm -f "$out" "$log"
    printf 'literal-dot-dir\n' >"$data/.dir"

    cat >"$src" <<'C'
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    DIR *directory;
    struct dirent *entry;
    FILE *file;
    char line[64];
    int found = 0;

    if (argc != 3)
        return 2;
    directory = opendir(argv[1]);
    if (!directory)
        return 3;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".dir") == 0)
            found = 1;
    }
    if (closedir(directory) != 0 || !found)
        return 4;
    file = fopen(argv[2], "r");
    if (!file || !fgets(line, sizeof(line), file) || fclose(file) != 0)
        return 5;
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, "literal-dot-dir") != 0)
        return 6;
    puts("directory-kind-ok");
    return 0;
}
C

    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -Wall -Wextra -Werror -o "$bin" "$src"; then
            fail "explicit VFS directory kind" "musl fixture compile failed"
            rm -rf "$root"
            rm -f "$out" "$log"
            return
        fi
    elif ! gcc -Wall -Wextra -Werror -o "$bin" "$src"; then
        fail "explicit VFS directory kind" "fixture compile failed"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi

    capture_output actual "$bin" "$data" "$data/.dir" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "$expected" ]; then
        fail "explicit VFS directory kind" \
            "native control exit=$rc output=$actual"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi

    freeze_require_direct "explicit VFS directory kind" "$log" "$out" \
        -t -f "$data/*" -- "$bin" "$data" "$data/.dir" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "explicit VFS directory kind replay" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi

    rm -rf "$data"
    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 \
        "$out" "$data" "$data/.dir" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ]; then
        pass "explicit VFS directory kind replay"
    else
        fail "explicit VFS directory kind replay" \
            "exit=$rc output=$actual"
    fi

    rm -rf "$root"
    rm -f "$out" "$log"
}

# Loader-owned directory streams must be identified by pointer ownership,
# never by inspecting an opaque target-libc DIR representation.  Exercise
# real and virtual streams concurrently, including dirfd/openat, fdopendir,
# positioning, close/reopen churn, and a forked live virtual handle.
test_vfs_dir_handle_registry() {
    echo "--- VFS DIR handle registry ---"
    local root="$BUILD/vfs-dir-registry"
    local data="$root/data" bin="$root/program"
    local out="$BUILD/vfs-dir-registry.frozen"
    local log="$BUILD/vfs-dir-registry.log"
    local expected="vfs-dir-registry-ok" actual=""
    local rc=0 freeze_rc=0

    rm -rf "$root"
    rm -f "$out" "$log"
    mkdir -p "$data"
    root=$(realpath "$root")
    data="$root/data"
    bin="$root/program"
    printf '1\n' >"$data/first.txt"
    printf '2\n' >"$data/second.txt"

    if ! gcc -Wall -Wextra -Werror -pthread \
            -o "$bin" tests/vfs_dir_registry.c; then
        fail "VFS DIR handle registry" "fixture compile failed"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi
    capture_output actual "$bin" "$data" "$data/second.txt" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "$expected" ]; then
        fail "native DIR handle registry control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi

    freeze_require_direct "VFS DIR handle registry" "$log" "$out" \
        -t -f "$data/*" -- "$bin" "$data" "$data/second.txt" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "VFS DIR handle registry" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        rm -f "$out" "$log"
        return
    fi

    rm -rf "$data"
    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 \
        "$out" "$data" "$data/second.txt" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ]; then
        pass "VFS DIR handle registry"
    else
        fail "VFS DIR handle registry" "exit=$rc output=$actual"
        tail -n 60 "$log" || true
    fi

    rm -rf "$root"
    rm -f "$out" "$log"
}

# ===================================================================
# Test 2b: direct-load never retries after application handoff
# ===================================================================
test_direct_handoff_once() {
    echo "--- direct handoff executes once ---"
    local src="$BUILD/handoff_once.c" bin="$BUILD/handoff_once"
    local out="$BUILD/handoff_once.frozen" marker="$BUILD/handoff_once.log"
    local pack_log="$BUILD/handoff_once.pack.log" freeze_rc=0
    local frozen_pid target_pid
    rm -f "$pack_log"
    cat > "$src" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) return 2;
    FILE *f = fopen(argv[1], "a");
    if (!f) return 3;
    if (argc == 3 && strcmp(argv[2], "pid") == 0)
        fprintf(f, "%ld\n", (long)getpid());
    else
        fputs("ran\n", f);
    fclose(f);
    if (argc == 3 && strcmp(argv[2], "signal") == 0) raise(SIGTERM);
    if (argc == 3 && strcmp(argv[2], "pid") == 0) return 0;
    return 200;
    }
C
    gcc -o "$bin" "$src"
    freeze_require_direct "direct handoff executes once" "$pack_log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct handoff executes once" "$DIRECT_FREEZE_REASON"
        skip "direct signal handoff executes once" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$marker" "$pack_log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$marker" "$pack_log"
        return
    fi

    rm -f "$marker"
    local rc=0 lines=0
    run_with_timeout env DLFREEZE_NO_FORK= "$out" "$marker" >/dev/null 2>&1 || rc=$?
    if [ -f "$marker" ]; then
        lines=$(wc -l < "$marker")
    fi
    if [ "$rc" -eq 200 ] && [ "$lines" -eq 1 ]; then
        pass "direct handoff executes once"
    else
        fail "direct handoff executes once" "exit=$rc executions=$lines"
    fi

    rm -f "$marker"
    rc=0
    run_with_timeout env DLFREEZE_NO_FORK= "$out" "$marker" signal \
        >/dev/null 2>&1 || rc=$?
    lines=0
    if [ -f "$marker" ]; then
        lines=$(wc -l < "$marker")
    fi
    if [ "$rc" -ne 0 ] && [ "$lines" -eq 1 ]; then
        pass "direct signal handoff executes once"
    else
        fail "direct signal handoff executes once" "exit=$rc executions=$lines"
    fi

    if grep -Eq '^[[:space:]]*pre-linked[[:space:]]*:[[:space:]]*yes' \
            "$pack_log"; then
        rm -f "$marker"
        rc=0
        env -u DLFREEZE_NO_FORK "$out" "$marker" pid \
            >/dev/null 2>&1 &
        frozen_pid=$!
        wait "$frozen_pid" || rc=$?
        target_pid=$(cat "$marker" 2>/dev/null || true)
        if [ "$rc" -eq 0 ] && [ "$target_pid" = "$frozen_pid" ]; then
            pass "prelinked direct process identity"
        else
            fail "prelinked direct process identity" \
                "launcher_pid=$frozen_pid target_pid=$target_pid exit=$rc"
        fi
    else
        skip "prelinked direct process identity" \
            "fixture used runtime relocation"
    fi
    rm -f "$src" "$bin" "$out" "$marker" "$pack_log"
}

# ===================================================================
# Test 2c: the fallback supervisor forwards signals to the application
# ===================================================================
test_supervisor_signal_forwarding() {
    echo "--- fallback supervisor signal forwarding ---"
    local src="$BUILD/direct_signal.c" bin="$BUILD/direct_signal"
    local timer_src="$BUILD/direct_signal_timer.c"
    local timer_bin="$BUILD/direct_signal_timer"
    local out="$BUILD/direct_signal.frozen" marker="$BUILD/direct_signal.ready"
    local log="$BUILD/direct_signal.log"
    local timer_lines=0
    rm -f "$log"
    cat > "$src" <<'C'
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
static volatile sig_atomic_t got_signal;
static volatile sig_atomic_t got_signal_count;
static void on_signal(int signal_number) {
    got_signal = signal_number;
    got_signal_count++;
}
int main(int argc, char **argv) {
    int expected_signal = 0;
    if (argc != 2 && argc != 3) return 2;
    if (argc == 3) {
        struct sigaction action = {0};
        if (strcmp(argv[2], "alarm") == 0) expected_signal = SIGALRM;
        else if (strcmp(argv[2], "winch") == 0) expected_signal = SIGWINCH;
        else if (strcmp(argv[2], "abrt") == 0) expected_signal = SIGABRT;
        else if (strcmp(argv[2], "segv") == 0) expected_signal = SIGSEGV;
        else return 8;
        action.sa_handler = on_signal;
        sigemptyset(&action.sa_mask);
        if (sigaction(expected_signal, &action, 0) != 0) return 5;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 3;
    if (write(fd, "ready\n", 6) != 6) return 4;
    close(fd);
    if (argc == 3) {
        while (got_signal != expected_signal || got_signal_count < 1) pause();
        fd = open(argv[1], O_WRONLY | O_APPEND);
        if (fd < 0) return 6;
        if (expected_signal == SIGSEGV) {
            if (write(fd, "segv1\n", 6) != 6) return 7;
            close(fd);
            while (got_signal_count < 2) pause();
            fd = open(argv[1], O_WRONLY | O_APPEND);
            if (fd < 0 || write(fd, "segv2\n", 6) != 6) return 7;
        } else if (write(fd, argv[2], strlen(argv[2])) !=
                       (ssize_t)strlen(argv[2]) ||
                   write(fd, "\n", 1) != 1) return 7;
        close(fd);
        if (expected_signal == SIGALRM) return 76;
        if (expected_signal == SIGWINCH) return 73;
        if (expected_signal == SIGABRT) return 74;
        return 75;
    }
    for (;;) pause();
}
C
    cat > "$timer_src" <<'C'
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 95;
    alarm(2);
    execl(argv[1], argv[1], argv[2], "alarm", (char *)0);
    return 96;
}
C
    if ! gcc -Wall -Wextra -Werror -o "$bin" "$src" ||
       ! gcc -Wall -Wextra -Werror -o "$timer_bin" "$timer_src" ||
       ! run_freeze "$DLFREEZE" -o "$out" -- "$bin" >"$log" 2>&1; then
        fail "fallback supervisor signal forwarding" \
            "could not build extraction fixture"
        rm -f "$src" "$bin" "$timer_src" "$timer_bin" \
            "$out" "$marker" "$log"
        return
    fi

    rm -f "$marker"
    env -u DLFREEZE_NO_FORK "$out" "$marker" >/dev/null 2>&1 &
    local wrapper=$! child="" rc=0
    for _ in {1..100}; do
        if [ -s "$marker" ]; then
            child=$(tr ' ' '\n' < "/proc/$wrapper/task/$wrapper/children" \
                2>/dev/null | sed -n '1p' || true)
            [ -n "$child" ] && break
        fi
        sleep 0.02
    done

    if [ -z "$child" ]; then
        kill -KILL "$wrapper" 2>/dev/null || true
        wait "$wrapper" 2>/dev/null || true
        fail "fallback supervisor signal forwarding" \
            "application child did not become ready"
    else
        kill -TERM "$wrapper"
        wait "$wrapper" || rc=$?
        local child_alive=0
        if kill -0 "$child" 2>/dev/null; then
            child_alive=1
            kill -KILL "$child" 2>/dev/null || true
        fi
        if [ "$rc" -eq 143 ] && [ "$child_alive" -eq 0 ]; then
            pass "fallback supervisor signal forwarding"
        else
            fail "fallback supervisor signal forwarding" \
                "wrapper exit=$rc child_alive=$child_alive"
        fi
    fi

    # Interval timers survive exec but are not inherited across fork.  The
    # timer therefore expires on the extraction supervisor, which must relay
    # its process-local SI_KERNEL SIGALRM to the application.  SI_KERNEL alone
    # must not be mistaken for a terminal-driver process-group broadcast.
    rm -f "$marker"
    rc=0
    run_with_timeout "$timer_bin" "$bin" "$marker" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 76 ] ||
       [ "$(tail -n 1 "$marker" 2>/dev/null)" != alarm ]; then
        fail "inherited interval timer native control" "exit=$rc"
    else
        rm -f "$marker"
        rc=0
        run_with_timeout "$timer_bin" "$out" "$marker" \
            >/dev/null 2>&1 || rc=$?
        timer_lines=0
        [ -f "$marker" ] && timer_lines=$(wc -l < "$marker")
        if [ "$rc" -eq 76 ] && [ "$timer_lines" -eq 2 ] &&
           [ "$(tail -n 1 "$marker" 2>/dev/null)" = alarm ]; then
            pass "fallback inherited interval timer forwarding"
        else
            fail "fallback inherited interval timer forwarding" \
                "wrapper exit=$rc marker_lines=$timer_lines"
        fi
    fi

    # Signals whose native disposition is commonly ignored still have to
    # reach an application handler.  SIGWINCH was previously swallowed by
    # both bootstrap supervisor paths because it was absent from a fixed
    # program-oriented forwarding list.
    rm -f "$marker"
    env -u DLFREEZE_NO_FORK "$out" "$marker" winch >/dev/null 2>&1 &
    wrapper=$! child="" rc=0
    for _ in {1..100}; do
        if [ -s "$marker" ]; then
            child=$(tr ' ' '\n' < "/proc/$wrapper/task/$wrapper/children" \
                2>/dev/null | sed -n '1p' || true)
            [ -n "$child" ] && break
        fi
        sleep 0.02
    done
    if [ -z "$child" ]; then
        kill -KILL "$wrapper" 2>/dev/null || true
        wait "$wrapper" 2>/dev/null || true
        fail "fallback asynchronous signal forwarding" \
            "application child did not become ready"
    else
        kill -WINCH "$wrapper"
        wait "$wrapper" || rc=$?
        local marker_lines=0
        child_alive=0
        [ -f "$marker" ] && marker_lines=$(wc -l < "$marker")
        if kill -0 "$child" 2>/dev/null; then
            child_alive=1
            kill -KILL "$child" 2>/dev/null || true
        fi
        if [ "$rc" -eq 73 ] && [ "$marker_lines" -eq 2 ] &&
           [ "$child_alive" -eq 0 ] &&
           [ "$(tail -n 1 "$marker" 2>/dev/null)" = winch ]; then
            pass "fallback asynchronous signal forwarding"
        else
            fail "fallback asynchronous signal forwarding" \
                "wrapper exit=$rc child_alive=$child_alive marker_lines=$marker_lines"
        fi
    fi

    # Fault-number signals are also valid asynchronous process-directed
    # signals.  The bootstrap must distinguish SI_USER/SI_QUEUE delivery from
    # a real supervisor fault so an explicit SIGABRT cannot orphan the child.
    rm -f "$marker"
    env -u DLFREEZE_NO_FORK "$out" "$marker" abrt >/dev/null 2>&1 &
    wrapper=$! child="" rc=0
    for _ in {1..100}; do
        if [ -s "$marker" ]; then
            child=$(tr ' ' '\n' < "/proc/$wrapper/task/$wrapper/children" \
                2>/dev/null | sed -n '1p' || true)
            [ -n "$child" ] && break
        fi
        sleep 0.02
    done
    if [ -z "$child" ]; then
        kill -KILL "$wrapper" 2>/dev/null || true
        wait "$wrapper" 2>/dev/null || true
        fail "fallback asynchronous fault-number forwarding" \
            "application child did not become ready"
    else
        kill -ABRT "$wrapper"
        wait "$wrapper" || rc=$?
        marker_lines=0 child_alive=0
        [ -f "$marker" ] && marker_lines=$(wc -l < "$marker")
        if kill -0 "$child" 2>/dev/null; then
            child_alive=1
            kill -KILL "$child" 2>/dev/null || true
        fi
        if [ "$rc" -eq 74 ] && [ "$marker_lines" -eq 2 ] &&
           [ "$child_alive" -eq 0 ] &&
           [ "$(tail -n 1 "$marker" 2>/dev/null)" = abrt ]; then
            pass "fallback asynchronous fault-number forwarding"
        else
            fail "fallback asynchronous fault-number forwarding" \
                "wrapper exit=$rc child_alive=$child_alive marker_lines=$marker_lines"
        fi
    fi

    # SA_RESETHAND is used so a real supervisor SIGSEGV terminates natively.
    # Asynchronously sent fault-number signals must rearm that action before
    # forwarding, or the second delivery kills the wrapper and orphans a
    # child whose application handler accepted the first one.
    rm -f "$marker"
    env -u DLFREEZE_NO_FORK "$out" "$marker" segv >/dev/null 2>&1 &
    wrapper=$! child="" rc=0
    for _ in {1..100}; do
        if [ -s "$marker" ]; then
            child=$(tr ' ' '\n' < "/proc/$wrapper/task/$wrapper/children" \
                2>/dev/null | sed -n '1p' || true)
            [ -n "$child" ] && break
        fi
        sleep 0.02
    done
    if [ -z "$child" ]; then
        kill -KILL "$wrapper" 2>/dev/null || true
        wait "$wrapper" 2>/dev/null || true
        fail "fallback repeated fault-number forwarding" \
            "application child did not become ready"
    else
        kill -SEGV "$wrapper"
        for _ in {1..100}; do
            [ "$(tail -n 1 "$marker" 2>/dev/null)" = segv1 ] && break
            sleep 0.02
        done
        if [ "$(tail -n 1 "$marker" 2>/dev/null)" != segv1 ]; then
            kill -KILL "$wrapper" "$child" 2>/dev/null || true
            wait "$wrapper" 2>/dev/null || true
            fail "fallback repeated fault-number forwarding" \
                "first SIGSEGV was not handled"
        else
            kill -SEGV "$wrapper"
            wait "$wrapper" || rc=$?
            marker_lines=0 child_alive=0
            [ -f "$marker" ] && marker_lines=$(wc -l < "$marker")
            if kill -0 "$child" 2>/dev/null; then
                child_alive=1
                kill -KILL "$child" 2>/dev/null || true
            fi
            if [ "$rc" -eq 75 ] && [ "$marker_lines" -eq 3 ] &&
               [ "$child_alive" -eq 0 ] &&
               [ "$(tail -n 1 "$marker" 2>/dev/null)" = segv2 ]; then
                pass "fallback repeated fault-number forwarding"
            else
                fail "fallback repeated fault-number forwarding" \
                    "wrapper exit=$rc child_alive=$child_alive marker_lines=$marker_lines"
            fi
        fi
    fi
    rm -f "$src" "$bin" "$timer_src" "$timer_bin" \
        "$out" "$marker" "$log"
}

# ===================================================================
# Test 2c1: inherited SIGCHLD=SIG_IGN cannot auto-reap supervisor child
# ===================================================================
test_supervisor_inherited_sigchld() {
    echo "--- supervisor inherited SIGCHLD disposition ---"
    local target_src="$BUILD/sigchld_target.c"
    local launcher_src="$BUILD/sigchld_launcher.c"
    local target="$BUILD/sigchld_target"
    local launcher="$BUILD/sigchld_launcher"
    local direct="$BUILD/sigchld_direct.frozen"
    local extracted="$BUILD/sigchld_extracted.frozen"
    local direct_log="$BUILD/sigchld_direct.log"
    local extracted_log="$BUILD/sigchld_extracted.log"
    local rc=0 freeze_rc=0

    cat > "$target_src" <<'C'
#include <signal.h>
int main(void) {
    struct sigaction action;
    if (sigaction(SIGCHLD, 0, &action) != 0) return 90;
    return action.sa_handler == SIG_IGN ? 37 : 91;
}
C
    cat > "$launcher_src" <<'C'
#include <signal.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct sigaction action = {0};
    if (argc != 2) return 92;
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, 0) != 0) return 93;
    execl(argv[1], argv[1], (char *)0);
    return 94;
}
C
    if ! gcc -Wall -Wextra -Werror -o "$target" "$target_src" ||
       ! gcc -Wall -Wextra -Werror -o "$launcher" "$launcher_src"; then
        fail "supervisor inherited SIGCHLD disposition" \
            "fixture compile failed"
        rm -f "$target_src" "$launcher_src" "$target" "$launcher" \
            "$direct" "$extracted" "$direct_log" "$extracted_log"
        return
    fi

    if ! run_freeze "$DLFREEZE" -o "$extracted" "$target" \
            >"$extracted_log" 2>&1; then
        fail "extraction supervisor inherited SIGCHLD" "freeze failed"
    else
        rc=0
        run_with_timeout env -u DLFREEZE_NO_FORK \
            "$launcher" "$extracted" || rc=$?
        if [ "$rc" -eq 37 ]; then
            pass "extraction supervisor preserves inherited SIGCHLD"
        else
            fail "extraction supervisor inherited SIGCHLD" "exit=$rc"
        fi
    fi

    freeze_require_direct "direct startup inherited SIGCHLD" \
        "$direct_log" "$direct" "$target" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct startup inherited SIGCHLD" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        run_with_timeout env -u DLFREEZE_NO_FORK \
            "$launcher" "$direct" || rc=$?
        if [ "$rc" -eq 37 ]; then
            pass "direct startup preserves inherited SIGCHLD"
        else
            fail "direct startup inherited SIGCHLD" "exit=$rc"
        fi
    fi

    rm -f "$target_src" "$launcher_src" "$target" "$launcher" \
        "$direct" "$extracted" "$direct_log" "$extracted_log"
}

# ===================================================================
# Test 2c2: controlling-terminal I/O and job-control signals survive
# both automatic direct-only selection and the explicit strict in-process
# diagnostic path.
# ===================================================================
test_direct_pty_interaction() {
    echo "--- direct controlling-PTY interaction ---"
    local helper="$BUILD/pty_interaction_gate"
    local out="$BUILD/pty_interaction.frozen"
    local pack_log="$BUILD/pty_interaction.pack.log"
    local native_log="$BUILD/pty_interaction.native.log"
    local supervised_log="$BUILD/pty_interaction.supervised.log"
    local strict_log="$BUILD/pty_interaction.strict.log"
    local trace_out="$BUILD/pty_interaction.trace.frozen"
    local trace_log="$BUILD/pty_interaction.trace.log"
    local freeze_rc=0

    rm -f "$helper" "$out" "$pack_log" "$native_log" \
        "$supervised_log" "$strict_log" "$trace_out" "$trace_log"
    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE \
            -o "$helper" tests/pty_interaction_gate.c; then
        fail "direct PTY interaction" "PTY helper compile failed"
        return
    fi

    if ! "$helper" --run -- "$helper" --target >"$native_log" 2>&1; then
        if grep -q 'could not create controlling PTY' "$native_log"; then
            skip "direct PTY interaction" \
                "controlling PTYs are unavailable in this environment"
            skip "interactive PTY trace packaging" \
                "controlling PTYs are unavailable in this environment"
        else
            fail "native PTY interaction control" "PTY protocol failed"
            tail -n 80 "$native_log" || true
        fi
        rm -f "$helper" "$out" "$pack_log" "$native_log" \
            "$supervised_log" "$strict_log" "$trace_out" "$trace_log"
        return
    fi
    pass "native PTY interaction control"

    freeze_require_direct "direct PTY interaction" "$pack_log" "$out" \
        "$helper" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "automatic direct PTY interaction" "$DIRECT_FREEZE_REASON"
        skip "strict direct PTY interaction" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        if "$helper" --run -- env -u DLFREEZE_NO_FORK \
                "$out" --target >"$supervised_log" 2>&1; then
            pass "automatic direct PTY interaction"
        else
            fail "automatic direct PTY interaction" \
                "terminal protocol failed"
            tail -n 80 "$supervised_log" || true
        fi

        if "$helper" --run -- env DLFREEZE_NO_FORK=1 \
                "$out" --target >"$strict_log" 2>&1; then
            pass "strict direct PTY interaction"
        else
            fail "strict direct PTY interaction" "terminal protocol failed"
            tail -n 80 "$strict_log" || true
        fi
    fi

    # -f selects the combined file/dlopen tracer, whose child must retain
    # foreground-terminal ownership while it reads the protocol input.  The
    # deliberately unmatched glob keeps this a terminal test, not a VFS test.
    if run_freeze env -u DLFREEZE_NO_FORK PTY_GATE_TIMEOUT_MS=60000 \
        "$helper" --run -- "$DLFREEZE" -d -t \
            -f "$BUILD/.dlfreeze-pty-no-match/*" -o "$trace_out" -- \
            "$helper" --target >"$trace_log" 2>&1 &&
       [ -x "$trace_out" ]; then
        pass "interactive PTY trace packaging"
    else
        fail "interactive PTY trace packaging" \
            "TTY-reading trace target did not package successfully"
        tail -n 80 "$trace_log" || true
    fi

    rm -f "$helper" "$out" "$pack_log" "$native_log" \
        "$supervised_log" "$strict_log" "$trace_out" "$trace_log"
}

# ===================================================================
# -t must either produce a versioned, complete dlopen trace or fail.  A
# missing/incompatible preload helper must never silently produce an artifact,
# while the traced program's own nonzero exit remains a valid trace run.
# ===================================================================
test_preload_helper_compile_matrix() {
    echo "--- preload helper libc compile matrix ---"

    local root="$BUILD/preload_compile_matrix"
    local compiler compiler_path compiler_triple seen="" variant=0 log output
    local -a arch_flags

    rm -rf "$root"
    mkdir -p "$root"

    # Check the actual Makefile products as well as the strict fixture builds
    # below.  On AArch64, outlined libgcc atomics from a glibc-target GCC can
    # inject __getauxval into a helper built through musl-gcc; that private
    # import makes the DSO fail before its constructor reports readiness.
    if command -v nm >/dev/null 2>&1; then
        for output in "$BUILD/dlfreeze-preload.so" \
                      "$BUILD/dlfreeze-preload-static.so"; do
            if nm -D "$output" 2>/dev/null |
                    grep -E '[[:space:]]U[[:space:]]+(__)?getauxval(@|$)' \
                        >/dev/null; then
                fail "preload helper libc compile matrix" \
                    "runtime-private auxv import in $output"
                rm -rf "$root"
                return
            fi
        done
    fi

    for compiler in "$TEST_REAL_GCC" "$(command -v musl-gcc 2>/dev/null || true)"; do
        [ -n "$compiler" ] || continue
        compiler_path=$(readlink -f "$compiler")
        case " $seen " in
            *" $compiler_path "*) continue ;;
        esac
        seen="$seen $compiler_path"
        variant=$((variant + 1))
        output="$root/helper-$variant.so"
        log="$root/helper-$variant.log"
        arch_flags=()
        compiler_triple=$("$compiler" -dumpmachine 2>/dev/null || true)
        case "$compiler_triple" in
            aarch64-*|arm64-*)
                if printf '' | "$compiler" -Werror \
                        -mno-outline-atomics -x c -c -o /dev/null - \
                        >/dev/null 2>&1; then
                    arch_flags=(-mno-outline-atomics)
                fi
                ;;
        esac
        if ! "$compiler" -Wall -Wextra -Werror -O2 -D_GNU_SOURCE \
                -Iinclude "${arch_flags[@]}" -U_FORTIFY_SOURCE -shared \
                -fPIC -Wl,-z,defs -o "$output" src/dlopen_preload.c \
                -ldl -lpthread \
                >"$log" 2>&1; then
            fail "preload helper libc compile matrix" \
                "strict compile failed with $compiler_path"
            tail -n 80 "$log" || true
            rm -rf "$root"
            return
        fi
        if command -v nm >/dev/null 2>&1 &&
           { ! nm -D "$output" | grep -E '[[:space:]]open$' >/dev/null ||
             ! nm -D "$output" | grep -E '[[:space:]]openat$' >/dev/null ||
             ! nm -D "$output" | grep -E '[[:space:]]fopen$' >/dev/null; }; then
            fail "preload helper libc compile matrix" \
                "base interposers missing with $compiler_path"
            rm -rf "$root"
            return
        fi
        if command -v nm >/dev/null 2>&1 &&
           nm -D "$output" |
                grep -E '[[:space:]]U[[:space:]]+(__)?getauxval(@|$)' \
                    >/dev/null; then
            fail "preload helper libc compile matrix" \
                "compiler injected a runtime-private auxv import with $compiler_path"
            rm -rf "$root"
            return
        fi
    done
    if [ "$variant" -eq 0 ]; then
        skip "preload helper libc compile matrix" "no C compiler installed"
    else
        pass "preload helper libc compile matrix"
    fi
    rm -rf "$root"
}

# ===================================================================
# Glibc fortify routes runtime-valued open/openat flags through private
# checked entry points instead of the public symbols.  The trace helper must
# observe those generic libc ABI paths as well, including FILE_OFFSET_BITS=64.
# ===================================================================
test_preload_fortified_open_entrypoints() {
    echo "--- preload helper fortified open entry points ---"

    local root="$BUILD/preload_fortify_open" input directory basename
    local input_hex directory_hex bin trace suffix expected_open expected_at
    local out log freeze_rc rc
    local -a large_file_flags

    if ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
        skip "preload helper fortified open entry points" \
            "checked open symbols are a glibc ABI"
        return
    fi

    rm -rf "$root"
    mkdir -p "$root/directory"
    root=$(cd "$root" && pwd -P)
    directory="$root/directory"
    basename="input.txt"
    input="$directory/$basename"
    printf '%s\n' fortify-open-ok > "$input"
    input_hex=$(printf '%s' "$input" | od -An -tx1 | tr -d ' \n')
    directory_hex=$(printf '%s' "$directory" | od -An -tx1 | tr -d ' \n')

    for suffix in base large; do
        large_file_flags=()
        expected_open=__open_2
        expected_at=__openat_2
        if [ "$suffix" = large ]; then
            large_file_flags=(-D_FILE_OFFSET_BITS=64)
            expected_open=__open64_2
            expected_at=__openat64_2
        fi
        bin="$root/target-$suffix"
        trace="$root/trace-$suffix"
        if ! "$TEST_REAL_GCC" -Wall -Wextra -Werror -O2 \
                -D_FORTIFY_SOURCE=2 "${large_file_flags[@]}" \
                -o "$bin" tests/preload_fortify_open.c ||
           ! nm -u "$bin" | grep -E "[[:space:]]${expected_open}(@|$)" \
                >/dev/null ||
           ! nm -u "$bin" | grep -E "[[:space:]]${expected_at}(@|$)" \
                >/dev/null; then
            fail "preload helper fortified open entry points" \
                "fixture did not import $expected_open and $expected_at"
            rm -rf "$root"
            return
        fi
        if env LD_PRELOAD="$BUILD/dlfreeze-preload.so" \
                DLFREEZE_FILE_TRACE_FILE="$trace" \
                "$bin" "$input" "$directory" "$basename" &&
           [ "$(grep -Fxc "F $input_hex $input_hex" "$trace")" -eq 2 ] &&
           [ "$(grep -Fxc "D $directory_hex $directory_hex" "$trace")" -eq 1 ] &&
           [ "$(wc -l < "$trace")" -eq 4 ]; then
            pass "preload helper traces fortified $suffix open/openat"
        else
            fail "preload helper fortified $suffix open entry points" \
                "checked calls were not recorded exactly"
        fi

        out="$root/target-$suffix.frozen"
        log="$root/target-$suffix.freeze.log"
        freeze_rc=0
        freeze_require_direct \
            "direct VFS fortified $suffix open/openat" "$log" "$out" \
            -t -f "$input" -- "$bin" "$input" "$directory" "$basename" \
            || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "direct VFS fortified $suffix open/openat" \
                "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            mv "$input" "$input.host"
            rc=0
            DLFREEZE_NO_FORK=1 run_with_timeout \
                "$out" "$input" "$directory" "$basename" \
                >/dev/null 2>&1 || rc=$?
            mv "$input.host" "$input"
            if [ "$rc" -eq 0 ]; then
                pass "direct VFS fortified $suffix open/openat"
            else
                fail "direct VFS fortified $suffix open/openat" \
                    "direct replay exit=$rc"
            fi
        fi
    done
    rm -rf "$root"
}

# ===================================================================
# The preload resolver can be entered before its constructor and from many
# threads at once (for example, from an earlier preload's constructor).  Build
# a helper whose constructor attributes are neutralized so the first wrapped
# calls deterministically exercise that lazy-publication path.
# ===================================================================
test_preload_helper_initialization_race() {
    echo "--- preload helper concurrent initialization ---"

    local root="$BUILD/preload_init_race"
    local helper="$root/dlfreeze-preload-lazy.so"
    local reentrant_helper="$root/dlfreeze-preload-reentrant.so"
    local target="$root/target" trace="$root/concurrent.trace"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -U_FORTIFY_SOURCE -Dconstructor=unused -Ddestructor=unused \
            -shared -fPIC -o "$helper" src/dlopen_preload.c -ldl -lpthread ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -U_FORTIFY_SOURCE -Dconstructor=unused -Ddestructor=unused \
            -shared -fPIC -Wl,--wrap=dlsym -o "$reentrant_helper" \
            src/dlopen_preload.c tests/preload_init_reentry.c -ldl -lpthread ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$target" \
            tests/preload_init_race.c -lpthread; then
        fail "preload helper concurrent initialization" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual env LD_PRELOAD="$helper" "$target" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = preload-init-race-ok ]; then
        pass "preload helper concurrent initialization"
    else
        fail "preload helper concurrent initialization" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env LD_PRELOAD="$reentrant_helper" \
        "$target" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = preload-init-race-ok ]; then
        pass "preload helper recursive initialization"
    else
        fail "preload helper recursive initialization" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env LD_PRELOAD="$helper" \
        DLFREEZE_FILE_TRACE_FILE="$trace" "$target" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = preload-init-race-ok ] &&
       [ "$(sed -n '1p' "$trace")" = "#DLFREEZE_PRELOAD_TRACE_V4" ] &&
       [ "$(grep -Fxc '#DLFREEZE_PRELOAD_TRACE_V4' "$trace")" -eq 1 ] &&
       [ "$(grep -Fxc 'D 2f646576 2f646576' "$trace")" -eq 3200 ] &&
       [ "$(wc -l < "$trace")" -eq 3201 ]; then
        pass "preload helper concurrent records remain atomic"
    else
        fail "preload helper concurrent record atomicity" \
            "exit=$rc output=$actual lines=$(wc -l <\"$trace\" 2>/dev/null || echo missing)"
    fi
    rm -rf "$root"
}

# ===================================================================
# An LD_PRELOAD interposer is visible before its constructor necessarily
# runs.  Link an earlier-constructor fixture as the helper's DT_NEEDED
# dependency so the ordering is deterministic: both its dlopen and open must
# lazily initialize the V4 streams and be recorded before the helper ctor.
# The dependency's destructor also runs after the helper's destructor would
# have run, so its final open must remain traceable until process teardown.
# ===================================================================
test_preload_helper_constructor_order() {
    echo "--- preload helper constructor/finalizer ordering ---"

    local root="$BUILD/preload_constructor_order"
    local early_dlopen="$root/libearly-dlopen.so"
    local early_preload="$root/libearly-preload.so"
    local helper="$root/dlfreeze-preload-ordered.so"
    local target="$root/target"
    local trace="$root/dlopen.trace" file_trace="$root/file.trace"
    local root_abs dlopen_path open_path late_path
    local dlopen_hex open_hex late_hex actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE \
            -DDLFREEZE_EARLY_DLOPEN_OBJECT -shared -fPIC \
            -o "$early_dlopen" tests/preload_early_constructor.c ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE \
            -DDLFREEZE_EARLY_PRELOAD -shared -fPIC \
            -o "$early_preload" tests/preload_early_constructor.c -ldl ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -U_FORTIFY_SOURCE -shared -fPIC -o "$helper" \
            src/dlopen_preload.c -Wl,--no-as-needed -L"$root" \
            -learly-preload -Wl,-rpath,'$ORIGIN' -ldl -lpthread ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE \
            -o "$target" tests/preload_early_constructor.c -ldl; then
        fail "preload helper constructor ordering" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    root_abs=$(readlink -f "$root")
    dlopen_path="$root_abs/libearly-dlopen.so"
    open_path=$(readlink -f tests/preload_early_constructor.c)
    late_path=$(readlink -f tests/preload_init_race.c)
    dlopen_hex=$(printf '%s' "$dlopen_path" | od -An -tx1 | tr -d ' \n')
    open_hex=$(printf '%s' "$open_path" | od -An -tx1 | tr -d ' \n')
    late_hex=$(printf '%s' "$late_path" | od -An -tx1 | tr -d ' \n')

    capture_output actual env \
        LD_PRELOAD="$root_abs/dlfreeze-preload-ordered.so" \
        DLFREEZE_TRACE_FILE="$root_abs/dlopen.trace" \
        DLFREEZE_FILE_TRACE_FILE="$root_abs/file.trace" \
        DLFREEZE_EARLY_DLOPEN="$dlopen_path" \
        DLFREEZE_EARLY_OPEN="$open_path" \
        DLFREEZE_LATE_DESTRUCTOR_OPEN="$late_path" \
        "$root_abs/target" || rc=$?

    if [ "$rc" -eq 0 ] &&
       [ "$actual" = preload-early-constructor-ok ] &&
       [ -r "$trace" ] && [ -r "$file_trace" ] &&
       [ "$(sed -n '1p' "$trace")" = "#DLFREEZE_DLOPEN_TRACE_V4" ] &&
       [ "$(sed -n '1p' "$file_trace")" = "#DLFREEZE_PRELOAD_TRACE_V4" ] &&
       [ "$(grep -Fxc '#DLFREEZE_DLOPEN_TRACE_V4' "$trace")" -eq 1 ] &&
       [ "$(grep -Fxc '#DLFREEZE_PRELOAD_TRACE_V4' "$file_trace")" -eq 1 ] &&
       grep -Fq "P $dlopen_hex $dlopen_hex $dlopen_hex" "$trace" &&
       grep -Fq "F $open_hex $open_hex" "$file_trace"; then
        pass "preload helper pre-constructor tracing"
    else
        fail "preload helper pre-constructor tracing" \
            "exit=$rc output=$actual or exact V4 records are missing"
    fi

    if [ -r "$file_trace" ] &&
       grep -Fq "F $late_hex $late_hex" "$file_trace"; then
        pass "preload helper post-finalizer tracing"
    else
        fail "preload helper post-finalizer tracing" \
            "late dependency-destructor record is missing"
    fi
    rm -rf "$root"
}

# A matching DT_NEEDED name does not make a preload helper ABI-compatible:
# every strong symbol-version requirement must be provided by the target's
# selected DSO, not by a same-SONAME library from the packer's host runtime.
test_trace_helper_symbol_version_compatibility() {
    echo "--- trace helper symbol-version compatibility ---"

    local root="$BUILD/trace_helper_versions"
    local old_dir="$root/old" new_dir="$root/new" tool_dir="$root/tool"
    local soname="libdlfreeze-trace-abi.so.1"
    local provider_src="$root/provider.c" helper_src="$root/helper.c"
    local target_src="$root/target.c"
    local old_map="$root/old.map" new_map="$root/new.map"
    local old_lib="$old_dir/$soname" new_lib="$new_dir/$soname"
    local helper="$tool_dir/dlfreeze-preload.so"
    local info_helper="$root/dlfreeze-preload-info.so"
    local lld_helper="$root/dlfreeze-preload-lld.so"
    local target="$root/target" gate log out actual libc_banner
    local primary_gate="" runtime_family=unknown
    local rc=0 variants=0 compiler

    rm -rf "$root"
    mkdir -p "$old_dir" "$new_dir" "$tool_dir"
    cat >"$provider_src" <<'C'
int dlfreeze_trace_abi(void) { return 17; }
C
    cat >"$helper_src" <<'C'
extern int dlfreeze_trace_abi(void);
static volatile int observed;
__attribute__((constructor)) static void initialize(void)
{
    observed = dlfreeze_trace_abi();
}
C
    cat >"$target_src" <<'C'
extern int dlfreeze_trace_abi(void);
int main(void) { return dlfreeze_trace_abi() == 17 ? 0 : 1; }
C
    cat >"$old_map" <<'MAP'
DLFREEZE_TRACE_1.0 { global: dlfreeze_trace_abi; local: *; };
MAP
    cat >"$new_map" <<'MAP'
DLFREEZE_TRACE_2.0 { global: dlfreeze_trace_abi; local: *; };
MAP

    if ! gcc -shared -fPIC -Wl,-soname,"$soname" \
            -Wl,--version-script="$old_map" -o "$old_lib" \
            "$provider_src" ||
       ! gcc -shared -fPIC -Wl,-soname,"$soname" \
            -Wl,--version-script="$new_map" -o "$new_lib" \
            "$provider_src" ||
       ! gcc -shared -fPIC -Wl,--no-as-needed \
            -Wl,-rpath,'$ORIGIN/../new' -L"$new_dir" -o "$helper" \
            "$helper_src" -l:"$soname" ||
       ! gcc -Wl,-rpath,'$ORIGIN/old' -L"$old_dir" -o "$target" \
            "$target_src" -l:"$soname"; then
        fail "trace helper symbol-version compatibility" \
            "versioned fixtures failed to compile"
        rm -rf "$root"
        return
    fi
    if ! run_with_timeout "$target"; then
        fail "trace helper symbol-version compatibility" \
            "older-provider native control failed"
        rm -rf "$root"
        return
    fi

    for compiler in gcc clang musl-gcc; do
        command -v "$compiler" >/dev/null 2>&1 || continue
        gate="$root/elf_version_gate-$compiler"
        if ! "$compiler" -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
                -Iinclude -o "$gate" tests/elf_version_gate.c \
                src/elf_parser.c ||
           ! "$gate" "$helper" "$new_lib" "$old_lib" "$soname"; then
            fail "ELF symbol-version bounds ($compiler)" \
                "match, old-provider rejection, or metadata gate failed"
            rm -rf "$root"
            return
        fi
        if [ -z "$primary_gate" ]; then
            primary_gate="$gate"
        fi
        variants=$((variants + 1))
    done
    if [ "$variants" -eq 0 ]; then
        fail "ELF symbol-version bounds" "no C compiler available"
        rm -rf "$root"
        return
    fi
    pass "ELF symbol-version bounds and provider matching"

    # LLVM/lld commonly keeps consecutive Verneed headers together and puts
    # their Vernaux lists afterward.  Those are independent offset chains;
    # accepting this valid layout must not depend on a particular executable.
    if command -v clang >/dev/null 2>&1 &&
       command -v ld.lld >/dev/null 2>&1 &&
       clang -fuse-ld=lld -shared -fPIC -Wl,--no-as-needed \
            -o "$lld_helper" "$helper_src" "$new_lib"; then
        if ! "$primary_gate" --require-split-verneed "$lld_helper"; then
            skip "ELF split version-record layout" \
                "installed lld did not emit the split layout"
        elif "$primary_gate" "$lld_helper" "$new_lib" "$old_lib" \
                "$soname"; then
            pass "ELF split version-record layout (LLVM/lld)"
        else
            fail "ELF split version-record layout (LLVM/lld)" \
                "valid separated header/auxiliary chains were rejected"
            rm -rf "$root"
            return
        fi
    else
        skip "ELF split version-record layout" \
            "clang with lld is unavailable"
    fi

    libc_banner=$(ldd --version 2>&1 || true)
    if grep -qi 'musl' <<<"$libc_banner"; then
        runtime_family=musl
    elif grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$libc_banner"; then
        runtime_family=gnu
    fi
    if ! "$primary_gate" --mark-info "$helper" "$info_helper" \
            "$soname"; then
        fail "ELF informational version requirement" \
            "could not construct the valid VER_FLG_INFO fixture"
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual env LD_LIBRARY_PATH="$old_dir" \
        LD_PRELOAD="$info_helper" "$target" || rc=$?
    if [ "$runtime_family" = gnu ]; then
        if [ "$rc" -ne 0 ] &&
           [[ "$actual" == *"DLFREEZE_TRACE_2.0"* ]] &&
           [[ "$actual" == *"not found"* ]]; then
            pass "GNU loader enforces VER_FLG_INFO requirement"
        else
            fail "GNU loader VER_FLG_INFO semantics" \
                "missing informational requirement was accepted (rc=$rc output=$actual)"
            rm -rf "$root"
            return
        fi
    elif [ "$runtime_family" = musl ]; then
        if [ "$rc" -eq 0 ]; then
            pass "musl loader ignores version requirement names"
        else
            fail "musl loader version-name semantics" \
                "native name-only lookup control failed (rc=$rc output=$actual)"
            rm -rf "$root"
            return
        fi
    else
        skip "native VER_FLG_INFO loader semantics" \
            "runtime family could not be identified"
    fi

    # The tool canonicalizes its own directory before reporting candidates.
    # Compare the same path identity rather than depending on whether the
    # test suite was invoked with a relative or absolute build directory.
    helper=$(realpath "$helper")

    if ! cp "$DLFREEZE" "$tool_dir/dlfreeze" ||
       ! cp "$BUILD/dlfreeze-bootstrap" "$tool_dir/dlfreeze-bootstrap"; then
        fail "trace helper symbol-version compatibility" \
            "could not prepare isolated tool fixture"
        rm -rf "$root"
        return
    fi
    log="$root/freeze.log"
    out="$root/target.frozen"
    if run_freeze "$tool_dir/dlfreeze" -v -t -o "$out" -- "$target" \
            >"$log" 2>&1; then
        fail "trace helper symbol-version compatibility" \
            "newer helper was selected for the older target provider"
    elif [ "$runtime_family" = musl ] &&
         grep -Fq "trace helper candidate: $helper" "$log" &&
         ! grep -Fq 'target ABI mismatch' "$log" &&
         grep -Fq 'no valid V4 readiness' "$log" && [ ! -e "$out" ]; then
        pass "musl trace helper uses name-only version semantics"
    elif [ "$runtime_family" != musl ] &&
         grep -Fq 'trace helper rejected:' "$log" &&
         grep -Fq 'target ABI mismatch' "$log" &&
         grep -Fq 'has no ABI-compatible preload helper' "$log" &&
         [ ! -e "$out" ]; then
        pass "newer trace helper rejected before target startup"
    else
        actual=$(cat "$log" 2>/dev/null || true)
        fail "trace helper symbol-version compatibility" \
            "precise pre-exec rejection missing: $actual"
    fi
    rm -rf "$root"
}

# glibc links an LD_PRELOAD object into the main executable's loader chain.
# An old-dtags main DT_RPATH therefore resolves the helper's own DT_NEEDED
# entries even when the target does not otherwise need that provider.  The
# read-only helper ABI check must select the same object; main DT_RUNPATH is
# intentionally not inherited by this relationship.
test_trace_helper_main_rpath_ancestry() {
    echo "--- trace helper GNU main-RPATH ancestry ---"

    local root="$BUILD/trace_helper_main_rpath"
    local private="$root/private"
    local soname="libdlfreeze-aux-main-rpath.so.1"
    local provider="$private/$soname"
    local helper="$root/helper.so" target="$root/target" gate="$root/gate"
    local banner actual="" rc=0

    banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$banner"; then
        skip "trace helper GNU main-RPATH ancestry" \
            "target runtime is not glibc"
        return
    fi

    rm -rf "$root"
    mkdir -p "$private"
    cat >"$root/provider.c" <<'C'
int dlfreeze_aux_main_rpath(void) { return 29; }
C
    cat >"$root/helper.c" <<'C'
extern int dlfreeze_aux_main_rpath(void);
__attribute__((constructor)) static void probe(void)
{
    if (dlfreeze_aux_main_rpath() != 29)
        __builtin_trap();
}
C
    cat >"$root/target.c" <<'C'
#include <stdio.h>
int main(void) { puts("aux-main-rpath-native-ok"); return 0; }
C

    if ! gcc -shared -fPIC -Wl,-soname,"$soname" \
            -o "$provider" "$root/provider.c" ||
       ! gcc -shared -fPIC -Wl,--no-as-needed -L"$private" \
            -o "$helper" "$root/helper.c" -l:"$soname" ||
       ! gcc -Wl,--disable-new-dtags -Wl,-rpath,'$ORIGIN/private' \
            -o "$target" "$root/target.c" ||
       ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$gate" tests/dep_aux_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "trace helper GNU main-RPATH ancestry" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual env LD_PRELOAD="$helper" "$target" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "aux-main-rpath-native-ok" ]; then
        fail "trace helper GNU main-RPATH ancestry" \
            "native preload control exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual "$gate" --expect "$target" "$helper" \
        "$soname" "$provider" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = "aux-main-rpath-ok" ]; then
        pass "trace helper inherits GNU main DT_RPATH"
    else
        fail "trace helper GNU main-RPATH ancestry" \
            "resolver exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

test_aux_dependency_lookup_status() {
    echo "--- auxiliary dependency lookup status contract ---"

    local root="$BUILD/aux_dependency_status"
    local target="$root/target" plain="$root/plain.so"
    local token="$root/token.so" gate="$root/gate"
    local malformed="$root/malformed.cache" missing="$root/missing.cache"
    local soname=libdlfreeze-aux-definitely-missing.so.1
    local log="$root/status.log" banner

    banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$banner"; then
        skip "auxiliary dependency lookup status contract" \
            "target runtime is not glibc"
        return
    fi

    rm -rf "$root"
    mkdir -p "$root"
    cat >"$root/target.c" <<'C'
int main(void) { return 0; }
C
    cat >"$root/helper.c" <<'C'
int dlfreeze_aux_status_fixture(void) { return 0; }
C
    if ! gcc -o "$target" "$root/target.c" ||
       ! gcc -shared -fPIC -o "$plain" "$root/helper.c" ||
       ! gcc -shared -fPIC -Wl,--enable-new-dtags \
            -Wl,-rpath,'$LIB' -o "$token" "$root/helper.c" ||
       ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$gate" tests/dep_aux_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c ||
       ! printf 'not a loader cache\n' >"$malformed"; then
        fail "auxiliary dependency lookup status contract" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if ! LC_ALL=C readelf -dW "$token" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$LIB' >/dev/null; then
        fail "auxiliary dependency lookup status contract" \
            "linker did not preserve the unsupported-token fixture"
        rm -rf "$root"
        return
    fi

    if env -u LD_LIBRARY_PATH "$gate" --expect-status "$target" \
            "$plain" "$soname" - 0 >"$log" 2>&1 &&
       env -u LD_LIBRARY_PATH "$gate" --expect-status "$target" \
            "$plain" "$soname" "$missing" -1 >>"$log" 2>&1 &&
       env -u LD_LIBRARY_PATH "$gate" --expect-status "$target" \
            "$plain" "$soname" "$malformed" -1 >>"$log" 2>&1 &&
       env -u LD_LIBRARY_PATH "$gate" --expect-status "$target" \
            "$token" "$soname" - -1 >>"$log" 2>&1; then
        pass "auxiliary lookup distinguishes miss from resolver errors"
    else
        fail "auxiliary dependency lookup status contract" \
            "$(tail -n 4 "$log" 2>/dev/null)"
    fi
    rm -rf "$root"
}

test_trace_helper_completeness() {
    echo "--- trace helper completeness ---"

    local root="$BUILD/trace_helper_completeness"
    local src="$root/target.c" bin="$root/target"
    local good="$root/good.frozen" good_log="$root/good.log"
    local missing_dir="$root/missing" missing_out="$root/missing.frozen"
    local missing_log="$root/missing.log"
    local bad_src="$root/incomplete.c"
    local bad_dir="$root/incompatible" bad_out="$root/incompatible.frozen"
    local bad_log="$root/incompatible.log"
    local mode_lib_src="$root/mode-lib.c" mode_lib="$root/libmode.so"
    local mode_src="$root/mode-target.c" mode_bin="$root/mode-target"
    local mode_out="$root/mode.frozen" mode_log="$root/mode.log"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$missing_dir" "$bad_dir"
    cat > "$src" <<'C'
int main(void) { return 127; }
C
    if ! gcc -o "$bin" "$src"; then
        fail "trace helper completeness" "target compile failed"
        rm -rf "$root"
        return
    fi

    if ! run_freeze "$DLFREEZE" -t -o "$good" -- "$bin" \
            >"$good_log" 2>&1; then
        fail "trace target nonzero exit" "packaging failed"
    else
        run_with_timeout "$good" >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 127 ]; then
            pass "trace target exit 127 preserved"
        else
            fail "trace target nonzero exit" "frozen exit=$rc"
        fi
    fi

    cat > "$mode_lib_src" <<'C'
int trace_mode_value(void) { return 1; }
C
    cat > "$mode_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0x00008
#endif
int main(int argc, char **argv) {
    void *handle;
    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_DEEPBIND);
    return handle ? 0 : 77;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libmode.so \
            -o "$mode_lib" "$mode_lib_src" ||
       ! gcc -o "$mode_bin" "$mode_src" -ldl; then
        fail "trace dlopen mode admission" "fixture compile failed"
    else
        rc=0
        capture_output actual "$mode_bin" "$mode_lib" || rc=$?
        if [ "$rc" -ne 0 ]; then
            skip "trace dlopen mode admission" \
                "native loader did not accept RTLD_DEEPBIND"
        elif run_freeze "$DLFREEZE" -t -o "$mode_out" -- \
                "$mode_bin" "$mode_lib" >"$mode_log" 2>&1; then
            fail "trace dlopen mode admission" \
                "unreplayable successful mode was packaged"
        elif grep -Fq \
                'successful-dlopen-used-unsupported-mode-flags' \
                "$mode_log" && [ ! -e "$mode_out" ]; then
            pass "trace rejects unreplayable successful dlopen flags"
        else
            fail "trace dlopen mode admission" \
                "precise failure or output cleanup missing"
        fi
    fi

    if ! cp "$DLFREEZE" "$missing_dir/dlfreeze" ||
       ! cp "$BUILD/dlfreeze-bootstrap" \
            "$missing_dir/dlfreeze-bootstrap"; then
        fail "missing trace helper refusal" "could not prepare fixture"
    elif run_freeze "$missing_dir/dlfreeze" -t -o "$missing_out" -- \
            "$bin" >"$missing_log" 2>&1; then
        fail "missing trace helper refusal" "packaging unexpectedly succeeded"
    elif grep -Fq \
            'syscall tracing cannot recover exact dlopen requests' \
            "$missing_log" && [ ! -e "$missing_out" ]; then
        pass "missing trace helper fails closed"
    else
        fail "missing trace helper refusal" \
            "precise diagnostic or output cleanup missing"
    fi

    if ! cp "$DLFREEZE" "$bad_dir/dlfreeze" ||
       ! cp "$BUILD/dlfreeze-bootstrap" "$bad_dir/dlfreeze-bootstrap"; then
        fail "incompatible trace helper refusal" "could not prepare fixture"
    else
        cat > "$bad_src" <<'C'
int dlfreeze_incomplete_helper(void) { return 0; }
C
        if ! gcc -shared -fPIC -o "$bad_dir/dlfreeze-preload.so" \
                "$bad_src"; then
            fail "incompatible trace helper refusal" \
                "could not compile incomplete helper"
        elif run_freeze "$bad_dir/dlfreeze" -t -o "$bad_out" -- "$bin" \
                >"$bad_log" 2>&1; then
            fail "incompatible trace helper refusal" \
                "packaging unexpectedly succeeded"
        elif grep -Fq 'produced no valid V4 readiness record' "$bad_log" &&
             [ ! -e "$bad_out" ]; then
            pass "incompatible trace helper fails closed"
        else
            fail "incompatible trace helper refusal" \
                "precise diagnostic or output cleanup missing"
        fi
    fi

    rm -rf "$root"
}

# ===================================================================
# Tracing is observational: helper-side metadata probes must not leak errno
# into successful libc calls.  Conversely, losing even a readiness record
# must terminate promptly with the reserved helper-failure status.
# ===================================================================
test_trace_helper_error_transparency() {
    echo "--- trace helper error transparency ---"

    local root="$BUILD/trace_helper_errors"
    local lib_src="$root/lib.c" lib="$root/libtrace_errno.so"
    local target_src="$root/target.c" target="$root/target"
    local mock_src="$root/mock.c" mock="$root/mock.so"
    local trace="$root/dlopen.trace" file_trace="$root/file.trace"
    local fd_reuse_target="$root/fd-reuse-target"
    local replacement="$root/replacement.trace"
    local actual="" expect="" rc=0 control_rc=0 elapsed=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$lib_src" <<'C'
int trace_errno_value(void) { return 1; }
C
    cat > "$target_src" <<'C'
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    void *handle;
    int fd;
    int dlopen_errno;
    int open_errno;

    if (argc != 3)
        return 2;
    errno = EDOM;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    dlopen_errno = errno;
    errno = ERANGE;
    fd = open(argv[2], O_RDONLY);
    if (fd < 0)
        return 5;
    open_errno = errno;
    close(fd);
    printf("trace-errno:%d:%d\n", dlopen_errno, open_errno);
    return 0;
}
C
    cat > "$mock_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>

int dlinfo(void *handle, int request, void *info) {
    (void)handle;
    (void)request;
    (void)info;
    errno = ENOTSUP;
    return -1;
}

int fstat(int fd, struct stat *st) {
    (void)fd;
    (void)st;
    errno = EBADF;
    return -1;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libtrace_errno.so \
            -o "$lib" "$lib_src" ||
       ! gcc -o "$target" "$target_src" -ldl ||
       ! gcc -shared -fPIC -o "$mock" "$mock_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$fd_reuse_target" \
            tests/preload_trace_fd_reuse.c; then
        fail "trace helper errno transparency" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output expect env LD_PRELOAD="$mock" \
        "$target" "$lib" "$target_src" || control_rc=$?
    capture_output actual env \
        LD_PRELOAD="$BUILD/dlfreeze-preload.so:$mock" \
        DLFREEZE_TRACE_FILE="$trace" \
        DLFREEZE_FILE_TRACE_FILE="$file_trace" \
        "$target" "$lib" "$target_src" || rc=$?
    if [ "$control_rc" -eq 0 ] && [ "$rc" -eq 0 ] &&
       [ "$actual" = "$expect" ] &&
       grep -Fq '! successful-dlopen-has-no-link-map' "$trace"; then
        pass "trace helper preserves wrapped-call errno"
    else
        fail "trace helper errno transparency" \
            "control=$control_rc/$expect traced=$rc/$actual"
    fi

    if [ ! -e /dev/full ]; then
        skip "trace helper write failure" "/dev/full is unavailable"
    else
        actual=""; rc=0; SECONDS=0
        capture_output actual env \
            LD_PRELOAD="$BUILD/dlfreeze-preload.so" \
            DLFREEZE_TRACE_FILE=/dev/full /bin/true || rc=$?
        elapsed=$SECONDS
        # The helper deliberately self-SIGKILLs: unlike an exit status, that
        # cannot collide with any valid target return code.  The diagnostic and
        # elapsed-time bound distinguish it from timeout's later SIGKILL.
        if [ "$rc" -eq 137 ] && [ "$elapsed" -lt 3 ] &&
           [[ "$actual" == *"cannot write a complete trace record"* ]]; then
            pass "trace helper write failure exits promptly"
        else
            fail "trace helper write failure" \
                "exit=$rc elapsed=${elapsed}s output=$actual"
        fi
    fi

    actual=""; rc=0
    capture_output actual env \
        LD_PRELOAD="$BUILD/dlfreeze-preload.so" \
        DLFREEZE_FILE_TRACE_FILE="$(readlink -f "$file_trace")" \
        "$fd_reuse_target" "$(readlink -f "$file_trace")" \
        "$replacement" "$target_src" || rc=$?
    if [ "$rc" -eq 137 ] && [ ! -s "$replacement" ] &&
       [[ "$actual" == *"cannot write a complete trace record"* ]]; then
        pass "trace helper descriptor-reuse failure is contained"
    else
        fail "trace helper descriptor-reuse containment" \
            "exit=$rc replacement-size=$(wc -c <\"$replacement\" 2>/dev/null || echo missing) output=$actual"
    fi

    rm -rf "$root"
}

# ===================================================================
# Every exec'd process may initialize the preload helper and append its own
# readiness header.  Those headers are valid process-boundary records.  A
# failed open for a reason other than nonexistence must also never become a
# negative VFS entry.
# ===================================================================
test_trace_exec_headers_and_open_errors() {
    echo "--- trace exec headers and open error classification ---"

    local root="$BUILD/trace_exec_headers"
    local child_src="$root/child.c" child="$root/child"
    local parent_src="$root/parent.c" parent="$root/parent"
    local resource="$root/resource.txt"
    local out="$root/parent.frozen" log="$root/parent.log"
    local freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root=$(cd "$root" && pwd -P)
    child_src="$root/child.c"
    child="$root/child"
    parent_src="$root/parent.c"
    parent="$root/parent"
    resource="$root/resource.txt"
    out="$root/parent.frozen"
    log="$root/parent.log"
    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "trace exec headers and open errors" "musl-gcc not installed"
        return
    fi

    cat > "$child_src" <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char line[64];
    FILE *stream;
    int fd;

    if (argc != 2)
        return 2;
    errno = 0;
    fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0 || errno != EEXIST) {
        if (fd >= 0)
            close(fd);
        return 3;
    }
    stream = fopen(argv[1], "r");
    if (!stream || !fgets(line, sizeof(line), stream))
        return 4;
    fputs(line, stdout);
    return fclose(stream) != 0;
}
C
    cat > "$parent_src" <<'C'
#include <unistd.h>

int main(int argc, char **argv) {
    char *child_argv[3];

    if (argc != 3)
        return 2;
    child_argv[0] = argv[1];
    child_argv[1] = argv[2];
    child_argv[2] = NULL;
    execv(argv[1], child_argv);
    return 3;
}
C
    printf '%s\n' 'exec-trace-ok' > "$resource"
    if ! musl-gcc -o "$child" "$child_src" ||
       ! musl-gcc -o "$parent" "$parent_src"; then
        fail "trace exec headers and open errors" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "trace exec headers and open errors" "$log" \
        "$out" -t -f "$root/*" -- "$parent" "$child" "$resource" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "trace exec headers and open errors" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        if grep -Eq '^[[:space:]]*data files[[:space:]]*:[[:space:]]*1 matched$' \
                "$log" &&
           grep -Fq 'exec-trace-ok' "$log" && [ -x "$out" ]; then
            pass "trace exec headers and open errors"
        else
            fail "trace exec headers and open errors" \
                "repeated header was rejected or failed open became DATA"
            tail -n 80 "$log" || true
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Successful opens outside the capture patterns are observations, not
# manifest inputs.  Writable opens describe mutable application output rather
# than immutable DATA, even when their paths match.  Both kinds of short-lived
# scratch file may disappear without invalidating an unrelated input capture.
# ===================================================================
test_trace_ignores_deleted_out_of_scope_file() {
    echo "--- trace ignores deleted out-of-scope file ---"

    local root="$BUILD/trace_deleted_out_of_scope"
    local capture="$root/capture" transient="$root/transient.tmp"
    local writable="$capture/writable.tmp"
    local retained="$capture/retained.txt"
    local src="$root/target.c" bin="$root/target"
    local out="$root/target.frozen" log="$root/target.log"
    local actual="" rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$capture"
    root=$(cd "$root" && pwd -P)
    capture="$root/capture"
    transient="$root/transient.tmp"
    writable="$capture/writable.tmp"
    retained="$capture/retained.txt"
    src="$root/target.c"
    bin="$root/target"
    out="$root/target.frozen"
    log="$root/target.log"
    cat > "$src" <<'C'
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char line[64];
    FILE *stream;

    if (argc != 4)
        return 2;
    for (int i = 1; i <= 2; i++) {
        stream = fopen(argv[i], "w+");
        if (!stream || fputs("temporary\n", stream) < 0 ||
            fclose(stream) != 0)
            return 3;
        if (unlink(argv[i]) != 0)
            return 4;
    }
    stream = fopen(argv[3], "r");
    if (!stream || !fgets(line, sizeof(line), stream))
        return 5;
    fputs(line, stdout);
    return fclose(stream) != 0;
}
C
    printf '%s\n' 'capture-filter-ok' > "$retained"
    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -o "$bin" "$src"; then
            fail "deleted out-of-scope trace file" "fixture compile failed"
            rm -rf "$root"
            return
        fi
    elif ! gcc -o "$bin" "$src"; then
        fail "deleted out-of-scope trace file" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "deleted out-of-scope trace file" "$log" "$out" \
        -t -f "$capture/*" -- "$bin" "$transient" "$writable" \
        "$retained" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "deleted out-of-scope trace file" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rm -f "$retained"
        capture_output actual "$out" "$transient" "$writable" \
            "$retained" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = "capture-filter-ok" ] &&
           grep -Eq '^[[:space:]]*data files[[:space:]]*:[[:space:]]*1 matched$' \
                "$log"; then
            pass "deleted out-of-scope trace file"
        else
            fail "deleted out-of-scope trace file" \
                "exit=$rc output=$actual or manifest count differs"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# PATH empty fields have execvp semantics: they search the current directory.
# ===================================================================
test_executable_path_empty_component() {
    echo "--- executable PATH empty-component semantics ---"

    local root="$BUILD/path_empty_component"
    local src="$root/target.c" bin="$root/dlfreeze-path-target"
    local out="$root/target.frozen" log="$root/target.log"
    local dlfreeze_abs actual="" rc=0
    local shadow_first shadow_second shadow_out shadow_log
    local default_out default_log

    rm -rf "$root"
    mkdir -p "$root"
    root=$(cd "$root" && pwd -P)
    src="$root/target.c"
    bin="$root/dlfreeze-path-target"
    out="$root/target.frozen"
    log="$root/target.log"
    dlfreeze_abs=$(realpath "$DLFREEZE")
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("path-empty-ok"); return 0; }
C
    if ! gcc -o "$bin" "$src"; then
        fail "executable PATH empty component" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if ! (cd "$root" &&
          run_freeze env PATH=:/usr/bin:/bin:/usr/sbin:/sbin \
              "$dlfreeze_abs" -o "$out" dlfreeze-path-target \
              >"$log" 2>&1); then
        fail "executable PATH empty component" "dlfreeze did not match execvp"
        rm -rf "$root"
        return
    fi
    capture_output actual "$out" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = "path-empty-ok" ]; then
        pass "executable PATH empty component"
    else
        fail "executable PATH empty component" \
            "exit=$rc output=$actual"
    fi

    shadow_first="$root/shadow-first"
    shadow_second="$root/shadow-second"
    shadow_out="$root/shadow.frozen"
    shadow_log="$root/shadow.log"
    mkdir -p "$shadow_first/dlfreeze-path-shadow" "$shadow_second"
    cp "$bin" "$shadow_second/dlfreeze-path-shadow"
    if run_freeze env PATH="$shadow_first:$shadow_second:/usr/bin:/bin" \
            "$dlfreeze_abs" -o "$shadow_out" dlfreeze-path-shadow \
            >"$shadow_log" 2>&1; then
        rc=0
        capture_output actual "$shadow_out" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = path-empty-ok ]; then
            pass "PATH search skips executable directory entries"
        else
            fail "PATH directory shadow" "exit=$rc output=$actual"
        fi
    else
        fail "PATH directory shadow" \
            "executable directory prevented later regular-file lookup"
    fi

    cat >"$shadow_first/dlfreeze-path-script" <<'SH'
#!/bin/sh
exit 0
SH
    chmod 0755 "$shadow_first/dlfreeze-path-script"
    cp "$bin" "$shadow_second/dlfreeze-path-script"
    if run_freeze env PATH="$shadow_first:$shadow_second:/usr/bin:/bin" \
            "$dlfreeze_abs" -o "$root/script.frozen" \
            dlfreeze-path-script >"$root/script.log" 2>&1; then
        fail "PATH executable script admission" \
            "search skipped the first executable script"
    elif grep -Fq 'not an ELF' "$root/script.log" &&
         [ ! -e "$root/script.frozen" ]; then
        pass "PATH preserves first executable script identity"
    else
        fail "PATH executable script admission" \
            "first executable script did not reach ELF admission"
    fi

    default_out="$root/default-path.frozen"
    default_log="$root/default-path.log"
    if run_freeze env -u PATH "$dlfreeze_abs" -o "$default_out" true \
            >"$default_log" 2>&1 && "$default_out"; then
        pass "unset PATH uses the system default search path"
    else
        fail "unset PATH executable lookup" \
            "_CS_PATH default did not resolve true"
    fi
    rm -rf "$root"
}

# ===================================================================
# Relative executable spellings are argv identity, not extraction paths.
# Only their final component may be materialized below the private root.
# ===================================================================
test_relative_executable_identity_extraction() {
    echo "--- relative executable identity in extraction mode ---"

    local root="$BUILD/relative_executable_identity"
    local src="$root/identity.c" parent="$root/parent"
    local child="$parent/child" root_abs dlfreeze_abs
    local escape_name="dlfreeze-relative-escape-$$-$RANDOM"
    local parent_bin dot_bin dot_out parent_out dot_log parent_log marker
    local dot_actual="" parent_actual="" marker_actual="" rc=0

    rm -rf "$root"
    mkdir -p "$child"
    root_abs=$(cd "$root" && pwd -P)
    dlfreeze_abs=$(realpath "$DLFREEZE")
    parent_bin="$parent/$escape_name"
    dot_bin="$child/dot-relative-target"
    dot_out="$root_abs/dot-relative.frozen"
    parent_out="$root_abs/parent-relative.frozen"
    dot_log="$root_abs/dot-relative.log"
    parent_log="$root_abs/parent-relative.log"
    marker="/tmp/$escape_name"

    cat > "$src" <<'C'
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 1 || !argv[0])
        return 2;
    puts(argv[0]);
    return 0;
}
C
    if ! gcc -o "$parent_bin" "$src" || ! cp "$parent_bin" "$dot_bin"; then
        fail "relative executable extraction identity" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    printf 'outside-sentinel\n' > "$marker"

    if ! (cd "$child" &&
          run_freeze "$dlfreeze_abs" -o "$dot_out" -- ./dot-relative-target \
              >"$dot_log" 2>&1) ||
       ! (cd "$child" &&
          run_freeze "$dlfreeze_abs" -o "$parent_out" -- "../$escape_name" \
              >"$parent_log" 2>&1); then
        fail "relative executable extraction identity" \
            "packing ./name or ../name failed"
        rm -f "$marker"
        rm -rf "$root"
        return
    fi

    capture_output dot_actual "$dot_out" || rc=$?
    capture_output parent_actual "$parent_out" || rc=$?
    marker_actual=$(cat "$marker" 2>/dev/null || true)
    if [ "$rc" -eq 0 ] &&
       [ "$dot_actual" = "./dot-relative-target" ] &&
       [ "$parent_actual" = "../$escape_name" ] &&
       [ "$marker_actual" = "outside-sentinel" ]; then
        pass "relative executable extraction identity"
    else
        fail "relative executable extraction identity" \
            "exit=$rc dot=$dot_actual parent=$parent_actual marker=$marker_actual"
    fi

    rm -f "$marker"
    rm -rf "$root"
}

# ===================================================================
# A duplicate extraction destination is safe only when both logical entries
# reference the exact same embedded range.  This supports runtimes whose
# interpreter is also a shared-library provider without accepting ambiguous
# basename collisions in a malformed manifest.
# ===================================================================
test_exact_range_duplicate_extraction() {
    echo "--- exact-range duplicate extraction destinations ---"

    local root="$BUILD/exact_range_duplicate_extraction"
    local src="$root/main.c" bin="$root/main"
    local base="$root/base.frozen" positive="$root/positive.frozen"
    local negative="$root/negative.frozen" log="$root/freeze.log"
    local size footer manifest count flags magic
    local main_index="" interp_index="" shlib_index=""
    local main_entry interp_entry shlib_entry
    local actual="" rc=0 i

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("exact-range-ok"); return 0; }
C
    if ! gcc -o "$bin" "$src" ||
       ! run_freeze "$DLFREEZE" -o "$base" -- "$bin" >"$log" 2>&1; then
        fail "exact-range duplicate extraction" "fixture creation failed"
        rm -rf "$root"
        return
    fi

    size=$(stat -c %s "$base")
    if [ "$size" -ge 64 ]; then
        magic=$(od -An -tx1 -j $((size - 64)) -N8 "$base" |
            tr -d '[:space:]')
    else
        magic=""
    fi
    if [ "$magic" != "444c465245455a00" ]; then
        fail "exact-range duplicate extraction" "footer is missing"
        rm -rf "$root"
        return
    fi
    footer=$((size - 64))
    count=$(od -An -tu4 -j $((footer + 12)) -N4 "$base" |
        tr -d '[:space:]')
    manifest=$(od -An -tu8 -j $((footer + 16)) -N8 "$base" |
        tr -d '[:space:]')
    if ! [[ "$count" =~ ^[0-9]+$ && "$manifest" =~ ^[0-9]+$ ]]; then
        fail "exact-range duplicate extraction" "footer fields are invalid"
        rm -rf "$root"
        return
    fi

    for ((i = 0; i < count; i++)); do
        flags=$(od -An -tu4 -j $((manifest + i * 32 + 16)) -N4 "$base" |
            tr -d '[:space:]')
        if ((flags & 1)); then main_index=$i; fi
        if ((flags & 2)); then interp_index=$i; fi
        if ((flags & 4)) && [ -z "$shlib_index" ]; then shlib_index=$i; fi
    done
    if [ -z "$main_index" ] || [ -z "$interp_index" ] ||
       [ -z "$shlib_index" ]; then
        skip "exact-range duplicate extraction" \
            "fixture has no dynamic interpreter/shared-library pair"
        rm -rf "$root"
        return
    fi

    main_entry=$((manifest + main_index * 32))
    interp_entry=$((manifest + interp_index * 32))
    shlib_entry=$((manifest + shlib_index * 32))
    cp "$base" "$positive"
    cp "$base" "$negative"

    # Give the SHLIB the interpreter's destination name in both artifacts.
    # The positive artifact also shares its exact range.  The negative one
    # deliberately points at the distinct main-executable range.
    dd if="$base" of="$root/interp-name" bs=1 \
        skip=$((interp_entry + 20)) count=4 status=none
    dd if="$base" of="$root/interp-range" bs=1 \
        skip="$interp_entry" count=16 status=none
    dd if="$base" of="$root/main-range" bs=1 \
        skip="$main_entry" count=16 status=none
    dd if="$root/interp-name" of="$positive" bs=1 \
        seek=$((shlib_entry + 20)) conv=notrunc status=none
    dd if="$root/interp-range" of="$positive" bs=1 \
        seek="$shlib_entry" conv=notrunc status=none
    dd if="$root/interp-name" of="$negative" bs=1 \
        seek=$((shlib_entry + 20)) conv=notrunc status=none
    dd if="$root/main-range" of="$negative" bs=1 \
        seek="$shlib_entry" conv=notrunc status=none
    # This case is specifically an extraction-destination collision.  Clear
    # the SHLIB's direct-only logical-name alias in the negative mutation so
    # the bootstrap reaches the extraction planner instead of correctly
    # refusing it earlier as an unextractable logical-name artifact.
    printf '\0\0\0\0' | dd of="$negative" bs=1 \
        seek=$((shlib_entry + 28)) count=4 conv=notrunc status=none

    capture_output actual "$positive" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "exact-range-ok" ]; then
        pass "exact-range duplicate extraction is coalesced"
    else
        fail "exact-range duplicate extraction" \
            "positive artifact exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual "$negative" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"invalid or conflicting extraction paths"* ]]; then
        pass "differing-range duplicate extraction is rejected"
    else
        fail "differing-range duplicate extraction" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2d: direct-load preserves glibc's main-thread fork invariants
# ===================================================================
test_direct_fork_lifecycle() {
    echo "--- direct fork/atfork lifecycle ---"
    local src="$BUILD/direct_fork.c" bin="$BUILD/direct_fork"
    local out="$BUILD/direct_fork.frozen" log="$BUILD/direct_fork.log"
    local actual rc=0 freeze_rc=0
    rm -f "$log"
    cat > "$src" <<'C'
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t prepare_calls;
static volatile sig_atomic_t parent_calls;
static volatile sig_atomic_t child_calls;

static void atfork_prepare(void) { prepare_calls++; }
static void atfork_parent(void) { parent_calls++; }
static void atfork_child(void) { child_calls++; }

static int wait_ok(pid_t pid) {
    int status = 0;
    return waitpid(pid, &status, 0) == pid &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void) {
    if (pthread_atfork(atfork_prepare, atfork_parent, atfork_child) != 0)
        return 2;

    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        if (pid < 0) return 3;
        if (pid == 0) {
            if (prepare_calls != i + 1 || parent_calls != i ||
                child_calls != 1)
                _exit(10);

            /* A post-fork child descriptor must itself remain forkable. */
            if (i == 2) {
                pid_t nested = fork();
                if (nested < 0) _exit(11);
                if (nested == 0)
                    _exit(prepare_calls == i + 2 && parent_calls == i &&
                          child_calls == 2 ? 0 : 12);
                if (!wait_ok(nested) || prepare_calls != i + 2 ||
                    parent_calls != i + 1 || child_calls != 1)
                    _exit(13);
            }
            _exit(0);
        }
        if (!wait_ok(pid)) return 4;
        if (prepare_calls != i + 1 || parent_calls != i + 1 || child_calls != 0)
            return 5;
    }

    puts("fork-ok");
    return 0;
}
C
    gcc -pthread -o "$bin" "$src"
    freeze_require_direct "direct fork/atfork lifecycle" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct fork/atfork lifecycle" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "fork-ok" ] && [ "$rc" -eq 0 ]; then
        pass "direct fork/atfork lifecycle"
    else
        fail "direct fork/atfork lifecycle" "exit=$rc output=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Loader-owned pthread bookkeeping binds the admitted libc itself.  Public
# executable definitions retain normal application interposition semantics,
# but neither an OBJECT collision nor a callable FUNC collision may redirect
# the loader's private key/atfork operations.
# ===================================================================
test_direct_runtime_service_collisions() {
    echo "--- direct runtime-service symbol collisions ---"
    local root="$BUILD/direct-runtime-service-collisions"
    local kind macro symbol symbol_type expected label
    local bin out log native actual rc freeze_rc

    rm -rf "$root"
    mkdir -p "$root"
    for kind in object function; do
        if [ "$kind" = object ]; then
            macro=DLFRZ_PTHREAD_OBJECT_COLLISION
            symbol=pthread_key_create
            symbol_type=OBJECT
            expected="runtime-service-object-collision-ok"
        else
            macro=DLFRZ_PTHREAD_FUNCTION_COLLISION
            symbol=pthread_atfork
            symbol_type=FUNC
            expected="runtime-service-function-collision-ok"
        fi
        label="direct runtime-service $kind collision"
        bin="$root/$kind"
        out="$root/$kind.frozen"
        log="$root/$kind.log"

        if ! gcc -O2 -g -Wall -Wextra -Werror -pthread -rdynamic \
                -D"$macro" -o "$bin" \
                tests/direct_runtime_service_collision.c; then
            fail "$label" "fixture compile failed"
            continue
        fi
        if ! readelf -Ws "$bin" | awk -v name="$symbol" \
                -v type="$symbol_type" \
                '$4 == type && $8 == name { found = 1 } \
                 END { exit found ? 0 : 1 }'; then
            fail "$label" "fixture did not export $symbol as $symbol_type"
            continue
        fi
        if [ "$kind" = function ] &&
           ! readelf -Ws "$bin" | awk \
                '$4 == "FUNC" && $8 == "__register_atfork" { found = 1 } \
                 END { exit found ? 0 : 1 }'; then
            fail "$label" \
                "fixture did not export __register_atfork as FUNC"
            continue
        fi
        native=""; rc=0
        capture_output native "$bin" || rc=$?
        if [ "$rc" -ne 0 ] || [ "$native" != "$expected" ]; then
            fail "$label native control" "exit=$rc output=$native"
            continue
        fi

        freeze_rc=0
        freeze_require_direct "$label" "$log" "$out" "$bin" || \
            freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$label" "$DIRECT_FREEZE_REASON"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            continue
        fi

        actual=""; rc=0
        capture_output actual "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ]; then
            pass "$label"
        else
            fail "$label" "exit=$rc output=$actual"
        fi
    done
    rm -rf "$root"
}

# ===================================================================
# The direct runtime loader owns one append-only object/scope/TLS table.
# Exercise its writer and every public reader concurrently, including a
# constructor which recursively dlopens another object and fork children
# which must inherit a coherent loader/VFS snapshot.
# ===================================================================
test_direct_runtime_loader_concurrency() {
    echo "--- direct runtime loader concurrency ---"
    local root="$BUILD/direct-loader-concurrency"
    local root_abs bin out log native actual rc=0 freeze_rc=0 suffix i

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libloader_stress_nested.so \
            -o "$root/libloader_stress_nested.so" \
            tests/direct_loader_concurrency_nested.c; then
        fail "direct runtime loader concurrency" \
            "nested fixture compile failed"
        rm -rf "$root"
        return
    fi
    for ((i = 0; i < 12; i++)); do
        printf -v suffix '%02d' "$i"
        if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
                -DPLUGIN_ID="$i" \
                -DNESTED_PATH="\"$root_abs/libloader_stress_nested.so\"" \
                -Wl,-soname,"libloader_stress_$suffix.so" \
                -Wl,-rpath,'$ORIGIN' \
                -o "$root/libloader_stress_$suffix.so" \
                tests/direct_loader_concurrency_plugin.c -ldl; then
            fail "direct runtime loader concurrency" \
                "plugin fixture $suffix compile failed"
            rm -rf "$root"
            return
        fi
    done
    bin="$root/main"
    out="$root/main.frozen"
    log="$root/freeze.log"
    if ! gcc -Wall -Wextra -Werror -O2 -pthread -rdynamic \
            -DPLUGIN_DIR="\"$root_abs\"" -o "$bin" \
            tests/direct_loader_concurrency.c -ldl; then
        fail "direct runtime loader concurrency" "main fixture compile failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output native "$bin" ||
       [ "$native" != "loader-concurrency-ok" ]; then
        fail "direct runtime loader concurrency native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "direct runtime loader concurrency" \
        "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct runtime loader concurrency" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "loader-concurrency-ok" ]; then
        pass "direct runtime loader concurrency"
    else
        fail "direct runtime loader concurrency" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Public loader introspection must never delegate dlfreeze's private
# loaded_obj handles to the target libc as if they were native link_map
# pointers.  Exercise one stable public map identity through dlinfo,
# dladdr1, and _dl_find_object, including no-allocation TLS_DATA semantics
# on a thread which predates the dlopen.
# ===================================================================
test_direct_loader_introspection() {
    echo "--- direct loader public introspection ---"
    local root="$BUILD/direct-loader-introspection"
    local root_abs lib late bin out log native actual rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    lib="$root_abs/libloader_introspection_plugin.so"
    late="$root_abs/libloader_introspection_late.so"
    bin="$root_abs/main"
    out="$root_abs/main.frozen"
    log="$root_abs/freeze.log"

    if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libloader_introspection_plugin.so \
            -o "$lib" tests/direct_loader_introspection_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libloader_introspection_late.so \
            -o "$late" tests/direct_loader_introspection_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -pthread -o "$bin" \
            tests/direct_loader_introspection.c -ldl; then
        fail "direct loader public introspection" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output native "$bin" "$lib" native "$late" ||
       [ "$native" != "loader-introspection-ok" ]; then
        fail "direct loader public introspection native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct loader public introspection" \
        "$log" "$out" -t -- "$bin" "$lib" native "$late" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct loader public introspection" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual "$out" "$lib" strict "$late" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "loader-introspection-ok" ]; then
        pass "direct loader public introspection"
    else
        fail "direct loader public introspection" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# ELF permits e_phoff to name a file-backed table outside every PT_LOAD and
# does not require natural alignment.  Direct mode must preserve the exact
# 64-bit provenance, publish one aligned read-only lifetime-stable view, and
# use it consistently for DSO APIs and the main executable's AT_PHDR.
# ===================================================================
test_external_program_headers_direct() {
    echo "--- external program-header tables ---"
    local root="$BUILD/external-program-headers"
    local root_abs mutator gate lib sparse truncated bad bin main
    local out runtime_out main_out log actual="" rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    mutator="$root_abs/mutator"
    gate="$root_abs/metadata-mutator"
    lib="$root_abs/libexternal-phdr.so"
    sparse="$root_abs/libexternal-phdr-sparse.so"
    truncated="$root_abs/libexternal-phdr-truncated.so"
    bin="$root_abs/probe"
    main="$root_abs/main"
    out="$root_abs/probe.frozen"
    runtime_out="$root_abs/probe-runtime.frozen"
    main_out="$root_abs/main.frozen"
    log="$root_abs/freeze.log"

    if ! gcc -Wall -Wextra -Werror -O2 -Iinclude -o "$mutator" \
            tests/external_phdr_mutator.c ||
       ! gcc -Wall -Wextra -Werror -O2 -Iinclude -o "$gate" \
            tests/direct_phdr_gate.c ||
       ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC -o "$lib" \
            tests/external_phdr_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$bin" \
            tests/external_phdr_probe.c -ldl ||
       ! "$mutator" --move "$lib"; then
        fail "external program headers" "fixture compile/mutation failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output actual "$bin" --load-only "$lib" ||
       [ "$actual" != external-phdr-ok ]; then
        fail "external program headers native load control" \
            "exit/output differs: $actual"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "external DSO program headers" "$log" "$out" \
        -t -- "$bin" --load-only "$lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "external program headers" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual "$out" --require-owned "$lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = external-phdr-ok ]; then
        pass "direct external DSO program headers"
    else
        fail "direct external DSO program headers" \
            "exit=$rc output=$actual"
    fi

    if ! gcc -Wall -Wextra -Werror -O2 -o "$main" \
            tests/external_phdr_main.c -ldl ||
       ! "$mutator" --move "$main"; then
        fail "external main program headers" "fixture mutation failed"
    else
        freeze_rc=0
        freeze_require_direct "external main program headers" "$log" \
            "$main_out" -- "$main" || freeze_rc=$?
        if [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc=0
            capture_output actual "$main_out" || rc=$?
            if [ "$rc" -eq 0 ] && [ "$actual" = external-main-ok ]; then
                pass "direct external main AT_PHDR"
            else
                fail "direct external main AT_PHDR" \
                    "exit=$rc output=$actual"
            fi
        elif [ "$freeze_rc" -eq 77 ]; then
            skip "external main program headers" "$DIRECT_FREEZE_REASON"
        fi
    fi

    # Runtime filesystem loading exercises the 64-bit provenance field
    # without materializing a multi-gigabyte frozen payload: the file is
    # sparse, while all actual PT_LOAD bytes remain at their original offsets.
    if gcc -Wall -Wextra -Werror -O2 -shared -fPIC -o "$sparse" \
            tests/external_phdr_plugin.c &&
       "$mutator" --move "$sparse" 0x100000001; then
        freeze_rc=0
        freeze_require_direct "64-bit external program-header offset" \
            "$log" "$runtime_out" -- "$bin" || freeze_rc=$?
        if [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc=0
            capture_output actual "$runtime_out" --require-owned "$sparse" ||
                rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] && [ "$actual" = external-phdr-ok ]; then
                pass "direct 64-bit external program-header offset"
            else
                fail "direct 64-bit external program-header offset" \
                    "exit=$rc output=$actual"
            fi
        elif [ "$freeze_rc" -eq 77 ]; then
            skip "64-bit external program-header offset" \
                "$DIRECT_FREEZE_REASON"
        fi
    else
        fail "64-bit external program-header offset" \
            "sparse fixture mutation failed"
    fi

    if gcc -Wall -Wextra -Werror -O2 -shared -fPIC -o "$truncated" \
            tests/external_phdr_plugin.c &&
       "$mutator" --truncate "$truncated"; then
        actual=""; rc=0
        capture_output actual "$runtime_out" --expect-fail "$truncated" ||
            rc=$?
        if [ "$rc" -eq 0 ]; then
            pass "direct truncated external program headers fail closed"
        else
            fail "direct truncated external program headers fail closed" \
                "exit=$rc output=$actual"
        fi
    else
        fail "truncated external program headers" "fixture mutation failed"
    fi

    for mutation in --truncate --move-bad-phdr --duplicate-phdr \
                    --partial-phdr; do
        bad="$root_abs/main-${mutation#--}"
        if ! gcc -Wall -Wextra -Werror -O2 -o "$bad" \
                tests/external_phdr_main.c -ldl ||
           ! "$mutator" "$mutation" "$bad"; then
            fail "malformed $mutation program headers" \
                "fixture mutation failed"
            continue
        fi
        if run_freeze "$DLFREEZE" -d -o "$bad.frozen" -- "$bad" \
                >"$root_abs/reject.log" 2>&1; then
            fail "malformed $mutation program headers" \
                "packer accepted malformed table"
        else
            pass "malformed $mutation program headers fail closed"
        fi
    done

    if [ -x "$main_out" ]; then
        cp "$main_out" "$root_abs/main-bad-provenance.frozen"
        if "$gate" --external-phdr-provenance \
                "$root_abs/main-bad-provenance.frozen"; then
            rc=0
            capture_output actual "$root_abs/main-bad-provenance.frozen" ||
                rc=$?
            if [ "$rc" -ne 0 ]; then
                pass "external program-header provenance fails closed"
            else
                fail "external program-header provenance fails closed" \
                    "mutated artifact ran successfully"
            fi
        else
            fail "external program-header provenance" \
                "metadata mutation failed"
        fi
    fi
    rm -rf "$root"
}

# glibc's SysV-hash dladdr fallback admits only GLOBAL/WEAK symbols with
# non-local visibility.  musl linearly scans the same bounded dynsym table,
# admits GNU_UNIQUE too, and intentionally does not reject HIDDEN visibility.
# Reorder a relocation-free fixture so its local-prefix invariant remains
# valid after changing one symbol's binding.
test_direct_dladdr_visibility() {
    echo "--- direct dladdr binding and visibility semantics ---"
    local root="$BUILD/direct-dladdr-visibility"
    local root_abs lib mutator bin out log native actual rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    lib="$root_abs/libdladdr_visibility.so"
    mutator="$root_abs/mutate"
    bin="$root_abs/main"
    out="$root_abs/main.frozen"
    log="$root_abs/freeze.log"

    if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -nostdlib -nodefaultlibs -Wl,-Bsymbolic \
            -Wl,--hash-style=sysv -Wl,-soname,libdladdr_visibility.so \
            -o "$lib" tests/direct_dladdr_visibility_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$mutator" \
            tests/direct_dladdr_visibility_mutator.c ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$bin" \
            tests/direct_dladdr_visibility.c -ldl ||
       ! "$mutator" "$lib"; then
        fail "direct dladdr binding and visibility" "fixture setup failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output native "$bin" "$lib" ||
       [ "$native" != "dladdr-visibility-ok" ]; then
        fail "direct dladdr binding and visibility native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "direct dladdr binding and visibility" \
        "$log" "$out" -t -- "$bin" "$lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dladdr binding and visibility" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rm -f "$lib"
    capture_output actual "$out" "$lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "dladdr-visibility-ok" ]; then
        pass "direct dladdr binding and visibility"
    else
        fail "direct dladdr binding and visibility" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# A nonzero lowest PT_LOAD distinguishes the relocation load bias from the
# public mapping base.  Moving .text several pages forward also creates a real
# inter-segment hole.  glibc reserves an ET_DYN image as one l_contiguous span
# and owns that PROT_NONE hole; musl continues to require an actual PT_LOAD.
test_direct_dladdr_layout() {
    echo "--- direct dladdr mapping layout semantics ---"
    local root="$BUILD/direct-dladdr-layout"
    local root_abs lib bin out log main_layout main_out main_log
    local native actual rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    lib="$root_abs/libdladdr_layout.so"
    bin="$root_abs/main"
    out="$root_abs/main.frozen"
    log="$root_abs/freeze.log"
    main_layout="$root_abs/main-layout"
    main_out="$root_abs/main-layout.frozen"
    main_log="$root_abs/main-layout.log"

    if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libdladdr_layout.so \
            -Wl,-Ttext-segment=0x10000 -Wl,-Ttext=0x18000 \
            -o "$lib" tests/direct_loader_introspection_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$bin" \
            tests/direct_dladdr_layout.c -ldl ||
       ! gcc -Wall -Wextra -Werror -O2 -no-pie \
            -Wl,-Ttext=0x480000 -o "$main_layout" \
            tests/direct_dladdr_layout.c -ldl; then
        fail "direct dladdr mapping layout" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output native "$bin" "$lib" ||
       [ "$native" != "dladdr-layout-ok" ]; then
        fail "direct dladdr mapping layout native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi
    if ! capture_output native "$main_layout" ||
       [ "$native" != "dladdr-layout-ok" ]; then
        fail "direct main dladdr mapping layout native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct dladdr mapping layout" "$log" "$out" \
        -t -- "$bin" "$lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dladdr mapping layout" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rm -f "$lib"
    capture_output actual "$out" "$lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "dladdr-layout-ok" ]; then
        pass "direct dladdr mapping base and noncontiguous ownership"
    else
        fail "direct dladdr mapping layout" "exit=$rc output=$actual"
    fi

    freeze_rc=0
    freeze_require_direct "direct main dladdr mapping layout" \
        "$main_log" "$main_out" "$main_layout" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct main dladdr mapping layout" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        actual=""; rc=0
        capture_output actual "$main_out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "dladdr-layout-ok" ]; then
            pass "direct main mapping base and aggregate ownership"
        else
            fail "direct main dladdr mapping layout" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Kernel vDSOs are usable through AT_SYSINFO_EHDR but are not members of
# the direct loader's public object namespace.  Bare reserved names must
# therefore fail coherently; a slash-containing ELF file with the same
# basename remains an ordinary traceable dlopen target.
# ===================================================================
test_direct_vdso_namespace() {
    echo "--- direct kernel-vDSO namespace contract ---"
    local root="$BUILD/direct-vdso-namespace"
    local root_abs lib hidden bin out log native actual rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    root_abs=$(realpath "$root")
    lib="$root_abs/linux-vdso.so.1"
    hidden="$lib.host-unavailable"
    bin="$root_abs/main"
    out="$root_abs/main.frozen"
    log="$root_abs/freeze.log"

    if ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,linux-vdso.so.1 -o "$lib" \
            tests/direct_vdso_named_plugin.c ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$bin" \
            tests/direct_vdso_namespace.c -ldl; then
        fail "direct kernel-vDSO namespace" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    if ! capture_output native "$bin" trace "$lib" ||
       [ "$native" != "vdso-path-trace-ok" ]; then
        fail "pathful vDSO-basename native control" \
            "exit/output differs: $native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct kernel-vDSO namespace" \
        "$log" "$out" -t -- "$bin" trace "$lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct kernel-vDSO namespace" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$lib" "$hidden"
    capture_output actual "$out" strict "$lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "vdso-namespace-ok" ]; then
        pass "direct kernel-vDSO namespace fails closed"
        pass "pathful vDSO basename remains an ordinary embedded DSO"
    else
        fail "direct kernel-vDSO namespace" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2e: direct main return runs target atexit and ELF finalizers
# ===================================================================
test_direct_exit_lifecycle() {
    echo "--- direct exit lifecycle ordering ---"
    local src="$BUILD/direct_exit_lifecycle.c"
    local expected=$'constructor\nmain\nmain-atexit\nconstructor-atexit\ndestructor'
    cat > "$src" <<'C'
#include <stdio.h>
#include <stdlib.h>

static void constructor_atexit(void) { puts("constructor-atexit"); }
static void main_atexit(void) { puts("main-atexit"); }

__attribute__((constructor))
static void constructor(void) {
    puts("constructor");
    if (atexit(constructor_atexit) != 0)
        abort();
}

__attribute__((destructor))
static void destructor(void) {
    puts("destructor");
}

int main(int argc, char **argv) {
    (void)argv;
    puts("main");
    if (atexit(main_atexit) != 0)
        return 72;
    if (argc > 1)
        exit(73);
    return 73;
}
C

    local cc runtime bin out actual rc mode log freeze_rc
    for runtime in glibc musl; do
        if [ "$runtime" = glibc ]; then
            cc=gcc
        else
            cc=musl-gcc
            if ! command -v "$cc" >/dev/null 2>&1; then
                skip "musl direct exit lifecycle" "musl-gcc not installed"
                continue
            fi
        fi

        bin="$BUILD/direct_exit_lifecycle.$runtime"
        out="$bin.frozen"
        log="$bin.log"
        rm -f "$log"
        if ! "$cc" -o "$bin" "$src"; then
            fail "$runtime direct exit lifecycle" "compiler failed"
            continue
        fi
        if [ "$runtime" = musl ] &&
           ! file "$bin" 2>/dev/null |
               grep 'interpreter .*ld-musl' >/dev/null; then
            skip "musl direct exit lifecycle" \
                "musl-gcc did not produce a dynamic musl executable"
            rm -f "$bin" "$out"
            continue
        fi
        freeze_rc=0
        freeze_require_direct "$runtime direct exit lifecycle" "$log" \
            "$out" "$bin" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$runtime direct return exit lifecycle" "$DIRECT_FREEZE_REASON"
            skip "$runtime direct explicit exit lifecycle" "$DIRECT_FREEZE_REASON"
            rm -f "$bin" "$out" "$log"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -f "$bin" "$out" "$log"
            continue
        fi

        for mode in return explicit; do
            actual=""; rc=0
            if [ "$mode" = explicit ]; then
                capture_output actual "$out" explicit || rc=$?
            else
                capture_output actual "$out" || rc=$?
            fi
            if [ "$actual" = "$expected" ] && [ "$rc" -eq 73 ]; then
                pass "$runtime direct $mode exit lifecycle"
            else
                fail "$runtime direct $mode exit lifecycle" \
                    "exit=$rc output=$actual"
            fi
        done
        rm -f "$bin" "$out" "$log"
    done
    rm -f "$src"
}

# ===================================================================
# Test 2f: application constructors retain native fatal-signal semantics
# ===================================================================
test_direct_constructor_signal() {
    echo "--- direct constructor signal semantics ---"
    local src="$BUILD/direct_ctor_signal.c" bin="$BUILD/direct_ctor_signal"
    local out="$BUILD/direct_ctor_signal.frozen" log="$BUILD/direct_ctor_signal.log"
    local actual rc mode freeze_rc=0
    rm -f "$log"
    cat > "$src" <<'C'
#include <signal.h>
#include <sys/resource.h>

__attribute__((constructor))
static void constructor(void) {
    const struct rlimit no_core = { 0, 0 };
    setrlimit(RLIMIT_CORE, &no_core);
    raise(SIGSEGV);
}

int main(void) { return 99; }
C
    gcc -o "$bin" "$src"
    freeze_require_direct "direct constructor signal" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct constructor signal (strict)" "$DIRECT_FREEZE_REASON"
        skip "direct constructor signal (automatic)" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    for mode in strict automatic; do
        actual=""; rc=0
        if [ "$mode" = strict ]; then
            capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        else
            capture_output actual env -u DLFREEZE_NO_FORK "$out" || rc=$?
        fi
        if [ "$rc" -eq 139 ]; then
            pass "direct constructor signal ($mode)"
        else
            fail "direct constructor signal ($mode)" "exit=$rc output=$actual"
        fi
    done
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 2g: direct PREINIT_ARRAY behavior matches the native runtime
# ===================================================================
test_direct_preinit_order() {
    echo "--- direct preinit ordering ---"
    local src="$BUILD/direct_preinit.c"
    cat > "$src" <<'C'
#include <unistd.h>

static void preinit(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;
    (void)write(STDOUT_FILENO, "preinit\n", 8);
}

__attribute__((section(".preinit_array"), used))
static void (*const preinit_slot)(int, char **, char **) = preinit;

__attribute__((constructor))
static void constructor(void) {
    (void)write(STDOUT_FILENO, "constructor\n", 12);
}

int main(void) {
    (void)write(STDOUT_FILENO, "main\n", 5);
    return 0;
}
C

    local cc runtime bin out log expected actual native_rc rc freeze_rc
    for runtime in glibc musl; do
        if [ "$runtime" = glibc ]; then
            cc=gcc
        else
            cc=musl-gcc
            if ! command -v "$cc" >/dev/null 2>&1; then
                skip "musl direct preinit order" "musl-gcc not installed"
                continue
            fi
        fi

        bin="$BUILD/direct_preinit.$runtime"
        out="$bin.frozen"
        log="$bin.log"
        rm -f "$log"
        if ! "$cc" -o "$bin" "$src"; then
            fail "$runtime direct preinit order" "compiler failed"
            continue
        fi
        if [ "$runtime" = musl ] &&
           ! file "$bin" 2>/dev/null |
               grep 'interpreter .*ld-musl' >/dev/null; then
            skip "musl direct preinit order" \
                "musl-gcc did not produce a dynamic musl executable"
            rm -f "$bin" "$out" "$log"
            continue
        fi

        expected=""; native_rc=0
        capture_output expected "$bin" || native_rc=$?
        if [ "$native_rc" -ne 0 ]; then
            if [ "$runtime" = musl ]; then
                skip "musl direct preinit order" \
                    "native musl fixture is not runnable (exit $native_rc)"
            else
                fail "glibc direct preinit order" \
                    "native fixture failed (exit $native_rc)"
            fi
            rm -f "$bin" "$out" "$log"
            continue
        fi

        freeze_rc=0
        freeze_require_direct "$runtime direct preinit order" "$log" \
            "$out" "$bin" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$runtime direct preinit order" "$DIRECT_FREEZE_REASON"
            rm -f "$bin" "$out" "$log"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -f "$bin" "$out" "$log"
            continue
        fi

        actual=""; rc=0
        capture_output actual "$out" || rc=$?
        if [ "$actual" = "$expected" ] && [ "$rc" -eq "$native_rc" ]; then
            pass "$runtime direct preinit order"
        else
            fail "$runtime direct preinit order" \
                "exit=$native_rc/$rc expected=$expected actual=$actual"
        fi
        rm -f "$bin" "$out" "$log"
    done
    rm -f "$src"
}

# Startup constructor traversal must use the exact dependency edges resolved
# during dynamic-graph validation.  A basename prefix such as
# libctorprefix.so.extra is an unrelated DSO, even though a textual prefix
# matcher could mistake it for DT_NEEDED libctorprefix.so.
test_direct_constructor_prefix_collision() {
    echo "--- direct constructor dependency prefix collision ---"
    local root="$BUILD/ctor-prefix-collision"
    local actual_src="$root/actual.c" fake_src="$root/fake.c"
    local parent_src="$root/parent.c" main_src="$root/main.c"
    local actual_lib="$root/libctorprefix.so"
    local fake_lib="$root/libctorprefix.so.extra"
    local parent_lib="$root/libctorparent.so"
    local bin="$root/program" out="$root/program.frozen"
    local log="$root/freeze.log" expect actual rc_e=0 rc_a=0 freeze_rc=0
    local cc=gcc
    local label="direct constructor dependency prefix collision"

    rm -rf "$root"
    mkdir -p "$root"
    cat >"$actual_src" <<'C'
static int ready;
__attribute__((constructor))
static void actual_init(void) { ready = 1; }
int dlfreeze_ctor_dependency_ready(void) { return ready; }
C
    cat >"$fake_src" <<'C'
int dlfreeze_ctor_collision_touch(void) { return 7; }
C
    cat >"$parent_src" <<'C'
extern int dlfreeze_ctor_dependency_ready(void);
static int saw_ready;
__attribute__((constructor))
static void parent_init(void) {
    saw_ready = dlfreeze_ctor_dependency_ready();
}
int dlfreeze_ctor_parent_saw_ready(void) { return saw_ready; }
C
    cat >"$main_src" <<'C'
#include <stdio.h>
extern int dlfreeze_ctor_parent_saw_ready(void);
extern int dlfreeze_ctor_collision_touch(void);
int main(void) {
    int ok = dlfreeze_ctor_parent_saw_ready() == 1 &&
             dlfreeze_ctor_collision_touch() == 7;
    puts(ok ? "ctor-order-ok" : "ctor-order-bad");
    return ok ? 0 : 1;
}
C

    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    fi
    if ! "$cc" -shared -fPIC -Wl,-soname,libctorprefix.so \
            -o "$actual_lib" "$actual_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,libctorprefix.so.extra \
            -o "$fake_lib" "$fake_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,libctorparent.so \
            -Wl,-rpath,'$ORIGIN' -L"$root" -o "$parent_lib" \
            "$parent_src" -l:libctorprefix.so ||
       ! "$cc" -Wl,-rpath,'$ORIGIN' -Wl,--no-as-needed -L"$root" \
            -o "$bin" "$main_src" -l:libctorparent.so \
            -l:libctorprefix.so.extra; then
        fail "$label" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "ctor-order-ok" ]; then
        fail "$label" "native control exit=$rc_e output=$expect"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2h: corrupt direct object metadata is rejected before mapping
# ===================================================================
test_direct_metadata_validation() {
    echo "--- direct object metadata validation ---"
    local src="$BUILD/direct_metadata.c" bin="$BUILD/direct_metadata"
    local out="$BUILD/direct_metadata.frozen"
    local prelinked="$BUILD/direct_metadata_prelinked.frozen"
    local early_invalid="$BUILD/direct_metadata_early_invalid.frozen"
    local bad_entry="$BUILD/direct_metadata_bad_entry.frozen"
    local bad_phdr="$BUILD/direct_metadata_bad_phdr.frozen"
    local zero_load="$BUILD/direct_metadata_zero_load.frozen"
    local bad_overlap="$BUILD/direct_metadata_overlap_load.frozen"
    local bad_stack="$BUILD/direct_metadata_bad_stack.frozen"
    local data="$BUILD/direct_metadata.data"
    local data_out="$BUILD/direct_metadata_data.frozen"
    local bad_meta="$BUILD/direct_metadata_noncanonical.frozen"
    local helper="$BUILD/direct_metadata_gate"
    local log="$BUILD/direct_metadata.log"
    local data_log="$BUILD/direct_metadata_data.log"
    local size meta_off meta_flags actual mode label data_abs rc=0 freeze_rc=0

    cat > "$src" <<'C'
#include <stdio.h>

/*
 * Reserve a private program-header slot for the mutations below.  Do not
 * depend on a linker-generated build-id, ABI tag, or GNU property note:
 * valid musl toolchains may emit none of them.  The mutator recognizes the
 * complete note identity, so it cannot accidentally consume an unrelated
 * toolchain note when several PT_NOTE entries exist.
 */
extern const unsigned char dlfrz_phdr_test_note[];
__asm__(
#if defined(__aarch64__)
    ".pushsection .note.dlfreeze.phdr-test,\"a\",%note\n"
#else
    ".pushsection .note.dlfreeze.phdr-test,\"a\",@note\n"
#endif
    ".balign 4\n"
    ".global dlfrz_phdr_test_note\n"
    "dlfrz_phdr_test_note:\n"
    ".long 8\n"
    ".long 8\n"
    ".long 0x44504844\n"
    ".ascii \"DLFREEZE\"\n"
    ".balign 4\n"
    ".ascii \"PHDRTEST\"\n"
    ".balign 4\n"
    ".popsection\n");

int main(int argc, char **argv) {
    __asm__ volatile("" : : "r"(dlfrz_phdr_test_note) : "memory");
    if (argc == 2) {
        FILE *file = fopen(argv[1], "r");
        int value;
        if (!file || (value = fgetc(file)) != 'x' || fclose(file) != 0)
            return 2;
    } else if (argc != 1) {
        return 3;
    }
    puts("metadata-target-ran");
    return 0;
}
C
    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$helper" tests/direct_phdr_gate.c; then
        fail "direct metadata validation" "mutation helper compile failed"
        rm -f "$helper" "$src"
        return
    fi
    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -fPIE -pie -o "$bin" "$src"; then
            fail "direct metadata validation" "musl compile failed"
            rm -f "$helper" "$src" "$bin"
            return
        fi
    elif ! gcc -fPIE -pie -o "$bin" "$src"; then
        fail "direct metadata validation" "compile failed"
        rm -f "$helper" "$src" "$bin" "$out" "$prelinked" \
              "$early_invalid" "$bad_entry" "$bad_phdr" "$zero_load" "$bad_overlap" "$bad_stack" "$data" \
              "$data_out" "$bad_meta" "$log" "$data_log"
        return
    fi

    freeze_require_direct "direct metadata validation" "$log" "$out" \
        "$bin" || freeze_rc=$?

    if [ "$freeze_rc" -eq 0 ] || [ "$freeze_rc" -eq 77 ]; then
        if readelf -W -l "$out" 2>/dev/null |
           grep -E 'GNU_STACK[[:space:]].*RW[[:space:]]' >/dev/null; then
            pass "frozen non-executable stack policy"
        else
            fail "frozen non-executable stack policy" \
                "PT_GNU_STACK is missing or executable"
        fi
    fi
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct metadata validation" "$DIRECT_FREEZE_REASON"
        rm -f "$helper" "$src" "$bin" "$out" "$prelinked" \
              "$early_invalid" "$bad_entry" "$bad_phdr" "$zero_load" "$bad_overlap" "$bad_stack" "$data" \
              "$data_out" "$bad_meta" "$log" "$data_log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$helper" "$src" "$bin" "$out" "$prelinked" \
              "$early_invalid" "$bad_entry" "$bad_phdr" "$zero_load" "$bad_overlap" "$bad_stack" "$data" \
              "$data_out" "$bad_meta" "$log" "$data_log"
        return
    fi

    size=$(stat -c %s "$out")
    meta_off=$DIRECT_META_OFF
    if [ "$meta_off" -gt $((size - 64 - 48)) ]; then
        fail "direct metadata validation" "metadata field lies outside payload"
        rm -f "$helper" "$src" "$bin" "$out" "$prelinked" \
              "$early_invalid" "$bad_entry" "$bad_phdr" "$zero_load" "$bad_overlap" "$bad_stack" "$data" \
              "$data_out" "$bad_meta" "$log" "$data_log"
        return
    fi

    # A prelinked artifact contains relocated PT_LOAD bytes and must never be
    # retried through the system dynamic linker after an unmarked child
    # failure.  Moving a PIE main to the bootstrap's own 0x40000000 mapping
    # keeps metadata structurally valid but makes MAP_FIXED_NOREPLACE fail
    # before handoff.  A zero ET_DYN base is intentionally rejected earlier
    # by the canonical metadata validator and would not exercise this path.
    meta_flags=$(od -An -tu4 -j $((meta_off + 48)) -N4 "$out" \
        2>/dev/null | tr -d '[:space:]')
    if [[ "$meta_flags" =~ ^[0-9]+$ ]] &&
       [ $((meta_flags & 16)) -ne 0 ]; then
        cp "$out" "$prelinked"
        printf '\000\000\000\100\000\000\000\000' |
            dd of="$prelinked" bs=1 seek="$meta_off" count=8 \
                conv=notrunc status=none
        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK "$prelinked" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"refusing extraction fallback for a prelinked"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "prelinked direct failure refuses extraction"
        else
            fail "prelinked direct failure refuses extraction" \
                "exit=$rc output=$actual"
        fi
    else
        skip "prelinked direct failure refuses extraction" \
            "fixture was not prelinked"
    fi

    # DLFRZ_FLAG_DLOPEN_EARLY is metadata-only and is valid exclusively on a
    # traced DLOPEN object.  Byte 49 is the second little-endian byte of the
    # 32-bit flags field; setting bit 0x04 there adds flag 0x400 to the main.
    cp "$out" "$early_invalid"
    printf '\004' | dd of="$early_invalid" bs=1 seek=$((meta_off + 49)) \
        conv=notrunc status=none
    actual=""; rc=0
    capture_output actual "$early_invalid" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
       [[ "$actual" != *"metadata-target-ran"* ]]; then
        pass "direct metadata dormant-flag validation"
    else
        fail "direct metadata dormant-flag validation" \
            "exit=$rc output=$actual"
    fi

    # The raw entry address must name file-backed code in a PF_X PT_LOAD,
    # not merely fall somewhere inside the object's aggregate VA range.
    cp "$out" "$bad_entry"
    if ! "$helper" --entry-nonexec "$bad_entry"; then
        fail "direct non-executable entry validation" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_entry" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct non-executable entry validation"
        else
            fail "direct non-executable entry validation" \
                "exit=$rc output=$actual"
        fi
    fi

    # A file byte range has one virtual address.  Conflicting PT_LOAD
    # translations must not be resolved by whichever header happens to be
    # visited last, even when metadata is changed to match that last value.
    cp "$out" "$bad_phdr"
    if ! "$helper" --phdr-ambiguous "$bad_phdr"; then
        fail "direct ambiguous PHDR mapping validation" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_phdr" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct ambiguous PHDR mapping validation"
        else
            fail "direct ambiguous PHDR mapping validation" \
                "exit=$rc output=$actual"
        fi
    fi

    # PT_DYNAMIC is a mapped control table: its file offset and virtual
    # address must describe the same complete bytes inside one PT_LOAD.
    # Reject a post-pack mutation before the target or loader parser runs.
    cp "$out" "$bad_phdr"
    if ! "$helper" --dynamic-outside "$bad_phdr"; then
        fail "direct PT_DYNAMIC containment" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_phdr" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct PT_DYNAMIC containment validation"
        else
            fail "direct PT_DYNAMIC containment" \
                "exit=$rc output=$actual"
        fi
    fi

    # Even individually valid PT_LOAD headers are unsafe when two of them
    # own the same runtime page: MAP_FIXED, BSS clearing, and mprotect would
    # otherwise make program-header order part of the executable semantics.
    cp "$out" "$bad_overlap"
    if ! "$helper" --overlap-load "$bad_overlap"; then
        fail "direct overlapping PT_LOAD validation" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_overlap" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct overlapping PT_LOAD validation"
        else
            fail "direct overlapping PT_LOAD validation" \
                "exit=$rc output=$actual"
        fi
    fi

    # A zero-sized PT_LOAD is a legal placeholder and contributes no mapped
    # address range, alignment requirement, or PHDR translation.  It must not
    # perturb the load bias or produce a zero-length mprotect range.
    cp "$out" "$zero_load"
    if ! "$helper" --zero-load "$zero_load"; then
        fail "direct zero-sized PT_LOAD handling" \
            "could not construct valid fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$zero_load" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = "metadata-target-ran" ]; then
            pass "direct zero-sized PT_LOAD handling"
        else
            fail "direct zero-sized PT_LOAD handling" \
                "exit=$rc output=$actual"
        fi
    fi

    cp "$out" "$bad_stack"
    if ! "$helper" --stack-exec "$bad_stack"; then
        fail "direct executable-stack validation" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_stack" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct executable-stack validation"
        else
            fail "direct executable-stack validation" \
                "exit=$rc output=$actual"
        fi
    fi

    cp "$out" "$bad_stack"
    if ! "$helper" --stack-missing "$bad_stack"; then
        fail "direct missing PT_GNU_STACK validation" \
            "could not construct legacy executable-stack fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_stack" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct missing PT_GNU_STACK validation"
        else
            fail "direct missing PT_GNU_STACK validation" \
                "exit=$rc output=$actual"
        fi
    fi

    # Admission must classify the same legacy ABI before metadata is emitted,
    # not rely only on the bootstrap catching a post-pack mutation.  The
    # ordinary extraction image remains a valid generic fallback.
    if ! cp "$bin" "$bad_stack" ||
       ! "$helper" --raw-stack-missing "$bad_stack"; then
        fail "pack-time missing PT_GNU_STACK admission" \
            "could not construct raw legacy executable-stack fixture"
    elif ! run_freeze "$DLFREEZE" -d -o "$bad_meta" "$bad_stack" \
            >"$data_log" 2>&1; then
        fail "pack-time missing PT_GNU_STACK admission" "freeze failed"
    else
        size=$(stat -c %s "$bad_meta" 2>/dev/null || true)
        meta_flags=""
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
            meta_flags=$(od -An -tu8 -j $((size - 24)) -N8 "$bad_meta" \
                2>/dev/null | tr -d '[:space:]')
        fi
        if [ "$meta_flags" = 0 ] &&
           grep -Fq 'has no PT_GNU_STACK and therefore requires legacy executable-stack semantics' \
               "$data_log" &&
           ! grep -Eq 'mode[[:space:]]*:[[:space:]]*direct-load' \
               "$data_log"; then
            pass "pack-time missing PT_GNU_STACK uses extraction"
        else
            fail "pack-time missing PT_GNU_STACK admission" \
                "artifact was not a diagnosed extraction fallback"
        fi
    fi

    # Apply the same contract to source ELFs.  A file-backed but unmapped
    # dynamic table must fail the pack transaction and leave no artifact,
    # rather than producing a direct image which first fails at startup.
    rm -f "$bad_meta"
    if ! cp "$bin" "$bad_stack" ||
       ! "$helper" --raw-dynamic-outside "$bad_stack"; then
        fail "pack-time PT_DYNAMIC containment" \
            "could not construct raw malformed fixture"
    elif run_freeze "$DLFREEZE" -d -o "$bad_meta" "$bad_stack" \
            >"$data_log" 2>&1; then
        fail "pack-time PT_DYNAMIC containment" \
            "packer accepted the malformed source"
    elif [ -e "$bad_meta" ]; then
        fail "pack-time PT_DYNAMIC containment" \
            "failed transaction left an output artifact"
    else
        pass "pack-time PT_DYNAMIC containment fails transactionally"
    fi

    # Startup objects use the same canonical ELF ABI header contract as the
    # pack-time parser and late runtime dlopen path.  Mutating a previously
    # admitted payload must not bypass that contract or reach target code.
    for mode in osabi abiversion ident-pad flags type; do
        cp "$out" "$bad_meta"
        if ! "$helper" "--elf-$mode" "$bad_meta"; then
            fail "direct ELF header validation ($mode)" \
                "could not construct malformed fixture"
            continue
        fi
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_meta" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct ELF header validation ($mode)"
        else
            fail "direct ELF header validation ($mode)" \
                "exit=$rc output=$actual"
        fi
    done

    # Inapplicable metadata fields have one canonical zero representation.
    # Exercise DATA-specific state and the runtime-relocation mode before the
    # loader maps any object; accepted-but-ignored metadata is not harmless in
    # an executable manifest.
    printf 'x\n' > "$data"
    data_abs=$(realpath "$data")
    freeze_rc=0
    freeze_require_direct "direct canonical DATA metadata" "$data_log" \
        "$data_out" -t -f "${data_abs%/*}/*" -- "$bin" "$data_abs" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct canonical DATA metadata" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        for mode in data-prelinked data-phdr data-empty-fixup-offset; do
            case "$mode" in
                data-prelinked) label="DATA PRELINKED flag" ;;
                data-phdr) label="DATA PHDR offset" ;;
                *) label="empty DATA fixup offset" ;;
            esac
            cp "$data_out" "$bad_meta"
            if ! "$helper" "--$mode" "$bad_meta"; then
                skip "direct canonical $label" \
                    "fixture has no applicable runtime-fixup table"
                continue
            fi
            actual=""; rc=0
            capture_output actual "$bad_meta" "$data_abs" || rc=$?
            if [ "$rc" -eq 127 ] &&
               [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
               [[ "$actual" != *"metadata-target-ran"* ]]; then
                pass "direct canonical $label"
            else
                fail "direct canonical $label" "exit=$rc output=$actual"
            fi
        done
    fi

    cp "$out" "$bad_meta"
    if ! "$helper" --runtime-relocated-fixups "$bad_meta"; then
        skip "direct runtime-relocated fixup metadata" \
            "fixture has no prelinked runtime fixups"
    else
        actual=""; rc=0
        capture_output actual "$bad_meta" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"metadata-target-ran"* ]]; then
            pass "direct runtime-relocated fixup metadata is zeroed"
        else
            fail "direct runtime-relocated fixup metadata" \
                "exit=$rc output=$actual"
        fi
    fi

    # dlfrz_lib_meta.phdr_entsz is the 16-bit field at byte offset 46.
    printf '\000\000' | dd of="$out" bs=1 seek=$((meta_off + 46)) \
        conv=notrunc status=none
    actual=""; rc=0
    capture_output actual "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"invalid direct-load object metadata"* ]]; then
        pass "direct metadata validation"
    else
        fail "direct metadata validation" "exit=$rc output=$actual"
    fi
    rm -f "$helper" "$src" "$bin" "$out" "$prelinked" \
          "$early_invalid" "$bad_entry" "$bad_phdr" "$zero_load" "$bad_overlap" "$bad_stack" "$data" \
          "$data_out" "$bad_meta" "$log" "$data_log"
}

# The prelinked compact runtime-fixup table is executable metadata.  Its
# per-object counts and encoded relocation sequence must exactly match the
# validated ELF relocation tables; bounds-valid omissions, duplicates, and
# reorderings must fail before TLS setup or target execution.
test_prelinked_runtime_fixup_canonical() {
    echo "--- prelinked runtime-fixup canonical form ---"
    local root="$BUILD/runtime-fixup-canonical"
    local src="$root/main.c" bin="$root/main" out="$root/main.frozen"
    local log="$root/freeze.log" gate="$root/runtime_fixup_gate"
    local mode bad actual="" rc=0 freeze_rc=0 mutate_rc=0
    local cc=gcc
    local label="prelinked runtime-fixup canonical form"

    rm -rf "$root"
    mkdir -p "$root"
    cat >"$src" <<'C'
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *message = malloc(64);

    if (!message)
        return 2;
    if (snprintf(message, 64, "%s", "runtime-fixup-target-ran") < 0) {
        free(message);
        return 3;
    }
    puts(message);
    free(message);
    return 0;
}
C
    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    fi
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$gate" tests/runtime_fixup_gate.c ||
       ! "$cc" -fPIE -pie -Wl,-z,now -o "$bin" "$src"; then
        fail "$label" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "$label" "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        for mode in omitted duplicated reordered; do
            skip "$mode prelinked runtime fixup" "$DIRECT_FREEZE_REASON"
        done
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    if ! grep -Eq \
            '^[[:space:]]*pre-linked[[:space:]]*:[[:space:]]*yes' "$log";
    then
        for mode in omitted duplicated reordered; do
            skip "$mode prelinked runtime fixup" \
                "fixture was not prelinked"
        done
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_PRELOAD -u LD_AUDIT \
        DLFREEZE_NO_FORK=1 "$out" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "runtime-fixup-target-ran" ]; then
        fail "$label" "valid control exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    for mode in omit duplicate reorder; do
        bad="$root/main.$mode.frozen"
        cp "$out" "$bad"
        set +e
        "$gate" "$mode" "$bad"
        mutate_rc=$?
        set -e
        if [ "$mutate_rc" -eq 77 ]; then
            skip "$mode prelinked runtime fixup" \
                "fixture has fewer than two compact fixups"
            continue
        fi
        if [ "$mutate_rc" -ne 0 ]; then
            fail "$mode prelinked runtime fixup" \
                "could not construct mutated artifact"
            continue
        fi

        actual=""; rc=0
        capture_output actual env -u LD_PRELOAD -u LD_AUDIT \
            DLFREEZE_NO_FORK=1 "$bad" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"non-canonical pre-linked runtime fixup metadata"* ]] &&
           [[ "$actual" != *"runtime-fixup-target-ran"* ]]; then
            pass "$mode prelinked runtime fixup rejected"
        else
            fail "$mode prelinked runtime fixup" "exit=$rc output=$actual"
        fi
    done

    bad="$root/main.unknown-relocation.frozen"
    cp "$out" "$bad"
    set +e
    "$gate" unknown-relocation "$bad"
    mutate_rc=$?
    set -e
    if [ "$mutate_rc" -eq 77 ]; then
        skip "unknown prelinked relocation" \
            "fixture has no prelinked relative relocation"
    elif [ "$mutate_rc" -ne 0 ]; then
        fail "unknown prelinked relocation" \
            "could not construct mutated artifact"
    else
        actual=""; rc=0
        capture_output actual env -u LD_PRELOAD -u LD_AUDIT \
            DLFREEZE_NO_FORK=1 "$bad" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"unsupported relocation"* ]] &&
           [[ "$actual" != *"runtime-fixup-target-ran"* ]]; then
            pass "unknown prelinked relocation rejected"
        else
            fail "unknown prelinked relocation" "exit=$rc output=$actual"
        fi
    fi

    rm -rf "$root"
}

# ===================================================================
# Test 2i: auxiliary program-header ranges cannot escape PT_LOAD
# ===================================================================
test_aux_phdr_bounds_direct() {
    echo "--- direct auxiliary program-header bounds ---"
    local helper="$BUILD/direct_phdr_gate"
    local src="$BUILD/direct_phdr_target.c" bin="$BUILD/direct_phdr_target"
    local out="$BUILD/direct_phdr_target.frozen"
    local bad_relro="$BUILD/direct_phdr_relro_bad.frozen"
    local bad_eh="$BUILD/direct_phdr_eh_bad.frozen"
    local bad_sframe="$BUILD/direct_phdr_sframe_bad.frozen"
    local log="$BUILD/direct_phdr_target.log"
    local actual rc=0 freeze_rc=0 is_musl=0

    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$helper" tests/direct_phdr_gate.c; then
        fail "direct auxiliary program-header bounds" "helper compile failed"
        return
    fi
    cat > "$src" <<'C'
#include <stdio.h>

extern const unsigned char dlfrz_phdr_test_note[];
__asm__(
#if defined(__aarch64__)
    ".pushsection .note.dlfreeze.phdr-test,\"a\",%note\n"
#else
    ".pushsection .note.dlfreeze.phdr-test,\"a\",@note\n"
#endif
    ".balign 4\n"
    ".global dlfrz_phdr_test_note\n"
    "dlfrz_phdr_test_note:\n"
    ".long 8\n"
    ".long 8\n"
    ".long 0x44504844\n"
    ".ascii \"DLFREEZE\"\n"
    ".balign 4\n"
    ".ascii \"PHDRTEST\"\n"
    ".balign 4\n"
    ".popsection\n");

int main(void) {
    __asm__ volatile("" : : "r"(dlfrz_phdr_test_note) : "memory");
    puts("phdr-target-ran");
    return 0;
}
C
    if ! gcc -fPIE -pie -Wl,-z,relro,-z,now -o "$bin" "$src"; then
        fail "direct auxiliary program-header bounds" "target compile failed"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    if file "$bin" | grep 'interpreter .*ld-musl' >/dev/null; then
        is_musl=1
    fi
    freeze_require_direct "direct auxiliary program-header bounds" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "malformed PT_GNU_RELRO rejection" "$DIRECT_FREEZE_REASON"
        skip "malformed PT_GNU_EH_FRAME rejection" "$DIRECT_FREEZE_REASON"
        skip "PT_GNU_SFRAME family validation" "$DIRECT_FREEZE_REASON"
        rm -f "$helper" "$src" "$bin" "$out" "$log" "$bad_sframe"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi

    cp "$out" "$bad_relro"
    if ! "$helper" --relro-outside "$bad_relro"; then
        fail "malformed PT_GNU_RELRO rejection" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_relro" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"cannot set final memory protections"* ]] &&
           [[ "$actual" != *"phdr-target-ran"* ]]; then
            pass "malformed PT_GNU_RELRO rejection"
        else
            fail "malformed PT_GNU_RELRO rejection" \
                "exit=$rc output=$actual"
        fi
    fi

    cp "$out" "$bad_eh"
    if ! "$helper" --eh-outside "$bad_eh"; then
        fail "malformed PT_GNU_EH_FRAME rejection" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_eh" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"malformed PT_GNU_EH_FRAME"* ]] &&
           [[ "$actual" != *"phdr-target-ran"* ]]; then
            pass "malformed PT_GNU_EH_FRAME rejection"
        else
            fail "malformed PT_GNU_EH_FRAME rejection" \
                "exit=$rc output=$actual"
        fi
    fi

    cp "$out" "$bad_sframe"
    if ! "$helper" --sframe-outside "$bad_sframe"; then
        fail "PT_GNU_SFRAME family validation" \
            "could not construct malformed fixture"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_sframe" || rc=$?
        if [ "$is_musl" -eq 0 ] && [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"malformed PT_GNU_SFRAME"* ]] &&
           [[ "$actual" != *"phdr-target-ran"* ]]; then
            pass "malformed PT_GNU_SFRAME rejected for glibc API"
        elif [ "$is_musl" -eq 1 ] && [ "$rc" -eq 0 ] &&
             [[ "$actual" == *"phdr-target-ran"* ]]; then
            pass "musl ignores GNU-only SFrame metadata"
        else
            fail "PT_GNU_SFRAME family validation" \
                "exit=$rc output=$actual musl=$is_musl"
        fi
    fi

    rm -f "$helper" "$src" "$bin" "$out" "$bad_relro" "$bad_eh" \
          "$bad_sframe" "$log"
}

# ===================================================================
# Test 2j: over-aligned static TLS and malformed PT_TLS rejection
# ===================================================================
test_static_tls_alignment_direct() {
    echo "--- static TLS alignment direct-load ---"
    local src="$BUILD/static_tls_align.c" bin="$BUILD/static_tls_align"
    local out="$BUILD/static_tls_align.frozen"
    local bad="$BUILD/static_tls_align_bad.frozen"
    local log="$BUILD/static_tls_align.log"
    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    local size footer_off manifest_off main_off phoff phentsz phnum
    local phdr_off ph_type tls_phdr_off="" i

    cat > "$src" <<'C'
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static __thread unsigned char tls_value
    __attribute__((aligned(8192))) = 41;

static void *worker(void *unused) {
    int ok;
    (void)unused;
    ok = ((uintptr_t)&tls_value % 8192) == 0 && tls_value == 41;
    tls_value++;
    return (void *)(uintptr_t)(ok && tls_value == 42);
}

int main(void) {
    pthread_t thread;
    void *thread_result = NULL;
    int main_ok = ((uintptr_t)&tls_value % 8192) == 0 && tls_value == 41;
    int thread_ok = 0;

    if (pthread_create(&thread, NULL, worker, NULL) == 0 &&
        pthread_join(thread, &thread_result) == 0)
        thread_ok = (int)(uintptr_t)thread_result;
    printf("main=%d thread=%d\n", main_ok, thread_ok);
    return !(main_ok && thread_ok);
}
C

    if ! gcc -pthread -o "$bin" "$src"; then
        fail "static TLS alignment direct-load" "compile failed"
        rm -f "$src" "$bin" "$out" "$bad" "$log"
        return
    fi
    if ! readelf -W -l "$bin" 2>/dev/null |
         grep -E 'TLS[[:space:]].*0x2000([[:space:]]|$)' >/dev/null; then
        fail "static TLS alignment direct-load" \
            "fixture does not contain an 8192-byte-aligned PT_TLS"
        rm -f "$src" "$bin" "$out" "$bad" "$log"
        return
    fi

    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "main=1 thread=1" ]; then
        fail "static TLS alignment direct-load" \
            "native fixture failed (exit=$rc_e output=$expect)"
        rm -f "$src" "$bin" "$out" "$bad" "$log"
        return
    fi

    freeze_require_direct "static TLS alignment direct-load" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "static TLS alignment direct-load" "$DIRECT_FREEZE_REASON"
        skip "malformed PT_TLS alignment rejection" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$bad" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$bad" "$log"
        return
    fi

    capture_output actual "$out" || rc_a=$?
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "static TLS alignment direct-load"
    else
        fail "static TLS alignment direct-load" \
            "exit=$rc_a expected=$expect actual=$actual"
    fi

    # Locate the main executable's embedded program-header table through
    # the footer and first manifest entry, then make PT_TLS.p_align invalid.
    # Elf64_Phdr.p_align is the 64-bit field at byte offset 48.
    cp "$out" "$bad"
    size=$(stat -c %s "$bad" 2>/dev/null || true)
    if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
        footer_off=$((size - 64))
        manifest_off=$(od -An -tu8 -j $((footer_off + 16)) -N8 "$bad" \
            2>/dev/null | tr -d '[:space:]')
    else
        manifest_off=""
    fi
    if [[ "$manifest_off" =~ ^[0-9]+$ ]]; then
        main_off=$(od -An -tu8 -j "$manifest_off" -N8 "$bad" \
            2>/dev/null | tr -d '[:space:]')
    else
        main_off=""
    fi
    if [[ "$main_off" =~ ^[0-9]+$ ]]; then
        phoff=$(od -An -tu8 -j $((main_off + 32)) -N8 "$bad" \
            2>/dev/null | tr -d '[:space:]')
        phentsz=$(od -An -tu2 -j $((main_off + 54)) -N2 "$bad" \
            2>/dev/null | tr -d '[:space:]')
        phnum=$(od -An -tu2 -j $((main_off + 56)) -N2 "$bad" \
            2>/dev/null | tr -d '[:space:]')
    else
        phoff=""; phentsz=""; phnum=""
    fi
    if [[ "$phoff" =~ ^[0-9]+$ ]] &&
       [[ "$phentsz" =~ ^[0-9]+$ ]] && [ "$phentsz" -ge 56 ] &&
       [[ "$phnum" =~ ^[0-9]+$ ]]; then
        for ((i = 0; i < phnum; i++)); do
            phdr_off=$((main_off + phoff + i * phentsz))
            ph_type=$(od -An -tu4 -j "$phdr_off" -N4 "$bad" \
                2>/dev/null | tr -d '[:space:]')
            if [ "$ph_type" = 7 ]; then
                tls_phdr_off=$phdr_off
                break
            fi
        done
    fi

    if [ -n "$tls_phdr_off" ]; then
        printf '\003\000\000\000\000\000\000\000' |
            dd of="$bad" bs=1 seek=$((tls_phdr_off + 48)) \
                conv=notrunc status=none
        actual=""; rc_a=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad" || rc_a=$?
        if [ "$rc_a" -eq 127 ] &&
           [[ "$actual" == *"invalid direct-load object metadata"* ]] &&
           [[ "$actual" != *"main=1"* ]]; then
            pass "malformed PT_TLS alignment rejection"
        else
            fail "malformed PT_TLS alignment rejection" \
                "exit=$rc_a output=$actual"
        fi
    else
        fail "malformed PT_TLS alignment rejection" \
            "could not locate embedded PT_TLS program header"
    fi

    rm -f "$src" "$bin" "$out" "$bad" "$log"
}

# ===================================================================
# Test 2j2: PT_TLS first-byte alignment semantics
#
# A TLS segment can begin at a non-zero residue modulo p_align.  Static TLS
# must preserve that residue, including in a newly-created pthread.  glibc's
# dynamically allocated DTV blocks instead align the block base itself; the
# ELF first-byte residue does not apply to that allocation path.
# ===================================================================
test_tls_firstbyte_semantics_direct() {
    echo "--- PT_TLS first-byte semantics direct-load ---"
    local root="$BUILD/tls-firstbyte"
    local static_bin="$root/static-main"
    local static_out="$root/static-main.frozen"
    local static_log="$root/static-main.log"
    local lib="$root/libtls-firstbyte.so"
    local lib_removed="$root/libtls-firstbyte.so.removed"
    local dynamic_bin="$root/dynamic-main"
    local dynamic_out="$root/dynamic-main.frozen"
    local dynamic_log="$root/dynamic-main.log"
    local tls_line tls_vaddr tls_align lib_abs libc_banner
    local expect="" actual="" rc_e=0 rc_a=0 freeze_rc=0

    mkdir -p "$root"
    if ! command -v readelf >/dev/null 2>&1; then
        skip "static TLS first-byte semantics" "readelf not installed"
        skip "glibc dynamic TLS block alignment" "readelf not installed"
        return
    fi
    # The direct metadata admits 4K, 16K, and 64K kernels.  Keep distinct
    # PT_LOAD segments distinct at the largest supported runtime page size;
    # a 4K-only fixture otherwise creates overlapping mappings on AArch64.
    if ! gcc -shared -fPIC -Wl,-z,max-page-size=65536 \
            -Wl,-T,tests/tls_firstbyte.ld \
            -Wl,-soname,libtls-firstbyte.so \
            -o "$lib" tests/tls_firstbyte_lib.c ||
       ! gcc -pthread -L"$root" -Wl,-rpath,'$ORIGIN' \
            -o "$static_bin" tests/tls_firstbyte_main.c \
            -Wl,--no-as-needed -Wl,-l:libtls-firstbyte.so ||
       ! gcc -pthread -o "$dynamic_bin" \
            tests/tls_firstbyte_dlopen.c -ldl; then
        skip "static TLS first-byte semantics" \
            "toolchain cannot build the linker-script fixture"
        skip "glibc dynamic TLS block alignment" \
            "toolchain cannot build the linker-script fixture"
        rm -f "$static_bin" "$static_out" "$static_log" "$lib" \
            "$lib_removed" "$dynamic_bin" "$dynamic_out" "$dynamic_log"
        return
    fi

    tls_line=$(LC_ALL=C readelf -W -l "$lib" 2>/dev/null |
        awk '$1 == "TLS" { print; exit }')
    tls_vaddr=$(awk '{ print $3 }' <<<"$tls_line")
    tls_align=$(awk '{ print $NF }' <<<"$tls_line")
    if [[ ! "$tls_vaddr" =~ ^0x[[:xdigit:]]+$ ]] ||
       [[ ! "$tls_align" =~ ^0x[[:xdigit:]]+$ ]] ||
       [ $((tls_align)) -ne 4096 ] ||
       [ $((tls_vaddr & (tls_align - 1))) -eq 0 ]; then
        skip "static TLS first-byte semantics" \
            "linker did not emit a nonzero-residue PT_TLS"
        skip "glibc dynamic TLS block alignment" \
            "linker did not emit a nonzero-residue PT_TLS"
        rm -f "$static_bin" "$static_out" "$static_log" "$lib" \
            "$lib_removed" "$dynamic_bin" "$dynamic_out" "$dynamic_log"
        return
    fi

    capture_output expect "$static_bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "static-tls-firstbyte-ok" ]; then
        skip "static TLS first-byte semantics" \
            "native loader lacks the fixture's first-byte TLS geometry"
    else
        freeze_require_direct "static TLS first-byte semantics" \
            "$static_log" "$static_out" "$static_bin" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "static TLS first-byte semantics" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc_a=0
            capture_output actual "$static_out" || rc_a=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
                pass "static TLS first-byte semantics"
            else
                fail "static TLS first-byte semantics" \
                    "exit=$rc_a expected=$expect actual=$actual"
            fi
        fi
    fi

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eq 'GNU libc|GLIBC' <<<"$libc_banner"; then
        skip "glibc dynamic TLS block alignment" "host runtime is not glibc"
        rm -f "$static_bin" "$static_out" "$static_log" "$lib" \
            "$lib_removed" "$dynamic_bin" "$dynamic_out" "$dynamic_log"
        return
    fi

    tls_line=$(LC_ALL=C readelf -W -l "$lib" 2>/dev/null |
        awk '$1 == "TLS" { print; exit }')
    tls_vaddr=$(awk '{ print $3 }' <<<"$tls_line")
    tls_align=$(awk '{ print $NF }' <<<"$tls_line")
    if [[ ! "$tls_vaddr" =~ ^0x[[:xdigit:]]+$ ]] ||
       [[ ! "$tls_align" =~ ^0x[[:xdigit:]]+$ ]] ||
       [ $((tls_align)) -ne 4096 ] ||
       [ $((tls_vaddr & (tls_align - 1))) -eq 0 ]; then
        skip "glibc dynamic TLS block alignment" \
            "linker did not emit a nonzero-residue DSO PT_TLS"
        rm -f "$static_bin" "$static_out" "$static_log" "$lib" \
            "$lib_removed" "$dynamic_bin" "$dynamic_out" "$dynamic_log"
        return
    fi

    lib_abs=$(realpath "$lib")
    expect=""; rc_e=0
    capture_output expect "$dynamic_bin" "$lib_abs" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "dynamic-tls-firstbyte-ok" ]; then
        fail "native glibc dynamic TLS alignment control" \
            "exit=$rc_e output=$expect"
    else
        freeze_rc=0
        freeze_require_direct "glibc dynamic TLS block alignment" \
            "$dynamic_log" "$dynamic_out" -t -- \
            "$dynamic_bin" "$lib_abs" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "glibc dynamic TLS block alignment" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            if ! mv "$lib" "$lib_removed"; then
                fail "glibc dynamic TLS block alignment" \
                    "could not hide the traced DSO"
            else
                actual=""; rc_a=0
                capture_output actual "$dynamic_out" "$lib_abs" || rc_a=$?
                mv "$lib_removed" "$lib"
                actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
                if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
                    pass "glibc dynamic TLS block alignment"
                else
                    fail "glibc dynamic TLS block alignment" \
                        "exit=$rc_a expected=$expect actual=$actual"
                fi
            fi
        fi
    fi

    rm -f "$static_bin" "$static_out" "$static_log" "$lib" \
        "$lib_removed" "$dynamic_bin" "$dynamic_out" "$dynamic_log"
    rmdir "$root" 2>/dev/null || true
}

# ===================================================================
# Test 2k: zero-file-size TLS need not have a PT_LOAD template
#
# Zig and other large binaries can describe pure .tbss with a PT_TLS whose
# virtual range begins outside every PT_LOAD.  There are no template bytes to
# map in that case; ld.so allocates and zeroes p_memsz bytes independently.
# Mutate a normal pure-.tbss fixture into that shape and require both native
# ld.so and the direct loader to retain the same TLS semantics.
# ===================================================================
test_nobits_tls_outside_load_direct() {
    echo "--- NOBITS TLS outside PT_LOAD direct-load ---"
    local src="$BUILD/nobits_tls.c" bin="$BUILD/nobits_tls"
    local mutsrc="$BUILD/nobits_tls_mutate.c" mut="$BUILD/nobits_tls_mutate"
    local out="$BUILD/nobits_tls.frozen" log="$BUILD/nobits_tls.log"
    local expect actual reason rc_e=0 rc_a=0 freeze_rc=0 mut_rc=0

    cat > "$src" <<'C'
#include <stdio.h>
static __thread volatile unsigned char zero_tls[0x4000];
int main(void) {
    printf("before=%u/%u\n", zero_tls[0], zero_tls[sizeof(zero_tls) - 1]);
    zero_tls[0] = 1;
    zero_tls[sizeof(zero_tls) - 1] = 2;
    printf("after=%u/%u\n", zero_tls[0], zero_tls[sizeof(zero_tls) - 1]);
    return 0;
}
C
    cat > "$mutsrc" <<'C'
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    Elf64_Ehdr eh;
    Elf64_Phdr *ph = NULL;
    Elf64_Phdr *tls = NULL;
    FILE *file;
    uint64_t step;
    int tls_index = -1;
    int changed = 0;

    if (argc != 2 || !(file = fopen(argv[1], "r+b")) ||
        fread(&eh, 1, sizeof(eh), file) != sizeof(eh) ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0)
        return 1;
    ph = calloc(eh.e_phnum, sizeof(*ph));
    if (!ph || fseek(file, (long)eh.e_phoff, SEEK_SET) != 0 ||
        fread(ph, sizeof(*ph), eh.e_phnum, file) != eh.e_phnum)
        return 2;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_TLS)
            continue;
        if (tls)
            return 3;
        tls = &ph[i];
        tls_index = i;
    }
    if (!tls || tls->p_filesz != 0 || tls->p_memsz < 0x4000 ||
        tls->p_align == 0 || (tls->p_align & (tls->p_align - 1)) != 0)
        return 4;

    step = tls->p_align > 0x1000 ? tls->p_align : 0x1000;
    for (uint64_t multiple = 1; multiple <= 64 && !changed; multiple++) {
        uint64_t shift;

        if (multiple > UINT64_MAX / step)
            break;
        shift = multiple * step;
        /* Prefer moving toward lower addresses, but old GNU ld can place a
         * pure-.tbss PT_TLS at a small file offset that cannot be reduced by
         * a page.  Moving vaddr and offset forward by the same aligned delta
         * preserves ELF congruence and represents the same zero-byte
         * template semantics. */
        for (int forward = 0; forward <= 1 && !changed; forward++) {
            Elf64_Phdr candidate = *tls;
            int contained = 0;

            if (!forward) {
                if (candidate.p_vaddr < shift ||
                    candidate.p_offset < shift)
                    continue;
                candidate.p_vaddr -= shift;
                if (candidate.p_paddr >= shift)
                    candidate.p_paddr -= shift;
                candidate.p_offset -= shift;
            } else {
                if (candidate.p_vaddr > UINT64_MAX - shift ||
                    candidate.p_paddr > UINT64_MAX - shift ||
                    candidate.p_offset > UINT64_MAX - shift)
                    continue;
                candidate.p_vaddr += shift;
                candidate.p_paddr += shift;
                candidate.p_offset += shift;
            }
            for (int i = 0; i < eh.e_phnum; i++) {
                uint64_t delta;
                if (ph[i].p_type != PT_LOAD ||
                    candidate.p_vaddr < ph[i].p_vaddr)
                    continue;
                delta = candidate.p_vaddr - ph[i].p_vaddr;
                if (delta <= ph[i].p_memsz &&
                    candidate.p_memsz <= ph[i].p_memsz - delta) {
                    contained = 1;
                    break;
                }
            }
            if (!contained) {
                *tls = candidate;
                changed = 1;
            }
        }
    }
    if (!changed)
        return 5;
    if (fseek(file, (long)(eh.e_phoff +
            (uint64_t)tls_index * sizeof(*ph)), SEEK_SET) != 0 ||
        fwrite(tls, 1, sizeof(*tls), file) != sizeof(*tls) ||
        fclose(file) != 0)
        return 6;
    free(ph);
    return 0;
}
C

    if ! gcc -fPIE -pie -o "$bin" "$src"; then
        fail "NOBITS TLS outside PT_LOAD direct-load" \
            "fixture compile failed"
        rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
        return
    fi
    if ! gcc -o "$mut" "$mutsrc"; then
        fail "NOBITS TLS outside PT_LOAD direct-load" \
            "fixture mutator compile failed"
        rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
        return
    fi
    "$mut" "$bin" || mut_rc=$?
    if [ "$mut_rc" -ge 3 ] && [ "$mut_rc" -le 5 ]; then
        case "$mut_rc" in
            3) reason="toolchain emitted more than one PT_TLS segment" ;;
            4) reason="toolchain did not emit a single zero-file-size PT_TLS segment" ;;
            5) reason="toolchain PT_TLS layout has no valid aligned move outside PT_LOAD" ;;
        esac
        skip "NOBITS TLS outside PT_LOAD direct-load" "$reason"
        rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
        return
    fi
    if [ "$mut_rc" -ne 0 ]; then
        fail "NOBITS TLS outside PT_LOAD direct-load" \
            "fixture mutation failed (exit=$mut_rc)"
        rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] ||
       [ "$expect" != $'before=0/0\nafter=1/2' ]; then
        fail "NOBITS TLS outside PT_LOAD direct-load" \
            "native loader rejected fixture (exit=$rc_e output=$expect)"
        rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
        return
    fi

    freeze_require_direct "NOBITS TLS outside PT_LOAD direct-load" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "NOBITS TLS outside PT_LOAD direct-load" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "NOBITS TLS outside PT_LOAD direct-load"
        else
            fail "NOBITS TLS outside PT_LOAD direct-load" \
                "exit=$rc_a expected=$expect actual=$actual"
        fi
    fi
    rm -f "$src" "$bin" "$mutsrc" "$mut" "$out" "$log"
}

# ===================================================================
# Test 2f: dependency search follows the target loader's foreign-ABI handling
# ===================================================================
test_dependency_abi_validation() {
    echo "--- dependency ABI validation ---"
    local lib_src="$BUILD/abi_dep.c" main_src="$BUILD/abi_main.c"
    local good="$BUILD/abi-good" bad="$BUILD/abi-bad"
    local lib="$good/libdlfreeze_abi_fixture.so"
    local bin="$BUILD/abi_main" out="$BUILD/abi_main.frozen" actual rc=0
    local log="$BUILD/abi_main.freeze.log"
    local mode candidate="$bad/libdlfreeze_abi_fixture.so"
    mkdir -p "$good" "$bad"
    cat > "$lib_src" <<'C'
#ifndef DLFREEZE_ABI_VALUE
#define DLFREEZE_ABI_VALUE 42
#endif
int abi_fixture_value(void) { return DLFREEZE_ABI_VALUE; }
C
    cat > "$main_src" <<'C'
#include <stdio.h>
int abi_fixture_value(void);
int main(void) { printf("%d\n", abi_fixture_value()); return 0; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfreeze_abi_fixture.so \
            -o "$lib" "$lib_src" ||
       ! gcc -Wl,-rpath,"$good" -L"$good" -o "$bin" "$main_src" \
            -ldlfreeze_abi_fixture; then
        fail "dependency ABI validation" "fixture compile failed"
        rm -rf "$good" "$bad"
        rm -f "$lib_src" "$main_src" "$bin" "$out" "$log"
        return
    fi
    for mode in machine osabi flags et-exec pie; do
        if [ "$mode" = pie ]; then
            cp "$bin" "$candidate"
        elif [ "$mode" = machine ]; then
            # Give the first candidate an observable value before changing
            # only e_machine.  GNU loaders skip it and reach the good DSO;
            # musl commits to the opened pathname.  Derive the assertion from
            # that native behavior instead of the compiler command name.
            if ! gcc -shared -fPIC -DDLFREEZE_ABI_VALUE=41 \
                    -Wl,-soname,libdlfreeze_abi_fixture.so \
                    -o "$candidate" "$lib_src" ||
               ! elf64_set_foreign_machine "$candidate"; then
                fail "dependency ABI candidate ($mode)" \
                    "fixture mutation failed"
                continue
            fi
        else
            cp "$lib" "$candidate"
            case "$mode" in
                osabi)
                    printf '\011' | dd of="$candidate" bs=1 seek=7 \
                        conv=notrunc status=none ;;
                flags)
                    printf '\001\000\000\000' | dd of="$candidate" bs=1 \
                        seek=48 conv=notrunc status=none ;;
                et-exec)
                    printf '\002\000' | dd of="$candidate" bs=1 seek=16 \
                        conv=notrunc status=none ;;
            esac
        fi

        rm -f "$out"
        actual=""; rc=0
        if [ "$mode" = machine ]; then
            local native="" native_rc=0
            capture_output native env LD_LIBRARY_PATH="$bad" "$bin" ||
                native_rc=$?
            if [ "$native_rc" -eq 0 ] && [ "$native" = 42 ]; then
                if ! run_freeze env LD_LIBRARY_PATH="$bad" "$DLFREEZE" \
                        -o "$out" "$bin" >"$log" 2>&1; then
                    fail "dependency ABI candidate ($mode)" \
                        "resolver rejected the target loader's valid fallback"
                    continue
                fi
                capture_output actual "$out" || rc=$?
                if [ "$rc" -eq 0 ] && [ "$actual" = 42 ]; then
                    pass "foreign-machine candidate follows native skip semantics"
                else
                    fail "dependency ABI candidate ($mode)" \
                        "exit=$rc output=$actual"
                fi
            elif [ "$native_rc" -eq 0 ] && [ "$native" = 41 ]; then
                if run_freeze env LD_LIBRARY_PATH="$bad" "$DLFREEZE" \
                        -o "$out" "$bin" >"$log" 2>&1; then
                    fail "dependency ABI candidate ($mode)" \
                        "resolver skipped a target-loader first-open candidate"
                elif [ ! -e "$out" ]; then
                    pass "foreign-machine first-open candidate fails closed"
                else
                    fail "dependency ABI candidate ($mode)" \
                        "failed pack left an output artifact"
                fi
            elif [ "$native_rc" -ne 0 ]; then
                if run_freeze env LD_LIBRARY_PATH="$bad" "$DLFREEZE" \
                        -o "$out" "$bin" >"$log" 2>&1; then
                    fail "dependency ABI candidate ($mode)" \
                        "resolver continued after the target loader rejected the candidate"
                elif [ ! -e "$out" ]; then
                    pass "foreign-machine candidate follows native rejection"
                else
                    fail "dependency ABI candidate ($mode)" \
                        "failed pack left an output artifact"
                fi
            else
                fail "native dependency ABI candidate ($mode) control" \
                    "exit=$native_rc output=$native"
            fi
        elif run_freeze env LD_LIBRARY_PATH="$bad" "$DLFREEZE" \
                -o "$out" "$bin" >"$log" 2>&1; then
            fail "dependency ABI candidate ($mode)" \
                "resolver skipped an opened unsupported candidate"
        elif [ ! -e "$out" ]; then
            pass "opened dependency candidate ($mode) fails closed"
        else
            fail "dependency ABI candidate ($mode)" \
                "failed pack left an output artifact"
        fi
    done

    rm -f "$out" "$lib"
    if run_freeze "$DLFREEZE" -o "$out" "$bin" >/dev/null 2>&1; then
        fail "missing dependency is fatal" "packaging unexpectedly succeeded"
    else
        pass "missing dependency is fatal"
    fi
    rm -rf "$good" "$bad"
    rm -f "$lib_src" "$main_src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 2g: interpreter-like prefixes are ordinary dependency names
# ===================================================================
test_interpreter_prefix_dependencies() {
    echo "--- interpreter-prefix dependency names ---"
    local root="$BUILD/interpreter-prefix" libdir="$BUILD/interpreter-prefix/lib"
    local linux_src="$root/ld_linux_fixture.c"
    local musl_src="$root/ld_musl_fixture.c" main_src="$root/main.c"
    local fake_src="$root/forged_glibc_interpreter.c"
    local fake_musl_src="$root/forged_musl_interpreter.c"
    local linux_lib="$libdir/ld-linux-dlfreeze-fixture.so"
    local musl_lib="$libdir/ld-musl-dlfreeze-fixture.so"
    local bin="$root/main" out="$root/main.frozen" actual rc=0
    local fake_interp="$root/forged-gnu-interpreter"
    local fake_bin="$root/forged-gnu-main" fake_out="$root/forged-gnu.frozen"
    local fake_log="$root/forged-gnu.log"
    local fake_musl_interp="$root/forged-musl-interpreter"
    local fake_musl_bin="$root/forged-musl-main"
    local fake_musl_out="$root/forged-musl.frozen"
    local fake_musl_log="$root/forged-musl.log"
    local fake_musl_soname

    rm -rf "$root"
    mkdir -p "$libdir"
    cat > "$linux_src" <<'C'
int dlfreeze_linux_prefix_value(void) { return 20; }
C
    cat > "$musl_src" <<'C'
int dlfreeze_musl_prefix_value(void) { return 22; }
C
    cat > "$main_src" <<'C'
#include <stdio.h>
int dlfreeze_linux_prefix_value(void);
int dlfreeze_musl_prefix_value(void);
int main(void) {
    printf("%d\n", dlfreeze_linux_prefix_value() +
                    dlfreeze_musl_prefix_value());
    return 0;
}
C
    cat > "$fake_src" <<'C'
/* This carries every prose token used by the historical family detector and
 * also defines plausible rtld OBJECTs.  It is still not glibc: the symbols
 * have no default GLIBC_PRIVATE version definition. */
const char dlfreeze_forged_glibc_markers[] =
    "ld.so (GNU libc) GLIBC_PRIVATE _rtld_global";
char _rtld_global[8];
char _rtld_global_ro[8];
C
    cat > "$fake_musl_src" <<'C'
/* These are the complete prose markers used by the historical musl family
 * detector.  A marker-bearing DSO is not musl's combined loader/libc ABI. */
const char dlfreeze_forged_musl_markers[] =
    "musl libc (forged) Dynamic Program Loader";
void _dlstart(void) {}
void __dls3(void) {}
void *_dl_debug_addr;
C
    case "$(uname -m)" in
        x86_64) fake_musl_soname=libc.musl-x86_64.so.1 ;;
        aarch64) fake_musl_soname=libc.musl-aarch64.so.1 ;;
        *)
            fail "interpreter-prefix dependency names" \
                "unsupported fixture architecture"
            rm -rf "$root"
            return
            ;;
    esac
    if ! gcc -shared -fPIC -Wl,-soname,ld-linux-dlfreeze-fixture.so \
            -o "$linux_lib" "$linux_src" ||
       ! gcc -shared -fPIC -Wl,-soname,ld-musl-dlfreeze-fixture.so \
            -o "$musl_lib" "$musl_src" ||
       ! gcc -shared -fPIC -Wl,-soname,ld-linux-forged.so.2 \
            -o "$fake_interp" "$fake_src" ||
       ! gcc -nostdlib -shared -fPIC -Wl,--hash-style=both \
            -Wl,-e,_dlstart -Wl,-soname,"$fake_musl_soname" \
            -o "$fake_musl_interp" "$fake_musl_src" ||
       ! gcc -Wl,-rpath,'$ORIGIN/lib' -L"$libdir" -o "$bin" "$main_src" \
            -Wl,--no-as-needed -l:ld-linux-dlfreeze-fixture.so \
            -l:ld-musl-dlfreeze-fixture.so; then
        fail "interpreter-prefix dependency names" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    if ! run_freeze "$DLFREEZE" -o "$out" "$bin" >/dev/null 2>&1; then
        fail "interpreter-prefix dependency names" "dlfreeze failed"
        rm -rf "$root"
        return
    fi

    # An interpreter-shaped ELF does not acquire GNU search semantics merely
    # by choosing an ld-linux* SONAME.  Runtime-family admission is derived
    # from loader content, so a forged name must fail before an artifact is
    # emitted.
    if ! command -v patchelf >/dev/null 2>&1; then
        skip "forged GNU interpreter identity" "patchelf not installed"
    elif ! cp "$bin" "$fake_bin" ||
         ! patchelf --set-interpreter "$fake_interp" "$fake_bin"; then
        fail "forged GNU interpreter identity" "fixture mutation failed"
    elif run_freeze "$DLFREEZE" -o "$fake_out" "$fake_bin" \
            >"$fake_log" 2>&1; then
        fail "forged GNU interpreter identity" \
            "name-only runtime classification produced an artifact"
    elif [ ! -e "$fake_out" ] &&
         grep -Fq 'unsupported target dynamic-linker search ABI' "$fake_log"; then
        pass "forged GNU interpreter identity rejected"
    else
        fail "forged GNU interpreter identity" \
            "unexpected refusal: $(tail -n 1 "$fake_log" 2>/dev/null)"
    fi

    if ! command -v patchelf >/dev/null 2>&1; then
        skip "forged musl interpreter identity" "patchelf not installed"
    elif ! cp "$bin" "$fake_musl_bin" ||
         ! patchelf --set-interpreter "$fake_musl_interp" \
            "$fake_musl_bin"; then
        fail "forged musl interpreter identity" "fixture mutation failed"
    elif run_freeze "$DLFREEZE" -o "$fake_musl_out" "$fake_musl_bin" \
            >"$fake_musl_log" 2>&1; then
        fail "forged musl interpreter identity" \
            "marker-only runtime classification produced an artifact"
    elif [ ! -e "$fake_musl_out" ] &&
         grep -Fq 'unsupported target dynamic-linker search ABI' \
            "$fake_musl_log"; then
        pass "forged musl interpreter identity rejected"
    else
        fail "forged musl interpreter identity" \
            "unexpected refusal: $(tail -n 1 "$fake_musl_log" 2>/dev/null)"
    fi

    # Remove the source DSOs so a passing run proves they were embedded, not
    # accidentally recovered from the host filesystem.
    rm -f "$linux_lib" "$musl_lib"
    capture_output actual "$out" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = 42 ]; then
        pass "interpreter-prefix dependency names"
    else
        fail "interpreter-prefix dependency names" "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2g2: startup dependency search retains loader ancestry
# ===================================================================
test_pack_search_semantics_gate() {
    echo "--- pack resolver search grammar and snapshot gate ---"
    local helper="$BUILD/dep_search_semantics_gate"

    if gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/dep_search_semantics_gate.c \
            src/elf_parser.c && "$helper"; then
        pass "pack search token boundaries and musl path snapshot"
    else
        fail "pack resolver search semantics gate" \
            "compile failed or search/snapshot policy differed"
    fi
    rm -f "$helper"
}

# ===================================================================
# GNU dynamic-string tokens carry target-loader policy.  $LIB is a
# build-time glibc constant, while x86-64 $PLATFORM is CPU/tunable
# dependent; neither may be guessed from the pack host.  AArch64 uses the
# kernel AT_PLATFORM string unchanged and is the one exact platform value
# the resolver can reproduce.  Unknown tokens intentionally fail closed
# even though native glibc leaves them literal.
# ===================================================================
test_gnu_pack_dynamic_tokens() {
    echo "--- GNU pack/aux dynamic-string token policy ---"
    local root
    root="$(realpath "$BUILD")/gnu-dynamic-tokens"
    local gate="$root/dep-gate" aux_gate="$root/aux-gate"
    local base_main="$root/base-main" platform_main="$root/platform-main"
    local platform_punct_main="$root/platform-punct-main"
    local lib_main="$root/lib-main" lib_punct_main="$root/lib-punct-main"
    local unknown_main="$root/unknown-main"
    local platform_requester="$root/platform-requester.so"
    local lib_requester="$root/lib-requester.so"
    local unknown_requester="$root/unknown-requester.so"
    local log="$root/resolver.log" aux_log="$root/aux.log"
    local platform_probe="$root/platform-probe"
    local platform provider interp diagnostics dst_lib actual="" rc=0
    local arch banner candidate
    local -a platform_candidates lib_candidates

    banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$banner"; then
        skip "GNU dynamic-string token policy" "target runtime is not GNU libc"
        return
    fi
    arch=$(uname -m)
    case "$arch" in
        x86_64) platform_candidates=(x86_64 haswell xeon_phi) ;;
        aarch64) platform_candidates=() ;;
        *)
            skip "GNU dynamic-string token policy" \
                "fixture supports x86_64 and aarch64"
            return
            ;;
    esac

    rm -rf "$root"
    mkdir -p "$root/link"
    cat >"$root/provider.c" <<'C'
#ifndef TOKEN_VALUE
# define TOKEN_VALUE 0
#endif
int dlfreeze_dst_value(void) { return TOKEN_VALUE; }
C
    cat >"$root/main.c" <<'C'
#include <stdio.h>
int dlfreeze_dst_value(void);
int main(void) { printf("%d\n", dlfreeze_dst_value()); return 0; }
C
    cat >"$root/base.c" <<'C'
int main(void) { return 0; }
C
    cat >"$root/requester.c" <<'C'
int dlfreeze_dst_requester(void) { return 0; }
C
    cat >"$root/platform.c" <<'C'
#include <stdio.h>
#include <sys/auxv.h>
int main(void) {
    const char *value = (const char *)getauxval(AT_PLATFORM);
    if (!value || !value[0]) return 1;
    return puts(value) < 0;
}
C
    if ! gcc -O2 -Wall -Wextra -Werror -o "$platform_probe" \
            "$root/platform.c" ||
       ! capture_output platform "$platform_probe" ||
       [ -z "$platform" ] || [[ "$platform" == */* ]] ||
       ! gcc -shared -fPIC -DTOKEN_VALUE=0 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/link/libdlfreeze_dst.so" "$root/provider.c" ||
       ! gcc -o "$base_main" "$root/base.c" ||
       ! gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c ||
       ! gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$aux_gate" tests/dep_aux_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "GNU dynamic-string token fixtures" "base fixture compile failed"
        rm -rf "$root"
        return
    fi
    platform_candidates+=("$platform")

    # Exact $PLATFORM.  AArch64 can snapshot this kernel identity; x86-64
    # native glibc may replace it with haswell/xeon_phi and is refused.
    if ! gcc -shared -fPIC -DTOKEN_VALUE=73 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/platform-provider.so" "$root/provider.c"; then
        fail "GNU PLATFORM token fixtures" "provider compile failed"
        rm -rf "$root"
        return
    fi
    for candidate in "${platform_candidates[@]}"; do
        mkdir -p "$root/$candidate"
        cp "$root/platform-provider.so" \
            "$root/$candidate/libdlfreeze_dst.so"
    done
    if ! gcc -Wl,-rpath,'$ORIGIN/$PLATFORM' -L"$root/link" \
            -o "$platform_main" "$root/main.c" -ldlfreeze_dst ||
       ! gcc -shared -fPIC -Wl,-rpath,'$ORIGIN/$PLATFORM' \
            -o "$platform_requester" "$root/requester.c"; then
        fail "GNU PLATFORM token fixtures" "consumer compile failed"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$platform_main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 73 ]; then
        fail "native GNU PLATFORM token control" \
            "exit=$rc output=$actual platform=$platform"
        rm -rf "$root"
        return
    fi
    pass "native GNU PLATFORM token control"
    if [ "$arch" = aarch64 ]; then
        if env -u LD_LIBRARY_PATH "$gate" "$platform_main" \
                >"$log" 2>&1 &&
           "$aux_gate" --expect "$base_main" "$platform_requester" \
                libdlfreeze_dst.so \
                "$root/$platform/libdlfreeze_dst.so" \
                >"$aux_log" 2>&1; then
            pass "AArch64 pack/aux PLATFORM uses kernel identity"
        else
            fail "AArch64 GNU PLATFORM resolution" \
                "pack or auxiliary lookup diverged from native"
        fi
    else
        if ! env -u LD_LIBRARY_PATH "$gate" "$platform_main" \
                >"$log" 2>&1 &&
           grep -Fq 'unsupported dynamic string token' "$log" &&
           "$aux_gate" --expect-status "$base_main" \
                "$platform_requester" libdlfreeze_dst.so - -1 \
                >"$aux_log" 2>&1; then
            pass "x86-64 pack/aux PLATFORM refuses host CPU policy"
        else
            fail "x86-64 GNU PLATFORM admission boundary" \
                "pack or auxiliary lookup guessed a platform"
        fi
    fi

    # Punctuation after an unbraced token is literal in official 2.27 and a
    # gABI boundary in 2.28+.  Provide both native outcomes, then require the
    # conservative resolver to refuse this structurally ambiguous spelling.
    mkdir -p "$root/\$PLATFORM.suffix"
    if ! gcc -shared -fPIC -DTOKEN_VALUE=81 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/\$PLATFORM.suffix/libdlfreeze_dst.so" \
            "$root/provider.c" ||
       ! gcc -shared -fPIC -DTOKEN_VALUE=82 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/platform-punct-provider.so" "$root/provider.c"; then
        fail "GNU PLATFORM punctuation fixtures" "provider compile failed"
        rm -rf "$root"
        return
    fi
    for candidate in "${platform_candidates[@]}"; do
        mkdir -p "$root/$candidate.suffix"
        cp "$root/platform-punct-provider.so" \
            "$root/$candidate.suffix/libdlfreeze_dst.so"
    done
    if ! gcc -Wl,-rpath,'$ORIGIN/$PLATFORM.suffix' -L"$root/link" \
            -o "$platform_punct_main" "$root/main.c" -ldlfreeze_dst; then
        fail "GNU PLATFORM punctuation fixtures" "consumer compile failed"
    else
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH \
            "$platform_punct_main" || rc=$?
        if [ "$rc" -eq 0 ] && { [ "$actual" = 81 ] ||
                                 [ "$actual" = 82 ]; } &&
           ! env -u LD_LIBRARY_PATH "$gate" "$platform_punct_main" \
                >"$log" 2>&1 &&
           grep -Fq 'unsupported dynamic string token' "$log"; then
            pass "GNU PLATFORM punctuation boundary fails closed"
        else
            fail "GNU PLATFORM punctuation boundary" \
                "native=$rc/$actual or resolver expanded ambiguous prefix"
        fi
    fi

    # Recover $LIB only for the native control.  Modern loaders report the
    # exact generated value; older CI releases use the known common install
    # basenames solely to make the control runnable.  The resolver never
    # consumes this host observation and always refuses $LIB.
    interp=$(LC_ALL=C readelf -W -l "$base_main" 2>/dev/null |
        sed -n 's@.*Requesting program interpreter: \([^]]*\).*@\1@p')
    diagnostics=$([ -n "$interp" ] && "$interp" --list-diagnostics \
        2>/dev/null || true)
    dst_lib=$(sed -n 's/^dl_dst_lib="\([^"]*\)"$/\1/p' \
        <<<"$diagnostics" | head -n1)
    lib_candidates=(lib lib64 x86_64-linux-gnu aarch64-linux-gnu)
    if [ -n "$dst_lib" ] && [[ "$dst_lib" != /* ]] &&
       [[ "/$dst_lib/" != */../* ]] &&
       [[ "/$dst_lib/" != */./* ]] &&
       [[ "$dst_lib" != *//* ]]; then
        lib_candidates+=("$dst_lib")
    fi
    if ! gcc -shared -fPIC -DTOKEN_VALUE=91 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/lib-provider.so" "$root/provider.c"; then
        fail "GNU LIB token fixtures" "provider compile failed"
        rm -rf "$root"
        return
    fi
    for candidate in "${lib_candidates[@]}"; do
        mkdir -p "$root/$candidate"
        cp "$root/lib-provider.so" "$root/$candidate/libdlfreeze_dst.so"
    done
    if ! gcc -Wl,-rpath,'$ORIGIN/$LIB' -L"$root/link" \
            -o "$lib_main" "$root/main.c" -ldlfreeze_dst ||
       ! gcc -shared -fPIC -Wl,-rpath,'$ORIGIN/$LIB' \
            -o "$lib_requester" "$root/requester.c"; then
        fail "GNU LIB token fixtures" "consumer compile failed"
    else
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$lib_main" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = 91 ]; then
            pass "native GNU LIB token control"
        else
            fail "native GNU LIB token control" \
                "exit=$rc output=$actual reported=$dst_lib"
        fi
        if ! env -u LD_LIBRARY_PATH "$gate" "$lib_main" \
                >"$log" 2>&1 &&
           grep -Fq 'unsupported dynamic string token' "$log" &&
           "$aux_gate" --expect-status "$base_main" "$lib_requester" \
                libdlfreeze_dst.so - -1 >"$aux_log" 2>&1; then
            pass "pack/aux LIB refuses target build-time guess"
        else
            fail "GNU LIB admission boundary" \
                "pack or auxiliary lookup guessed DL_DST_LIB"
        fi
    fi

    mkdir -p "$root/\$LIB.suffix"
    if ! gcc -shared -fPIC -DTOKEN_VALUE=92 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/\$LIB.suffix/libdlfreeze_dst.so" \
            "$root/provider.c" ||
       ! gcc -shared -fPIC -DTOKEN_VALUE=93 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/lib-punct-provider.so" "$root/provider.c"; then
        fail "GNU LIB punctuation fixtures" "provider compile failed"
    else
        for candidate in "${lib_candidates[@]}"; do
            mkdir -p "$root/$candidate.suffix"
            cp "$root/lib-punct-provider.so" \
                "$root/$candidate.suffix/libdlfreeze_dst.so"
        done
        if gcc -Wl,-rpath,'$ORIGIN/$LIB.suffix' -L"$root/link" \
                -o "$lib_punct_main" "$root/main.c" -ldlfreeze_dst; then
            rc=0
            capture_output actual env -u LD_LIBRARY_PATH \
                "$lib_punct_main" || rc=$?
            if [ "$rc" -eq 0 ] && { [ "$actual" = 92 ] ||
                                     [ "$actual" = 93 ]; } &&
               ! env -u LD_LIBRARY_PATH "$gate" "$lib_punct_main" \
                    >"$log" 2>&1 &&
               grep -Fq 'unsupported dynamic string token' "$log"; then
                pass "GNU LIB punctuation boundary fails closed"
            else
                fail "GNU LIB punctuation boundary" \
                    "native=$rc/$actual or resolver expanded ambiguous prefix"
            fi
        else
            fail "GNU LIB punctuation fixtures" "consumer compile failed"
        fi
    fi

    # Unknown GNU tokens are literal natively.  Refusal is intentional: a
    # literal `$FOO` directory is observable but cannot prove user intent.
    mkdir -p "$root/\$FOO"
    if ! gcc -shared -fPIC -DTOKEN_VALUE=101 \
            -Wl,-soname,libdlfreeze_dst.so \
            -o "$root/\$FOO/libdlfreeze_dst.so" "$root/provider.c" ||
       ! gcc -Wl,-rpath,'$ORIGIN/$FOO' -L"$root/link" \
            -o "$unknown_main" "$root/main.c" -ldlfreeze_dst ||
       ! gcc -shared -fPIC -Wl,-rpath,'$ORIGIN/$FOO' \
            -o "$unknown_requester" "$root/requester.c"; then
        fail "unknown GNU token fixtures" "fixture compile failed"
    else
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$unknown_main" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = 101 ] &&
           ! env -u LD_LIBRARY_PATH "$gate" "$unknown_main" \
                >"$log" 2>&1 &&
           grep -Fq 'unsupported dynamic string token' "$log" &&
           "$aux_gate" --expect-status "$base_main" \
                "$unknown_requester" libdlfreeze_dst.so - -1 \
                >"$aux_log" 2>&1; then
            pass "unknown GNU token literal/native divergence is fail-closed"
        else
            fail "unknown GNU token admission boundary" \
                "native=$rc/$actual or resolver accepted literal token"
        fi
    fi
    rm -rf "$root"
}

test_resolver_to_packer_snapshot_gate() {
    echo "--- resolver-to-packer source snapshot gate ---"
    local root bootstrap
    root="$(realpath "$BUILD")/resolver-snapshot"
    bootstrap="$(realpath "$BUILD/dlfreeze-bootstrap")"
    local libs="$root/libs"
    local lib="$libs/libdlfreeze_snapshot.so"
    local replacement="$root/replacement.so" main="$root/main"
    local gate="$root/gate" out="$root/main.frozen" log="$root/gate.log"

    rm -rf "$root"
    mkdir -p "$libs"
    cat >"$root/library.c" <<'C'
#ifndef SNAPSHOT_VALUE
#define SNAPSHOT_VALUE 0
#endif
int dlfreeze_snapshot_value(void) { return SNAPSHOT_VALUE; }
C
    cat >"$root/main.c" <<'C'
int dlfreeze_snapshot_value(void);
int main(void) { return dlfreeze_snapshot_value() == 1 ? 0 : 1; }
C
    if ! gcc -shared -fPIC -DSNAPSHOT_VALUE=1 \
            -Wl,-soname,libdlfreeze_snapshot.so \
            -o "$lib" "$root/library.c" ||
       ! gcc -shared -fPIC -DSNAPSHOT_VALUE=2 \
            -Wl,-soname,libdlfreeze_snapshot.so \
            -o "$replacement" "$root/library.c" ||
       ! gcc -Wl,-rpath,'$ORIGIN/libs' -L"$libs" -o "$main" \
            "$root/main.c" -ldlfreeze_snapshot ||
       ! gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/resolver_snapshot_gate.c \
            src/packer.c src/dep_resolver.c src/elf_parser.c; then
        fail "resolver-to-packer source snapshot" "fixture compile failed"
    elif "$gate" "$main" "$bootstrap" "$lib" "$replacement" "$out" \
            >"$log" 2>&1 &&
         grep -Fq 'resolved input changed before packing' "$log"; then
        pass "pathname replacement after resolution fails closed"
    else
        fail "resolver-to-packer source snapshot" \
            "replacement was packed, output leaked, or diagnostic missing"
    fi
    rm -rf "$root"
}

test_dependency_search_semantics() {
    echo "--- startup dependency search semantics ---"
    local root="$BUILD/dependency-search" gate="$BUILD/dep_resolver_gate"
    local leaf_src="$root/leaf.c" middle_src="$root/middle.c"
    local main_src="$root/main.c" choice_src="$root/choice.c"
    local private="$root/private" middle_dir="$root/deep/mid"
    local bin_dir="$root/bin"
    local rpath_bin="$bin_dir/rpath-main"
    local runpath_bin="$bin_dir/runpath-main" log="$root/resolver.log"
    local slash_dir="$root/slash"
    local slash_lib="$slash_dir/libslash.so"
    local slash_bin="$root/slash-main" dynamic actual rc=0 gate_rc=0
    local slash_out="$root/slash-main.frozen"
    local slash_no_meta="$root/slash-main.no-meta.frozen"
    local slash_extract="$root/slash-main.extract.frozen"
    local slash_pack_log="$root/slash-pack.log" freeze_rc=0
    local slash_cc=gcc

    if command -v musl-gcc >/dev/null 2>&1; then
        # The static-musl bootstrap can exercise strict direct replay even
        # when the host glibc layout is newer than the audited direct loader.
        slash_cc=musl-gcc
    fi

    rm -rf "$root"
    mkdir -p "$private" "$middle_dir" "$bin_dir" "$slash_dir"
    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "startup dependency search semantics" \
            "resolver gate compile failed"
        return
    fi

    cat > "$leaf_src" <<'C'
int dlfreeze_search_leaf(void) { return 42; }
C
    cat > "$middle_src" <<'C'
int dlfreeze_search_leaf(void);
int dlfreeze_search_middle(void) { return dlfreeze_search_leaf(); }
C
    cat > "$main_src" <<'C'
#include <stdio.h>
int dlfreeze_search_middle(void);
int main(void) {
    printf("%d\n", dlfreeze_search_middle());
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfreeze_search_leaf.so \
            -o "$private/libdlfreeze_search_leaf.so" "$leaf_src" ||
       ! gcc -shared -fPIC -Wl,-soname,libdlfreeze_search_middle.so \
            -o "$middle_dir/libdlfreeze_search_middle.so" "$middle_src" \
            -L"$private" -ldlfreeze_search_leaf ||
       ! gcc -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../deep/mid:$ORIGIN/../private' \
            -Wl,-rpath-link,"$private" -L"$middle_dir" -o "$rpath_bin" \
            "$main_src" -ldlfreeze_search_middle ||
       ! gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../deep/mid:$ORIGIN/../private' \
            -Wl,-rpath-link,"$private" -L"$middle_dir" -o "$runpath_bin" \
            "$main_src" -ldlfreeze_search_middle; then
        fail "startup dependency search semantics" "fixture compile failed"
        rm -rf "$root"
        rm -f "$gate"
        return
    fi

    dynamic=$(LC_ALL=C readelf -d "$rpath_bin" 2>/dev/null || true)
    if ! grep -q '(RPATH)' <<<"$dynamic" ||
       grep -q '(RUNPATH)' <<<"$dynamic"; then
        skip "startup inherited DT_RPATH" \
            "linker did not emit old-style DT_RPATH"
    else
        actual=""; rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$rpath_bin" || rc=$?
        if [ "$rc" -ne 0 ] || [ "$actual" != 42 ]; then
            fail "native inherited DT_RPATH control" \
                "exit=$rc output=$actual"
        elif env -u LD_LIBRARY_PATH "$gate" "$rpath_bin" >"$log" 2>&1 &&
             grep -Fq "$private/libdlfreeze_search_leaf.so" "$log"; then
            pass "startup inherited DT_RPATH keeps requester ORIGIN"
        else
            fail "startup inherited DT_RPATH" \
                "resolver missed the requester's transitive search scope"
        fi
    fi

    dynamic=$(LC_ALL=C readelf -d "$runpath_bin" 2>/dev/null || true)
    if ! grep -q '(RUNPATH)' <<<"$dynamic"; then
        skip "startup DT_RUNPATH non-inheritance" \
            "linker did not emit DT_RUNPATH"
    else
        actual=""; rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$runpath_bin" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = 42 ]; then
            if env -u LD_LIBRARY_PATH "$gate" "$runpath_bin" \
                    >"$log" 2>&1 &&
               grep -Fq "$private/libdlfreeze_search_leaf.so" "$log"; then
                pass "target RUNPATH inheritance matches native loader"
            else
                fail "target RUNPATH inheritance" \
                    "resolver differs from native target loader"
            fi
        elif [ "$rc" -ne 0 ] &&
             ! env -u LD_LIBRARY_PATH "$gate" "$runpath_bin" \
                >"$log" 2>&1 &&
             grep -Fq 'libdlfreeze_search_leaf.so' "$log"; then
            pass "startup DT_RUNPATH is not inherited"
        else
            fail "startup DT_RUNPATH non-inheritance" \
                "resolver differs from native target loader"
        fi
    fi

    # Presence of DT_RUNPATH suppresses the inherited GNU RPATH chain even
    # when the RUNPATH string itself is empty.  Pointer/value emptiness must
    # not be used as a proxy for dynamic-tag presence.
    local empty_dir="$root/empty-runpath/mid"
    local empty_middle="$empty_dir/libdlfreeze_search_middle.so"
    local empty_bin="$bin_dir/empty-runpath-main"
    local empty_marker=DLFREEZE_EMPTY_RUNPATH_MARKER empty_marker_offset
    mkdir -p "$empty_dir"
    if ! gcc -shared -fPIC -Wl,--enable-new-dtags \
            -Wl,-rpath,"$empty_marker" \
            -Wl,-soname,libdlfreeze_search_middle.so \
            -Wl,-rpath-link,"$private" -L"$private" \
            -o "$empty_middle" "$middle_src" \
            -ldlfreeze_search_leaf; then
        fail "empty DT_RUNPATH suppresses inherited RPATH" \
            "fixture DSO compile failed"
    else
        empty_marker_offset=$(LC_ALL=C strings -a -td "$empty_middle" |
            awk -v marker="$empty_marker" \
                '$2 == marker { print $1; exit }')
        if [[ ! "$empty_marker_offset" =~ ^[0-9]+$ ]] ||
           ! printf '\0' | dd of="$empty_middle" bs=1 \
                seek="$empty_marker_offset" count=1 conv=notrunc \
                2>/dev/null ||
           ! gcc -Wl,--disable-new-dtags \
                -Wl,-rpath,'$ORIGIN/../empty-runpath/mid:$ORIGIN/../private' \
                -Wl,-rpath-link,"$private" -L"$empty_dir" \
                -o "$empty_bin" "$main_src" \
                -ldlfreeze_search_middle; then
            fail "empty DT_RUNPATH suppresses inherited RPATH" \
                "fixture construction failed"
        else
            dynamic=$(LC_ALL=C readelf -d "$empty_middle" \
                2>/dev/null || true)
            actual=""; rc=0
            capture_output actual env -u LD_LIBRARY_PATH \
                "$empty_bin" || rc=$?
            if ! grep -q '(RUNPATH).*\[\]' <<<"$dynamic"; then
                fail "empty DT_RUNPATH suppresses inherited RPATH" \
                    "fixture mutation did not retain an empty tag"
            else
                gate_rc=0
                env -u LD_LIBRARY_PATH "$gate" "$empty_bin" \
                    >"$log" 2>&1 || gate_rc=$?
                if [ "$rc" -eq 0 ] && [ "$actual" = 42 ] &&
                   [ "$gate_rc" -eq 0 ] &&
                   grep -Fq "$private/libdlfreeze_search_leaf.so" "$log"; then
                    pass "target empty DT_RUNPATH ancestry matches native loader"
                elif [ "$rc" -ne 0 ] && [ "$gate_rc" -ne 0 ] &&
                     grep -Fq 'libdlfreeze_search_leaf.so' "$log"; then
                    pass "empty DT_RUNPATH suppresses inherited RPATH"
                else
                    fail "empty DT_RUNPATH ancestry" \
                        "native exit=$rc output=$actual resolver_exit=$gate_rc"
                fi
            fi
        fi
    fi

    # PT_INTERP is not a PIE discriminator.  A shared object can be directly
    # executable (libc.so.6 is a real-world example) while remaining a valid
    # dependency because it does not carry DF_1_PIE.
    local interp_dso_dir="$root/interp-dso"
    local interp_dso="$interp_dso_dir/libdlfreeze_interp_dso.so"
    local interp_dso_bin="$interp_dso_dir/main"
    local interp_dso_dynamic interp_dso_program_headers
    mkdir -p "$interp_dso_dir"
    cat > "$interp_dso_dir/library.c" <<'C'
__asm__(".section .interp,\"a\"\n"
        ".string \"/dlfreeze/nonexecuted-interpreter\"\n"
        ".previous");
int dlfreeze_interp_dso_value(void) { return 29; }
C
    cat > "$interp_dso_dir/main.c" <<'C'
#include <stdio.h>
int dlfreeze_interp_dso_value(void);
int main(void) {
    printf("%d\n", dlfreeze_interp_dso_value());
    return 0;
}
C
    if ! gcc -shared -fPIC \
            -Wl,-soname,libdlfreeze_interp_dso.so \
            -o "$interp_dso" "$interp_dso_dir/library.c" ||
       ! gcc -Wl,-rpath,'$ORIGIN' -L"$interp_dso_dir" \
            -o "$interp_dso_bin" "$interp_dso_dir/main.c" \
            -ldlfreeze_interp_dso; then
        fail "PT_INTERP-bearing DSO dependency" "fixture compile failed"
    else
        interp_dso_program_headers=$(LC_ALL=C readelf -lW "$interp_dso" \
            2>/dev/null || true)
        interp_dso_dynamic=$(LC_ALL=C readelf -dW "$interp_dso" \
            2>/dev/null || true)
        actual=""; rc=0
        capture_output actual env -u LD_LIBRARY_PATH \
            "$interp_dso_bin" || rc=$?
        if ! grep -q 'INTERP' <<<"$interp_dso_program_headers" ||
           grep -q 'FLAGS_1.*PIE' <<<"$interp_dso_dynamic"; then
            fail "PT_INTERP-bearing DSO dependency" \
                "linker did not create the requested non-PIE DSO"
        elif [ "$rc" -ne 0 ] || [ "$actual" != 29 ]; then
            fail "native PT_INTERP-bearing DSO control" \
                "exit=$rc output=$actual"
        elif env -u LD_LIBRARY_PATH "$gate" "$interp_dso_bin" \
                >"$log" 2>&1 && grep -Fq "$interp_dso" "$log"; then
            pass "PT_INTERP-bearing non-PIE DSO is a valid dependency"
        else
            fail "PT_INTERP-bearing DSO dependency" \
                "resolver treated PT_INTERP as an executable marker"
        fi
    fi

    # A DT_NEEDED entry containing '/' is a pathname, not a search name.
    cat > "$slash_dir/slash.c" <<'C'
int dlfreeze_slash_value(void) { return 17; }
C
    cat > "$slash_dir/main.c" <<'C'
#include <stdio.h>
int dlfreeze_slash_value(void);
int main(void) {
    printf("%d\n", dlfreeze_slash_value());
    return 0;
}
C
    if ! "$slash_cc" -shared -fPIC -o "$slash_lib" \
            "$slash_dir/slash.c" ||
       ! "$slash_cc" -o "$slash_bin" "$slash_dir/main.c" "$slash_lib"; then
        fail "slash-containing DT_NEEDED pathname" "fixture compile failed"
    else
        dynamic=$(LC_ALL=C readelf -d "$slash_bin" 2>/dev/null || true)
        actual=""; rc=0
        capture_output actual "$slash_bin" || rc=$?
        if ! grep -Fq "$slash_lib" <<<"$dynamic"; then
            skip "slash-containing DT_NEEDED pathname" \
                "linker replaced the pathname with a SONAME"
        elif [ "$rc" -ne 0 ] || [ "$actual" != 17 ]; then
            fail "native slash-containing DT_NEEDED control" \
                "exit=$rc output=$actual"
        elif "$gate" "$slash_bin" >"$log" 2>&1 &&
             grep -Fq "$slash_lib" "$log"; then
            pass "slash-containing DT_NEEDED is resolved as a pathname"
        else
            fail "slash-containing DT_NEEDED pathname" \
                "resolver did not preserve pathname semantics"
        fi

        if grep -Fq "$slash_lib" <<<"$dynamic" &&
           [ "$rc" -eq 0 ] && [ "$actual" = 17 ]; then
            if run_freeze "$DLFREEZE" -o "$slash_extract" -- "$slash_bin" \
                    >"$slash_pack_log" 2>&1; then
                fail "pathful DT_NEEDED extraction refusal" \
                    "packer created an extraction-mode artifact"
            elif [ -e "$slash_extract" ]; then
                fail "pathful DT_NEEDED extraction refusal" \
                    "failed pack left an output artifact"
            elif grep -Fq \
                    'pathful DT_NEEDED entries require a supported direct-load mode' \
                    "$slash_pack_log"; then
                pass "pathful DT_NEEDED requires direct-load"
            else
                fail "pathful DT_NEEDED extraction refusal" \
                    "precise diagnostic missing"
            fi

            freeze_rc=0
            freeze_require_direct "pathful DT_NEEDED direct replay" \
                "$slash_pack_log" "$slash_out" -- "$slash_bin" ||
                freeze_rc=$?
            if [ "$freeze_rc" -eq 77 ]; then
                skip "pathful DT_NEEDED direct replay" \
                    "$DIRECT_FREEZE_REASON"
            elif [ "$freeze_rc" -eq 0 ]; then
                if ! mv "$slash_lib" "$slash_lib.removed"; then
                    fail "pathful DT_NEEDED direct replay" \
                        "could not remove the source dependency"
                else
                    actual=""; rc=0
                    capture_output actual "$slash_out" || rc=$?
                    if [ "$rc" -eq 0 ] && [ "$actual" = 17 ]; then
                        pass "pathful DT_NEEDED replays after source removal"
                    else
                        fail "pathful DT_NEEDED direct replay" \
                            "exit=$rc output=$actual"
                    fi
                fi

                local slash_size
                slash_size=$(stat -c %s "$slash_out" 2>/dev/null || true)
                if [[ ! "$slash_size" =~ ^[0-9]+$ ]] ||
                   [ "$slash_size" -lt 64 ] ||
                   ! cp "$slash_out" "$slash_no_meta" ||
                   ! dd if=/dev/zero of="$slash_no_meta" bs=1 \
                        seek=$((slash_size - 24)) count=24 conv=notrunc \
                        2>/dev/null; then
                    fail "pathful DT_NEEDED fallback refusal" \
                        "could not remove direct metadata pointer"
                else
                    actual=""; rc=0
                    capture_output actual env -u DLFREEZE_NO_FORK \
                        "$slash_no_meta" || rc=$?
                    if [ "$rc" -eq 127 ] &&
                       [[ "$actual" == *"refusing extraction fallback for an artifact with pathful DT_NEEDED entries"* ]]; then
                        pass "pathful DT_NEEDED refuses extraction fallback"
                    else
                        fail "pathful DT_NEEDED fallback refusal" \
                            "exit=$rc output=$actual"
                    fi
                fi
            fi
        fi
    fi

    # Distinct DT_NEEDED spellings may reach one inode.  Native loaders keep
    # both lookup names while mapping and traversing that source only once;
    # retain both manifest aliases as well.
    local alias_dir="$root/bare-alias"
    local alias_real="$alias_dir/libdlfreeze_alias_real.so"
    local alias_one="$alias_dir/libdlfreeze_alias_one.so"
    local alias_two="$alias_dir/libdlfreeze_alias_two.so"
    local alias_mid_one="$alias_dir/libdlfreeze_mid_one.so"
    local alias_mid_two="$alias_dir/libdlfreeze_mid_two.so"
    local alias_bin="$alias_dir/main" alias_dynamic
    mkdir -p "$alias_dir"
    cat > "$alias_dir/leaf.c" <<'C'
int dlfreeze_alias_leaf(void) { return 23; }
C
    cat > "$alias_dir/mid-one.c" <<'C'
int dlfreeze_alias_leaf(void);
int dlfreeze_alias_mid_one(void) { return dlfreeze_alias_leaf(); }
C
    cat > "$alias_dir/mid-two.c" <<'C'
int dlfreeze_alias_leaf(void);
int dlfreeze_alias_mid_two(void) { return dlfreeze_alias_leaf(); }
C
    cat > "$alias_dir/main.c" <<'C'
#include <stdio.h>
int dlfreeze_alias_mid_one(void);
int dlfreeze_alias_mid_two(void);
int main(void) {
    printf("%d\n", dlfreeze_alias_mid_one() + dlfreeze_alias_mid_two());
    return 0;
}
C
    if ! gcc -shared -fPIC -o "$alias_real" "$alias_dir/leaf.c" ||
       ! ln -s "$(basename "$alias_real")" "$alias_one" ||
       ! ln -s "$(basename "$alias_real")" "$alias_two" ||
       ! gcc -shared -fPIC -Wl,-soname,"$(basename "$alias_mid_one")" \
            -L"$alias_dir" -o "$alias_mid_one" "$alias_dir/mid-one.c" \
            -Wl,-l:"$(basename "$alias_one")" ||
       ! gcc -shared -fPIC -Wl,-soname,"$(basename "$alias_mid_two")" \
            -L"$alias_dir" -o "$alias_mid_two" "$alias_dir/mid-two.c" \
            -Wl,-l:"$(basename "$alias_two")" ||
       ! gcc -Wl,-rpath,'$ORIGIN' -Wl,-rpath-link,"$alias_dir" \
            -L"$alias_dir" -o "$alias_bin" "$alias_dir/main.c" \
            -Wl,-l:"$(basename "$alias_mid_one")" \
            -Wl,-l:"$(basename "$alias_mid_two")"; then
        fail "conflicting bare DT_NEEDED aliases" "fixture compile failed"
    else
        alias_dynamic=$(LC_ALL=C readelf -d "$alias_mid_one" 2>/dev/null;
                        LC_ALL=C readelf -d "$alias_mid_two" 2>/dev/null)
        actual=""; rc=0
        capture_output actual env LD_LIBRARY_PATH="$alias_dir" \
            "$alias_bin" || rc=$?
        if ! grep -Fq "$(basename "$alias_one")" <<<"$alias_dynamic" ||
           ! grep -Fq "$(basename "$alias_two")" <<<"$alias_dynamic"; then
            skip "conflicting bare DT_NEEDED aliases" \
                "linker did not retain both alias names"
        elif [ "$rc" -ne 0 ] || [ "$actual" != 46 ]; then
            fail "native bare DT_NEEDED alias control" \
                "exit=$rc output=$actual"
        elif env LD_LIBRARY_PATH="$alias_dir" "$gate" "$alias_bin" \
                >"$log" 2>&1 &&
             grep -Fq "NEEDED=$(basename "$alias_one")" "$log" &&
             grep -Fq "NEEDED=$(basename "$alias_two")" "$log"; then
            pass "distinct bare DT_NEEDED source aliases are retained"
        else
            fail "bare DT_NEEDED source aliases" \
                "resolver did not retain both native lookup identities"
        fi
    fi

    # $ORIGIN is implemented above with its owning-object context.  Do not
    # interpret other loader-specific tokens as literal directories and then
    # silently select a different host DSO.
    cat > "$root/token-main.c" <<'C'
int dlfreeze_search_leaf(void);
int main(void) { return dlfreeze_search_leaf() == 42 ? 0 : 1; }
C
    local token_bin="$root/token-main"
    if ! gcc -Wl,-rpath,'$ORIGIN/$LIB' -L"$private" -o "$token_bin" \
            "$root/token-main.c" -Wl,--no-as-needed \
            -ldlfreeze_search_leaf; then
        fail "unsupported dynamic search token refusal" \
            "fixture compile failed"
    elif "$gate" "$token_bin" >"$log" 2>&1; then
        fail "unsupported dynamic search token refusal" \
            "resolver treated a loader-specific token as a literal path"
    elif compiler_targets_glibc && grep -Fq \
            'unsupported dynamic string token in library search path' \
            "$log"; then
        pass "unsupported dynamic search tokens fail closed"
    elif ! compiler_targets_glibc &&
         grep -Fq 'required library not found or incompatible' "$log"; then
        # musl invalidates an object's complete RPATH when it contains an
        # unknown token, then continues with later mechanisms.  With no later
        # provider this is an ordinary miss, not GNU's unsupported-DST
        # diagnostic.  The important invariant is that the literal path was
        # not selected.
        pass "non-GNU unknown search token follows target miss semantics"
    else
        fail "unsupported dynamic search token refusal" \
            "precise diagnostic missing"
    fi

    # The second closure walk which promotes traced initial-exec TLS must use
    # the same inherited search scope as the initial dependency resolution.
    local early="$root/early" early_request="$root/early/request"
    local early_deep="$root/early/deep" early_private="$root/early/private"
    local early_root="$early_request/libdlfreeze_scope_root.so"
    local early_middle="$early_deep/libdlfreeze_scope_middle.so"
    local early_leaf="$early_private/libdlfreeze_scope_leaf.so"
    local early_main="$early/main" trace="$early/trace"
    local root_abs root_hex
    mkdir -p "$early_request" "$early_deep" "$early_private"
    cat > "$early/leaf.c" <<'C'
static __thread int dlfreeze_scope_tls = 42;
int dlfreeze_scope_leaf(void) { return dlfreeze_scope_tls; }
C
    cat > "$early/middle.c" <<'C'
int dlfreeze_scope_leaf(void);
int dlfreeze_scope_middle(void) { return dlfreeze_scope_leaf(); }
C
    cat > "$early/root.c" <<'C'
int dlfreeze_scope_middle(void);
int dlfreeze_scope_root(void) { return dlfreeze_scope_middle(); }
C
    cat > "$early/main.c" <<'C'
int main(void) { return 0; }
C
    if ! gcc -shared -fPIC -ftls-model=initial-exec \
            -Wl,-soname,libdlfreeze_scope_leaf.so \
            -o "$early_leaf" "$early/leaf.c" ||
       ! gcc -shared -fPIC -Wl,-soname,libdlfreeze_scope_middle.so \
            -L"$early_private" -o "$early_middle" "$early/middle.c" \
            -ldlfreeze_scope_leaf ||
       ! gcc -shared -fPIC -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../deep:$ORIGIN/../private' \
            -Wl,-rpath-link,"$early_private" \
            -Wl,-soname,libdlfreeze_scope_root.so -L"$early_deep" \
            -o "$early_root" "$early/root.c" \
            -ldlfreeze_scope_middle ||
       ! gcc -o "$early_main" "$early/main.c"; then
        fail "traced TLS inherited RPATH scope" "fixture compile failed"
    else
        root_abs=$(realpath "$early_root")
        root_hex=$(printf '%s' "$root_abs" | od -An -tx1 | tr -d ' \n')
        printf '#DLFREEZE_DLOPEN_TRACE_V4\nP %s %s %s\n' \
            "$root_hex" "$root_hex" "$root_hex" > "$trace"
        if "$gate" "$early_main" "$trace" >"$log" 2>&1 &&
           grep -Eq '^NEEDED=libdlfreeze_scope_root[.]so[[:space:]].*EARLY=1$' \
                "$log" &&
           grep -Eq '^NEEDED=libdlfreeze_scope_middle[.]so[[:space:]].*EARLY=1$' \
                "$log" &&
           grep -Eq '^NEEDED=libdlfreeze_scope_leaf[.]so[[:space:]].*EARLY=1$' \
                "$log"; then
            pass "traced TLS promotion retains inherited DT_RPATH scope"
        else
            fail "traced TLS inherited RPATH scope" \
                "closure rewalk lost the ancestor search scope"
        fi
    fi

    # Compare target-loader ordering, not the libc linked into the resolver.
    # GNU loaders prefer old DT_RPATH; musl prefers LD_LIBRARY_PATH.
    cat > "$choice_src" <<'C'
#ifndef DLFREEZE_CHOICE
#define DLFREEZE_CHOICE 0
#endif
int dlfreeze_search_choice(void) { return DLFREEZE_CHOICE; }
C
    cat > "$root/choice-main.c" <<'C'
#include <stdio.h>
int dlfreeze_search_choice(void);
int main(void) {
    printf("%d\n", dlfreeze_search_choice());
    return 0;
}
C
    local order_root="$root/native-order"
    local order_rpath="$order_root/rpath" order_env="$order_root/env"
    local order_bin="$order_root/main" expected_path
    mkdir -p "$order_rpath" "$order_env"
    if ! gcc -shared -fPIC -DDLFREEZE_CHOICE=11 \
            -Wl,-soname,libdlfreeze_search_choice.so \
            -o "$order_rpath/libdlfreeze_search_choice.so" "$choice_src" ||
       ! gcc -shared -fPIC -DDLFREEZE_CHOICE=22 \
            -Wl,-soname,libdlfreeze_search_choice.so \
            -o "$order_env/libdlfreeze_search_choice.so" "$choice_src" ||
       ! gcc -Wl,--disable-new-dtags -Wl,-rpath,'$ORIGIN/rpath' \
            -L"$order_rpath" -o "$order_bin" "$root/choice-main.c" \
            -ldlfreeze_search_choice; then
        fail "target loader search ordering" "native fixture compile failed"
    else
        actual=""; rc=0
        capture_output actual env LD_LIBRARY_PATH="$order_env" \
            "$order_bin" || rc=$?
        case "$actual:$rc" in
            11:0) expected_path="$order_rpath/libdlfreeze_search_choice.so" ;;
            22:0) expected_path="$order_env/libdlfreeze_search_choice.so" ;;
            *) expected_path="" ;;
        esac
        if [ -z "$expected_path" ]; then
            fail "native target loader search ordering control" \
                "exit=$rc output=$actual"
        elif env LD_LIBRARY_PATH="$order_env" "$gate" "$order_bin" \
                >"$log" 2>&1 && grep -Fq "$expected_path" "$log"; then
            pass "dependency search follows target loader ordering"
        else
            fail "target loader search ordering" \
                "resolver choice differs from native target loader"
        fi
    fi

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl LD_LIBRARY_PATH-before-RPATH ordering" \
            "musl-gcc not installed"
    else
        local musl_root="$root/musl-order"
        local musl_rpath="$musl_root/rpath" musl_env="$musl_root/env"
        local musl_bin="$musl_root/main"
        mkdir -p "$musl_rpath" "$musl_env"
        if ! musl-gcc -shared -fPIC -DDLFREEZE_CHOICE=11 \
                -Wl,-soname,libdlfreeze_musl_search_choice.so \
                -o "$musl_rpath/libdlfreeze_musl_search_choice.so" \
                "$choice_src" ||
           ! musl-gcc -shared -fPIC -DDLFREEZE_CHOICE=22 \
                -Wl,-soname,libdlfreeze_musl_search_choice.so \
                -o "$musl_env/libdlfreeze_musl_search_choice.so" \
                "$choice_src" ||
           ! musl-gcc -Wl,--disable-new-dtags -Wl,-rpath,'$ORIGIN/rpath' \
                -L"$musl_rpath" -o "$musl_bin" "$root/choice-main.c" \
                -ldlfreeze_musl_search_choice; then
            fail "musl target loader search ordering" \
                "fixture compile failed"
        else
            actual=""; rc=0
            capture_output actual env LD_LIBRARY_PATH="$musl_env" \
                "$musl_bin" || rc=$?
            if [ "$rc" -ne 0 ] || [ "$actual" != 22 ]; then
                fail "native musl search ordering control" \
                    "exit=$rc output=$actual"
            elif env LD_LIBRARY_PATH="$musl_env" "$gate" "$musl_bin" \
                    >"$log" 2>&1 &&
                 grep -Fq "$musl_env/libdlfreeze_musl_search_choice.so" \
                    "$log"; then
                pass "musl LD_LIBRARY_PATH precedes inherited RPATH"
            else
                fail "musl target loader search ordering" \
                    "resolver applied host-loader ordering"
            fi
        fi
    fi

    # A non-system musl installation reads its path file below the install
    # prefix.  That configured list replaces the built-in system list, and
    # the directory containing the interpreter is not a separate search
    # stage.  Keep a same-SONAME decoy there to catch either shortcut.
    if command -v musl-gcc >/dev/null 2>&1; then
        if ! command -v patchelf >/dev/null 2>&1; then
            skip "musl prefixed system path" "patchelf not installed"
        else
        local prefix_root
        prefix_root="$(realpath "$root")/musl-prefix"
        local prefix="$prefix_root/install"
        local prefix_lib="$prefix/lib" prefix_etc="$prefix/etc"
        local prefix_config="$prefix_root/configured"
        local prefix_probe="$prefix_root/probe"
        local prefix_bin="$prefix_root/main"
        local source_interp custom_interp interp_base musl_arch path_file

        mkdir -p "$prefix_lib" "$prefix_etc" "$prefix_config"
        if ! musl-gcc -o "$prefix_probe" "$root/choice-main.c" \
                "$musl_env/libdlfreeze_musl_search_choice.so"; then
            fail "musl prefixed system path" "probe compile failed"
        else
            source_interp=$(LC_ALL=C readelf -l "$prefix_probe" 2>/dev/null |
                sed -n \
                    's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' |
                head -n 1)
            interp_base=${source_interp##*/}
            musl_arch=${interp_base#ld-musl-}
            musl_arch=${musl_arch%%.so*}
            # The loader's search ABI is an ELF/content property; its
            # installed filename is not part of that ABI.
            custom_interp="$prefix_lib/renamed-runtime"
            path_file="$prefix_etc/ld-musl-$musl_arch.path"

            if [ -z "$source_interp" ] || [ ! -f "$source_interp" ] ||
               [ "$musl_arch" = "$interp_base" ] || [ -z "$musl_arch" ] ||
               ! cp "$source_interp" "$custom_interp" ||
               ! printf '%s\n' "$prefix_config" >"$path_file" ||
               ! musl-gcc -shared -fPIC -DDLFREEZE_CHOICE=33 \
                    -Wl,-soname,libdlfreeze_musl_prefix_choice.so \
                    -o "$prefix_lib/libdlfreeze_musl_prefix_choice.so" \
                    "$choice_src" ||
               ! musl-gcc -shared -fPIC -DDLFREEZE_CHOICE=44 \
                    -Wl,-soname,libdlfreeze_musl_prefix_choice.so \
                    -o "$prefix_config/libdlfreeze_musl_prefix_choice.so" \
                    "$choice_src" ||
               ! musl-gcc -L"$prefix_config" -o "$prefix_bin" \
                    "$root/choice-main.c" \
                    -l:libdlfreeze_musl_prefix_choice.so ||
               ! patchelf --set-interpreter "$custom_interp" \
                    "$prefix_bin"; then
                fail "musl prefixed system path" "fixture compile failed"
            else
                actual=""; rc=0
                capture_output actual env -u LD_LIBRARY_PATH \
                    "$prefix_bin" || rc=$?
                if [ "$rc" -ne 0 ] || [ "$actual" != 44 ]; then
                    fail "native musl prefixed path control" \
                        "exit=$rc output=$actual"
                elif env -u LD_LIBRARY_PATH "$gate" "$prefix_bin" \
                        >"$log" 2>&1 &&
                     grep -Fq \
                        "$prefix_config/libdlfreeze_musl_prefix_choice.so" \
                        "$log" &&
                     ! grep -Fq \
                        "$prefix_lib/libdlfreeze_musl_prefix_choice.so" \
                        "$log"; then
                    pass "musl prefixed path replaces loader-dir heuristic"
                else
                    fail "musl prefixed system path" \
                        "resolver differs from native target loader"
                fi
            fi
        fi
        fi
    fi

    rm -rf "$root"
    rm -f "$gate"
}

run_first_opened_candidate_case() {
    local cc="$1" toolchain="$2" root="$3" gate="$4"
    local bad="$root/bad" good="$root/good" bin="$root/main"
    local name=libdlfrz_first_open_candidate.so
    local log="$root/resolver.log" actual rc=0 gate_rc=0

    mkdir -p "$bad" "$good"
    cat >"$root/library.c" <<'C'
#ifndef DLFREEZE_VALUE
#define DLFREEZE_VALUE 0
#endif
int dlfreeze_first_open_value(void) { return DLFREEZE_VALUE; }
C
    cat >"$root/main.c" <<'C'
#include <stdio.h>
int dlfreeze_first_open_value(void);
int main(void) {
    printf("%d\n", dlfreeze_first_open_value());
    return 0;
}
C
    if ! "$cc" -shared -fPIC -DDLFREEZE_VALUE=77 \
            -Wl,-soname,"$name" -o "$good/$name" "$root/library.c" ||
       ! "$cc" -Wl,--disable-new-dtags -Wl,-rpath,"$bad:$good" \
            -L"$good" -o "$bin" "$root/main.c" -Wl,-l:"$name" ||
       ! "$cc" -fPIC -c -o "$bad/$name" "$root/library.c"; then
        fail "$toolchain first-opened candidate semantics" \
            "fixture compile failed"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$bin" || rc=$?
    env -u LD_LIBRARY_PATH "$gate" "$bin" >"$log" 2>&1 || gate_rc=$?
    if [ "$rc" -ne 0 ] && [ "$gate_rc" -ne 0 ]; then
        pass "$toolchain malformed first-opened candidate is fatal"
    else
        fail "$toolchain malformed first-opened candidate" \
            "native_exit=$rc native_output=$actual resolver_exit=$gate_rc"
    fi

    if ! "$cc" -shared -fPIC -DDLFREEZE_VALUE=41 \
            -Wl,-soname,"$name" -o "$bad/$name" "$root/library.c" ||
       ! elf64_set_foreign_machine "$bad/$name"; then
        fail "$toolchain foreign-ABI first-opened candidate" \
            "fixture mutation failed"
        return
    fi
    actual=""; rc=0; gate_rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$bin" || rc=$?
    env -u LD_LIBRARY_PATH "$gate" "$bin" >"$log" 2>&1 || gate_rc=$?
    if [ "$rc" -eq 0 ] && [ "$actual" = 77 ] &&
       [ "$gate_rc" -eq 0 ] && grep -Fq "$good/$name" "$log"; then
        pass "$toolchain foreign-ABI search candidate follows native skip"
    elif [ "$rc" -eq 0 ] && [ "$actual" = 41 ] &&
         [ "$gate_rc" -ne 0 ] && ! grep -Fq "$good/$name" "$log"; then
        # A loader which commits the first open fd without using e_machine as
        # an admission discriminator must not be modeled as GNU merely
        # because its compiler command is named gcc.  The resolver cannot
        # safely pack the unsupported header, so it fails at that pathname.
        pass "$toolchain foreign-ABI first-open candidate stops search"
    elif [ "$rc" -ne 0 ] && [ "$gate_rc" -ne 0 ] &&
         ! grep -Fq "$good/$name" "$log"; then
        pass "$toolchain foreign-ABI candidate follows native rejection"
    else
        fail "$toolchain foreign-ABI first-opened candidate" \
            "native_exit=$rc native_output=$actual resolver_exit=$gate_rc"
    fi
}

test_first_opened_search_candidate() {
    echo "--- first-opened dependency search candidate ---"
    local root="$BUILD/first-opened-candidate"
    local gate="$root/dep-resolver-gate"

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "first-opened dependency search candidate" \
            "resolver gate compile failed"
        rm -rf "$root"
        return
    fi
    run_first_opened_candidate_case gcc gcc "$root/gcc" "$gate"
    if command -v musl-gcc >/dev/null 2>&1; then
        run_first_opened_candidate_case \
            musl-gcc musl "$root/musl" "$gate"
    else
        skip "musl first-opened candidate semantics" \
            "musl-gcc not installed"
    fi
    rm -rf "$root"
}

run_logical_load_path_case() {
    local cc="$1" family="$2" root="$3" gate="$4"
    local store="$root/store" a_dir="$root/a" b_dir="$root/b"
    local parents="$root/parents" bin_dir="$root/bin"
    local leaf_name=libdlfrz_origin_identity_leaf.so
    local top_name=libdlfrz_origin_identity_top.so
    local parent_a_name=libdlfrz_origin_parent_a.so
    local parent_b_name=libdlfrz_origin_parent_b.so
    local top="$store/$top_name" main="$bin_dir/main"
    local out="$bin_dir/main.frozen" log="$root/freeze.log"
    local resolver_log="$root/resolver.log"
    local expect actual top_count rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$store/deps" "$a_dir/deps" "$b_dir/deps" \
        "$parents" "$bin_dir"
    cat >"$root/leaf.c" <<'C'
#ifndef DLFREEZE_VALUE
#define DLFREEZE_VALUE 0
#endif
int dlfreeze_origin_leaf(void) { return DLFREEZE_VALUE; }
C
    cat >"$root/top.c" <<'C'
int dlfreeze_origin_leaf(void);
int dlfreeze_origin_top(void) {
    return dlfreeze_origin_leaf();
}
C
    cat >"$root/parent-a.c" <<'C'
int dlfreeze_origin_top(void);
int dlfreeze_origin_parent_a(void) { return dlfreeze_origin_top(); }
void *dlfreeze_origin_top_address(void) {
    return (void *)dlfreeze_origin_top;
}
C
    cat >"$root/parent-b.c" <<'C'
int dlfreeze_origin_top(void);
int dlfreeze_origin_parent_b(void) { return dlfreeze_origin_top(); }
C
    cat >"$root/main.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
int dlfreeze_origin_parent_a(void);
int dlfreeze_origin_parent_b(void);
void *dlfreeze_origin_top_address(void);
int main(void) {
    Dl_info info;
    if (!dladdr(dlfreeze_origin_top_address(), &info) || !info.dli_fname)
        return 3;
    printf("%d:%d:%s\n", dlfreeze_origin_parent_a(),
           dlfreeze_origin_parent_b(), info.dli_fname);
    return 0;
}
C

    if ! "$cc" -shared -fPIC -DDLFREEZE_VALUE=9 \
            -Wl,-soname,"$leaf_name" \
            -o "$store/deps/$leaf_name" "$root/leaf.c" ||
       ! "$cc" -shared -fPIC -DDLFREEZE_VALUE=101 \
            -Wl,-soname,"$leaf_name" \
            -o "$a_dir/deps/$leaf_name" "$root/leaf.c" ||
       ! "$cc" -shared -fPIC -DDLFREEZE_VALUE=202 \
            -Wl,-soname,"$leaf_name" \
            -o "$b_dir/deps/$leaf_name" "$root/leaf.c" ||
       ! "$cc" -shared -fPIC -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/deps' \
            -Wl,-rpath-link,"$store/deps" -L"$store/deps" \
            -o "$top" "$root/top.c" \
            -Wl,--no-as-needed -Wl,-l:"$leaf_name" ||
       ! ln -s "../store/$top_name" "$a_dir/$top_name" ||
       ! ln "$top" "$b_dir/$top_name" ||
       ! "$cc" -shared -fPIC -Wl,-soname,"$parent_a_name" \
            -Wl,--enable-new-dtags -Wl,-rpath,"$a_dir" \
            -Wl,-rpath-link,"$a_dir/deps" -L"$a_dir" \
            -o "$parents/$parent_a_name" "$root/parent-a.c" \
            -Wl,--no-as-needed -Wl,-l:"$top_name" ||
       ! "$cc" -shared -fPIC -Wl,-soname,"$parent_b_name" \
            -Wl,--enable-new-dtags -Wl,-rpath,"$b_dir" \
            -Wl,-rpath-link,"$b_dir/deps" -L"$b_dir" \
            -o "$parents/$parent_b_name" "$root/parent-b.c" \
            -Wl,--no-as-needed -Wl,-l:"$top_name" ||
       ! "$cc" -Wl,--enable-new-dtags -Wl,-rpath,"$parents" \
            -Wl,-rpath-link,"$a_dir" -Wl,-rpath-link,"$b_dir" \
            -Wl,-rpath-link,"$a_dir/deps" -L"$parents" \
            -o "$main" "$root/main.c" -Wl,--no-as-needed \
            -Wl,-l:"$parent_a_name" -Wl,-l:"$parent_b_name" -ldl; then
        fail "$family logical load-path identity" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if LC_ALL=C readelf -dW "$top" 2>/dev/null |
            grep '(SONAME)' >/dev/null ||
       ! LC_ALL=C readelf -dW "$top" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/deps' >/dev/null; then
        fail "$family logical load-path identity" \
            "linker did not preserve the filename/RUNPATH fixture"
        rm -rf "$root"
        return
    fi

    capture_output expect env -u LD_LIBRARY_PATH "$main" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [ "$expect" != "101:101:$a_dir/$top_name" ]; then
        fail "native $family logical load-path control" \
            "exit=$rc output=$expect"
        rm -rf "$root"
        return
    fi

    if ! env -u LD_LIBRARY_PATH "$gate" "$main" \
            >"$resolver_log" 2>&1; then
        fail "$family logical load-path resolver" \
            "resolver rejected the native fixture"
    else
        top_count=$(grep -c "^NEEDED=$top_name" "$resolver_log" || true)
        if [ "$top_count" -eq 1 ] &&
           grep -Fq "$top" "$resolver_log" &&
           grep -Fq "LOGICAL=$a_dir/$top_name" "$resolver_log" &&
           grep -Fq "$a_dir/deps/$leaf_name" "$resolver_log" &&
           ! grep -Fq "$b_dir/deps/$leaf_name" "$resolver_log" &&
           ! grep -Fq "$store/deps/$leaf_name" "$resolver_log"; then
            pass "$family resolver preserves first logical inode origin"
        else
            fail "$family logical load-path resolver" \
                "expected one inode map rooted at the first alias"
        fi
    fi

    freeze_require_direct "$family direct logical load-path identity" \
        "$log" "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$family direct logical load-path identity" \
            "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rm -f "$a_dir/$top_name" "$b_dir/$top_name" "$top" \
            "$a_dir/deps/$leaf_name" "$b_dir/deps/$leaf_name" \
            "$store/deps/$leaf_name" \
            "$parents/$parent_a_name" "$parents/$parent_b_name"
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$family direct manifest retains first logical origin"
        else
            fail "$family direct logical load-path identity" \
                "exit=$rc expected=$expect output=$actual"
        fi
    fi
    rm -rf "$root"
}

test_logical_load_path_identity() {
    echo "--- logical load path versus canonical snapshot identity ---"
    local root="$BUILD/logical_load_path" gate="$BUILD/logical-path-gate"
    local gcc_family

    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "logical load-path identity" "resolver gate compile failed"
        return
    fi
    if compiler_targets_glibc gcc; then
        gcc_family=GNU
    else
        gcc_family=musl
    fi
    run_logical_load_path_case gcc "$gcc_family" \
        "$root/${gcc_family,,}" "$gate"
    if [ "$gcc_family" = GNU ] && \
       command -v musl-gcc >/dev/null 2>&1; then
        run_logical_load_path_case musl-gcc musl "$root/musl" "$gate"
    elif [ "$gcc_family" = GNU ]; then
        skip "musl resolver logical load-path identity" \
            "musl-gcc not installed"
        skip "musl direct logical load-path identity" \
            "musl-gcc not installed"
    fi
    rm -rf "$root"
    rm -f "$gate"
}

test_needed_source_alias_identity() {
    echo "--- distinct DT_NEEDED aliases for one source identity ---"
    local root
    root="$(realpath "$BUILD")/needed-source-alias"
    local gate="$root/dep-gate"
    local store="$root/store" aliases="$root/aliases"
    local parents="$root/parents" bin_dir="$root/bin"
    local alias_a=libdlfrz_needed_alias_a.so
    local alias_b=libdlfrz_needed_alias_b.so
    local parent_a=libdlfrz_needed_parent_a.so
    local parent_b=libdlfrz_needed_parent_b.so
    local payload="$store/payload.so" main="$bin_dir/main"
    local out="$bin_dir/main.frozen" resolver_log="$root/resolver.log"
    local freeze_log="$root/freeze.log" expected actual rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$store" "$aliases" "$parents" "$bin_dir"
    cat >"$root/payload.c" <<'C'
#include <stdio.h>
__attribute__((constructor)) static void payload_ctor(void) {
    puts("needed-alias-ctor");
}
int dlfreeze_needed_alias_value(void) { return 71; }
C
    cat >"$root/parent-a.c" <<'C'
int dlfreeze_needed_alias_value(void);
int dlfreeze_needed_parent_a(void) { return dlfreeze_needed_alias_value(); }
void *dlfreeze_needed_parent_a_address(void) {
    return (void *)dlfreeze_needed_alias_value;
}
C
    cat >"$root/parent-b.c" <<'C'
int dlfreeze_needed_alias_value(void);
int dlfreeze_needed_parent_b(void) { return dlfreeze_needed_alias_value(); }
void *dlfreeze_needed_parent_b_address(void) {
    return (void *)dlfreeze_needed_alias_value;
}
C
    cat >"$root/main.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
int dlfreeze_needed_parent_a(void);
int dlfreeze_needed_parent_b(void);
void *dlfreeze_needed_parent_a_address(void);
void *dlfreeze_needed_parent_b_address(void);
int main(void) {
    Dl_info info;
    void *a = dlfreeze_needed_parent_a_address();
    void *b = dlfreeze_needed_parent_b_address();
    if (!dladdr(a, &info) || !info.dli_fname) return 2;
    printf("%d:%d:%d:%s\n", dlfreeze_needed_parent_a(),
           dlfreeze_needed_parent_b(), a == b, info.dli_fname);
    return 0;
}
C

    if ! gcc -shared -fPIC -o "$payload" "$root/payload.c" ||
       ! ln "$payload" "$aliases/$alias_a" ||
       ! ln "$payload" "$aliases/$alias_b" ||
       ! gcc -shared -fPIC -Wl,-soname,"$parent_a" \
            -Wl,--enable-new-dtags -Wl,-rpath,"$aliases" \
            -L"$aliases" -o "$parents/$parent_a" "$root/parent-a.c" \
            -Wl,--no-as-needed -Wl,-l:"$alias_a" ||
       ! gcc -shared -fPIC -Wl,-soname,"$parent_b" \
            -Wl,--enable-new-dtags -Wl,-rpath,"$aliases" \
            -L"$aliases" -o "$parents/$parent_b" "$root/parent-b.c" \
            -Wl,--no-as-needed -Wl,-l:"$alias_b" ||
       ! gcc -Wl,--enable-new-dtags -Wl,-rpath,'$ORIGIN/../parents' \
            -Wl,-rpath-link,"$aliases" -L"$parents" -o "$main" \
            "$root/main.c" -Wl,--no-as-needed -Wl,-l:"$parent_a" \
            -Wl,-l:"$parent_b" -ldl ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "DT_NEEDED source aliases" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if LC_ALL=C readelf -dW "$payload" 2>/dev/null |
            grep '(SONAME)' >/dev/null ||
       ! LC_ALL=C readelf -dW "$parents/$parent_a" 2>/dev/null |
            grep -F "Shared library: [$alias_a]" >/dev/null ||
       ! LC_ALL=C readelf -dW "$parents/$parent_b" 2>/dev/null |
            grep -F "Shared library: [$alias_b]" >/dev/null; then
        fail "DT_NEEDED source aliases" \
            "fixture did not retain two names for a SONAME-less DSO"
        rm -rf "$root"
        return
    fi

    capture_output expected env -u LD_LIBRARY_PATH "$main" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [ "$expected" != $'needed-alias-ctor\n71:71:1:'"$aliases/$alias_a" ]; then
        fail "native DT_NEEDED source-alias control" \
            "exit=$rc output=$expected"
        rm -rf "$root"
        return
    fi
    if ! env -u LD_LIBRARY_PATH "$gate" "$main" \
            >"$resolver_log" 2>&1 ||
       ! grep -Fq "NEEDED=$alias_a" "$resolver_log" ||
       ! grep -Fq "NEEDED=$alias_b" "$resolver_log" ||
       ! grep -Fq $'\t'"$aliases/$alias_a"$'\t' "$resolver_log" ||
       ! grep -Fq $'\t'"$aliases/$alias_b"$'\t' "$resolver_log"; then
        fail "DT_NEEDED source-alias resolver" \
            "resolver did not retain both names for one source"
        rm -rf "$root"
        return
    fi
    pass "resolver retains distinct DT_NEEDED source aliases"

    freeze_require_direct "DT_NEEDED source-alias direct replay" \
        "$freeze_log" "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "DT_NEEDED source-alias direct replay" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rm -f "$payload" "$aliases/$alias_a" "$aliases/$alias_b" \
            "$parents/$parent_a" "$parents/$parent_b"
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ]; then
            pass "direct loader maps DT_NEEDED source aliases once"
        else
            fail "DT_NEEDED source-alias direct replay" \
                "exit=$rc expected=$expected output=$actual"
        fi
    fi
    rm -rf "$root"
}

test_pathful_glibc_direct_admission() {
    echo "--- pathful glibc provider direct admission ---"
    local root
    root="$(realpath "$BUILD")/pathful-glibc"
    local main="$root/main" out="$root/main.frozen"
    local gate="$root/dep-gate" log="$root/resolver.log"
    local freeze_log="$root/freeze.log" libc_path dynamic
    local expected actual rc=0 freeze_rc=0

    if ! command -v patchelf >/dev/null 2>&1; then
        skip "pathful glibc direct admission" "patchelf not installed"
        return
    fi
    rm -rf "$root"
    mkdir -p "$root"
    cat >"$root/main.c" <<'C'
#include <stdio.h>
int main(void) { puts("pathful-glibc-ok"); return 0; }
C
    if ! gcc -o "$main" "$root/main.c"; then
        fail "pathful glibc direct admission" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    libc_path=$(LC_ALL=C ldd "$main" 2>/dev/null |
        awk '$1 == "libc.so.6" { print $3; exit }')
    libc_path=$(realpath "$libc_path" 2>/dev/null || true)
    if [ -z "$libc_path" ]; then
        skip "pathful glibc direct admission" \
            "target has no separately mapped libc.so.6"
        rm -rf "$root"
        return
    fi
    if ! patchelf --replace-needed libc.so.6 "$libc_path" "$main" ||
       ! gcc -O2 -g -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "pathful glibc direct admission" "fixture patch failed"
        rm -rf "$root"
        return
    fi
    dynamic=$(LC_ALL=C readelf -dW "$main" 2>/dev/null || true)
    capture_output expected env -u LD_LIBRARY_PATH "$main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expected" != pathful-glibc-ok ] ||
       ! grep -Fq "Shared library: [$libc_path]" <<<"$dynamic"; then
        fail "native pathful glibc control" \
            "exit=$rc output=$expected"
        rm -rf "$root"
        return
    elif ! env -u LD_LIBRARY_PATH "$gate" "$main" >"$log" 2>&1 ||
         ! grep -Fq "NEEDED=$libc_path" "$log"; then
        fail "pathful glibc resolver" \
            "absolute DT_NEEDED identity was not retained"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "pathful glibc direct admission" "$freeze_log" \
        "$out" -v -t -- "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        fail "pathful glibc direct admission" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ] &&
           grep -Fq 'trace helper:' "$freeze_log"; then
            pass "pathful libc uses structural DT_SONAME admission"
        else
            fail "pathful glibc direct replay" \
                "exit=$rc expected=$expected actual=$actual"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2g3: GNU cache parsing is bounded and follows loader-owned ABI
# ===================================================================
test_gnu_pack_cache_contract() {
    echo "--- GNU pack-time cache contract ---"
    local root="$BUILD/gnu-pack-cache"
    local cache_gate="$root/cache-gate" dep_gate="$root/dep-gate"
    local log="$root/resolver.log"
    local oracle_src="$root/oracle.c" oracle_bin="$root/oracle"
    local interp needed resolver_path loader_path resolver_real loader_real
    local miss_lib="$root/libdlfreeze_uncached_probe.so"
    local miss_bin="$root/uncached-main" nodefault_bin="$root/nodefault-main"
    local renamed_interp="$root/renamed-rtld"
    local renamed_bin="$root/renamed-main"
    local renamed_out="$root/renamed.frozen"
    local renamed_log="$root/renamed.log"
    local actual rc=0 dynamic

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$cache_gate" tests/gnu_pack_cache_gate.c \
            src/elf_parser.c; then
        fail "GNU pack cache parser contract" "gate compile failed"
        rm -rf "$root"
        return
    elif "$cache_gate"; then
        pass "GNU cache new/compat/miss/malformed states"
    else
        fail "GNU pack cache parser contract" \
            "synthetic cache state gate failed"
    fi

    if ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$dep_gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "GNU pack cache native oracle" "resolver gate compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$oracle_src" <<'C'
#include <stdio.h>
int main(void) { return puts("cache-oracle") < 0; }
C
    if ! gcc -o "$oracle_bin" "$oracle_src"; then
        fail "GNU pack cache native oracle" "fixture compile failed"
    elif ! command -v getconf >/dev/null 2>&1 ||
         ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
        skip "GNU pack cache native oracle" "target runtime is not GNU libc"
        skip "GNU pack cache miss refusal" "target runtime is not GNU libc"
        skip "GNU DF_1_NODEFLIB refusal" "target runtime is not GNU libc"
        rm -rf "$root"
        return
    else
        interp=$(LC_ALL=C readelf -lW "$oracle_bin" 2>/dev/null |
            sed -n \
                's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' |
            head -n 1)
        needed=$(LC_ALL=C readelf -dW "$oracle_bin" 2>/dev/null |
            sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
            head -n 1)
        loader_path=$(env -u LD_LIBRARY_PATH "$interp" --list \
            "$oracle_bin" 2>/dev/null |
            awk -v needed="$needed" \
                '$1 == needed && $2 == "=>" { print $3; exit }')
        if ! env -u LD_LIBRARY_PATH "$dep_gate" "$oracle_bin" \
                >"$log" 2>&1; then
            fail "GNU pack cache native oracle" \
                "resolver rejected a native-loadable fixture"
        else
            resolver_path=$(awk -F '\t' -v needed="NEEDED=$needed" \
                '$1 == needed { print $2; exit }' "$log")
            resolver_real=$(realpath "$resolver_path" 2>/dev/null || true)
            loader_real=$(realpath "$loader_path" 2>/dev/null || true)
            if [ -n "$resolver_real" ] &&
               [ "$resolver_real" = "$loader_real" ]; then
                pass "GNU pack cache path matches native loader"
            elif [[ "$loader_path" == */glibc-hwcaps/* ]] &&
                 [ -n "$resolver_real" ]; then
                skip "GNU pack cache native oracle" \
                    "native loader selected an optimized hwcaps variant"
            else
                fail "GNU pack cache native oracle" \
                    "resolver=$resolver_path loader=$loader_path"
            fi
        fi

        if ! cp "$interp" "$renamed_interp" ||
           ! renamed_interp=$(realpath "$renamed_interp") ||
           ! gcc "-Wl,--dynamic-linker=$renamed_interp" \
                -o "$renamed_bin" "$oracle_src"; then
            fail "renamed GNU interpreter identity" \
                "fixture construction failed"
        else
            actual=""; rc=0
            capture_output actual "$renamed_bin" || rc=$?
            if [ "$rc" -ne 0 ] || [ "$actual" != cache-oracle ]; then
                fail "renamed GNU interpreter native control" \
                    "exit=$rc output=$actual"
            else
                local renamed_freeze_rc=0

                freeze_require_direct "renamed GNU interpreter identity" \
                    "$renamed_log" "$renamed_out" "$renamed_bin" ||
                    renamed_freeze_rc=$?
                if [ "$renamed_freeze_rc" -eq 77 ]; then
                    skip "renamed GNU interpreter direct-load" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$renamed_freeze_rc" -eq 0 ]; then
                    actual=""; rc=0
                    capture_output actual env -u DLFREEZE_NO_FORK \
                        "$renamed_out" || rc=$?
                    if [ "$rc" -eq 0 ] &&
                       [ "$actual" = cache-oracle ]; then
                        pass "renamed GNU interpreter uses DT_SONAME identity"
                    else
                        fail "renamed GNU interpreter direct-load" \
                            "exit=$rc output=$actual"
                    fi
                fi
            fi
        fi

        cat > "$root/uncached-lib.c" <<'C'
int dlfreeze_uncached_probe(void) { return 19; }
C
        cat > "$root/uncached-main.c" <<'C'
int dlfreeze_uncached_probe(void);
int main(void) { return dlfreeze_uncached_probe() == 19 ? 0 : 1; }
C
        if ! gcc -shared -fPIC \
                -Wl,-soname,libdlfreeze_uncached_probe.so \
                -o "$miss_lib" "$root/uncached-lib.c" ||
           ! gcc -L"$root" -o "$miss_bin" "$root/uncached-main.c" \
                -l:libdlfreeze_uncached_probe.so; then
            fail "GNU pack cache miss refusal" "fixture compile failed"
        else
            actual=""; rc=0
            capture_output actual env LD_LIBRARY_PATH="$root" \
                "$miss_bin" || rc=$?
            if [ "$rc" -ne 0 ]; then
                fail "GNU pack cache miss native control" \
                    "exit=$rc output=$actual"
            elif env -u LD_LIBRARY_PATH "$dep_gate" "$miss_bin" \
                    >"$log" 2>&1; then
                fail "GNU pack cache miss refusal" \
                    "resolver guessed a non-cache default directory"
            elif grep -Fq \
                    'is absent from the GNU runtime cache' "$log"; then
                pass "GNU cache miss refuses guessed default directories"
            else
                fail "GNU pack cache miss refusal" \
                    "precise cache-miss diagnostic missing"
            fi
        fi

        if ! gcc -Wl,-z,nodefaultlib -o "$nodefault_bin" \
                "$oracle_src" 2>"$log"; then
            skip "GNU DF_1_NODEFLIB refusal" \
                "linker does not support -z nodefaultlib"
        else
            dynamic=$(LC_ALL=C readelf -dW "$nodefault_bin" \
                2>/dev/null || true)
            if ! grep -Fq 'NODEFLIB' <<<"$dynamic"; then
                skip "GNU DF_1_NODEFLIB refusal" \
                    "linker did not emit DF_1_NODEFLIB"
            elif env -u LD_LIBRARY_PATH "$dep_gate" "$nodefault_bin" \
                    >"$log" 2>&1; then
                fail "GNU DF_1_NODEFLIB refusal" \
                    "resolver used an unclassified cache/default path"
            elif grep -Fq \
                    'DF_1_NODEFLIB cache lookup cannot be classified safely' \
                    "$log"; then
                pass "GNU DF_1_NODEFLIB cache lookup fails closed"
            else
                fail "GNU DF_1_NODEFLIB refusal" \
                    "precise refusal diagnostic missing"
            fi
        fi
    fi

    rm -rf "$root"
}

# ===================================================================
# Test 2h: ELF metadata strings are bounded by their mapped string table,
# not by private parser buffers.
# ===================================================================
test_long_elf_metadata_strings() {
    echo "--- long ELF metadata strings ---"
    local root="$BUILD/long_elf_metadata" provider="$BUILD/long_elf_metadata/provider"
    local libsrc="$root/lib.c" mainsrc="$root/main.c" plain="$root/plain.c"
    local lib="$provider/libdlfrz_long_metadata.so"
    local runpath_bin="$root/runpath-main" rpath_bin="$root/rpath-main"
    local soname_lib="$root/long-soname.so" interp_bin="$root/long-interp"
    local gate="$root/elf-dynamic-strings-gate"
    local out="$root/runpath-main.frozen" log="$root/freeze.log"
    local long_paths="" long_soname long_interp component padded
    local expect actual i rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$provider"
    cat > "$libsrc" <<'C'
int dlfrz_long_metadata_value(void) { return 91; }
C
    cat > "$mainsrc" <<'C'
#include <stdio.h>
int dlfrz_long_metadata_value(void);
int main(void) {
    printf("metadata=%d\n", dlfrz_long_metadata_value());
    return 0;
}
C
    cat > "$plain" <<'C'
int main(void) { return 0; }
C

    for ((i = 0; i < 18; i++)); do
        printf -v padded '%0080d' "$i"
        component="$root/missing-$padded"
        long_paths="${long_paths:+$long_paths:}$component"
    done
    long_paths="$long_paths:$provider"
    printf -v long_soname 'lib%01280d.so' 0
    printf -v long_interp '/nonexistent/%01280d' 0
    if [ "${#long_paths}" -le 1024 ] ||
       [ "${#long_soname}" -le 256 ] || [ "${#long_interp}" -le 256 ]; then
        fail "long ELF metadata strings" "fixture lengths are too short"
        rm -rf "$root"
        return
    fi

    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_long_metadata.so \
            -o "$lib" "$libsrc" ||
       ! gcc -Wl,--enable-new-dtags -Wl,-rpath,"$long_paths" \
            -Wl,-rpath-link,"$provider" -L"$provider" \
            -o "$runpath_bin" "$mainsrc" -ldlfrz_long_metadata ||
       ! gcc -Wl,--disable-new-dtags -Wl,-rpath,"$long_paths" \
            -o "$rpath_bin" "$plain" ||
       ! gcc -shared -fPIC -Wl,-soname,"$long_soname" \
            -o "$soname_lib" "$libsrc" ||
       ! gcc -Wl,--dynamic-linker,"$long_interp" \
            -o "$interp_bin" "$plain" ||
       ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$gate" tests/elf_dynamic_strings_gate.c \
            src/elf_parser.c; then
        fail "long ELF metadata strings" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if "$gate" "$runpath_bin" "$rpath_bin" "$soname_lib" \
            "$interp_bin"; then
        pass "ELF parser accepts complete dynamic strings"
    else
        fail "long ELF metadata strings" "parser truncated or rejected metadata"
        rm -rf "$root"
        return
    fi

    capture_output expect env -u LD_LIBRARY_PATH "$runpath_bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "metadata=91" ]; then
        fail "native long RUNPATH control" "exit=$rc_e output=$expect"
        rm -rf "$root"
        return
    fi
    if ! run_freeze env -u LD_LIBRARY_PATH "$DLFREEZE" -o "$out" -- \
            "$runpath_bin" >"$log" 2>&1; then
        fail "long RUNPATH dependency resolution" \
            "dlfreeze failed: $(tail -n 1 "$log" 2>/dev/null)"
        rm -rf "$root"
        return
    fi
    rm -f "$lib"
    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "dependency resolver consumes complete RUNPATH"
    else
        fail "long RUNPATH dependency resolution" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 2i: captured-file tables grow beyond their former fixed limits
# ===================================================================
test_vfs_hash_complexity_gate() {
    echo "--- keyed VFS hash and linear directory derivation gate ---"
    local gate="$BUILD/vfs_hash_complexity_gate"
    local rc=0

    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -ffunction-sections -fdata-sections -fno-stack-protector \
            -Wl,--gc-sections -o "$gate" \
            tests/vfs_hash_complexity_gate.c -ldl -pthread; then
        fail "VFS adversarial complexity gate" "fixture compile failed"
        rm -f "$gate"
        return
    fi
    run_with_timeout_seconds 10 "$gate" || rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "keyed VFS hashing and linear immutable directory spans"
    else
        fail "VFS adversarial complexity gate" \
            "exit=$rc (timeout or structural mismatch)"
    fi
    rm -f "$gate"
}

test_high_cardinality_data_manifest() {
    echo "--- high-cardinality captured-file manifest ---"
    local src="$BUILD/high_cardinality_manifest.c"
    local bin="$BUILD/high_cardinality_manifest"
    local tree=""
    local out="$BUILD/high_cardinality_manifest.frozen"
    local log="$BUILD/high_cardinality_manifest.log"
    local tree_abs actual rc=0 freeze_rc=0 cleanup_failed=0 count=4105

    rm -f "$src" "$bin" "$out" "$log"
    cat > "$src" <<'C'
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_path(char *path, size_t size, const char *root, int index,
                     int file) {
    int n = snprintf(path, size, file ? "%s/d%05d/value" : "%s/d%05d",
                     root, index);
    return n >= 0 && (size_t)n < size ? 0 : -1;
}

#define DEEP_COMPONENTS 1200

static int make_deep_path(char *path, size_t size, const char *root,
                          int file) {
    int n = snprintf(path, size, "%s/d00000", root);
    size_t position;

    if (n < 0 || (size_t)n >= size)
        return -1;
    position = (size_t)n;
    for (int i = 0; i < DEEP_COMPONENTS; i++) {
        if (position > size - 3)
            return -1;
        path[position++] = '/';
        path[position++] = 'x';
    }
    if (file) {
        static const char suffix[] = "/deep-value";

        if (sizeof(suffix) > size - position)
            return -1;
        memcpy(path + position, suffix, sizeof(suffix));
    } else {
        path[position] = '\0';
    }
    return 0;
}

static int create_deep_path(const char *root) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/d00000", root);
    size_t position;

    if (n < 0 || (size_t)n >= sizeof(path))
        return -1;
    position = (size_t)n;
    for (int i = 0; i < DEEP_COMPONENTS; i++) {
        if (position > sizeof(path) - 3)
            return -1;
        path[position++] = '/';
        path[position++] = 'x';
        path[position] = '\0';
        if (mkdir(path, 0700) < 0 && errno != EEXIST)
            return -1;
    }
    if (sizeof("/deep-value") > sizeof(path) - position)
        return -1;
    memcpy(path + position, "/deep-value", sizeof("/deep-value"));
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "deep\n", 5) != 5 || close(fd) < 0)
        return -1;
    return 0;
}

static int create_tree(const char *root, int count) {
    char path[PATH_MAX];

    if (mkdir(root, 0700) < 0 && errno != EEXIST)
        return 2;
    for (int i = 0; i < count; i++) {
        int fd;
        char value[32];
        int length;

        if (make_path(path, sizeof(path), root, i, 0) < 0 ||
            (mkdir(path, 0700) < 0 && errno != EEXIST) ||
            make_path(path, sizeof(path), root, i, 1) < 0)
            return 3;
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return 4;
        length = snprintf(value, sizeof(value), "%d\n", i);
        if (write(fd, value, (size_t)length) != length || close(fd) < 0)
            return 5;
    }
    return create_deep_path(root) == 0 ? 0 : 6;
}

static int unlink_if_present(const char *path) {
    if (unlink(path) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int rmdir_if_present(const char *path) {
    if (rmdir(path) == 0 || errno == ENOENT)
        return 0;
    return -1;
}

static int remove_tree(const char *root, int count) {
    char path[PATH_MAX];
    size_t position;

    /* Remove ordinary leaves before d00000's nested stress path.  Missing
     * entries are accepted so this also cleans a partially-created tree and
     * is safe to call again from the common test teardown. */
    for (int i = 0; i < count; i++) {
        if (make_path(path, sizeof(path), root, i, 1) < 0 ||
            unlink_if_present(path) < 0)
            return 30;
    }
    if (make_deep_path(path, sizeof(path), root, 1) < 0 ||
        unlink_if_present(path) < 0)
        return 31;

    /* Host rm implementations need not support a 1200-component recursive
     * walk.  The fixture knows the exact chain, so remove it bottom-up while
     * every individual rmdir pathname remains within PATH_MAX. */
    if (make_deep_path(path, sizeof(path), root, 0) < 0)
        return 32;
    position = strlen(path);
    for (int i = 0; i < DEEP_COMPONENTS; i++) {
        if (rmdir_if_present(path) < 0 || position < 2)
            return 33;
        position -= 2;
        path[position] = '\0';
    }

    for (int i = count; i-- > 0;) {
        if (make_path(path, sizeof(path), root, i, 0) < 0 ||
            rmdir_if_present(path) < 0)
            return 34;
    }
    return rmdir_if_present(root) == 0 ? 0 : 35;
}

static int probe_tree(const char *root, int count) {
    char path[PATH_MAX];
    char value[32];
    int directories = 0;
    int deep_entry = 0;
    DIR *held[80] = {0};
    DIR *dir;
    struct dirent *entry;

    for (int i = 0; i < count; i++) {
        int fd;
        ssize_t length;
        char *end;
        long parsed;

        if (make_path(path, sizeof(path), root, i, 1) < 0)
            return 10;
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return 11;
        length = read(fd, value, sizeof(value) - 1);
        if (length <= 0 || close(fd) < 0)
            return 12;
        value[length] = '\0';
        parsed = strtol(value, &end, 10);
        if (parsed != i || (*end != '\n' && *end != '\0'))
            return 13;
    }

    /* Keep enough directory streams and dirfds live concurrently to catch
     * fixed handle tables, silent fd-map eviction, and relative-open mixups. */
    for (int i = 0; i < 80 && i < count; i++) {
        int fd;
        ssize_t length;
        long parsed;
        char *end;

        if (make_path(path, sizeof(path), root, i, 0) < 0 ||
            !(held[i] = opendir(path)) ||
            (fd = openat(dirfd(held[i]), "value", O_RDONLY)) < 0)
            return 16;
        length = read(fd, value, sizeof(value) - 1);
        if (length <= 0 || close(fd) < 0)
            return 17;
        value[length] = '\0';
        parsed = strtol(value, &end, 10);
        if (parsed != i || (*end != '\n' && *end != '\0'))
            return 18;
    }
    for (int i = 0; i < 80 && i < count; i++)
        if (closedir(held[i]) < 0)
            return 19;

    if (make_deep_path(path, sizeof(path), root, 1) < 0)
        return 20;
    {
        int fd = open(path, O_RDONLY);
        ssize_t length;

        if (fd < 0)
            return 21;
        length = read(fd, value, sizeof(value));
        if (length != 5 || memcmp(value, "deep\n", 5) != 0 ||
            close(fd) < 0)
            return 22;
    }
    if (make_deep_path(path, sizeof(path), root, 0) < 0 ||
        !(dir = opendir(path)))
        return 23;
    while ((entry = readdir(dir)) != NULL)
        if (strcmp(entry->d_name, "deep-value") == 0)
            deep_entry = 1;
    if (closedir(dir) < 0 || !deep_entry)
        return 24;

    dir = opendir(root);
    if (!dir)
        return 14;
    while ((entry = readdir(dir)) != NULL)
        if (entry->d_name[0] == 'd')
            directories++;
    if (closedir(dir) < 0 || directories != count)
        return 15;
    printf("files=%d dirs=%d deep=ok\n", count, directories);
    return 0;
}

int main(int argc, char **argv) {
    int count;

    if (argc != 4)
        return 1;
    count = atoi(argv[3]);
    if (count <= 0)
        return 1;
    if (strcmp(argv[1], "create") == 0)
        return create_tree(argv[2], count);
    if (strcmp(argv[1], "probe") == 0)
        return probe_tree(argv[2], count);
    if (strcmp(argv[1], "remove") == 0)
        return remove_tree(argv[2], count);
    return 1;
}
C
    if command -v musl-gcc >/dev/null 2>&1; then
        musl-gcc -o "$bin" "$src" || {
            fail "high-cardinality captured-file manifest" \
                "musl fixture compile failed"
            rm -f "$src" "$bin"
            return
        }
    elif ! gcc -o "$bin" "$src"; then
        fail "high-cardinality captured-file manifest" "fixture compile failed"
        rm -f "$src" "$bin"
        return
    fi
    if ! tree=$(mktemp -d "$BUILD/high-cardinality-tree.XXXXXX"); then
        fail "high-cardinality captured-file manifest" \
            "could not create unique fixture root"
        rm -f "$src" "$bin"
        return
    fi
    case "$tree" in
        /*) tree_abs="$tree" ;;
        *)  tree_abs="$(pwd -P)/$tree" ;;
    esac
    if ! "$bin" create "$tree_abs" "$count"; then
        fail "high-cardinality captured-file manifest" "fixture creation failed"
        if ! "$bin" remove "$tree_abs" "$count"; then
            fail "high-cardinality captured-file manifest" \
                "partial fixture cleanup failed"
        fi
        rm -f "$src" "$bin"
        return
    fi

    freeze_require_direct "high-cardinality captured-file manifest" "$log" \
        "$out" -t -f "$tree_abs/*" -- "$bin" probe "$tree_abs" "$count" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "high-cardinality captured-file manifest" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        if ! "$bin" remove "$tree_abs" "$count"; then
            fail "high-cardinality captured-file manifest" \
                "fixture cleanup before replay failed"
            cleanup_failed=1
        else
            capture_output actual "$out" probe "$tree_abs" "$count" || rc=$?
            if [ "$rc" -eq 0 ] &&
               [ "$actual" = "files=$count dirs=$count deep=ok" ]; then
                pass "high-cardinality captured-file manifest"
            else
                fail "high-cardinality captured-file manifest" \
                    "exit=$rc output=$actual"
            fi
        fi
    fi
    if ! "$bin" remove "$tree_abs" "$count" &&
       [ "$cleanup_failed" -eq 0 ]; then
        fail "high-cardinality captured-file manifest" \
            "final fixture cleanup failed"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 3: /bin/ls
# ===================================================================
test_ls() {
    echo "--- ls ---"
    local out="$BUILD/ls.frozen"

    # Use /usr/bin — stable and no tmpdir contamination
    freeze_and_compare "ls /usr/bin" /bin/ls "$out" /usr/bin
    rm -f "$out"

    # ls -la on a stable directory
    freeze_and_compare "ls -la /etc" /bin/ls "$out" -la /etc
    rm -f "$out"
}

# ===================================================================
# Test 4: /bin/cat (stdin + file)
# ===================================================================
test_cat() {
    echo "--- cat ---"
    local out="$BUILD/cat.frozen"
    local testfile=/etc/hostname
    [ -f "$testfile" ] || testfile=/etc/os-release

    freeze_and_compare "cat file" /bin/cat "$out" "$testfile"
    rm -f "$out"

    # stdin
    if ! run_freeze "$DLFREEZE" -o "$out" /bin/cat; then fail "cat stdin" "dlfreeze failed"; return; fi
    local expect actual
    expect=$(echo "hello world" | /bin/cat)
    actual=$(echo "hello world" | run_with_timeout "$out")
    if [ "$expect" = "$actual" ]; then pass "cat stdin"; else fail "cat stdin" "output differs"; fi
    rm -f "$out"
}

# ===================================================================
# Test 4a: negative VFS entries may retain safe, non-extractable dot paths
# ===================================================================
test_negative_dot_path_manifest() {
    echo "--- negative dotted VFS path ---"
    local build_abs root existing missing probe src bin out log
    local actual rc=0 freeze_rc=0

    build_abs=$(cd "$BUILD" && pwd -P)
    root="$build_abs/vfs_negative_dot_root"
    existing="$root/existing"
    missing="$root/missing.txt"
    probe="$existing/../missing.txt"
    src="$build_abs/vfs_negative_dot.c"
    bin="$build_abs/vfs_negative_dot"
    out="$build_abs/vfs_negative_dot.frozen"
    log="$build_abs/vfs_negative_dot.log"

    rm -rf "$root"
    rm -f "$src" "$bin" "$out" "$log"
    mkdir -p "$existing"
    cat > "$src" <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd;

    if (argc != 2)
        return 2;
    fd = open(argv[1], O_RDONLY);
    if (fd >= 0) {
        close(fd);
        puts("unexpected-present");
        return 3;
    }
    if (errno != ENOENT && errno != ENOTDIR) {
        perror("open");
        return 4;
    }
    puts("negative-dot-ok");
    return 0;
}
C

    if ! gcc -o "$bin" "$src"; then
        fail "negative dotted VFS path" "fixture compile failed"
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "negative dotted VFS path" "$log" "$out" \
        -t -f "$root/*" "$bin" "$probe" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "negative dotted VFS path" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    printf '%s\n' 'host file must stay hidden' > "$missing"
    capture_output actual "$out" "$probe" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "negative-dot-ok" ]; then
        pass "negative dotted VFS path"
    else
        fail "negative dotted VFS path" "exit=$rc output=$actual"
    fi

    rm -rf "$root"
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 4b: startup ELFs remain readable through a sealed data-file VFS
# ===================================================================
test_direct_startup_elf_vfs() {
    echo "--- direct startup ELF VFS visibility ---"
    local build_abs root lib_src lib src bin data out log
    local actual rc=0 freeze_rc=0

    build_abs=$(cd "$BUILD" && pwd -P)
    root="$build_abs/vfs_startup_elf_root"
    lib_src="$root/libprobe.c"
    lib="$root/libvfs_startup_probe.so"
    src="$root/main.c"
    bin="$root/main"
    data="$root/data.txt"
    out="$root/main.frozen"
    log="$root/main.log"

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$lib_src" <<'C'
int vfs_startup_probe(void) { return 41; }
C
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

static int deny_add_seals(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fcntl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_ADD_SEALS, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

extern int vfs_startup_probe(void);

int main(int argc, char **argv) {
    unsigned char magic[4];
    char data_byte;
    struct stat st;
    FILE *stream;
    int descriptor_flags;
    int frozen_check;
    int status_flags;
    int fd;

    frozen_check = argc == 4 && strcmp(argv[3], "frozen") == 0;
    if ((argc != 3 && !frozen_check) || vfs_startup_probe() != 41)
        return 2;
    fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_APPEND | O_NONBLOCK);
    descriptor_flags = fd < 0 ? -1 : fcntl(fd, F_GETFD);
    status_flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
    if (fd < 0 || (descriptor_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_ACCMODE) != O_RDONLY ||
        (status_flags & (O_APPEND | O_NONBLOCK)) !=
            (O_APPEND | O_NONBLOCK) ||
        read(fd, &data_byte, 1) != 1 || data_byte != 'd')
        return 3;
    errno = 0;
    if (write(fd, "x", 1) >= 0 || errno != EBADF)
        return 3;
    close(fd);

    fd = open(argv[2], O_RDONLY);
    descriptor_flags = fd < 0 ? -1 : fcntl(fd, F_GETFD);
    status_flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
    if (fd < 0 || (descriptor_flags & FD_CLOEXEC) != 0 ||
        (status_flags & O_ACCMODE) != O_RDONLY ||
        read(fd, magic, sizeof(magic)) != (ssize_t)sizeof(magic))
        return 4;
    if (memcmp(magic, "\177ELF", sizeof(magic)) != 0)
        return 5;
    if (!frozen_check) {
        close(fd);
        puts("startup-elf-vfs-trace-ok");
        return 0;
    }
    if ((fcntl(fd, F_GET_SEALS) & F_SEAL_WRITE) == 0)
        return 6;
    close(fd);

    errno = 0;
    fd = open(argv[2], O_RDWR);
    if (fd >= 0 || errno != EROFS)
        return 7;

    errno = 0;
    fd = open(argv[2], O_RDONLY | O_DIRECTORY);
    if (fd >= 0 || errno != ENOTDIR)
        return 8;

    fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_APPEND | O_NONBLOCK);
    descriptor_flags = fd < 0 ? -1 : fcntl(fd, F_GETFD);
    status_flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
    if (fd < 0 || (descriptor_flags & FD_CLOEXEC) == 0 ||
        (status_flags & O_ACCMODE) != O_RDONLY ||
        (status_flags & (O_APPEND | O_NONBLOCK)) !=
            (O_APPEND | O_NONBLOCK)) {
        fprintf(stderr, "sealed ELF reopen: fd=%d fdflags=%#x "
                "status=%#x errno=%d\n", fd, descriptor_flags,
                status_flags, errno);
        return 9;
    }
    close(fd);

#ifdef O_PATH
    fd = open(argv[2], O_PATH | O_CLOEXEC);
    if (fd < 0 || (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(fd, F_GETFL) & O_PATH) == 0)
        return 10;
    errno = 0;
    if (read(fd, magic, sizeof(magic)) >= 0 || errno != EBADF)
        return 11;
    close(fd);
#endif

    stream = fopen(argv[2], "re");
    if (!stream || (fcntl(fileno(stream), F_GETFD) & FD_CLOEXEC) == 0)
        return 12;
    fclose(stream);

    if (stat(argv[1], &st) < 0 || (st.st_mode & 0777) != 0444 ||
        access(argv[1], R_OK) != 0)
        return 13;
    errno = 0;
    if (access(argv[1], W_OK) == 0 || errno != EROFS)
        return 14;
    errno = 0;
    if (access(argv[1], X_OK) == 0 || errno != EACCES)
        return 15;

    if (stat(argv[2], &st) < 0 || (st.st_mode & 0777) != 0555 ||
        access(argv[2], R_OK | X_OK) != 0)
        return 16;
    errno = 0;
    if (faccessat(AT_FDCWD, argv[2], W_OK, 0) == 0 || errno != EROFS)
        return 17;

    if (deny_add_seals() < 0) {
        puts("startup-elf-vfs-ok:seccomp-unavailable");
        return 0;
    }
    errno = 0;
    fd = open(argv[1], O_RDONLY);
    if (fd >= 0 || errno != EPERM)
        return 18;
    puts("startup-elf-vfs-ok:fail-closed");
    return 0;
}
C
    printf '%s\n' 'data-file' > "$data"

    if ! gcc -shared -fPIC -Wl,-soname,libvfs_startup_probe.so \
            -o "$lib" "$lib_src" ||
       ! gcc -Wl,-rpath,'$ORIGIN' -L"$root" -o "$bin" "$src" \
            -lvfs_startup_probe; then
        fail "direct startup ELF VFS visibility" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct startup ELF VFS visibility" "$log" "$out" \
        -t -f "$root/*" "$bin" "$data" "$lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct startup ELF VFS visibility" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$lib" "${lib}.bak"
    mv "$data" "${data}.bak"
    printf '%s\n' 'host-replacement' > "$data"
    capture_output actual "$out" "$data" "$lib" frozen || rc=$?
    mv "${lib}.bak" "$lib"
    rm -f "$data"
    mv "${data}.bak" "$data"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "startup-elf-vfs-ok:fail-closed" ]; then
        pass "direct startup ELF VFS visibility"
        pass "VFS sealing failure is fail-closed"
    elif [ "$rc" -eq 0 ] &&
         [ "$actual" = "startup-elf-vfs-ok:seccomp-unavailable" ]; then
        pass "direct startup ELF VFS visibility"
        skip "VFS sealing failure is fail-closed" "seccomp unavailable"
    else
        fail "direct startup ELF VFS visibility" "exit=$rc output=$actual"
        tail -n 60 "$log" || true
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 4c: faccessat flags use the matching Linux syscall semantics
# ===================================================================
test_vfs_faccessat_flag_routing() {
    echo "--- direct VFS faccessat flag routing ---"
    local build_abs root bin data regular dangling out log
    local actual rc=0 freeze_rc=0

    build_abs=$(cd "$BUILD" && pwd -P)
    root="$build_abs/vfs_faccessat_root"
    bin="$root/main"
    data="$root/captured.dat"
    regular="$root/regular.dat"
    dangling="$root/dangling"
    out="$root/main.frozen"
    log="$root/main.log"

    rm -rf "$root"
    mkdir -p "$root"
    printf '%s\n' 'captured-data' > "$data"
    printf '%s\n' 'regular-data' > "$regular"
    ln -s missing-target "$dangling"

    if ! gcc -Wall -Wextra -Werror -O2 -o "$bin" \
            tests/vfs_faccessat_flags.c; then
        fail "direct VFS faccessat flag routing" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct VFS faccessat flag routing" "$log" "$out" \
        -t -f "$data" "$bin" "$data" "$regular" "$dangling" trace || \
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct VFS faccessat flag routing" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$data" "${data}.bak"
    capture_output actual "$out" "$data" "$regular" "$dangling" frozen || \
        rc=$?
    mv "${data}.bak" "$data"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)

    if [ "$rc" -ne 0 ]; then
        fail "direct VFS faccessat flag routing" \
            "exit=$rc output=$actual"
    elif [[ "$actual" != vfs-faccessat-ok:kernel=*,seccomp=* ]]; then
        fail "direct VFS faccessat flag routing" "unexpected output=$actual"
    else
        pass "direct VFS faccessat flags=0 legacy behavior"
        case "$actual" in
            *kernel=faccessat2,*)
                pass "direct VFS faccessat2 flag semantics"
                ;;
            *kernel=unsupported,*)
                skip "direct VFS faccessat2 flag semantics" \
                    "running kernel has no faccessat2"
                ;;
        esac
        case "$actual" in
            *,seccomp=verified)
                pass "direct VFS faccessat syscall routing"
                pass "direct VFS faccessat2 ENOSYS is fail-closed"
                ;;
            *,seccomp=unavailable)
                skip "direct VFS faccessat syscall routing" \
                    "seccomp unavailable"
                skip "direct VFS faccessat2 ENOSYS is fail-closed" \
                    "seccomp unavailable"
                ;;
        esac
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 4d: VFS does not rewrite process identity or compiler environment
# ===================================================================
test_vfs_environment_and_kernel_identity() {
    echo "--- VFS environment and kernel executable identity ---"
    local build_abs root src bin data out log sentinel bin_abs out_abs
    local actual rc=0 freeze_rc=0

    build_abs=$(cd "$BUILD" && pwd -P)
    root="$build_abs/vfs_kernel_identity_root"
    src="$root/main.c"
    bin="$root/main"
    data="$root/libcaptured-input.so"
    out="$root/main.frozen"
    log="$root/main.log"
    sentinel="dlfreeze-library-path-sentinel"

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int terminate_link(char *path, size_t size, ssize_t length) {
    if (length < 0 || (size_t)length >= size)
        return -1;
    path[length] = '\0';
    return 0;
}

int main(int argc, char **argv) {
    char libc_self[PATH_MAX];
    char libc_at_self[PATH_MAX];
    char raw_self[PATH_MAX];
    char pid_path[64];
    char libc_pid[PATH_MAX];
    char raw_pid[PATH_MAX];
    char line[64];
    const char *library_path;
    FILE *file;

    if (argc != 4)
        return 2;
    library_path = getenv("LIBRARY_PATH");
    if (!library_path || strcmp(library_path, argv[2]) != 0)
        return 3;
    if (strstr(library_path, "/tmp/dlfreeze-vfs-") != NULL)
        return 4;

    file = fopen(argv[1], "r");
    if (!file)
        return 5;
    if (!fgets(line, sizeof(line), file) || strcmp(line, "captured-data\n") != 0) {
        fclose(file);
        return 6;
    }
    fclose(file);

    if (terminate_link(libc_self, sizeof(libc_self),
                       readlink("/proc/self/exe", libc_self,
                                sizeof(libc_self))) < 0 ||
        terminate_link(libc_at_self, sizeof(libc_at_self),
                       readlinkat(AT_FDCWD, "/proc/self/exe", libc_at_self,
                                  sizeof(libc_at_self))) < 0 ||
        terminate_link(raw_self, sizeof(raw_self),
                       syscall(SYS_readlinkat, AT_FDCWD, "/proc/self/exe",
                               raw_self, sizeof(raw_self))) < 0)
        return 7;
    if (snprintf(pid_path, sizeof(pid_path), "/proc/%ld/exe",
                 (long)getpid()) >= (int)sizeof(pid_path) ||
        terminate_link(libc_pid, sizeof(libc_pid),
                       readlink(pid_path, libc_pid, sizeof(libc_pid))) < 0 ||
        terminate_link(raw_pid, sizeof(raw_pid),
                       syscall(SYS_readlinkat, AT_FDCWD, pid_path,
                               raw_pid, sizeof(raw_pid))) < 0)
        return 8;

    if (strcmp(libc_self, raw_self) != 0 ||
        strcmp(libc_at_self, raw_self) != 0 ||
        strcmp(libc_pid, raw_self) != 0 ||
        strcmp(raw_pid, raw_self) != 0)
        return 9;
    if (strcmp(raw_self, argv[3]) != 0)
        return 10;

    puts("vfs-kernel-identity-ok");
    return 0;
}
C
    printf '%s\n' 'captured-data' > "$data"

    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -o "$bin" "$src"; then
            fail "VFS environment and kernel identity" \
                "musl fixture compile failed"
            rm -rf "$root"
            return
        fi
    elif ! gcc -o "$bin" "$src"; then
        fail "VFS environment and kernel identity" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    bin_abs=$(realpath "$bin")

    LIBRARY_PATH="$sentinel" \
        freeze_require_direct "VFS environment and kernel identity" \
        "$log" "$out" -t -f "$root/*" -- "$bin" "$data" \
        "$sentinel" "$bin_abs" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "VFS environment and kernel identity" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    out_abs=$(realpath "$out")
    mv "$data" "${data}.host"
    rc=0
    capture_output actual env LIBRARY_PATH="$sentinel" "$out" "$data" \
        "$sentinel" "$out_abs" || rc=$?
    mv "${data}.host" "$data"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "vfs-kernel-identity-ok" ]; then
        pass "VFS environment and kernel identity"
    else
        fail "VFS environment and kernel identity" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 4cc: glibc private rtld state preserves kernel auxv parameters
# ===================================================================
test_direct_kernel_runtime_parameters() {
    echo "--- direct kernel signal-stack and clock parameters ---"
    local src="$BUILD/kernel_runtime_parameters.c"
    local bin="$BUILD/kernel_runtime_parameters"
    local out="$BUILD/kernel_runtime_parameters.frozen"
    local log="$BUILD/kernel_runtime_parameters.log"
    local expect actual freeze_rc=0 rc_e=0 rc=0

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>
#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51
#endif
int main(void) {
    unsigned long aux_min = getauxval(AT_MINSIGSTKSZ);
    unsigned long aux_clk = getauxval(AT_CLKTCK);
#ifdef _SC_MINSIGSTKSZ
    long sc_min = sysconf(_SC_MINSIGSTKSZ);
#else
    long sc_min = -2;
#endif
    long sc_clk = sysconf(_SC_CLK_TCK);
    if (aux_clk == 0 || sc_clk <= 0)
        return 2;
    printf("min=%lu/%ld clock=%lu/%ld\n",
           aux_min, sc_min, aux_clk, sc_clk);
    return 0;
}
C
    if ! gcc -o "$bin" "$src"; then
        fail "direct kernel runtime parameters" "fixture compile failed"
        rm -f "$src" "$bin"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "native kernel runtime parameters" \
            "exit=$rc_e output=$expect"
        rm -f "$src" "$bin"
        return
    fi

    freeze_require_direct "direct kernel runtime parameters" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct kernel runtime parameters" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct kernel runtime parameters match native"
    else
        fail "direct kernel runtime parameters" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 4d: direct startup is the ELF entry point, not a discovered main
# ===================================================================
test_packer_main_detection() {
    echo "--- ELF entry-point startup ---"
    local pos_src="$BUILD/main_detect_positive.c"
    local neg_src="$BUILD/main_detect_opaque.c"
    local pos_bin="$BUILD/main_detect_positive"
    local neg_bin="$BUILD/main_detect_opaque"
    local pos_out="$BUILD/main_detect_positive.frozen"
    local neg_out="$BUILD/main_detect_opaque.frozen"
    local log="$BUILD/main_detect.log" rc=0 freeze_rc=0

    cat > "$pos_src" <<'C'
int main(void) { return 37; }
C
    cat > "$neg_src" <<'C'
#include <unistd.h>
__attribute__((noreturn)) void opaque_start(void) { _exit(23); }
C

    if command -v musl-gcc >/dev/null 2>&1; then
        musl-gcc -O2 -o "$pos_bin" "$pos_src"
        musl-gcc -O2 -nostartfiles -Wl,-e,opaque_start \
            -o "$neg_bin" "$neg_src"
    else
        gcc -O2 -o "$pos_bin" "$pos_src"
        gcc -O2 -nostartfiles -Wl,-e,opaque_start -o "$neg_bin" "$neg_src"
    fi
    strip --strip-all "$pos_bin" "$neg_bin"

    freeze_require_direct "stripped conventional entry" "$log" \
        "$pos_out" "$pos_bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "stripped conventional entry" "$DIRECT_FREEZE_REASON"
        skip "custom entry without main" "$DIRECT_FREEZE_REASON"
        rm -f "$pos_src" "$neg_src" "$pos_bin" "$neg_bin" \
              "$pos_out" "$neg_out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$pos_src" "$neg_src" "$pos_bin" "$neg_bin" \
              "$pos_out" "$neg_out" "$log"
        return
    fi

    rc=0
    run_with_timeout env DLFREEZE_NO_FORK=1 "$pos_out" \
        >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 37 ]; then
        pass "stripped conventional entry"
    else
        fail "stripped conventional entry" "exit=$rc"
    fi

    freeze_rc=0
    freeze_require_direct "custom entry without main" "$log" \
        "$neg_out" "$neg_bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "custom entry without main" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        run_with_timeout env DLFREEZE_NO_FORK=1 "$neg_out" \
            >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 23 ]; then
            pass "custom entry without main"
        else
            fail "custom entry without main" "exit=$rc"
        fi
    fi

    rm -f "$pos_src" "$neg_src" "$pos_bin" "$neg_bin" \
          "$pos_out" "$neg_out" "$log"
}

smoke_direct_program() {
    local label="$1" binary="$2" out="$BUILD/program-smoke.frozen"
    local log="$BUILD/program-smoke.log" freeze_rc=0
    shift 2
    rm -f "$log"

    if [ -z "$binary" ] || [ ! -x "$binary" ]; then
        skip "$label" "program not installed"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$binary" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$out" "$log"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    capture_output expect "$binary" "$@" || rc_e=$?
    capture_output actual "$out" "$@" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_e" -ne 0 ]; then
        fail "$label" "native command failed (exit $rc_e)"
    elif [ "$expect" = "$actual" ] && [ "$rc_a" -eq 0 ]; then
        pass "$label"
    else
        fail "$label" "output or exit differs (exit $rc_e vs $rc_a)"
    fi
    rm -f "$out" "$log"
}

# ===================================================================
# Test 4b: representative programs in extraction and strict direct modes
# ===================================================================
test_program_smoke_matrix() {
    echo "--- representative program smoke matrix ---"
    local bash_bin
    bash_bin="$(command -v bash || true)"
    if [ -n "$bash_bin" ]; then
        freeze_and_compare "bash fork/exec" "$bash_bin" \
            "$BUILD/program-bash.frozen" -c \
            'printf "parent\n"; /bin/printf "child\n"'
        rm -f "$BUILD/program-bash.frozen"
    else
        skip "bash fork/exec" "program not installed"
    fi
    smoke_direct_program "bash arithmetic" "$bash_bin" \
        -c 'x=$((20 + 22)); printf "value=%s\n" "$x"'
    smoke_direct_program "git ref parser" "$(command -v git || true)" \
        check-ref-format refs/heads/feature/test
    smoke_direct_program "openssl digest" "$(command -v openssl || true)" \
        dgst -sha256 /etc/hostname
    smoke_direct_program "sqlite query" "$(command -v sqlite3 || true)" \
        :memory: 'select hex(zeroblob(4)), 6 * 7;'
    smoke_direct_program "zig version" "$(command -v zig || true)" version

}

# Exercise Zig as a compiler, not just as a single-process version probe.
# This is intentionally the ordinary CLI contract: no executable-name or
# compiler-specific behavior is available to the loader.  Tracing the compile
# also covers Zig's self-exec/subtool path and the captured-file manifest used
# by `-f '/usr/*'`.
test_zig_cc_trace_direct() {
    echo "--- Zig cc traced direct-load ---"
    local zig_bin src native_bin trace_bin frozen_bin out log
    local expect actual rc=0 freeze_rc=0
    local label="Zig cc traced direct-load"

    zig_bin=$(command -v zig || true)
    if [ -z "$zig_bin" ] || [ ! -x "$zig_bin" ]; then
        skip "$label" "zig is not installed"
        return
    fi

    src="$BUILD/zig_cc_trace.c"
    native_bin="$BUILD/zig_cc_native"
    trace_bin="$BUILD/zig_cc_trace"
    frozen_bin="$BUILD/zig_cc_frozen"
    out="$BUILD/zig_cc.frozen"
    log="$BUILD/zig_cc.log"
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) {
    puts("zig-cc-ok");
    return 0;
}
C

    if ! run_with_timeout "$zig_bin" cc "$src" -o "$native_bin" \
            >"$BUILD/zig_cc_native.log" 2>&1; then
        fail "$label" "native zig cc failed"
        rm -f "$src" "$native_bin" "$trace_bin" "$frozen_bin" \
              "$out" "$log" "$BUILD/zig_cc_native.log"
        return
    fi
    capture_output expect "$native_bin" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect" != "zig-cc-ok" ]; then
        fail "$label" "native Zig output failed (exit=$rc output=$expect)"
        rm -f "$src" "$native_bin" "$trace_bin" "$frozen_bin" \
              "$out" "$log" "$BUILD/zig_cc_native.log"
        return
    fi

    freeze_require_direct "$label" "$log" "$out" \
        -t -f '/usr/*' -- "$zig_bin" cc "$src" -o "$trace_bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$native_bin" "$trace_bin" "$frozen_bin" \
              "$out" "$log" "$BUILD/zig_cc_native.log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$native_bin" "$trace_bin" "$frozen_bin" \
              "$out" "$log" "$BUILD/zig_cc_native.log"
        return
    fi

    rm -f "$trace_bin"
    rc=0
    run_with_timeout env DLFREEZE_NO_FORK=1 "$out" cc "$src" \
        -o "$frozen_bin" >"$BUILD/zig_cc_frozen.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] || [ ! -x "$frozen_bin" ]; then
        actual=$(<"$BUILD/zig_cc_frozen.log")
        fail "$label" "frozen zig cc failed (exit=$rc output=$actual)"
    else
        rc=0
        capture_output actual "$frozen_bin" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$label"
        else
            fail "$label" \
                "compiled output differs (exit=$rc output=$actual)"
        fi
    fi
    rm -f "$src" "$native_bin" "$trace_bin" "$frozen_bin" "$out" \
          "$log" "$BUILD/zig_cc_native.log" "$BUILD/zig_cc_frozen.log"
}

# ===================================================================
# Test 4c: direct-load preserves requested executable identity
# ===================================================================
test_symlink_exe_identity_direct() {
    echo "--- symlink executable identity direct-load ---"
    local src="$BUILD/identity_main.c" bin="$BUILD/identity-target"
    local alpha="$BUILD/identity-alpha" beta="$BUILD/identity-beta"
    local out_alpha="$BUILD/identity-alpha.frozen" out_beta="$BUILD/identity-beta.frozen"
    local log_alpha="$BUILD/identity-alpha.log" log_beta="$BUILD/identity-beta.log"
    local freeze_rc=0
    rm -f "$log_alpha" "$log_beta"

    cat > "$src" <<'C'
#include <stdio.h>
#include <string.h>

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int main(int argc, char **argv) {
    const char *name = base_name(argv[0]);
    printf("name=%s\n", name);
    if (strcmp(name, "identity-alpha") == 0) puts("mode=alpha");
    else if (strcmp(name, "identity-beta") == 0) puts("mode=beta");
    else puts("mode=unknown");
    printf("argc=%d\n", argc);
    return 0;
}
C
    gcc -o "$bin" "$src"
    ln -sf "$(basename "$bin")" "$alpha"
    ln -sf "$(basename "$bin")" "$beta"

    freeze_require_direct "symlink executable identity direct-load" \
        "$log_alpha" "$out_alpha" "$alpha" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "symlink executable identity direct-load" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$alpha" "$beta" "$out_alpha" "$out_beta" \
              "$log_alpha" "$log_beta"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$alpha" "$beta" "$out_alpha" "$out_beta" \
              "$log_alpha" "$log_beta"
        return
    fi
    freeze_rc=0
    freeze_require_direct "symlink executable identity direct-load" \
        "$log_beta" "$out_beta" "$beta" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "symlink executable identity direct-load" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$alpha" "$beta" "$out_alpha" "$out_beta" \
              "$log_alpha" "$log_beta"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$alpha" "$beta" "$out_alpha" "$out_beta" \
              "$log_alpha" "$log_beta"
        return
    fi

    local expect_alpha actual_alpha expect_beta actual_beta rc=0
    capture_output expect_alpha "$alpha" arg1 || rc=$?
    capture_output actual_alpha "$out_alpha" arg1 || rc=$?
    capture_output expect_beta "$beta" arg1 arg2 || rc=$?
    capture_output actual_beta "$out_beta" arg1 arg2 || rc=$?
    actual_alpha=$(printf '%s\n' "$actual_alpha" | strip_dlfreeze_warnings)
    actual_beta=$(printf '%s\n' "$actual_beta" | strip_dlfreeze_warnings)

    if [ "$rc" = "0" ] && [ "$expect_alpha" = "$actual_alpha" ] && [ "$expect_beta" = "$actual_beta" ]; then
        pass "symlink executable identity direct-load"
    else
        fail "symlink executable identity direct-load" "argv[0] identity differs"
        diff -u <(printf '%s\n' "$expect_alpha") <(printf '%s\n' "$actual_alpha") | head -20 || true
        diff -u <(printf '%s\n' "$expect_beta") <(printf '%s\n' "$actual_beta") | head -20 || true
    fi
    rm -f "$src" "$bin" "$alpha" "$beta" "$out_alpha" "$out_beta" \
          "$log_alpha" "$log_beta"
}

# ===================================================================
# Test 5: python3 (with dlopen tracing)
# ===================================================================
test_python3() {
    echo "--- python3 ---"
    if ! command -v python3 &>/dev/null; then skip "python3" "not installed"; return; fi

    local pypath out="$BUILD/python3.frozen" log="$BUILD/python3.log"
    local freeze_rc=0
    pypath=$(readlink -f "$(command -v python3)")

    freeze_require_direct "python3" "$log" "$out" -v -t -- \
        "$pypath" -c 'import json,math; print("ok")' || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "python3 print" "$DIRECT_FREEZE_REASON"
        skip "python3 math" "$DIRECT_FREEZE_REASON"
        skip "python3 json" "$DIRECT_FREEZE_REASON"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$out" "$log"
        return
    fi

    # simple print
    local expect actual rc_e=0 rc_a=0
    capture_output expect python3 -c 'print("Hello from Python!")' || rc_e=$?
    capture_output actual "$out" -c 'print("Hello from Python!")' || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "python3 print"
    else
        fail "python3 print" "output or exit differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    # math
    rc_e=0; rc_a=0
    capture_output expect python3 -c 'import math; print(math.pi)' || rc_e=$?
    capture_output actual "$out" -c 'import math; print(math.pi)' || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "python3 math"
    else
        fail "python3 math" "output or exit differs (exit $rc_e vs $rc_a)"
    fi

    # json (pure-python module)
    rc_e=0; rc_a=0
    capture_output expect python3 -c 'import json; print(json.dumps({"a":1}))' || rc_e=$?
    capture_output actual "$out" -c 'import json; print(json.dumps({"a":1}))' || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "python3 json"
    else
        fail "python3 json" "output or exit differs (exit $rc_e vs $rc_a)"
    fi

    rm -f "$out" "$log"
}

# ===================================================================
# Test 6: program that uses dlopen at runtime
# ===================================================================
test_dlopen_program() {
    echo "--- dlopen ---"
    local shlib_src="$BUILD/mylib.c"  shlib="$BUILD/libmylib.so"
    local prog_src="$BUILD/usedl.c"   prog="$BUILD/usedl"
    local out="$BUILD/usedl.frozen"

    cat > "$shlib_src" <<'C'
#include <stdio.h>
int mylib_add(int a, int b) { return a + b; }
const char *mylib_greet(void) { return "hello from mylib"; }
C
    gcc -shared -fPIC -o "$shlib" "$shlib_src"

    cat > "$prog_src" <<'C'
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("libmylib.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*add)(int,int) = dlsym(h, "mylib_add");
    const char *(*greet)(void) = dlsym(h, "mylib_greet");
    if (!add || !greet) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("%s\n", greet());
    printf("3+4=%d\n", add(3,4));
    dlclose(h);
    return 0;
}
C
    gcc -o "$prog" "$prog_src" -ldl

    # the regular program needs LD_LIBRARY_PATH to find the .so
    local expect actual rc_e=0 rc_a=0
    capture_output expect env LD_LIBRARY_PATH="$BUILD" "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "dlopen native control" "exit=$rc_e output=$expect"
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out"
        return
    fi

    # Freeze with dlopen tracing — LD_LIBRARY_PATH is needed during trace
    if ! run_freeze env LD_LIBRARY_PATH="$BUILD" "$DLFREEZE" -v -t -o "$out" "$prog" \
            -- 2>&1; then
        fail "dlopen" "dlfreeze failed"; return
    fi

    # The frozen binary should work without LD_LIBRARY_PATH
    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc_a=$?

    if [ "$expect" = "$actual" ] && [ "$rc_a" -eq 0 ]; then
        pass "dlopen (traced)"
    else
        fail "dlopen (traced)" "output or exit differs (exit 0 vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out"
}

# ===================================================================
# Path-qualified traced dlopen cannot be reproduced by extraction: dlopen with
# a slash never searches LD_LIBRARY_PATH.  Refuse such an image before an
# apparently successful but host-dependent artifact is created.
test_pathful_dlopen_requires_direct() {
    echo "--- pathful traced dlopen extraction gate ---"
    local dir="$BUILD/pathful-dlopen"
    local lib_src="$dir/libpathful.c" lib="$dir/libpathful.so"
    local prog_src="$dir/pathful.c" prog="$dir/pathful"
    local out="$dir/pathful.frozen" log="$dir/freeze.log"

    mkdir -p "$dir"
    cat > "$lib_src" <<'C'
int pathful_value(void) { return 73; }
C
    cat > "$prog_src" <<'C'
#include <dlfcn.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 3;
    int (*value)(void) = (int (*)(void))dlsym(handle, "pathful_value");
    return value && value() == 73 ? 0 : 4;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libpathful.so -o "$lib" "$lib_src" ||
       ! gcc -o "$prog" "$prog_src" -ldl || ! "$prog" "$lib"; then
        fail "pathful traced dlopen extraction gate" "fixture failed"
        return
    fi

    local rc=0
    if run_freeze "$DLFREEZE" -t -o "$out" -- "$prog" "$lib" \
            >"$log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -ne 0 ] && [ ! -e "$out" ] &&
       grep -Fq 'pathful traced dlopen entries require a supported direct-load mode' \
           "$log"; then
        pass "pathful traced dlopen extraction gate"
    else
        fail "pathful traced dlopen extraction gate" \
            "exit=$rc artifact=$([ -e "$out" ] && echo yes || echo no)"
    fi
    rm -f "$lib_src" "$lib" "$prog_src" "$prog" "$out" "$log"
    rmdir "$dir" 2>/dev/null || true
}

# Test 6b: dlopen fallback — frozen binary loads a lib NOT embedded
# ===================================================================
test_dlopen_fallback() {
    echo "--- dlopen fallback ---"
    local shlib_src="$BUILD/fallback_lib.c"  shlib="$BUILD/libfallback.so"
    local prog_src="$BUILD/usefb.c"          prog="$BUILD/usefb"
    local out="$BUILD/usefb.frozen"

    # Build a shared library that will exist on the system but NOT be
    # captured during freezing (we freeze without tracing).
    cat > "$shlib_src" <<'C'
int fallback_mul(int a, int b) { return a * b; }
C
    gcc -shared -fPIC -o "$shlib" "$shlib_src"
    local shlib_abs
    shlib_abs=$(realpath "$shlib")

    # Program loads the library via an absolute path at runtime.
    cat > "$prog_src" <<C
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    printf("before dlopen\n");
    void *h = dlopen("$shlib_abs", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*mul)(int,int) = dlsym(h, "fallback_mul");
    if (!mul) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("5*6=%d\n", mul(5,6));
    dlclose(h);
    return 0;
}
C
    gcc -o "$prog" "$prog_src" -ldl

    # Freeze WITHOUT tracing — libfallback.so will NOT be embedded
    if ! run_freeze "$DLFREEZE" -v -o "$out" "$prog"; then
        fail "dlopen-fallback" "dlfreeze failed"; return
    fi

    # The frozen binary should still work because the bundled ld.so
    # falls back to loading from the real filesystem.
    local expect actual rc_e=0 rc_a=0
    capture_output expect "$prog" || rc_e=$?
    capture_output actual "$out" || rc_a=$?

    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "dlopen fallback (system lib)"
    else
        fail "dlopen fallback" \
            "output or exit differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out"
}

# ===================================================================
# Test 7: python3 more complex — subprocess, os, sys
# ===================================================================
test_python3_advanced() {
    echo "--- python3 advanced ---"
    if ! command -v python3 &>/dev/null; then skip "python3-adv" "not installed"; return; fi

    local pypath out="$BUILD/python3a.frozen" log="$BUILD/python3a.log"
    local freeze_rc=0
    pypath=$(readlink -f "$(command -v python3)")

    # Trace with a broader import set
    freeze_require_direct "python3-adv" "$log" "$out" -t -- \
        "$pypath" -c \
        'import os,sys,json,hashlib,socket,ssl,sqlite3; print("traced")' ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "python3 os" "$DIRECT_FREEZE_REASON"
        skip "python3 hashlib" "$DIRECT_FREEZE_REASON"
        skip "python3 sqlite3" "$DIRECT_FREEZE_REASON"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$out" "$log"
        return
    fi

    # os module
    local expect actual rc_e=0 rc_a=0
    capture_output expect python3 -c 'import os; print(os.getpid.__name__)' || rc_e=$?
    capture_output actual "$out" -c 'import os; print(os.getpid.__name__)' || rc_a=$?
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "python3 os"
    else
        fail "python3 os" \
            "output or exit differs (exit $rc_e vs $rc_a): $expect vs $actual"
    fi

    # hashlib
    rc_e=0; rc_a=0
    capture_output expect python3 -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())' || rc_e=$?
    capture_output actual "$out" -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())' || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" -eq "$rc_a" ]; then
        pass "python3 hashlib"
    else
        fail "python3 hashlib" \
            "output or exit differs (exit $rc_e vs $rc_a)"
    fi

    # sqlite3
    rc_e=0; rc_a=0
    capture_output expect python3 -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])' || rc_e=$?
    capture_output actual "$out" -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])' || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" -eq "$rc_a" ]; then
        pass "python3 sqlite3"
    else
        fail "python3 sqlite3" \
            "output or exit differs (exit $rc_e vs $rc_a): expected=$expect actual=$actual"
    fi

    rm -f "$out" "$log"
}

# ===================================================================
# Test 8: direct-mode dlopen from frozen image (embedded loading)
# ===================================================================
test_direct_dlopen_embedded() {
    echo "--- direct dlopen (embedded) ---"
    local shlib_src="$BUILD/emb_lib.c"  shlib="$BUILD/libemb.so"
    local prog_src="$BUILD/use_emb.c"   prog="$BUILD/use_emb"
    local out="$BUILD/use_emb.frozen" log="$BUILD/use_emb.log"
    local bad="$BUILD/use_emb_bad_manifest.frozen"
    local size footer manifest count entry_flags dlopen_index="" i
    local freeze_rc=0
    rm -f "$log" "$bad"

    cat > "$shlib_src" <<'C'
#include <stdio.h>
int emb_add(int a, int b) { return a + b; }
const char *emb_greet(void) { return "hello from embedded"; }
C
    gcc -shared -fPIC -o "$shlib" "$shlib_src"

    cat > "$prog_src" <<'C'
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("libemb.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*add)(int,int) = dlsym(h, "emb_add");
    const char *(*greet)(void) = dlsym(h, "emb_greet");
    if (!add || !greet) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("%s\n", greet());
    printf("10+20=%d\n", add(10,20));
    dlclose(h);
    return 0;
}
C
    gcc -o "$prog" "$prog_src" -ldl

    local expect rc_e=0
    capture_output expect env LD_LIBRARY_PATH="$BUILD" "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "direct-dlopen-embedded" "native fixture failed (exit $rc_e)"
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
    fi

    # Freeze with -d (direct) and -t (trace dlopen)
    LD_LIBRARY_PATH="$BUILD" freeze_require_direct \
        "direct-dlopen-embedded" "$log" "$out" -t "$prog" -- ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen-embedded" "$DIRECT_FREEZE_REASON"
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log" \
              "$bad"
        return
    fi

    # The manifest requires the exact request identity for every traced
    # dlopen root.  Silently falling back to a basename would change lookup
    # semantics, so a missing request offset must fail before direct loading.
    size=$(stat -c %s "$out")
    footer=$((size - 64))
    count=$(od -An -tu4 -j $((footer + 12)) -N4 "$out" |
        tr -d '[:space:]')
    manifest=$(od -An -tu8 -j $((footer + 16)) -N8 "$out" |
        tr -d '[:space:]')
    if [[ "$count" =~ ^[0-9]+$ && "$manifest" =~ ^[0-9]+$ ]]; then
        for ((i = 0; i < count; i++)); do
            entry_flags=$(od -An -tu4 \
                -j $((manifest + i * 32 + 16)) -N4 "$out" |
                tr -d '[:space:]')
            entry_request=$(od -An -tu4 \
                -j $((manifest + i * 32 + 24)) -N4 "$out" |
                tr -d '[:space:]')
            if [[ "$entry_flags" =~ ^[0-9]+$ ]] &&
               [[ "$entry_request" =~ ^[0-9]+$ ]] &&
               [ $((entry_flags & 0x08)) -ne 0 ] &&
               [ "$entry_request" -ne 0 ]; then
                dlopen_index=$i
                break
            fi
        done
    fi
    if [ -z "$dlopen_index" ]; then
        fail "traced dlopen request manifest" \
            "fixture produced no traced dlopen entry"
    else
        cp "$out" "$bad"
        dd if=/dev/zero of="$bad" bs=1 \
            seek=$((manifest + dlopen_index * 32 + 24)) count=4 \
            conv=notrunc status=none
        local bad_actual="" bad_rc=0
        capture_output bad_actual "$bad" || bad_rc=$?
        if [ "$bad_rc" -eq 127 ] &&
           [[ "$bad_actual" == *"invalid direct-load object metadata"* ]]; then
            pass "traced dlopen request manifest"
        else
            fail "traced dlopen request manifest" \
                "exit=$bad_rc output=$bad_actual"
        fi
    fi

    # Run frozen binary — should load libemb.so from embedded image,
    # NOT from the filesystem.  Remove the .so to prove it.
    mv "$shlib" "${shlib}.bak"
    local actual rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    mv "${shlib}.bak" "$shlib"

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        pass "direct-dlopen embedded"
    else
        fail "direct-dlopen embedded" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log" \
          "$bad"
}

# ===================================================================
# Test 9: direct-mode dlopen with transitive DT_NEEDED deps
# ===================================================================
test_direct_dlopen_deps() {
    echo "--- direct dlopen (deps) ---"
    local dep_src="$BUILD/dep_lib.c"  dep="$BUILD/libdep.so"
    local top_src="$BUILD/top_lib.c"  top="$BUILD/libtop.so"
    local prog_src="$BUILD/use_dep.c" prog="$BUILD/use_dep"
    local out="$BUILD/use_dep.frozen" log="$BUILD/use_dep.log"
    local freeze_rc=0
    rm -f "$log"

    # Dependency library
    cat > "$dep_src" <<'C'
int dep_mul(int a, int b) { return a * b; }
C
    gcc -shared -fPIC -o "$dep" "$dep_src"

    # Top-level library that depends on libdep.so
    cat > "$top_src" <<'C'
extern int dep_mul(int a, int b);
int top_compute(int x) { return dep_mul(x, x); }
C
    gcc -shared -fPIC -o "$top" "$top_src" -L"$BUILD" -ldep

    cat > "$prog_src" <<'C'
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("libtop.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*compute)(int) = dlsym(h, "top_compute");
    if (!compute) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("7^2=%d\n", compute(7));
    dlclose(h);
    return 0;
}
C
    gcc -o "$prog" "$prog_src" -ldl

    local expect rc_e=0
    capture_output expect env LD_LIBRARY_PATH="$BUILD" "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "direct-dlopen-deps" "native fixture failed (exit $rc_e)"
        rm -f "$dep_src" "$dep" "$top_src" "$top" "$prog_src" "$prog" \
              "$out" "$log"
        return
    fi

    # Freeze with -d -t — both libtop.so and libdep.so should be captured
    LD_LIBRARY_PATH="$BUILD" freeze_require_direct \
        "direct-dlopen-deps" "$log" "$out" -t "$prog" -- ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen-deps" "$DIRECT_FREEZE_REASON"
        rm -f "$dep_src" "$dep" "$top_src" "$top" "$prog_src" "$prog" \
              "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$dep_src" "$dep" "$top_src" "$top" "$prog_src" "$prog" \
              "$out" "$log"
        return
    fi

    # Remove both .so files to prove they load from frozen image
    mv "$dep" "${dep}.bak"
    mv "$top" "${top}.bak"
    local actual rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    mv "${dep}.bak" "$dep"
    mv "${top}.bak" "$top"

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        pass "direct-dlopen deps"
    else
        fail "direct-dlopen deps" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$dep_src" "$dep" "$top_src" "$top" "$prog_src" "$prog" \
          "$out" "$log"
}

# Exercise late dependency discovery from a deliberately small pthread stack.
# The chain is acyclic and bounded well below MAX_TOTAL_OBJS; its depth is
# enough to expose a recursive loader which keeps PATH_MAX search buffers in
# every frame.  Test both uncaptured filesystem loading and a traced embedded
# closure, and compare each target runtime with its native loader first.
run_direct_small_stack_chain_runtime() {
    local family="$1" cc="$2"
    local root="$BUILD/direct_small_stack_chain_$family"
    local libdir="$root/libs" hidden="$root/libs.hidden"
    local main="$root/main" top="$libdir/libdlfrz_stack_0.so"
    local disk_out="$root/main.disk.frozen" disk_log="$root/disk.log"
    local embedded_out="$root/main.embedded.frozen"
    local embedded_log="$root/embedded.log"
    local depth=32 i symbol next library next_library top_abs
    local expect actual probe freeze_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$libdir"
    for ((i = depth - 1; i >= 0; i--)); do
        symbol="dlfrz_chain_$i"
        library="$libdir/libdlfrz_stack_$i.so"
        if [ "$i" -eq $((depth - 1)) ]; then
            if ! "$cc" -Wall -Wextra -Werror -O2 -shared -fPIC \
                    -DDLFREEZE_CHAIN_SYMBOL="$symbol" \
                    -DDLFREEZE_CHAIN_LEAF \
                    -Wl,-soname,"libdlfrz_stack_$i.so" \
                    -o "$library" tests/direct_small_stack_chain_lib.c; then
                fail "$family small-stack dlopen chain" \
                    "leaf fixture compile failed"
                rm -rf "$root"
                return
            fi
        else
            next="dlfrz_chain_$((i + 1))"
            next_library="libdlfrz_stack_$((i + 1)).so"
            if ! "$cc" -Wall -Wextra -Werror -O2 -shared -fPIC \
                    -DDLFREEZE_CHAIN_SYMBOL="$symbol" \
                    -DDLFREEZE_CHAIN_NEXT="$next" \
                    -Wl,-soname,"libdlfrz_stack_$i.so" \
                    -Wl,-rpath,'$ORIGIN' -L"$libdir" \
                    -Wl,--no-as-needed -Wl,-l:"$next_library" \
                    -Wl,--as-needed -o "$library" \
                    tests/direct_small_stack_chain_lib.c; then
                fail "$family small-stack dlopen chain" \
                    "fixture compile failed at depth $i"
                rm -rf "$root"
                return
            fi
        fi
    done
    if ! "$cc" -Wall -Wextra -Werror -O2 -pthread \
            -o "$main" tests/direct_small_stack_chain_main.c -ldl; then
        fail "$family small-stack dlopen chain" \
            "pthread fixture compile failed"
        rm -rf "$root"
        return
    fi
    if ! capture_output probe "$main" || [ "$probe" != small-stack-ready ]; then
        skip "$family small-stack dlopen chain" \
            "compiled runtime cannot execute on this host"
        rm -rf "$root"
        return
    fi
    if ! readelf -d "$top" 2>/dev/null |
            grep 'Shared library: \[libdlfrz_stack_1.so\]' >/dev/null ||
       ! readelf -d "$top" 2>/dev/null |
            grep '\(RUNPATH\).*\$ORIGIN' >/dev/null; then
        fail "$family small-stack dlopen chain" \
            "linker did not retain the chain RUNPATH/DT_NEEDED metadata"
        rm -rf "$root"
        return
    fi

    top_abs=$(realpath "$top")
    capture_output expect env -u LD_LIBRARY_PATH \
        "$main" "$top_abs" "$depth" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [[ "$expect" != "small-stack-chain=$depth stack="* ]]; then
        fail "native $family small-stack dlopen chain" \
            "exit=$rc output=$expect"
        rm -rf "$root"
        return
    fi
    pass "native $family small-stack dlopen chain"

    freeze_rc=0
    freeze_require_direct "$family filesystem small-stack dlopen chain" \
        "$disk_log" "$disk_out" -- "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$family direct filesystem small-stack dlopen chain" \
            "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH \
            "$disk_out" "$top_abs" "$depth" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$family direct filesystem small-stack dlopen chain"
        else
            fail "$family direct filesystem small-stack dlopen chain" \
                "exit=$rc expected=$expect actual=$actual"
        fi
    fi

    freeze_rc=0
    freeze_require_direct "$family embedded small-stack dlopen chain" \
        "$embedded_log" "$embedded_out" -t -- \
        "$main" "$top_abs" "$depth" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$family direct embedded small-stack dlopen chain" \
            "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        mv "$libdir" "$hidden"
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH \
            "$embedded_out" "$top_abs" "$depth" || rc=$?
        mv "$hidden" "$libdir"
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$family direct embedded small-stack dlopen chain"
        else
            fail "$family direct embedded small-stack dlopen chain" \
                "exit=$rc expected=$expect actual=$actual"
        fi
    fi
    rm -rf "$root"
}

test_direct_small_stack_dlopen_chain() {
    echo "--- direct dlopen dependency chain on a small pthread stack ---"
    run_direct_small_stack_chain_runtime GNU "$TEST_REAL_GCC"
    if command -v musl-gcc >/dev/null 2>&1; then
        run_direct_small_stack_chain_runtime musl \
            "$(command -v musl-gcc)"
    else
        skip "musl direct filesystem small-stack dlopen chain" \
            "musl-gcc is unavailable"
        skip "musl direct embedded small-stack dlopen chain" \
            "musl-gcc is unavailable"
    fi
}

# ===================================================================
# Test 9b: filesystem dlopen resolves a transitive dependency via RUNPATH
# ===================================================================
test_direct_dlopen_runpath_origin() {
    echo "--- direct dlopen transitive RUNPATH/ORIGIN ---"
    local root="$BUILD/dlopen_runpath_origin"
    local deps="$root/deps"
    local dep_src="$root/dep.c" dep="$deps/libdlfrz_origin_dep.so"
    local top_src="$root/top.c" top="$root/libdlfrz_origin_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local top_abs expect actual freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$deps"
    cat > "$dep_src" <<'C'
#include <stdio.h>
__attribute__((constructor)) static void dep_ctor(void) {
    puts("origin-dep-ctor");
}
int origin_dep_value(void) { return 41; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_origin_dep.so \
            -o "$dep" "$dep_src"; then
        fail "direct-dlopen RUNPATH/ORIGIN" "dependency compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$top_src" <<'C'
#include <stdio.h>
extern int origin_dep_value(void);
__attribute__((constructor)) static void top_ctor(void) {
    printf("origin-top-ctor=%d\n", origin_dep_value());
}
int origin_top_value(void) { return origin_dep_value() + 1; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_origin_top.so \
            -Wl,-rpath,'$ORIGIN/deps' -o "$top" "$top_src" \
            -L"$deps" -ldlfrz_origin_dep; then
        fail "direct-dlopen RUNPATH/ORIGIN" "requester compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf -d "$top" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/deps' >/dev/null; then
        skip "direct-dlopen RUNPATH/ORIGIN" \
            "linker did not emit the requested DT_RUNPATH"
        rm -rf "$root"
        return
    fi

    top_abs=$(realpath "$top")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    puts("origin-main-before");
    void *h = dlopen("$top_abs", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*value)(void) = (int (*)(void))dlsym(h, "origin_top_value");
    if (!value) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
    printf("origin-result=%d\n", value());
    return 0;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen RUNPATH/ORIGIN" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect env -u LD_LIBRARY_PATH "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "direct-dlopen RUNPATH/ORIGIN" \
            "native fixture failed (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen RUNPATH/ORIGIN" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen RUNPATH/ORIGIN" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ] &&
       [[ "$actual" == *"origin-dep-ctor"* ]] &&
       [[ "$actual" == *"origin-top-ctor=41"* ]] &&
       [[ "$actual" == *"origin-result=42"* ]]; then
        pass "direct-dlopen transitive RUNPATH/ORIGIN"
    else
        fail "direct-dlopen RUNPATH/ORIGIN" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# GNU late loading walks the requester's l_loader RPATH ancestry, but an
# immediate DT_RUNPATH suppresses that complete chain.  Compare both cases
# with the native loader using closures which are intentionally not traced or
# embedded.
test_gnu_direct_runtime_search_ancestry() {
    echo "--- GNU direct runtime loader ancestry ---"
    local root="$BUILD/gnu_runtime_ancestry"
    local child_dir="$root/child" plugin_dir="$root/plugin"
    local wrong_dir="$root/wrong" right_dir="$root/right"
    local stage_dir="$root/stage"
    local loop_dir="$root/open-error-loop"
    local main_src="$root/main.c" main="$root/main"
    local plugin_src="$root/plugin.c" plugin="$plugin_dir/libancestry_plugin.so"
    local inherit_child_src="$root/inherit-child.c"
    local inherit_child="$child_dir/libancestry_inherit_child.so"
    local inherit_root_src="$root/inherit-root.c"
    local inherit_root="$root/libancestry_inherit_root.so"
    local choice_src="$root/choice.c"
    local wrong_choice="$wrong_dir/libancestry_choice.so"
    local right_choice="$right_dir/libancestry_choice.so"
    local run_child_src="$root/run-child.c"
    local run_child="$child_dir/libancestry_run_child.so"
    local run_root_src="$root/run-root.c"
    local run_root="$root/libancestry_run_root.so"
    local overlong_src="$root/overlong.c"
    local open_start_src="$root/open-start.c"
    local open_absolute_src="$root/open-absolute-start.c"
    local overlong_name=libancestry_overlong.so
    local overlong_lib="$right_dir/$overlong_name"
    local stage_lib="$stage_dir/$overlong_name"
    local prime_name=libancestry_prime.so
    local prime_lib="$loop_dir/$prime_name"
    local open_start="$root/open-start" dep_gate="$root/dep-gate"
    local open_stage_start="$root/open-stage-start"
    local open_absolute_start="$root/open-absolute-start"
    local resolver_log="$root/resolver.log"
    local out="$root/main.frozen" log="$root/main.log"
    local inherit_expect="" run_expect=""
    local open_error_expect="" actual=""
    local path_max overlong_component absolute_overlong_component
    local rc=0 freeze_rc=0 libc_banner

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$libc_banner"; then
        skip "GNU direct inherited RPATH ancestry" \
            "target runtime is not glibc"
        skip "GNU direct RUNPATH suppresses inherited RPATH" \
            "target runtime is not glibc"
        return
    fi

    rm -rf "$root"
    mkdir -p "$child_dir" "$plugin_dir" "$wrong_dir" "$right_dir" \
        "$stage_dir" "$loop_dir"
    path_max=$(getconf PATH_MAX "$root" 2>/dev/null || true)
    if [[ ! "$path_max" =~ ^[0-9]+$ ]] || [ "$path_max" -le 0 ]; then
        skip "GNU direct runtime loader ancestry" \
            "cannot determine target filesystem PATH_MAX"
        rm -rf "$root"
        return
    fi
    printf -v overlong_component '%*s' "$path_max" ''
    overlong_component=${overlong_component// /x}
    absolute_overlong_component="/$overlong_component"
    cat > "$main_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
typedef int (*value_fn)(void);
int main(int argc, char **argv) {
    const char *request;
    if (argc != 2 && argc != 3)
        return 2;
    if (argc == 3) {
        void *prime = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (!prime) {
            fprintf(stderr, "prime dlopen: %s\n", dlerror());
            return 5;
        }
        request = argv[2];
    } else {
        request = argv[1];
    }
    void *handle = dlopen(request, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    value_fn value = (value_fn)dlsym(handle, "ancestry_root_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    cat > "$open_absolute_src" <<'C'
#include <stdio.h>
int ancestry_root_value(void);
int main(void) { printf("%d\n", ancestry_root_value()); return 0; }
C
    cat > "$plugin_src" <<'C'
int ancestry_plugin_value(void) { return 61; }
C
    cat > "$inherit_child_src" <<'C'
#include <dlfcn.h>
typedef int (*value_fn)(void);
int ancestry_inherit_child_value(void) {
    void *handle = dlopen("libancestry_plugin.so", RTLD_NOW | RTLD_LOCAL);
    value_fn value = handle
        ? (value_fn)dlsym(handle, "ancestry_plugin_value") : 0;
    return value ? value() : -1;
}
C
    cat > "$inherit_root_src" <<'C'
extern int ancestry_inherit_child_value(void);
int ancestry_root_value(void) { return ancestry_inherit_child_value(); }
C
    cat > "$choice_src" <<'C'
#ifndef CHOICE_VALUE
#define CHOICE_VALUE 0
#endif
int ancestry_choice_value(void) { return CHOICE_VALUE; }
C
    cat > "$run_child_src" <<'C'
extern int ancestry_choice_value(void);
int ancestry_run_child_value(void) { return ancestry_choice_value(); }
C
    cat > "$run_root_src" <<'C'
extern int ancestry_run_child_value(void);
int ancestry_root_value(void) { return ancestry_run_child_value(); }
C
    cat > "$overlong_src" <<'C'
#ifndef ANCESTRY_VALUE
#define ANCESTRY_VALUE 0
#endif
int ancestry_root_value(void) { return ANCESTRY_VALUE; }
C
    cat > "$open_start_src" <<'C'
#include <stdio.h>
int ancestry_root_value(void);
int ancestry_prime_value(void);
int main(void) {
    printf("%d:%d\n", ancestry_prime_value(), ancestry_root_value());
    return 0;
}
C

    if ! gcc -Wl,--enable-new-dtags -Wl,-rpath,"$stage_dir" \
            -o "$main" "$main_src" -ldl ||
       ! gcc -shared -fPIC -Wl,-soname,libancestry_plugin.so \
            -o "$plugin" "$plugin_src" ||
       ! gcc -shared -fPIC -Wl,-soname,libancestry_inherit_child.so \
            -o "$inherit_child" "$inherit_child_src" -ldl ||
       ! gcc -shared -fPIC -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/child:$ORIGIN/plugin' \
            -Wl,-rpath-link,"$child_dir" \
            -Wl,-soname,libancestry_inherit_root.so \
            -L"$child_dir" -o "$inherit_root" "$inherit_root_src" \
            -Wl,--no-as-needed -lancestry_inherit_child ||
       ! gcc -shared -fPIC -DCHOICE_VALUE=41 \
            -Wl,-soname,libancestry_choice.so \
            -o "$wrong_choice" "$choice_src" ||
       ! gcc -shared -fPIC -DCHOICE_VALUE=72 \
            -Wl,-soname,libancestry_choice.so \
            -o "$right_choice" "$choice_src" ||
       ! gcc -shared -fPIC -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../right' \
            -Wl,-soname,libancestry_run_child.so \
            -L"$right_dir" -o "$run_child" "$run_child_src" \
            -Wl,--no-as-needed -lancestry_choice ||
       ! gcc -shared -fPIC -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/child:$ORIGIN/wrong' \
            -Wl,-rpath-link,"$child_dir:$right_dir" \
            -Wl,-soname,libancestry_run_root.so \
            -L"$child_dir" -o "$run_root" "$run_root_src" \
            -Wl,--no-as-needed -lancestry_run_child ||
       ! gcc -shared -fPIC -DANCESTRY_VALUE=83 \
            -Wl,-soname,"$overlong_name" \
            -o "$overlong_lib" "$overlong_src" ||
       ! gcc -shared -fPIC -DANCESTRY_VALUE=84 \
            -Wl,-soname,"$overlong_name" \
            -o "$stage_lib" "$overlong_src" ||
       ! gcc -shared -fPIC -DANCESTRY_VALUE=7 \
            -Wl,-soname,"$prime_name" \
            -Dancestry_root_value=ancestry_prime_value \
            -o "$prime_lib" "$overlong_src" ||
       ! ln -s "$overlong_name" \
            "$loop_dir/$overlong_name" ||
       ! gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,"$loop_dir:$right_dir" \
            -L"$loop_dir" -L"$right_dir" \
            -o "$open_start" "$open_start_src" \
            -Wl,--no-as-needed -Wl,-l:"$prime_name" \
            -Wl,-l:"$overlong_name" ||
       ! gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,"$stage_dir" \
            -L"$loop_dir" -L"$stage_dir" \
            -o "$open_stage_start" "$open_start_src" \
            -Wl,--no-as-needed -Wl,-l:"$prime_name" \
            -Wl,-l:"$overlong_name" ||
       ! gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,"$stage_dir" -L"$stage_dir" \
            -o "$open_absolute_start" "$open_absolute_src" \
            -Wl,--no-as-needed -Wl,-l:"$overlong_name" ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$dep_gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "GNU direct runtime loader ancestry" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf -d "$inherit_root" 2>/dev/null |
            grep -E '\(RPATH\).*\$ORIGIN/child.*\$ORIGIN/plugin' \
                >/dev/null ||
       ! readelf -d "$run_child" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/../right' >/dev/null; then
        skip "GNU direct runtime loader ancestry" \
            "linker did not preserve RPATH/RUNPATH fixture metadata"
        rm -rf "$root"
        return
    fi

    capture_output inherit_expect env -u LD_LIBRARY_PATH \
        "$main" "$inherit_root" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$inherit_expect" != 61 ]; then
        fail "native GNU inherited RPATH control" \
            "exit=$rc output=$inherit_expect"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output run_expect env -u LD_LIBRARY_PATH \
        "$main" "$run_root" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$run_expect" != 72 ]; then
        fail "native GNU RUNPATH suppression control" \
            "exit=$rc output=$run_expect"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output open_error_expect env \
        LD_LIBRARY_PATH="$loop_dir:$right_dir" \
        "$main" "$prime_name" "$overlong_name" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$open_error_expect" != 84 ]; then
        fail "native GNU search open-error stage control" \
            "exit=$rc output=$open_error_expect"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$open_start" || rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "native GNU same-list open-error stop control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    elif env -u LD_LIBRARY_PATH "$dep_gate" "$open_start" \
            >"$resolver_log" 2>&1 ||
         grep -Fq "$right_dir/$overlong_name" "$resolver_log"; then
        fail "GNU pack same-list open-error stop" \
            "resolver searched past ELOOP in one RUNPATH list"
        rm -rf "$root"
        return
    else
        pass "GNU pack stops only the current path list on ELOOP"
    fi
    rc=0
    capture_output actual env LD_LIBRARY_PATH="$loop_dir:$right_dir" \
        "$open_stage_start" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 7:84 ]; then
        fail "native GNU environment-to-RUNPATH stage control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    elif ! env LD_LIBRARY_PATH="$loop_dir:$right_dir" \
            "$dep_gate" "$open_stage_start" >"$resolver_log" 2>&1 ||
         ! grep -Fq "$stage_dir/$overlong_name" "$resolver_log" ||
         grep -Fq "$right_dir/$overlong_name" "$resolver_log"; then
        fail "GNU pack environment-to-RUNPATH stage" \
            "resolver did not stop env and continue with RUNPATH"
        rm -rf "$root"
        return
    else
        pass "GNU pack continues with RUNPATH after env ELOOP"
    fi
    rc=0
    capture_output actual env \
        LD_LIBRARY_PATH="$absolute_overlong_component:$right_dir" \
        "$open_absolute_start" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 83 ]; then
        fail "native GNU absolute-overlong directory control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    elif ! env \
            LD_LIBRARY_PATH="$absolute_overlong_component:$right_dir" \
            "$dep_gate" "$open_absolute_start" >"$resolver_log" 2>&1 ||
         ! grep -Fq "$right_dir/$overlong_name" "$resolver_log"; then
        fail "GNU pack absolute-overlong directory" \
            "resolver did not continue within the environment list"
        rm -rf "$root"
        return
    else
        pass "GNU pack skips nonexisting absolute-overlong directory"
    fi

    freeze_require_direct "GNU direct runtime loader ancestry" "$log" \
        "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "GNU direct inherited RPATH ancestry" "$DIRECT_FREEZE_REASON"
        skip "GNU direct RUNPATH suppresses inherited RPATH" \
            "$DIRECT_FREEZE_REASON"
        skip "GNU direct overlong search component continues" \
            "$DIRECT_FREEZE_REASON"
        skip "GNU direct search open error continues" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rc=0
    capture_output actual env -u LD_LIBRARY_PATH \
        "$out" "$inherit_root" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$inherit_expect" ]; then
        pass "GNU direct dlopen inherits loader RPATH ancestry"
    else
        fail "GNU direct inherited RPATH ancestry" \
            "exit=$rc expected=$inherit_expect actual=$actual"
    fi

    rc=0
    actual=""
    capture_output actual env -u LD_LIBRARY_PATH \
        "$out" "$run_root" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$run_expect" ]; then
        pass "GNU direct RUNPATH suppresses inherited RPATH chain"
    else
        fail "GNU direct RUNPATH suppression" \
            "exit=$rc expected=$run_expect actual=$actual"
    fi

    rc=0
    actual=""
    capture_output actual env \
        LD_LIBRARY_PATH="$overlong_component:$right_dir" \
        "$out" "$overlong_name" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = 84 ]; then
        pass "GNU direct overlong component advances search stage"
    else
        fail "GNU direct overlong search component" \
            "exit=$rc expected=84 actual=$actual"
    fi

    rc=0
    actual=""
    capture_output actual env LD_LIBRARY_PATH="$loop_dir:$right_dir" \
        "$out" "$prime_name" "$overlong_name" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$open_error_expect" ]; then
        pass "GNU direct ELOOP advances from environment to RUNPATH"
    else
        fail "GNU direct search open-error continuation" \
            "exit=$rc expected=$open_error_expect actual=$actual"
    fi

    rc=0
    actual=""
    capture_output actual env \
        LD_LIBRARY_PATH="$absolute_overlong_component:$right_dir" \
        "$out" "$overlong_name" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = 83 ]; then
        pass "GNU direct skips nonexisting absolute-overlong directory"
    else
        fail "GNU direct absolute-overlong directory" \
            "exit=$rc expected=83 actual=$actual"
    fi
    rm -rf "$root"
}

test_gnu_runtime_dynamic_token_gate() {
    echo "--- GNU direct runtime dynamic-token grammar gate ---"
    local gate="$BUILD/gnu_runtime_token_gate"

    if gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -ffunction-sections -fdata-sections -fno-stack-protector \
            -Wl,--gc-sections -o "$gate" \
            tests/gnu_runtime_token_gate.c -ldl -pthread &&
       "$gate"; then
        pass "GNU direct runtime dynamic-token grammar"
    else
        fail "GNU direct runtime dynamic-token grammar" \
            "compile failed or token policy was misclassified"
    fi
    rm -f "$gate"
}

# Exercise dynamic-token policy in a real late dlopen.  The first directory
# contains the requested DSO: a direct success would therefore prove that
# lookup returned early without preflighting the complete GNU path list.
# On AArch64, also compare exact runtime expansion of kernel AT_PLATFORM.
test_gnu_direct_runtime_dynamic_tokens() {
    echo "--- GNU direct runtime dynamic-string token policy ---"
    local root="$BUILD/gnu_runtime_tokens"
    local good="$root/good" platform_dir
    local name=libdlfreeze_runtime_token.so
    local lib_src="$root/library.c" main_src="$root/main.c"
    local probe_src="$root/platform.c" probe="$root/platform"
    local main="$root/main" out="$root/main.frozen" log="$root/freeze.log"
    local banner arch platform="" expected="" actual=""
    local rc=0 freeze_rc=0

    banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$banner"; then
        skip "GNU direct runtime dynamic-string tokens" \
            "target runtime is not glibc"
        return
    fi
    arch=$(uname -m)
    if [ "$arch" != x86_64 ] && [ "$arch" != aarch64 ]; then
        skip "GNU direct runtime dynamic-string tokens" \
            "target architecture is unsupported"
        return
    fi

    rm -rf "$root"
    mkdir -p "$good"
    cat >"$lib_src" <<'C'
int dlfreeze_runtime_token_value(void) { return 67; }
C
    cat >"$main_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
typedef int (*value_fn)(void);
int main(void) {
    void *handle;
    value_fn value;
    if (!getenv("DLFREEZE_TEST_RUNTIME_TOKENS")) {
        puts("trace-skip");
        return 0;
    }
    handle = dlopen("libdlfreeze_runtime_token.so",
                    RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    value = (value_fn)dlsym(handle, "dlfreeze_runtime_token_value");
    if (!value) return 3;
    printf("%d\n", value());
    return 0;
}
C
    cat >"$probe_src" <<'C'
#include <stdio.h>
#include <sys/auxv.h>
int main(void) {
    const char *platform = (const char *)getauxval(AT_PLATFORM);
    if (!platform || !platform[0]) return 1;
    return puts(platform) < 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,"$name" \
            -o "$good/$name" "$lib_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$main" "$main_src" -ldl ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$probe" "$probe_src"; then
        fail "GNU direct runtime dynamic-token fixtures" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    rc=0
    capture_output expected env DLFREEZE_TEST_RUNTIME_TOKENS=1 \
        LD_LIBRARY_PATH="$good:\$LIB" "$main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expected" != 67 ]; then
        fail "native GNU full-list dynamic-token control" \
            "exit=$rc output=$expected"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "GNU direct runtime dynamic-string tokens" \
        "$log" "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "GNU direct runtime dynamic-string tokens" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    elif [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rc=0
    capture_output actual env DLFREEZE_TEST_RUNTIME_TOKENS=1 \
        LD_LIBRARY_PATH="$good:\$LIB" "$out" || rc=$?
    if [ "$rc" -ne 0 ] &&
       grep -Fq 'unsupported dynamic string token' <<<"$actual"; then
        pass "GNU direct preflights complete dynamic-token path list"
    else
        fail "GNU direct full-list dynamic-token admission" \
            "exit=$rc output=$actual"
    fi

    if [ "$arch" = x86_64 ]; then
        rc=0
        actual=""
        capture_output actual env DLFREEZE_TEST_RUNTIME_TOKENS=1 \
            LD_LIBRARY_PATH="$good:\$PLATFORM" "$out" || rc=$?
        if [ "$rc" -ne 0 ] &&
           grep -Fq 'unsupported dynamic string token' <<<"$actual"; then
            pass "GNU direct x86 PLATFORM policy fails closed"
        else
            fail "GNU direct x86 PLATFORM admission" \
                "exit=$rc output=$actual"
        fi
    else
        rc=0
        capture_output platform "$probe" || rc=$?
        platform_dir="$root/$platform"
        if [ "$rc" -ne 0 ] || [ -z "$platform" ] ||
           [[ "$platform" == */* ]] ||
           ! mkdir -p "$platform_dir" ||
           ! cp "$good/$name" "$platform_dir/$name"; then
            fail "GNU direct AArch64 PLATFORM fixtures" \
                "cannot obtain bounded kernel platform"
        else
            rc=0
            capture_output expected env DLFREEZE_TEST_RUNTIME_TOKENS=1 \
                LD_LIBRARY_PATH="$root/\$PLATFORM" "$main" || rc=$?
            actual=""
            if [ "$rc" -eq 0 ]; then
                capture_output actual env \
                    DLFREEZE_TEST_RUNTIME_TOKENS=1 \
                    LD_LIBRARY_PATH="$root/\$PLATFORM" "$out" || rc=$?
                actual=$(printf '%s\n' "$actual" |
                    strip_dlfreeze_warnings)
            fi
            if [ "$rc" -eq 0 ] && [ "$expected" = 67 ] &&
               [ "$actual" = "$expected" ]; then
                pass "GNU direct AArch64 PLATFORM uses kernel identity"
            else
                fail "GNU direct AArch64 PLATFORM expansion" \
                    "exit=$rc expected=$expected actual=$actual"
            fi
        fi
    fi
    rm -rf "$root"
}

# glibc prepends active built-in glibc-hwcaps subdirectories to every
# ordinary search-path component, independently of ld.so.cache selection.
# Keep this a late filesystem load so the traced manifest cannot hide the
# runtime path-list ordering under test.
test_gnu_direct_runtime_hwcaps_paths() {
    echo "--- GNU direct runtime glibc-hwcaps path ordering ---"
    local root="$BUILD/gnu_runtime_hwcaps"
    local base="$root/search"
    local v2="$base/glibc-hwcaps/x86-64-v2"
    local v3="$base/glibc-hwcaps/x86-64-v3"
    local v4="$base/glibc-hwcaps/x86-64-v4"
    local name=libdlfreeze_runtime_hwcaps.so
    local lib_src="$root/library.c" main_src="$root/main.c"
    local main="$root/main" out="$root/main.frozen" log="$root/freeze.log"
    local expected="" fallback_expected="" actual="" selected=""
    local rc=0 freeze_rc=0 libc_banner

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$libc_banner"; then
        skip "GNU direct runtime glibc-hwcaps paths" \
            "target runtime is not glibc"
        return
    fi

    rm -rf "$root"
    mkdir -p "$base" "$v2" "$v3" "$v4"
    cat >"$lib_src" <<'C'
#ifndef HWCAPS_VALUE
#define HWCAPS_VALUE 0
#endif
int dlfreeze_runtime_hwcaps_value(void) { return HWCAPS_VALUE; }
C
    cat >"$main_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef int (*value_fn)(void);
int main(void) {
    Dl_info info;
    value_fn value;
    void *handle;
    if (!getenv("DLFREEZE_TEST_RUNTIME_HWCAPS")) {
        puts("trace-skip");
        return 0;
    }
    handle = dlopen("libdlfreeze_runtime_hwcaps.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    value = (value_fn)dlsym(handle, "dlfreeze_runtime_hwcaps_value");
    if (!value || !dladdr((void *)(uintptr_t)value, &info) || !info.dli_fname)
        return 3;
    printf("%d:%s\n", value(), info.dli_fname);
    return 0;
}
C
    if ! gcc -shared -fPIC -DHWCAPS_VALUE=11 -Wl,-soname,"$name" \
            -o "$base/$name" "$lib_src" ||
       ! gcc -shared -fPIC -DHWCAPS_VALUE=22 -Wl,-soname,"$name" \
            -o "$v2/$name" "$lib_src" ||
       ! gcc -shared -fPIC -DHWCAPS_VALUE=33 -Wl,-soname,"$name" \
            -o "$v3/$name" "$lib_src" ||
       ! gcc -shared -fPIC -DHWCAPS_VALUE=44 -Wl,-soname,"$name" \
            -o "$v4/$name" "$lib_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -o "$main" "$main_src" -ldl; then
        fail "GNU direct runtime glibc-hwcaps paths" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output expected env DLFREEZE_TEST_RUNTIME_HWCAPS=1 \
        LD_LIBRARY_PATH="$base" "$main" || rc=$?
    if [ "$rc" -ne 0 ] ||
       [[ ! "$expected" =~ ^(11|22|33|44): ]]; then
        fail "native GNU runtime glibc-hwcaps path control" \
            "exit=$rc output=$expected"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "GNU direct runtime glibc-hwcaps paths" \
        "$log" "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "GNU direct runtime glibc-hwcaps paths" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    elif [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rc=0
    capture_output actual env DLFREEZE_TEST_RUNTIME_HWCAPS=1 \
        LD_LIBRARY_PATH="$base" "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expected" ]; then
        pass "GNU direct runtime glibc-hwcaps path ordering"
    else
        fail "GNU direct runtime glibc-hwcaps path ordering" \
            "exit=$rc expected=$expected actual=$actual"
    fi

    case "$expected" in
        44:*) selected="$v4/$name" ;;
        33:*) selected="$v3/$name" ;;
        22:*) selected="$v2/$name" ;;
    esac
    if [ -n "$selected" ]; then
        mv "$selected" "$selected.disabled"
        rc=0
        capture_output fallback_expected env \
            DLFREEZE_TEST_RUNTIME_HWCAPS=1 LD_LIBRARY_PATH="$base" \
            "$main" || rc=$?
        if [ "$rc" -ne 0 ] ||
           [[ ! "$fallback_expected" =~ ^(11|22|33): ]]; then
            fail "native GNU runtime glibc-hwcaps fallback control" \
                "exit=$rc output=$fallback_expected"
        else
            rc=0
            actual=""
            capture_output actual env DLFREEZE_TEST_RUNTIME_HWCAPS=1 \
                LD_LIBRARY_PATH="$base" "$out" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] && [ "$actual" = "$fallback_expected" ]; then
                pass "GNU direct runtime glibc-hwcaps lower-level fallback"
            else
                fail "GNU direct runtime glibc-hwcaps lower-level fallback" \
                    "exit=$rc expected=$fallback_expected actual=$actual"
            fi
        fi
    fi

    rm -f "$v2/$name" "$v3/$name" "$v4/$name"
    rc=0
    capture_output fallback_expected env DLFREEZE_TEST_RUNTIME_HWCAPS=1 \
        LD_LIBRARY_PATH="$base" "$main" || rc=$?
    actual=""
    if [ "$rc" -eq 0 ] && [[ "$fallback_expected" == 11:* ]]; then
        capture_output actual env DLFREEZE_TEST_RUNTIME_HWCAPS=1 \
            LD_LIBRARY_PATH="$base" "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    fi
    if [ "$rc" -eq 0 ] && [ "$actual" = "$fallback_expected" ]; then
        pass "GNU direct runtime glibc-hwcaps base fallback"
    else
        fail "GNU direct runtime glibc-hwcaps base fallback" \
            "exit=$rc expected=$fallback_expected actual=$actual"
    fi
    rm -rf "$root"
}

# Identity de-duplication is by device/inode, not pathname.  A second
# top-level dlopen through a hardlink must select the already-loaded object's
# scope as a valid no-new-mapping transaction root.
test_direct_dlopen_inode_alias() {
    echo "--- direct dlopen inode alias ---"
    local root="$BUILD/dlopen_inode_alias"
    local lib_src="$root/library.c" main_src="$root/main.c"
    local original="$root/libdlfrz_inode_original.so"
    local alias="$root/libdlfrz_inode_alias.so"
    local main="$root/main" out="$root/main.frozen" log="$root/freeze.log"
    local expect="" actual="" rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat >"$lib_src" <<'C'
int dlfreeze_inode_value(void) { return 91; }
C
    cat >"$main_src" <<C
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int (*value)(void);
    void *first;
    void *second;

    if (!getenv("DLFREEZE_TEST_INODE_ALIAS")) {
        puts("trace-skip");
        return 0;
    }
    first = dlopen("$original", RTLD_NOW | RTLD_LOCAL);
    if (!first) return 2;
    second = dlopen("$alias", RTLD_NOW | RTLD_LOCAL);
    if (!second) return 3;
    value = (int (*)(void))dlsym(second, "dlfreeze_inode_value");
    if (!value) return 4;
    printf("same=%d value=%d\n", first == second, value());
    return 0;
}
C

    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_inode_original.so \
            -o "$original" "$lib_src" ||
       ! ln "$original" "$alias" ||
       ! gcc -o "$main" "$main_src" -ldl; then
        fail "direct dlopen inode alias" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output expect env DLFREEZE_TEST_INODE_ALIAS=1 "$main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect" != "same=1 value=91" ]; then
        fail "native dlopen inode alias control" \
            "exit=$rc output=$expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct dlopen inode alias" "$log" "$out" \
        "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dlopen inode alias" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rc=0
    capture_output actual env DLFREEZE_TEST_INODE_ALIAS=1 "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct dlopen reuses inode-alias scope"
    else
        fail "direct dlopen inode alias" \
            "exit=$rc expected=$expect output=$actual"
    fi
    rm -rf "$root"
}

# Loaded-name identity is state created by an actual bare search, not by the
# basename of an earlier pathful load.  Exercise both target families, GNU's
# alias retention after an inode-deduplicated search, musl's native singular
# shortname behavior, and pathful inode reuse.
test_direct_dlopen_loaded_name_identity() {
    echo "--- direct dlopen loaded-name identity ---"
    local family compiler root lib_src main_src main out log
    local first_dir search_dir link_dir inode_dir
    local common_name=libdlfrz_loaded_name.so
    local common_link=libdlfrz_loaded_name_link.so
    local inode_original=libdlfrz_inode_name_original.so
    local inode_bare=libdlfrz_inode_name_bare.so
    local inode_same=libdlfrz_inode_name_same.so
    local expect actual rc freeze_rc

    for family in gnu musl; do
        if [ "$family" = gnu ]; then
            compiler=gcc
        elif command -v musl-gcc >/dev/null 2>&1; then
            compiler=musl-gcc
        else
            skip "musl direct loaded-name identity" \
                "musl-gcc not installed"
            continue
        fi
        root="$BUILD/dlopen_loaded_name_$family"
        lib_src="$root/library.c"
        main_src="$root/main.c"
        main="$root/main"
        out="$root/main.frozen"
        log="$root/freeze.log"
        first_dir="$root/first"
        search_dir="$root/search"
        link_dir="$root/link"
        inode_dir="$root/inode"
        rm -rf "$root"
        mkdir -p "$first_dir" "$search_dir" "$link_dir" "$inode_dir"

        cat >"$lib_src" <<'C'
#ifndef LOADED_NAME_VALUE
#define LOADED_NAME_VALUE 0
#endif
int dlfreeze_loaded_name_value(void) { return LOADED_NAME_VALUE; }
C
        cat >"$main_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*value_fn)(void);

static int value(void *handle) {
    value_fn fn = handle
        ? (value_fn)dlsym(handle, "dlfreeze_loaded_name_value") : 0;
    return fn ? fn() : -1;
}

int main(int argc, char **argv) {
    void *pathful_first;
    void *bare_other;
    void *pathful_same;
    void *inode_first;
    void *inode_bare_first;
    void *inode_bare_repeat;
    void *same_first;
    void *same_bare_first;
    void *same_bare_repeat;

    if (!getenv("DLFREEZE_TEST_LOADED_NAME")) {
        puts("trace-skip");
        return 0;
    }
    if (argc != 7) return 10;
    pathful_first = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    bare_other = dlopen("libdlfrz_loaded_name.so", RTLD_NOW | RTLD_LOCAL);
    pathful_same = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    inode_first = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    inode_bare_first = dlopen(
        "libdlfrz_inode_name_bare.so", RTLD_NOW | RTLD_LOCAL);
    if (unlink(argv[4]) != 0) return 11;
    inode_bare_repeat = dlopen(
        "libdlfrz_inode_name_bare.so", RTLD_NOW | RTLD_LOCAL);
    same_first = dlopen(argv[5], RTLD_NOW | RTLD_LOCAL);
    same_bare_first = dlopen(
        "libdlfrz_inode_name_same.so", RTLD_NOW | RTLD_LOCAL);
    if (unlink(argv[6]) != 0) return 12;
    same_bare_repeat = dlopen(
        "libdlfrz_inode_name_same.so", RTLD_NOW | RTLD_LOCAL);
    printf("values=%d,%d distinct=%d pathful-same=%d "
           "inode-first=%d inode-repeat=%d "
           "samebase-first=%d samebase-repeat=%d\n",
           value(pathful_first), value(bare_other),
           pathful_first != bare_other,
           bare_other == pathful_same,
           inode_first == inode_bare_first,
           inode_bare_first == inode_bare_repeat,
           same_first == same_bare_first,
           same_bare_first == same_bare_repeat);
    return 0;
}
C
        if ! "$compiler" -shared -fPIC -DLOADED_NAME_VALUE=11 \
                -o "$first_dir/$common_name" "$lib_src" ||
           ! "$compiler" -shared -fPIC -DLOADED_NAME_VALUE=22 \
                -o "$search_dir/$common_name" "$lib_src" ||
           ! ln "$search_dir/$common_name" \
                "$link_dir/$common_link" ||
           ! "$compiler" -shared -fPIC -DLOADED_NAME_VALUE=33 \
                -o "$inode_dir/$inode_original" "$lib_src" ||
           ! ln "$inode_dir/$inode_original" \
                "$search_dir/$inode_bare" ||
           ! "$compiler" -shared -fPIC -DLOADED_NAME_VALUE=44 \
                -o "$inode_dir/$inode_same" "$lib_src" ||
           ! ln "$inode_dir/$inode_same" \
                "$search_dir/$inode_same" ||
           ! "$compiler" -Wall -Wextra -Werror -o "$main" \
                "$main_src" -ldl; then
            fail "$family direct loaded-name identity" \
                "fixture compile failed"
            rm -rf "$root"
            continue
        fi

        rc=0
        capture_output expect env \
            LD_LIBRARY_PATH="$search_dir" \
            DLFREEZE_TEST_LOADED_NAME=1 "$main" \
            "$first_dir/$common_name" "$link_dir/$common_link" \
            "$inode_dir/$inode_original" \
            "$search_dir/$inode_bare" "$inode_dir/$inode_same" \
            "$search_dir/$inode_same" || rc=$?
        if [ "$rc" -ne 0 ] ||
           [[ "$expect" != values=11,22\ distinct=1\ pathful-same=1\ inode-first=1\ inode-repeat=*\ samebase-first=1\ samebase-repeat=1 ]]; then
            fail "native $family loaded-name identity control" \
                "exit=$rc output=$expect"
            rm -rf "$root"
            continue
        fi
        # Restore the unlinked hardlink before running the direct artifact.
        ln "$inode_dir/$inode_original" "$search_dir/$inode_bare"
        ln "$inode_dir/$inode_same" "$search_dir/$inode_same"

        freeze_rc=0
        freeze_require_direct "$family direct loaded-name identity" \
            "$log" "$out" "$main" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$family direct loaded-name identity" \
                "$DIRECT_FREEZE_REASON"
            rm -rf "$root"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -rf "$root"
            continue
        fi

        rc=0
        capture_output actual env \
            LD_LIBRARY_PATH="$search_dir" \
            DLFREEZE_TEST_LOADED_NAME=1 "$out" \
            "$first_dir/$common_name" "$link_dir/$common_link" \
            "$inode_dir/$inode_original" \
            "$search_dir/$inode_bare" "$inode_dir/$inode_same" \
            "$search_dir/$inode_same" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$family direct preserves native loaded-name identity"
        else
            fail "$family direct loaded-name identity" \
                "exit=$rc expected=$expect output=$actual"
        fi
        rm -rf "$root"
    done
}

# musl's runtime filesystem search is a different contract from GNU ld.so:
# raw LD_LIBRARY_PATH comes first, RUNPATH and RPATH form one inherited chain,
# and a prefix-relative ld-musl-<arch>.path replaces the built-in defaults.
test_musl_direct_runtime_search_semantics() {
    echo "--- musl direct runtime filesystem search semantics ---"
    local build_abs root
    build_abs=$(realpath "$BUILD")
    root="$build_abs/musl_runtime_search"
    local bin_dir="$root/bin" rpath_dir="$root/rpath" env_dir="$root/env"
    local literal_dir="$root/\$ORIGIN/raw" expanded_dir="$bin_dir/raw"
    local origin_prefix_dir="${bin_dir}suffix"
    local first_dir="$root/first-open/first"
    local second_dir="$root/first-open/second"
    local chain_mid="$root/chain/mid" chain_private="$root/chain/private"
    local token_root="$root/unknown-token"
    local token_child_dir="$token_root/child"
    local token_right_dir="$token_root/right"
    local token_wrong_dir="$token_root/wrong"
    local choice_src="$root/choice.c" main_src="$root/main.c"
    local boundary_start_src="$root/boundary-start.c"
    local leaf_src="$root/leaf.c" middle_src="$root/middle.c"
    local top_src="$root/top.c" main="$bin_dir/main"
    local choice_name=libdlfrz_musl_runtime_choice.so
    local raw_name=libdlfrz_musl_runtime_raw.so
    local first_name=libdlfrz_musl_runtime_first_open.so
    local boundary_name=libdlfrz_musl_search_boundary.so
    local origin_prefix_name=libdlfrz_musl_origin_prefix.so
    local leaf_name=libdlfrz_musl_runtime_leaf.so
    local middle_name=libdlfrz_musl_runtime_middle.so
    local top_name=libdlfrz_musl_runtime_top.so
    local token_leaf_name=libdlfrz_musl_token_leaf.so
    local token_child_name=libdlfrz_musl_token_child.so
    local token_top_name=libdlfrz_musl_token_top.so
    local top="$root/chain/$top_name"
    local token_top="$token_root/$token_top_name"
    local token_start="$token_root/start"
    local boundary_start="$bin_dir/boundary-start"
    local boundary_gate="$root/dep-resolver-gate"
    local boundary_resolver_log="$root/boundary-resolver.log"
    local out="$root/main.frozen" log="$root/freeze.log"
    local boundary_accept_rel="" boundary_reject_rel=""
    local boundary_accept_dir boundary_reject_dir
    local name_max search_buffer accept_dir_length reject_dir_length
    local accept_rel_length reject_rel_length component remaining take
    local expect_order expect_raw expect_chain expect_token expect_boundary
    local expect_pathful_boundary expect_origin_prefix actual
    local rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$bin_dir" "$rpath_dir" "$env_dir" "$literal_dir" \
        "$expanded_dir" "$origin_prefix_dir" "$first_dir" "$second_dir" \
        "$chain_mid" "$chain_private" "$token_child_dir" \
        "$token_right_dir" "$token_wrong_dir"
    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl direct runtime search semantics" "musl-gcc not installed"
        rm -rf "$root"
        return
    fi

    name_max=$(getconf NAME_MAX "$root" 2>/dev/null || true)
    if [[ ! "$name_max" =~ ^[0-9]+$ ]] || [ "$name_max" -le 0 ]; then
        skip "musl direct runtime search semantics" \
            "cannot determine target filesystem NAME_MAX"
        rm -rf "$root"
        return
    fi
    search_buffer=$((2 * name_max + 2))
    accept_dir_length=$((search_buffer - 2 - ${#boundary_name}))
    reject_dir_length=$((search_buffer - 1 - ${#boundary_name}))
    accept_rel_length=$((accept_dir_length - ${#bin_dir} - 1))
    reject_rel_length=$((reject_dir_length - ${#bin_dir} - 1))
    if [ "$accept_rel_length" -le 0 ] || [ "$reject_rel_length" -le 0 ]; then
        skip "musl direct runtime search semantics" \
            "build pathname is too long for boundary fixture"
        rm -rf "$root"
        return
    fi
    while [ "${#boundary_accept_rel}" -lt "$accept_rel_length" ]; do
        remaining=$((accept_rel_length - ${#boundary_accept_rel}))
        if [ -n "$boundary_accept_rel" ]; then
            remaining=$((remaining - 1))
        fi
        take=$remaining
        if [ "$take" -gt 200 ]; then take=200; fi
        printf -v component '%*s' "$take" ''
        component=${component// /a}
        if [ -n "$boundary_accept_rel" ]; then
            boundary_accept_rel+="/"
        fi
        boundary_accept_rel+="$component"
    done
    while [ "${#boundary_reject_rel}" -lt "$reject_rel_length" ]; do
        remaining=$((reject_rel_length - ${#boundary_reject_rel}))
        if [ -n "$boundary_reject_rel" ]; then
            remaining=$((remaining - 1))
        fi
        take=$remaining
        if [ "$take" -gt 200 ]; then take=200; fi
        printf -v component '%*s' "$take" ''
        component=${component// /b}
        if [ -n "$boundary_reject_rel" ]; then
            boundary_reject_rel+="/"
        fi
        boundary_reject_rel+="$component"
    done
    boundary_accept_dir="$bin_dir/$boundary_accept_rel"
    boundary_reject_dir="$bin_dir/$boundary_reject_rel"
    if [ $((${#boundary_accept_dir} + 1 + ${#boundary_name})) \
            -ne $((search_buffer - 1)) ] ||
       [ $((${#boundary_reject_dir} + 1 + ${#boundary_name})) \
            -ne "$search_buffer" ]; then
        fail "musl search candidate boundary" \
            "could not construct exact native buffer boundaries"
        rm -rf "$root"
        return
    fi
    mkdir -p "$boundary_accept_dir" "$boundary_reject_dir"

    cat > "$choice_src" <<'C'
#ifndef DLFREEZE_VALUE
#define DLFREEZE_VALUE 0
#endif
int dlfreeze_runtime_value(void) { return DLFREEZE_VALUE; }
C
    cat > "$main_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 10;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 11;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle, argv[2]);
    if (!value) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 12;
    }
    printf("%d\n", value());
    return 0;
}
C
    cat > "$boundary_start_src" <<'C'
#include <stdio.h>
int dlfreeze_runtime_value(void);
int main(void) { printf("%d\n", dlfreeze_runtime_value()); return 0; }
C
    cat > "$leaf_src" <<'C'
int dlfreeze_runtime_leaf(void) { return 70; }
C
    cat > "$middle_src" <<'C'
int dlfreeze_runtime_leaf(void);
int dlfreeze_runtime_middle(void) { return dlfreeze_runtime_leaf() + 6; }
C
    cat > "$top_src" <<'C'
int dlfreeze_runtime_middle(void);
int dlfreeze_runtime_top(void) { return dlfreeze_runtime_middle() + 1; }
C
    cat > "$token_root/token-child.c" <<'C'
int dlfreeze_runtime_value(void);
int dlfreeze_musl_token_child(void) { return dlfreeze_runtime_value(); }
C
    cat > "$token_root/token-top.c" <<'C'
int dlfreeze_musl_token_child(void);
int dlfreeze_musl_token_top(void) { return dlfreeze_musl_token_child(); }
C
    cat > "$token_root/token-start.c" <<'C'
#include <stdio.h>
int dlfreeze_musl_token_top(void);
int main(void) { printf("%d\n", dlfreeze_musl_token_top()); return 0; }
C

    if ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=11 \
            -Wl,-soname,"$choice_name" -o "$rpath_dir/$choice_name" \
            "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=22 \
            -Wl,-soname,"$choice_name" -o "$env_dir/$choice_name" \
            "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=33 \
            -Wl,-soname,"$raw_name" -o "$literal_dir/$raw_name" \
            "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=44 \
            -Wl,-soname,"$raw_name" -o "$expanded_dir/$raw_name" \
            "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=88 \
            -Wl,-soname,"$first_name" -o "$first_dir/$first_name" \
            "$choice_src" ||
       ! elf64_set_foreign_machine "$first_dir/$first_name" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=99 \
            -Wl,-soname,"$first_name" -o "$second_dir/$first_name" \
            "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=112 \
            -Wl,-soname,"$boundary_name" \
            -o "$boundary_accept_dir/$boundary_name" "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=111 \
            -Wl,-soname,"$boundary_name" \
            -o "$boundary_reject_dir/$boundary_name" "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=122 \
            -Wl,-soname,"$origin_prefix_name" \
            -o "$origin_prefix_dir/$origin_prefix_name" "$choice_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$leaf_name" \
            -o "$chain_private/$leaf_name" "$leaf_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$middle_name" \
            -L"$chain_private" -o "$chain_mid/$middle_name" \
            "$middle_src" -Wl,-l:"$leaf_name" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$top_name" \
            -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/mid:$ORIGIN/private' \
            -Wl,-rpath-link,"$chain_private" -L"$chain_mid" -o "$top" \
            "$top_src" -Wl,-l:"$middle_name" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=90 \
            -Wl,-soname,"$token_leaf_name" \
            -o "$token_wrong_dir/$token_leaf_name" "$choice_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=91 \
            -Wl,-soname,"$token_leaf_name" \
            -o "$token_right_dir/$token_leaf_name" "$choice_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$token_child_name" \
            -Wl,--enable-new-dtags \
            -Wl,-rpath,"$token_wrong_dir:\$UNKNOWN" \
            -L"$token_right_dir" \
            -o "$token_child_dir/$token_child_name" \
            "$token_root/token-child.c" \
            -Wl,--no-as-needed -Wl,-l:"$token_leaf_name" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$token_top_name" \
            -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/child:$ORIGIN/right' \
            -Wl,-rpath-link,"$token_child_dir:$token_right_dir" \
            -L"$token_child_dir" -o "$token_top" \
            "$token_root/token-top.c" \
            -Wl,--no-as-needed -Wl,-l:"$token_child_name" ||
       ! musl-gcc -Wl,--disable-new-dtags -Wl,-rpath,'$ORIGIN' \
            -Wl,-rpath-link,"$token_child_dir:$token_right_dir" \
            -L"$token_root" -o "$token_start" \
            "$token_root/token-start.c" \
            -Wl,--no-as-needed -Wl,-l:"$token_top_name" ||
       ! musl-gcc -Wl,--disable-new-dtags \
            -Wl,-rpath,"\$ORIGIN/$boundary_reject_rel:\$ORIGIN/$boundary_accept_rel:\$ORIGIN/../rpath:\$ORIGINsuffix" \
            -o "$main" "$main_src" -ldl ||
       ! musl-gcc -Wl,--disable-new-dtags \
            -Wl,-rpath,"\$ORIGIN/$boundary_reject_rel:\$ORIGIN/$boundary_accept_rel" \
            -L"$boundary_accept_dir" -o "$boundary_start" \
            "$boundary_start_src" -Wl,--no-as-needed \
            -Wl,-l:"$boundary_name" ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$boundary_gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "musl direct runtime search semantics" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if ! file "$main" 2>/dev/null | grep 'interpreter .*ld-musl' >/dev/null ||
       ! readelf -d "$top" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/mid.*\$ORIGIN/private' \
                >/dev/null ||
       ! readelf -d "$main" 2>/dev/null |
            grep -E '\(RPATH\).*\$ORIGIN/' >/dev/null; then
        skip "musl direct runtime search semantics" \
            "toolchain did not emit the requested musl/RUNPATH fixture"
        rm -rf "$root"
        return
    fi

    capture_output expect_order env LD_LIBRARY_PATH="$env_dir" "$main" \
        "$choice_name" dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_order" != 22 ]; then
        fail "native musl LD_LIBRARY_PATH ordering control" \
            "exit=$rc output=$expect_order"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output_in_dir expect_raw "$root" env \
        'LD_LIBRARY_PATH=$ORIGIN/raw' "$main" "$raw_name" \
        dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_raw" != 33 ]; then
        fail "native musl raw LD_LIBRARY_PATH control" \
            "exit=$rc output=$expect_raw"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output expect_chain env -u LD_LIBRARY_PATH "$main" "$top" \
        dlfreeze_runtime_top || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_chain" != 77 ]; then
        fail "native musl inherited RUNPATH control" \
            "exit=$rc output=$expect_chain"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output expect_token env -u LD_LIBRARY_PATH "$main" \
        "$token_top" dlfreeze_musl_token_top || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_token" != 91 ]; then
        fail "native musl unknown-token RPATH control" \
            "exit=$rc output=$expect_token"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$token_start" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 91 ]; then
        fail "native musl startup unknown-token RPATH control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    elif ! env -u LD_LIBRARY_PATH "$boundary_gate" "$token_start" \
            >"$boundary_resolver_log" 2>&1 ||
         ! grep -Fq "$token_right_dir/$token_leaf_name" \
            "$boundary_resolver_log" ||
         grep -Fq "$token_wrong_dir/$token_leaf_name" \
            "$boundary_resolver_log"; then
        fail "musl pack unknown-token RPATH" \
            "resolver did not discard the complete invalid child list"
        rm -rf "$root"
        return
    else
        pass "musl pack discards complete RPATH with unknown token"
    fi
    rc=0
    capture_output actual env LD_LIBRARY_PATH="$first_dir:$second_dir" \
        "$main" "$first_name" dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 88 ]; then
        fail "native musl first-opened ABI candidate control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output expect_boundary env -u LD_LIBRARY_PATH "$main" \
        "$boundary_name" dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_boundary" != 112 ]; then
        fail "native musl search-buffer boundary control" \
            "exit=$rc output=$expect_boundary"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$boundary_start" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 112 ]; then
        fail "native musl startup search-buffer boundary control" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    elif ! env -u LD_LIBRARY_PATH "$boundary_gate" "$boundary_start" \
            >"$boundary_resolver_log" 2>&1 ||
         ! grep -Fq "$boundary_accept_dir/$boundary_name" \
            "$boundary_resolver_log" ||
         grep -Fq "$boundary_reject_dir/$boundary_name" \
            "$boundary_resolver_log"; then
        fail "musl pack search-buffer boundary" \
            "resolver differed from native 2*NAME_MAX+2 search"
        rm -rf "$root"
        return
    else
        pass "musl pack resolver uses native search-buffer boundary"
    fi
    rc=0
    capture_output expect_pathful_boundary env -u LD_LIBRARY_PATH "$main" \
        "$boundary_reject_dir/$boundary_name" dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_pathful_boundary" != 111 ]; then
        fail "native musl pathful search-buffer non-boundary control" \
            "exit=$rc output=$expect_pathful_boundary"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output expect_origin_prefix env -u LD_LIBRARY_PATH "$main" \
        "$origin_prefix_name" dlfreeze_runtime_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect_origin_prefix" != 122 ]; then
        fail "native musl ORIGIN-prefix substitution control" \
            "exit=$rc output=$expect_origin_prefix"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "musl direct runtime search semantics" "$log" \
        "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl direct LD_LIBRARY_PATH-before-RPATH" "$DIRECT_FREEZE_REASON"
        skip "musl direct raw LD_LIBRARY_PATH" "$DIRECT_FREEZE_REASON"
        skip "musl direct inherited RUNPATH" "$DIRECT_FREEZE_REASON"
        skip "musl direct unknown-token RPATH" "$DIRECT_FREEZE_REASON"
        skip "musl direct first-opened ABI candidate" \
            "$DIRECT_FREEZE_REASON"
        skip "musl direct search-buffer boundary" "$DIRECT_FREEZE_REASON"
        skip "musl direct pathful search-buffer non-boundary" \
            "$DIRECT_FREEZE_REASON"
        skip "musl direct ORIGIN-prefix substitution" \
            "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        capture_output actual env LD_LIBRARY_PATH="$env_dir" "$out" \
            "$choice_name" dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_order" ]; then
            pass "musl direct LD_LIBRARY_PATH precedes RPATH"
        else
            fail "musl direct LD_LIBRARY_PATH-before-RPATH" \
                "exit=$rc expected=$expect_order output=$actual"
        fi

        rc=0
        capture_output_in_dir actual "$root" env \
            'LD_LIBRARY_PATH=$ORIGIN/raw' "$out" "$raw_name" \
            dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_raw" ]; then
            pass "musl direct LD_LIBRARY_PATH remains raw"
        else
            fail "musl direct raw LD_LIBRARY_PATH" \
                "exit=$rc expected=$expect_raw output=$actual"
        fi

        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" "$top" \
            dlfreeze_runtime_top || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_chain" ]; then
            pass "musl direct RUNPATH is inherited"
        else
            fail "musl direct inherited RUNPATH" \
                "exit=$rc expected=$expect_chain output=$actual"
        fi

        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" "$token_top" \
            dlfreeze_musl_token_top || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_token" ]; then
            pass "musl direct discards complete RPATH with unknown token"
        else
            fail "musl direct unknown-token RPATH" \
                "exit=$rc expected=$expect_token output=$actual"
        fi

        rc=0
        capture_output actual env \
            LD_LIBRARY_PATH="$first_dir:$second_dir" "$out" \
            "$first_name" dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 11 ] &&
           [[ "$actual" == *"unsupported shared object ABI"* ]] &&
           [[ "$actual" != *$'\n99' ]] && [ "$actual" != 99 ]; then
            pass "musl direct first-opened ABI candidate stops search"
        else
            fail "musl direct first-opened ABI candidate" \
                "exit=$rc output=$actual"
        fi

        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" \
            "$boundary_name" dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_boundary" ]; then
            pass "musl direct search uses native 2*NAME_MAX+2 boundary"
        else
            fail "musl direct search-buffer boundary" \
                "exit=$rc expected=$expect_boundary output=$actual"
        fi

        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" \
            "$boundary_reject_dir/$boundary_name" \
            dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] &&
           [ "$actual" = "$expect_pathful_boundary" ]; then
            pass "musl direct pathful dlopen bypasses search-buffer bound"
        else
            fail "musl direct pathful search-buffer non-boundary" \
                "exit=$rc expected=$expect_pathful_boundary output=$actual"
        fi

        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" \
            "$origin_prefix_name" dlfreeze_runtime_value || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect_origin_prefix" ]; then
            pass "musl direct substitutes ORIGIN before identifier suffix"
        else
            fail "musl direct ORIGIN-prefix substitution" \
                "exit=$rc expected=$expect_origin_prefix output=$actual"
        fi
    fi

    if command -v patchelf >/dev/null 2>&1; then
        local prefix="$root/prefix/install"
        local prefix_lib="$prefix/lib" prefix_etc="$prefix/etc"
        local configured="$root/prefix/configured"
        local prefix_main="$root/prefix/main"
        local prefix_out="$root/prefix/main.frozen"
        local prefix_log="$root/prefix/freeze.log"
        local prefix_name=libdlfrz_musl_prefix_runtime.so
        local snapshot_first_name=libdlfrz_musl_snapshot_first.so
        local snapshot_second_name=libdlfrz_musl_snapshot_second.so
        local source_interp interp_base musl_arch custom_interp path_file
        local prefix_expect prefix_actual prefix_rc=0 prefix_freeze_rc=0
        local alternate="$root/prefix/alternate"
        local snapshot_src="$root/prefix/snapshot.c"
        local snapshot_main="$root/prefix/snapshot-main"
        local snapshot_out="$root/prefix/snapshot-main.frozen"
        local snapshot_log="$root/prefix/snapshot.log"
        local snapshot_expect snapshot_actual snapshot_rc=0
        local snapshot_freeze_rc=0

        mkdir -p "$prefix_lib" "$prefix_etc" "$configured" "$alternate"
        source_interp=$(LC_ALL=C readelf -l "$main" 2>/dev/null |
            sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' |
            head -n 1)
        interp_base=${source_interp##*/}
        musl_arch=${interp_base#ld-musl-}
        musl_arch=${musl_arch%%.so*}
        custom_interp="$prefix_lib/renamed-runtime"
        path_file="$prefix_etc/ld-musl-$musl_arch.path"
        if [ -z "$source_interp" ] || [ ! -f "$source_interp" ] ||
           [ -z "$musl_arch" ] || [ "$musl_arch" = "$interp_base" ] ||
           ! cp "$source_interp" "$custom_interp" ||
           ! printf '%s\n' "$configured" >"$path_file" ||
           ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=55 \
                -Wl,-soname,"$prefix_name" -o "$configured/$prefix_name" \
                "$choice_src" ||
           ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=66 \
                -Wl,-soname,"$prefix_name" -o "$prefix_lib/$prefix_name" \
                "$choice_src" ||
           ! cp "$main" "$prefix_main" ||
           ! patchelf --set-interpreter "$custom_interp" "$prefix_main"; then
            fail "musl direct prefix path-file search" \
                "fixture compile failed"
        else
            capture_output prefix_expect env -u LD_LIBRARY_PATH \
                "$prefix_main" "$prefix_name" dlfreeze_runtime_value ||
                prefix_rc=$?
            if [ "$prefix_rc" -ne 0 ] || [ "$prefix_expect" != 55 ]; then
                fail "native musl prefix path-file control" \
                    "exit=$prefix_rc output=$prefix_expect"
            else
                freeze_require_direct "musl direct prefix path-file search" \
                    "$prefix_log" "$prefix_out" "$prefix_main" ||
                    prefix_freeze_rc=$?
                if [ "$prefix_freeze_rc" -eq 77 ]; then
                    skip "musl direct prefix path-file search" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$prefix_freeze_rc" -eq 0 ]; then
                    prefix_rc=0
                    capture_output prefix_actual env -u LD_LIBRARY_PATH \
                        "$prefix_out" "$prefix_name" \
                        dlfreeze_runtime_value || prefix_rc=$?
                    prefix_actual=$(printf '%s\n' "$prefix_actual" |
                        strip_dlfreeze_warnings)
                    if [ "$prefix_rc" -eq 0 ] &&
                       [ "$prefix_actual" = "$prefix_expect" ]; then
                        pass "musl direct prefix path file replaces defaults"
                    else
                        fail "musl direct prefix path-file search" \
                            "exit=$prefix_rc expected=$prefix_expect output=$prefix_actual"
                    fi
                fi
            fi
        fi

        cat > "$snapshot_src" <<C
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
typedef int (*value_fn)(void);
static int lookup_value(const char *name) {
    void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    value_fn value = handle
        ? (value_fn)dlsym(handle, "dlfreeze_runtime_value") : 0;
    return value ? value() : -100;
}
static int replace_path_file(const char *path, const char *directory) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    size_t length = strlen(directory);
    if (fd < 0 || write(fd, directory, length) != (ssize_t)length ||
        write(fd, "\n", 1) != 1 || close(fd) != 0)
        return -1;
    return 0;
}
int main(int argc, char **argv) {
    int first;
    int second;
    if (argc != 3) return 10;
    first = lookup_value("$snapshot_first_name");
    if (first < 0 || replace_path_file(argv[1], argv[2]) < 0)
        return 11;
    second = lookup_value("$snapshot_second_name");
    printf("first=%d second=%d\n", first, second);
    return second < 0 ? 12 : 0;
}
C
        if ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=71 \
                -Wl,-soname,"$snapshot_first_name" \
                -o "$configured/$snapshot_first_name" "$choice_src" ||
           ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=72 \
                -Wl,-soname,"$snapshot_second_name" \
                -o "$configured/$snapshot_second_name" "$choice_src" ||
           ! musl-gcc -shared -fPIC -DDLFREEZE_VALUE=82 \
                -Wl,-soname,"$snapshot_second_name" \
                -o "$alternate/$snapshot_second_name" "$choice_src" ||
           ! musl-gcc -Wall -Wextra -Werror -o "$snapshot_main" \
                "$snapshot_src" -ldl ||
           ! patchelf --set-interpreter "$custom_interp" "$snapshot_main" ||
           ! printf '%s\n' "$configured" >"$path_file"; then
            fail "musl path-file snapshot" "fixture compile failed"
        else
            capture_output snapshot_expect env -u LD_LIBRARY_PATH \
                "$snapshot_main" "$path_file" "$alternate" ||
                snapshot_rc=$?
            if [ "$snapshot_rc" -ne 0 ] ||
               [ "$snapshot_expect" != "first=71 second=72" ]; then
                fail "native musl path-file snapshot control" \
                    "exit=$snapshot_rc output=$snapshot_expect"
            else
                printf '%s\n' "$configured" >"$path_file"
                freeze_require_direct "musl direct path-file snapshot" \
                    "$snapshot_log" "$snapshot_out" "$snapshot_main" ||
                    snapshot_freeze_rc=$?
                if [ "$snapshot_freeze_rc" -eq 77 ]; then
                    skip "musl direct path-file snapshot" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$snapshot_freeze_rc" -eq 0 ]; then
                    printf '%s\n' "$configured" >"$path_file"
                    snapshot_rc=0
                    capture_output snapshot_actual env -u LD_LIBRARY_PATH \
                        "$snapshot_out" "$path_file" "$alternate" ||
                        snapshot_rc=$?
                    snapshot_actual=$(printf '%s\n' "$snapshot_actual" |
                        strip_dlfreeze_warnings)
                    if [ "$snapshot_rc" -eq 0 ] &&
                       [ "$snapshot_actual" = "$snapshot_expect" ]; then
                        pass "musl direct path file is snapshotted once"
                    else
                        fail "musl direct path-file snapshot" \
                            "exit=$snapshot_rc expected=$snapshot_expect output=$snapshot_actual"
                    fi
                fi
            fi
        fi
        printf '%s\n' "$configured" >"$path_file"
    else
        skip "musl direct prefix path-file search" "patchelf not installed"
        skip "musl direct path-file snapshot" "patchelf not installed"
    fi
    rm -rf "$root"
}

# Both target loaders capture LD_LIBRARY_PATH during startup.  Application
# setenv/unsetenv calls must not change the loader's later bare-name search,
# even though they may replace or compact the original environment vector.
test_direct_library_path_snapshot() {
    echo "--- direct startup LD_LIBRARY_PATH snapshot ---"
    local root="$BUILD/library_path_snapshot"
    local src="$root/main.c" lib_src="$root/library.c"
    local lib_name=libdlfrz_library_path_snapshot.so
    local musl_root="$root/musl" musl_initial musl_alternate
    local musl_main musl_out musl_log
    local gnu_root="$root/gnu" gnu_initial gnu_alternate
    local gnu_main gnu_out gnu_log
    local native_unset native_set actual rc=0 freeze_rc=0 libc_banner
    local native_unset_rc=0 native_set_rc=0

    rm -rf "$root"
    musl_initial="$musl_root/initial"
    musl_alternate="$musl_root/alternate"
    musl_main="$musl_root/main"
    musl_out="$musl_root/main.frozen"
    musl_log="$musl_root/freeze.log"
    gnu_initial="$gnu_root/initial"
    gnu_alternate="$gnu_root/alternate"
    gnu_main="$gnu_root/main"
    gnu_out="$gnu_root/main.frozen"
    gnu_log="$gnu_root/freeze.log"
    mkdir -p "$musl_initial" "$musl_alternate" \
        "$gnu_initial" "$gnu_alternate"
    cat > "$lib_src" <<'C'
#ifndef SNAPSHOT_VALUE
#define SNAPSHOT_VALUE 0
#endif
int dlfreeze_library_path_snapshot_value(void) { return SNAPSHOT_VALUE; }
C
    cat > "$src" <<C
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int (*value_fn)(void);
int main(int argc, char **argv) {
    void *handle;
    value_fn value;
    if (argc != 3) return 10;
    if (!strcmp(argv[1], "unset")) {
        if (unsetenv("LD_LIBRARY_PATH") != 0) return 11;
    } else if (!strcmp(argv[1], "set")) {
        if (setenv("LD_LIBRARY_PATH", argv[2], 1) != 0) return 12;
    } else {
        return 13;
    }
    handle = dlopen("$lib_name", RTLD_NOW | RTLD_LOCAL);
    value = handle ? (value_fn)dlsym(
        handle, "dlfreeze_library_path_snapshot_value") : 0;
    printf("%s=%d\n", argv[1], value ? value() : -100);
    return 0;
}
C

    if command -v musl-gcc >/dev/null 2>&1; then
        if ! musl-gcc -shared -fPIC -DSNAPSHOT_VALUE=31 \
                -Wl,-soname,"$lib_name" \
                -o "$musl_initial/$lib_name" "$lib_src" ||
           ! musl-gcc -shared -fPIC -DSNAPSHOT_VALUE=41 \
                -Wl,-soname,"$lib_name" \
                -o "$musl_alternate/$lib_name" "$lib_src" ||
           ! musl-gcc -Wall -Wextra -Werror -o "$musl_main" "$src" -ldl; then
            fail "musl LD_LIBRARY_PATH snapshot" "fixture compile failed"
        else
            capture_output native_unset env \
                LD_LIBRARY_PATH="$musl_initial" "$musl_main" unset \
                "$musl_alternate" || native_unset_rc=$?
            capture_output native_set env \
                LD_LIBRARY_PATH="$musl_initial" "$musl_main" set \
                "$musl_alternate" || native_set_rc=$?
            if [ "$native_unset" != "unset=31" ] ||
               [ "$native_set" != "set=31" ] ||
               [ "$native_unset_rc" -ne 0 ] ||
               [ "$native_set_rc" -ne 0 ]; then
                fail "native musl LD_LIBRARY_PATH snapshot control" \
                    "unset=$native_unset/$native_unset_rc set=$native_set/$native_set_rc"
            else
                freeze_rc=0
                LD_LIBRARY_PATH="$musl_initial" freeze_require_direct \
                    "musl direct LD_LIBRARY_PATH snapshot" "$musl_log" \
                    "$musl_out" "$musl_main" || freeze_rc=$?
                if [ "$freeze_rc" -eq 77 ]; then
                    skip "musl direct LD_LIBRARY_PATH snapshot" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$freeze_rc" -eq 0 ]; then
                    rc=0
                    capture_output actual env \
                        LD_LIBRARY_PATH="$musl_initial" "$musl_out" unset \
                        "$musl_alternate" || rc=$?
                    actual=$(printf '%s\n' "$actual" |
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_unset" ]; then
                        pass "musl direct LD_LIBRARY_PATH survives unsetenv"
                    else
                        fail "musl direct LD_LIBRARY_PATH unsetenv snapshot" \
                            "exit=$rc expected=$native_unset output=$actual"
                    fi
                    rc=0
                    capture_output actual env \
                        LD_LIBRARY_PATH="$musl_initial" "$musl_out" set \
                        "$musl_alternate" || rc=$?
                    actual=$(printf '%s\n' "$actual" |
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_set" ]; then
                        pass "musl direct LD_LIBRARY_PATH survives setenv"
                    else
                        fail "musl direct LD_LIBRARY_PATH setenv snapshot" \
                            "exit=$rc expected=$native_set output=$actual"
                    fi
                fi
            fi
        fi
    else
        skip "musl direct LD_LIBRARY_PATH snapshot" "musl-gcc not installed"
    fi

    libc_banner=$(ldd --version 2>&1 || true)
    if grep -Eqi 'glibc|GNU libc|GNU C Library' <<<"$libc_banner"; then
        if ! gcc -shared -fPIC -DSNAPSHOT_VALUE=31 \
                -Wl,-soname,"$lib_name" \
                -o "$gnu_initial/$lib_name" "$lib_src" ||
           ! gcc -shared -fPIC -DSNAPSHOT_VALUE=41 \
                -Wl,-soname,"$lib_name" \
                -o "$gnu_alternate/$lib_name" "$lib_src" ||
           ! gcc -Wall -Wextra -Werror -o "$gnu_main" "$src" -ldl; then
            fail "GNU LD_LIBRARY_PATH snapshot" "fixture compile failed"
        else
            native_unset_rc=0
            native_set_rc=0
            rc=0
            capture_output native_unset env \
                LD_LIBRARY_PATH="$gnu_initial" "$gnu_main" unset \
                "$gnu_alternate" || native_unset_rc=$?
            capture_output native_set env \
                LD_LIBRARY_PATH="$gnu_initial" "$gnu_main" set \
                "$gnu_alternate" || native_set_rc=$?
            if [ "$native_unset" != "unset=31" ] ||
               [ "$native_set" != "set=31" ] ||
               [ "$native_unset_rc" -ne 0 ] ||
               [ "$native_set_rc" -ne 0 ]; then
                fail "native GNU LD_LIBRARY_PATH snapshot control" \
                    "unset=$native_unset/$native_unset_rc set=$native_set/$native_set_rc"
            else
                freeze_rc=0
                LD_LIBRARY_PATH="$gnu_initial" freeze_require_direct \
                    "GNU direct LD_LIBRARY_PATH snapshot" "$gnu_log" \
                    "$gnu_out" "$gnu_main" || freeze_rc=$?
                if [ "$freeze_rc" -eq 77 ]; then
                    skip "GNU direct LD_LIBRARY_PATH snapshot" \
                        "$DIRECT_FREEZE_REASON"
                elif [ "$freeze_rc" -eq 0 ]; then
                    rc=0
                    capture_output actual env \
                        LD_LIBRARY_PATH="$gnu_initial" "$gnu_out" unset \
                        "$gnu_alternate" || rc=$?
                    actual=$(printf '%s\n' "$actual" |
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_unset" ]; then
                        pass "GNU direct LD_LIBRARY_PATH survives unsetenv"
                    else
                        fail "GNU direct LD_LIBRARY_PATH unsetenv snapshot" \
                            "exit=$rc expected=$native_unset output=$actual"
                    fi
                    rc=0
                    capture_output actual env \
                        LD_LIBRARY_PATH="$gnu_initial" "$gnu_out" set \
                        "$gnu_alternate" || rc=$?
                    actual=$(printf '%s\n' "$actual" |
                        strip_dlfreeze_warnings)
                    if [ "$rc" -eq 0 ] && [ "$actual" = "$native_set" ]; then
                        pass "GNU direct LD_LIBRARY_PATH survives setenv"
                    else
                        fail "GNU direct LD_LIBRARY_PATH setenv snapshot" \
                            "exit=$rc expected=$native_set output=$actual"
                    fi
                fi
            fi
        fi
    else
        skip "GNU direct LD_LIBRARY_PATH snapshot" \
            "target runtime is not glibc"
    fi
    rm -rf "$root"
}

# musl decodes DT_RPATH first and DT_RUNPATH second, so merely having a
# DT_RUNPATH tag suppresses the same object's DT_RPATH even when the selected
# string is empty.  A three-level chain also proves the empty path is not
# accidentally inherited by children and that the older needed_by ancestry
# remains available.
test_musl_dual_search_tags() {
    echo "--- musl dual DT_RPATH/DT_RUNPATH precedence ---"
    local build_abs root bin_dir top_dir good_dir bad_dir
    local leaf_src middle_src top_src startup_src dlopen_src
    local leaf_name=libdlfrz_musl_dual_leaf.so
    local middle_name=libdlfrz_musl_dual_middle.so
    local top_name=libdlfrz_musl_dual_top.so
    local top startup_main dlopen_main out log gate gate_log dynamic
    local native_start native_late actual rc=0 gate_rc=0 freeze_rc=0

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl dual search-tag resolver precedence" \
            "musl-gcc not installed"
        skip "musl direct dual search-tag precedence" \
            "musl-gcc not installed"
        return
    fi
    build_abs=$(realpath "$BUILD")
    root="$build_abs/musl_dual_search_tags"
    bin_dir="$root/bin"
    top_dir="$root/top"
    good_dir="$root/good"
    bad_dir="$root/bad"
    leaf_src="$root/leaf.c"
    middle_src="$root/middle.c"
    top_src="$root/top.c"
    startup_src="$root/startup.c"
    dlopen_src="$root/dlopen.c"
    top="$top_dir/$top_name"
    startup_main="$bin_dir/startup"
    dlopen_main="$bin_dir/dlopen"
    out="$bin_dir/dlopen.frozen"
    log="$root/freeze.log"
    gate="$root/dep-resolver-gate"
    gate_log="$root/resolver.log"

    rm -rf "$root"
    mkdir -p "$bin_dir" "$top_dir" "$good_dir" "$bad_dir"
    cat > "$leaf_src" <<'C'
#ifndef DLFREEZE_LEAF_VALUE
#define DLFREEZE_LEAF_VALUE 0
#endif
int dlfreeze_musl_dual_leaf(void) { return DLFREEZE_LEAF_VALUE; }
C
    cat > "$middle_src" <<'C'
int dlfreeze_musl_dual_leaf(void);
int dlfreeze_musl_dual_middle(void) {
    return dlfreeze_musl_dual_leaf() + 1;
}
C
    cat > "$top_src" <<'C'
int dlfreeze_musl_dual_middle(void);
int dlfreeze_musl_dual_top(void) {
    return dlfreeze_musl_dual_middle() + 1;
}
C
    cat > "$startup_src" <<'C'
#include <stdio.h>
int dlfreeze_musl_dual_top(void);
int main(void) {
    printf("%d\n", dlfreeze_musl_dual_top());
    return 0;
}
C
    cat > "$dlopen_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 10;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 11;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle, argv[2]);
    if (!value) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 12;
    }
    printf("%d\n", value());
    return 0;
}
C

    if ! musl-gcc -shared -fPIC -DDLFREEZE_LEAF_VALUE=80 \
            -Wl,-soname,"$leaf_name" -o "$good_dir/$leaf_name" \
            "$leaf_src" ||
       ! musl-gcc -shared -fPIC -DDLFREEZE_LEAF_VALUE=10 \
            -Wl,-soname,"$leaf_name" -o "$bad_dir/$leaf_name" \
            "$leaf_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$middle_name" \
            -L"$good_dir" -o "$good_dir/$middle_name" "$middle_src" \
            -Wl,-l:"$leaf_name" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$middle_name" \
            -L"$bad_dir" -o "$bad_dir/$middle_name" "$middle_src" \
            -Wl,-l:"$leaf_name" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$top_name" \
            -Wl,--disable-new-dtags -Wl,--spare-dynamic-tags=2 \
            -Wl,-rpath,'$ORIGIN/../bad' \
            -Wl,-rpath-link,"$bad_dir" -L"$bad_dir" -o "$top" \
            "$top_src" -Wl,-l:"$middle_name" ||
       ! elf64_inject_empty_runpath "$top" ||
       ! musl-gcc -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../top:$ORIGIN/../good' \
            -Wl,-rpath-link,"$top_dir" -Wl,-rpath-link,"$bad_dir" \
            -L"$top_dir" -o "$startup_main" "$startup_src" \
            -Wl,-l:"$top_name" ||
       ! musl-gcc -Wl,--disable-new-dtags \
            -Wl,-rpath,'$ORIGIN/../top:$ORIGIN/../good' \
            -o "$dlopen_main" "$dlopen_src" -ldl ||
       ! gcc -Wall -Wextra -Werror -O2 -D_GNU_SOURCE -Iinclude \
            -o "$gate" tests/dep_resolver_gate.c \
            src/dep_resolver.c src/elf_parser.c; then
        fail "musl dual search-tag semantics" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    dynamic=$(LC_ALL=C readelf -dW "$top" 2>/dev/null || true)
    if ! grep -Eq '\(RPATH\).*\$ORIGIN/\.\./bad' <<<"$dynamic" ||
       ! grep -Eq '\(RUNPATH\).*[[]]' <<<"$dynamic"; then
        fail "musl dual search-tag semantics" \
            "fixture does not contain RPATH plus empty RUNPATH"
        rm -rf "$root"
        return
    fi

    capture_output native_start env -u LD_LIBRARY_PATH \
        "$startup_main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$native_start" != 82 ]; then
        fail "native musl dual search-tag control" \
            "exit=$rc output=$native_start"
        rm -rf "$root"
        return
    fi
    env -u LD_LIBRARY_PATH "$gate" "$startup_main" \
        >"$gate_log" 2>&1 || gate_rc=$?
    if [ "$gate_rc" -eq 0 ] &&
       grep -Fq "$good_dir/$middle_name" "$gate_log" &&
       grep -Fq "$good_dir/$leaf_name" "$gate_log" &&
       ! grep -Fq "$bad_dir/" "$gate_log"; then
        pass "musl empty DT_RUNPATH suppresses same-object DT_RPATH"
    else
        fail "musl dual search-tag resolver precedence" \
            "resolver_exit=$gate_rc; expected good needed_by ancestry"
    fi

    rc=0
    capture_output native_late env -u LD_LIBRARY_PATH "$dlopen_main" \
        "$top_name" dlfreeze_musl_dual_top || rc=$?
    if [ "$rc" -ne 0 ] || [ "$native_late" != 82 ]; then
        fail "native musl late dual search-tag control" \
            "exit=$rc output=$native_late"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "musl direct dual search-tag precedence" "$log" \
        "$out" "$dlopen_main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl direct dual search-tag precedence" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" \
            "$top_name" dlfreeze_musl_dual_top || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$native_late" ]; then
            pass "musl direct empty DT_RUNPATH suppresses DT_RPATH"
        else
            fail "musl direct dual search-tag precedence" \
                "exit=$rc expected=$native_late output=$actual"
        fi
    fi
    rm -rf "$root"
}

# A musl caller with no search path inherits the first loader ancestry which
# brought it into the process.  Exercise a later dlopen, after startup has
# completed, so the direct loader must retain that needed_by identity rather
# than relying on the ephemeral recursive-load scope.
test_musl_direct_late_dlopen_ancestry() {
    echo "--- musl direct later dlopen needed_by ancestry ---"
    local build_abs root lib_dir private_dir
    local plugin_name=libdlfrz_musl_late_plugin.so
    local child_name=libdlfrz_musl_late_child.so
    local plugin_src child_src main_src plugin child main out log
    local expect actual rc=0 freeze_rc=0

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl direct later dlopen ancestry" "musl-gcc not installed"
        return
    fi
    build_abs=$(realpath "$BUILD")
    root="$build_abs/musl_late_dlopen_ancestry"
    lib_dir="$root/lib"
    private_dir="$root/private"
    plugin_src="$root/plugin.c"
    child_src="$root/child.c"
    main_src="$root/main.c"
    plugin="$private_dir/$plugin_name"
    child="$lib_dir/$child_name"
    main="$root/main"
    out="$root/main.frozen"
    log="$root/freeze.log"

    rm -rf "$root"
    mkdir -p "$lib_dir" "$private_dir"
    cat > "$plugin_src" <<'C'
int dlfreeze_musl_late_plugin(void) { return 88; }
C
    cat > "$child_src" <<C
#include <dlfcn.h>
int dlfreeze_musl_late_from_child(void) {
    void *handle = dlopen("$plugin_name", RTLD_NOW);
    if (!handle) return -1;
    int (*value)(void) =
        (int (*)(void))dlsym(handle, "dlfreeze_musl_late_plugin");
    return value ? value() : -2;
}
C
    cat > "$main_src" <<'C'
#include <stdio.h>
int dlfreeze_musl_late_from_child(void);
int main(void) {
    printf("late=%d\n", dlfreeze_musl_late_from_child());
    return 0;
}
C

    if ! musl-gcc -shared -fPIC -Wl,-soname,"$plugin_name" \
            -o "$plugin" "$plugin_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,"$child_name" \
            -o "$child" "$child_src" -ldl ||
       ! musl-gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/lib:$ORIGIN/private' \
            -Wl,-rpath-link,"$lib_dir" -L"$lib_dir" -o "$main" \
            "$main_src" -Wl,-l:"$child_name"; then
        fail "musl direct later dlopen ancestry" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if readelf -d "$child" 2>/dev/null |
            grep -E '\((RPATH|RUNPATH)\)' >/dev/null ||
       ! readelf -d "$main" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/lib.*\$ORIGIN/private' \
                >/dev/null; then
        skip "musl direct later dlopen ancestry" \
            "toolchain did not emit the requested path ownership"
        rm -rf "$root"
        return
    fi

    capture_output expect env -u LD_LIBRARY_PATH "$main" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect" != "late=88" ]; then
        fail "native musl later dlopen ancestry control" \
            "exit=$rc output=$expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "musl direct later dlopen ancestry" "$log" \
        "$out" "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl direct later dlopen ancestry" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$child" "$child.bak"
    rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    mv "$child.bak" "$child"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "musl direct later dlopen inherits needed_by RUNPATH"
    else
        fail "musl direct later dlopen ancestry" \
            "exit=$rc expected=$expect output=$actual"
    fi
    rm -rf "$root"
}

# musl implements public dlopen as load_library(file, head).  A DSO's own
# RUNPATH must therefore not steer a bare top-level request, and even a
# pathful root gets the main program as its needed_by ancestor for DT_NEEDED
# resolution.  Exercise uncaptured filesystem loads plus a captured root whose
# constructor performs a nested, intentionally untraced filesystem load.
test_musl_direct_dlopen_head_scope() {
    echo "--- musl direct dlopen main/head scope ---"
    local build_abs root startup private head deps external
    local caller_src main_src value_src path_dep_src path_root_src
    local leaf_src embedded_src
    local caller main fallback_out fallback_log embedded_out embedded_log
    local choice_head choice_private caller_only path_dep_head path_dep_private
    local path_root leaf embedded nested_head nested_private
    local choice_native missing_native path_native embedded_native
    local choice_actual missing_actual path_actual embedded_actual
    local rc=0 freeze_rc=0

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl direct dlopen main/head scope" "musl-gcc not installed"
        return
    fi
    build_abs=$(realpath "$BUILD")
    root="$build_abs/musl_dlopen_head_scope"
    startup="$root/startup"
    private="$startup/private"
    head="$root/head"
    deps="$head/deps"
    external="$root/external"
    caller_src="$root/caller.c"
    main_src="$root/main.c"
    value_src="$root/value.c"
    path_dep_src="$root/path-dep.c"
    path_root_src="$root/path-root.c"
    leaf_src="$root/leaf.c"
    embedded_src="$root/embedded.c"
    caller="$startup/libdlfrz_musl_head_caller.so"
    main="$root/main"
    fallback_out="$root/main-fallback.frozen"
    fallback_log="$root/fallback.log"
    embedded_out="$root/main-embedded.frozen"
    embedded_log="$root/embedded.log"
    choice_head="$head/libdlfrz_musl_head_choice.so"
    choice_private="$private/libdlfrz_musl_head_choice.so"
    caller_only="$private/libdlfrz_musl_caller_only.so"
    path_dep_head="$head/libdlfrz_musl_path_dep.so"
    path_dep_private="$private/libdlfrz_musl_path_dep.so"
    path_root="$external/libdlfrz_musl_path_root.so"
    leaf="$deps/libdlfrz_musl_embedded_leaf.so"
    embedded="$head/libdlfrz_musl_embedded_root.so"
    nested_head="$head/libdlfrz_musl_nested.so"
    nested_private="$private/libdlfrz_musl_nested.so"

    rm -rf "$root"
    mkdir -p "$private" "$deps" "$external"
    cat > "$value_src" <<'C'
#ifndef TEST_SYMBOL
#define TEST_SYMBOL dlfreeze_scope_value
#endif
#ifndef TEST_VALUE
#define TEST_VALUE 0
#endif
int TEST_SYMBOL(void) { return TEST_VALUE; }
C
    cat > "$path_dep_src" <<'C'
#ifndef TEST_VALUE
#define TEST_VALUE 0
#endif
int dlfreeze_path_dep_value(void) { return TEST_VALUE; }
C
    cat > "$path_root_src" <<'C'
extern int dlfreeze_path_dep_value(void);
int dlfreeze_path_root_value(void) {
    return dlfreeze_path_dep_value() + 1;
}
C
    cat > "$leaf_src" <<'C'
int dlfreeze_embedded_leaf_value(void) { return 72; }
C
    cat > "$embedded_src" <<'C'
#include <dlfcn.h>
#include <stdlib.h>
typedef int (*value_fn)(void);
extern int dlfreeze_embedded_leaf_value(void);
static int nested_value = -1;
__attribute__((constructor)) static void embedded_ctor(void) {
    void *handle;
    value_fn value;

    if (!getenv("DLFREEZE_TEST_MUSL_NESTED"))
        return;
    handle = dlopen("libdlfrz_musl_nested.so", RTLD_NOW | RTLD_LOCAL);
    value = handle
        ? (value_fn)dlsym(handle, "dlfreeze_nested_value") : NULL;
    nested_value = value ? value() : -100;
}
int dlfreeze_embedded_value(void) {
    return dlfreeze_embedded_leaf_value() + nested_value;
}
C
    cat > "$caller_src" <<'C'
#include <dlfcn.h>
typedef int (*value_fn)(void);
int dlfreeze_call_bare(const char *name, const char *symbol) {
    void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    value_fn value = handle ? (value_fn)dlsym(handle, symbol) : 0;
    return value ? value() : -100;
}
int dlfreeze_call_path(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    value_fn value = handle
        ? (value_fn)dlsym(handle, "dlfreeze_path_root_value") : 0;
    return value ? value() : -100;
}
C
    cat > "$main_src" <<'C'
#include <stdio.h>
#include <string.h>
int dlfreeze_call_bare(const char *, const char *);
int dlfreeze_call_path(const char *);
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "noop")) {
        puts("head-scope-noop");
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "bare")) {
        printf("bare=%d\n", dlfreeze_call_bare(argv[2], argv[3]));
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "path")) {
        printf("path=%d\n", dlfreeze_call_path(argv[2]));
        return 0;
    }
    return 2;
}
C

    if ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_head_choice.so \
            -DTEST_VALUE=31 -o "$choice_head" "$value_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_head_choice.so \
            -DTEST_VALUE=41 -o "$choice_private" "$value_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_caller_only.so \
            -DTEST_VALUE=51 -o "$caller_only" "$value_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_path_dep.so \
            -DTEST_VALUE=60 -o "$path_dep_head" "$path_dep_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_path_dep.so \
            -DTEST_VALUE=61 -o "$path_dep_private" "$path_dep_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_path_root.so \
            -Wl,--no-as-needed -L"$head" -o "$path_root" \
            "$path_root_src" -Wl,-l:libdlfrz_musl_path_dep.so ||
       ! musl-gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_musl_embedded_leaf.so \
            -o "$leaf" "$leaf_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_nested.so \
            -DTEST_SYMBOL=dlfreeze_nested_value -DTEST_VALUE=90 \
            -o "$nested_head" "$value_src" ||
       ! musl-gcc -shared -fPIC -Wl,-soname,libdlfrz_musl_nested.so \
            -DTEST_SYMBOL=dlfreeze_nested_value -DTEST_VALUE=91 \
            -o "$nested_private" "$value_src" ||
       ! musl-gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_musl_embedded_root.so \
            -Wl,-rpath,'$ORIGIN/deps:$ORIGIN/../startup/private' \
            -Wl,--no-as-needed -L"$deps" -o "$embedded" \
            "$embedded_src" -Wl,-l:libdlfrz_musl_embedded_leaf.so -ldl ||
       ! musl-gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_musl_head_caller.so \
            -Wl,-rpath,'$ORIGIN/private' -o "$caller" "$caller_src" -ldl ||
       ! musl-gcc -Wl,-rpath,'$ORIGIN/startup:$ORIGIN/head' \
            -Wl,--no-as-needed -L"$startup" -o "$main" "$main_src" \
            -Wl,-l:libdlfrz_musl_head_caller.so; then
        fail "musl direct dlopen main/head scope" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    if readelf -d "$path_root" 2>/dev/null |
            grep -E '\((RPATH|RUNPATH)\)' >/dev/null ||
       ! readelf -d "$caller" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/private' >/dev/null ||
       ! readelf -d "$main" 2>/dev/null |
            grep -E '\(RUNPATH\).*\$ORIGIN/startup.*\$ORIGIN/head' \
                >/dev/null; then
        skip "musl direct dlopen main/head scope" \
            "linker did not emit the requested search-path ownership"
        rm -rf "$root"
        return
    fi

    capture_output choice_native env -u LD_LIBRARY_PATH "$main" bare \
        libdlfrz_musl_head_choice.so dlfreeze_scope_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$choice_native" != "bare=31" ]; then
        fail "native musl dlopen main/head choice" \
            "exit=$rc output=$choice_native"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output missing_native env -u LD_LIBRARY_PATH "$main" bare \
        libdlfrz_musl_caller_only.so dlfreeze_scope_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$missing_native" != "bare=-100" ]; then
        fail "native musl dlopen ignores caller RUNPATH" \
            "exit=$rc output=$missing_native"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output path_native env -u LD_LIBRARY_PATH "$main" path \
        "$path_root" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$path_native" != "path=61" ]; then
        fail "native musl pathful root main ancestry" \
            "exit=$rc output=$path_native"
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output embedded_native env -u LD_LIBRARY_PATH \
        DLFREEZE_TEST_MUSL_NESTED=1 "$main" bare \
        libdlfrz_musl_embedded_root.so dlfreeze_embedded_value || rc=$?
    if [ "$rc" -ne 0 ] || [ "$embedded_native" != "bare=162" ]; then
        fail "native musl embedded-root nested head scope" \
            "exit=$rc output=$embedded_native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "musl direct filesystem main/head scope" \
        "$fallback_log" "$fallback_out" -t -- "$main" noop || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl direct filesystem main/head scope" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    rc=0
    capture_output choice_actual env -u LD_LIBRARY_PATH "$fallback_out" \
        bare libdlfrz_musl_head_choice.so dlfreeze_scope_value || rc=$?
    choice_actual=$(printf '%s\n' "$choice_actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$choice_actual" = "$choice_native" ]; then
        pass "musl direct bare dlopen searches main/head RUNPATH"
    else
        fail "musl direct bare dlopen main/head choice" \
            "exit=$rc expected=$choice_native output=$choice_actual"
    fi
    rc=0
    capture_output missing_actual env -u LD_LIBRARY_PATH "$fallback_out" \
        bare libdlfrz_musl_caller_only.so dlfreeze_scope_value || rc=$?
    missing_actual=$(printf '%s\n' "$missing_actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$missing_actual" = "$missing_native" ]; then
        pass "musl direct bare dlopen ignores caller RUNPATH"
    else
        fail "musl direct bare dlopen caller-only negative" \
            "exit=$rc expected=$missing_native output=$missing_actual"
    fi
    rc=0
    capture_output path_actual env -u LD_LIBRARY_PATH "$fallback_out" path \
        "$path_root" || rc=$?
    path_actual=$(printf '%s\n' "$path_actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$path_actual" = "$path_native" ]; then
        pass "musl direct pathful dlopen root inherits main/head path"
    else
        fail "musl direct pathful dlopen root ancestry" \
            "exit=$rc expected=$path_native output=$path_actual"
    fi

    freeze_rc=0
    freeze_require_direct "musl direct embedded-root head scope" \
        "$embedded_log" "$embedded_out" -t -- "$main" bare \
        libdlfrz_musl_embedded_root.so dlfreeze_embedded_value || \
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "musl direct embedded-root head scope" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    mv "$embedded" "$embedded.bak"
    mv "$leaf" "$leaf.bak"
    rc=0
    capture_output embedded_actual env -u LD_LIBRARY_PATH \
        DLFREEZE_TEST_MUSL_NESTED=1 "$embedded_out" bare \
        libdlfrz_musl_embedded_root.so dlfreeze_embedded_value || rc=$?
    mv "$embedded.bak" "$embedded"
    mv "$leaf.bak" "$leaf"
    embedded_actual=$(printf '%s\n' "$embedded_actual" |
        strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$embedded_actual" = "$embedded_native" ]; then
        pass "musl direct embedded root keeps main/head dlopen semantics"
    else
        fail "musl direct embedded-root nested head scope" \
            "exit=$rc expected=$embedded_native output=$embedded_actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9bb: ELF paths keep ';' literal; LD_LIBRARY_PATH follows target libc
# ===================================================================
test_direct_dlopen_path_delimiters() {
    echo "--- direct dlopen search-path delimiters ---"
    local root="$BUILD/dlopen_path_delimiters"
    local literal="$root/run;path" ld_dir="$root/ld-library"
    local libsrc="$root/lib.c" mainsrc="$root/main.c"
    local run_lib="$literal/libdlfrz_run_semicolon.so"
    local ld_lib="$ld_dir/libdlfrz_ld_semicolon.so"
    local run_bin="$root/main-runpath" ld_bin="$root/main-ldpath"
    local run_out="$root/main-runpath.frozen" ld_out="$root/main-ldpath.frozen"
    local run_log="$root/main-runpath.log" ld_log="$root/main-ldpath.log"
    local run_expect ld_expect run_actual ld_actual ld_path root_abs relocs
    local run_rc_e=0 ld_rc_e=0 run_rc=0 ld_rc=0
    local run_freeze_rc=0 ld_freeze_rc=0
    local ld_native_accepts_semicolon=0

    rm -rf "$root"
    mkdir -p "$literal" "$ld_dir"
    cat > "$libsrc" <<'C'
#ifndef PATH_VALUE
#define PATH_VALUE 0
#endif
int dlfreeze_path_value(void) { return PATH_VALUE; }
C
    cat > "$mainsrc" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2)
        return 10;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 11;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle,
                                               "dlfreeze_path_value");
    if (!value)
        return 12;
    printf("value=%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -DPATH_VALUE=41 \
            -Wl,-soname,libdlfrz_run_semicolon.so -o "$run_lib" "$libsrc" ||
       ! gcc -shared -fPIC -DPATH_VALUE=42 \
            -Wl,-soname,libdlfrz_ld_semicolon.so -o "$ld_lib" "$libsrc" ||
       ! gcc -Wl,--enable-new-dtags \
            -Wl,-rpath,'$ORIGIN/run;path' -o "$run_bin" "$mainsrc" -ldl ||
       ! gcc -o "$ld_bin" "$mainsrc" -ldl; then
        fail "direct-dlopen search-path delimiters" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    relocs=$(readelf -d "$run_bin" 2>/dev/null || true)
    if ! grep -Eq '\(RUNPATH\).*\$ORIGIN/run;path' <<<"$relocs"; then
        skip "direct-dlopen search-path delimiters" \
            "linker did not preserve the literal semicolon in DT_RUNPATH"
        rm -rf "$root"
        return
    fi
    root_abs=$(realpath "$root")
    ld_path="$root_abs/missing;$root_abs/ld-library"

    capture_output run_expect env -u LD_LIBRARY_PATH "$run_bin" \
        libdlfrz_run_semicolon.so || run_rc_e=$?
    capture_output ld_expect env LD_LIBRARY_PATH="$ld_path" "$ld_bin" \
        libdlfrz_ld_semicolon.so || ld_rc_e=$?
    if [ "$run_rc_e" -ne 0 ] || [ "$run_expect" != "value=41" ]; then
        fail "direct-dlopen search-path delimiters" \
            "native RUNPATH result: exit=$run_rc_e output=$run_expect"
        rm -rf "$root"
        return
    fi
    if [ "$ld_rc_e" -eq 0 ]; then
        if [ "$ld_expect" != "value=42" ]; then
            fail "direct-dlopen search-path delimiters" \
                "native LD_LIBRARY_PATH result: exit=$ld_rc_e output=$ld_expect"
            rm -rf "$root"
            return
        fi
        ld_native_accepts_semicolon=1
    fi

    freeze_require_direct "DT_RUNPATH literal semicolon" "$run_log" \
        "$run_out" "$run_bin" || run_freeze_rc=$?
    if [ "$run_freeze_rc" -eq 77 ]; then
        skip "DT_RUNPATH literal semicolon" "$DIRECT_FREEZE_REASON"
    elif [ "$run_freeze_rc" -eq 0 ]; then
        capture_output run_actual env -u LD_LIBRARY_PATH "$run_out" \
            libdlfrz_run_semicolon.so || run_rc=$?
        run_actual=$(printf '%s\n' "$run_actual" | strip_dlfreeze_warnings)
        if [ "$run_rc" -eq 0 ] && [ "$run_actual" = "$run_expect" ]; then
            pass "DT_RUNPATH keeps semicolon literal"
        else
            fail "DT_RUNPATH literal semicolon" \
                "exit=$run_rc expected=$run_expect actual=$run_actual"
        fi
    fi

    freeze_require_direct "LD_LIBRARY_PATH semicolon delimiter" "$ld_log" \
        "$ld_out" "$ld_bin" || ld_freeze_rc=$?
    if [ "$ld_freeze_rc" -eq 77 ]; then
        skip "LD_LIBRARY_PATH semicolon delimiter" "$DIRECT_FREEZE_REASON"
    elif [ "$ld_freeze_rc" -eq 0 ]; then
        capture_output ld_actual env LD_LIBRARY_PATH="$ld_path" "$ld_out" \
            libdlfrz_ld_semicolon.so || ld_rc=$?
        ld_actual=$(printf '%s\n' "$ld_actual" | strip_dlfreeze_warnings)
        if [ "$ld_native_accepts_semicolon" -eq 1 ] &&
           [ "$ld_rc" -eq 0 ] && [ "$ld_actual" = "value=42" ]; then
            pass "LD_LIBRARY_PATH accepts native semicolon delimiter"
        elif [ "$ld_native_accepts_semicolon" -eq 0 ] &&
             [ "$ld_rc" -ne 0 ] && [ "$ld_actual" != "value=42" ]; then
            pass "LD_LIBRARY_PATH matches native semicolon rejection"
        else
            fail "LD_LIBRARY_PATH semicolon delimiter" \
                "native=$ld_rc_e/$ld_expect direct=$ld_rc/$ld_actual"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9bc: runtime search consumes the complete bounded input
# ===================================================================
test_direct_dlopen_long_search_path() {
    echo "--- direct dlopen complete LD_LIBRARY_PATH search ---"
    local root="$BUILD/dlopen_long_search_path"
    local libdir="$root/provider" libsrc="$root/provider.c"
    local lib="$libdir/libdlfrz_long_search.so"
    local mainsrc="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local search="" component padded expect actual i
    local freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$libdir"
    cat > "$libsrc" <<'C'
int dlfrz_long_search_value(void) { return 129; }
C
    cat > "$mainsrc" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *handle = dlopen("libdlfrz_long_search.so", RTLD_NOW | RTLD_LOCAL);
    int (*value)(void);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    value = (int (*)(void))dlsym(handle, "dlfrz_long_search_value");
    if (!value)
        return 3;
    printf("long-search=%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_long_search.so \
            -o "$lib" "$libsrc" ||
       ! gcc -o "$bin" "$mainsrc" -ldl; then
        fail "direct complete LD_LIBRARY_PATH search" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    # The provider is deliberately both after the former 128-component cap
    # and after the former 16-KiB byte cap.  Each component remains a valid
    # kernel pathname, so native loader behavior is the only oracle needed.
    for ((i = 0; i < 140; i++)); do
        printf -v padded '%0120d' "$i"
        component="$root/missing-$padded"
        search="${search:+$search:}$component"
    done
    search="$search:$libdir"
    if [ "${#search}" -le 16384 ]; then
        fail "direct complete LD_LIBRARY_PATH search" \
            "fixture path did not cross the intended byte boundary"
        rm -rf "$root"
        return
    fi

    capture_output expect env LD_LIBRARY_PATH="$search" "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "long-search=129" ]; then
        fail "native complete LD_LIBRARY_PATH search" \
            "exit=$rc_e output=$expect"
        rm -rf "$root"
        return
    fi

    LD_LIBRARY_PATH='' freeze_require_direct \
        "direct complete LD_LIBRARY_PATH search" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct complete LD_LIBRARY_PATH search" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env LD_LIBRARY_PATH="$search" "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct loader searches complete LD_LIBRARY_PATH"
    else
        fail "direct complete LD_LIBRARY_PATH search" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9bd: late-load object names scale with the mapped object graph
# ===================================================================
test_direct_dlopen_name_storage_scaling() {
    echo "--- direct dlopen name-storage scaling ---"
    local root="$BUILD/dlopen_name_storage" libsrc="$BUILD/dlopen_name_storage.c"
    local libname="libdlfrz_name_storage.so" template="$root/libdlfrz_name_storage.so"
    local mainsrc="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local root_abs component directory expect actual i total_name_bytes=0
    local freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
int dlfrz_name_storage_value(void) { return 1; }
C
    cat > "$mainsrc" <<'C'
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define OBJECT_COUNT 40

int main(int argc, char **argv) {
    void *handles[OBJECT_COUNT];
    char path[1024];
    int sum = 0;

    if (argc != 2)
        return 2;
    memset(handles, 0, sizeof(handles));
    for (int i = 0; i < OBJECT_COUNT; i++) {
        int length = snprintf(path, sizeof(path),
            "%s/provider-%02d-%0180d/libdlfrz_name_storage.so",
            argv[1], i, i);
        if (length < 0 || (size_t)length >= sizeof(path))
            return 3;
        handles[i] = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!handles[i]) {
            fprintf(stderr, "dlopen[%d]: %s\n", i, dlerror());
            return 4;
        }
        int (*value)(void) =
            (int (*)(void))dlsym(handles[i], "dlfrz_name_storage_value");
        if (!value)
            return 5;
        sum += value();
    }
    printf("name-storage=%d\n", sum);
    return 0;
}
C
    if ! gcc -shared -fPIC -o "$template" "$libsrc" ||
       ! gcc -o "$bin" "$mainsrc" -ldl; then
        fail "direct dlopen name-storage scaling" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    root_abs=$(realpath "$root")
    for ((i = 0; i < 40; i++)); do
        printf -v component 'provider-%02d-%0180d' "$i" "$i"
        directory="$root/$component"
        mkdir -p "$directory"
        cp "$template" "$directory/libdlfrz_name_storage.so"
        total_name_bytes=$((total_name_bytes +
            ${#root_abs} + 1 + ${#component} + 1 +
            ${#libname} + 1))
    done
    if [ "$total_name_bytes" -le 8192 ]; then
        fail "direct dlopen name-storage scaling" \
            "fixture did not cross the former aggregate boundary"
        rm -rf "$root"
        return
    fi

    capture_output expect "$bin" "$root_abs" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "name-storage=40" ]; then
        fail "native dlopen name-storage scaling control" \
            "exit=$rc_e output=$expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct dlopen name-storage scaling" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dlopen name-storage scaling" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual "$out" "$root_abs" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct dlopen name storage follows object count"
    else
        fail "direct dlopen name-storage scaling" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9c: a missing DT_NEEDED edge fails dlopen before constructors
# ===================================================================
test_direct_dlopen_missing_needed() {
    echo "--- direct dlopen missing DT_NEEDED ---"
    local root="$BUILD/dlopen_missing_needed"
    local deps="$root/missing-deps"
    local dep_src="$root/dep.c" dep="$deps/libdlfrz_missing_dep.so"
    local top_src="$root/top.c" top="$root/libdlfrz_missing_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local top_abs expect actual freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$deps"
    cat > "$dep_src" <<'C'
int missing_dep_anchor(void) { return 1; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_missing_dep.so \
            -o "$dep" "$dep_src"; then
        fail "direct-dlopen missing dependency" "dependency compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$top_src" <<'C'
#include <stdio.h>
__attribute__((constructor)) static void forbidden_ctor(void) {
    puts("MISSING-DEPENDENCY-CONSTRUCTOR-RAN");
}
int missing_top_value(void) { return 7; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_missing_top.so \
            -Wl,--no-as-needed -L"$deps" -ldlfrz_missing_dep \
            -Wl,--as-needed -Wl,-rpath,'$ORIGIN/missing-deps' \
            -o "$top" "$top_src"; then
        fail "direct-dlopen missing dependency" "requester compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf -d "$top" 2>/dev/null |
            grep 'Shared library: \[libdlfrz_missing_dep.so\]' >/dev/null; then
        fail "direct-dlopen missing dependency" \
            "linker did not retain the DT_NEEDED edge"
        rm -rf "$root"
        return
    fi

    top_abs=$(realpath "$top")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    puts("missing-main-before");
    void *h = dlopen("$top_abs", RTLD_NOW);
    if (h) { puts("missing-dlopen-unexpected-success"); return 2; }
    const char *error = dlerror();
    printf("missing-dlopen-failed=%d\n", error != NULL);
    return error ? 0 : 3;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen missing dependency" "program compile failed"
        rm -rf "$root"
        return
    fi
    rm -f "$dep"
    capture_output expect env -u LD_LIBRARY_PATH "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] ||
       [[ "$expect" == *"MISSING-DEPENDENCY-CONSTRUCTOR-RAN"* ]]; then
        fail "direct-dlopen missing dependency" \
            "native fixture did not fail cleanly (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen missing dependency" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen missing dependency" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ] &&
       [[ "$actual" == *"missing-dlopen-failed=1"* ]] &&
       [[ "$actual" != *"MISSING-DEPENDENCY-CONSTRUCTOR-RAN"* ]]; then
        pass "direct-dlopen missing dependency is transactional"
    else
        fail "direct-dlopen missing dependency" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9d: relocate only after all DT_NEEDED siblings are mapped
# ===================================================================
test_direct_dlopen_sibling_scope() {
    echo "--- direct dlopen sibling symbol scope ---"
    local root="$BUILD/dlopen_sibling_scope"
    local b_src="$root/b.c" b="$root/libdlfrz_sibling_b.so"
    local c_src="$root/c.c" c="$root/libdlfrz_sibling_c.so"
    local top_src="$root/top.c" top="$root/libdlfrz_sibling_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local top_abs needed_order expect actual freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$c_src" <<'C'
int sibling_provider(void) { return 55; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_sibling_c.so \
            -o "$c" "$c_src"; then
        fail "direct-dlopen sibling scope" "provider compile failed"
        rm -rf "$root"
        return
    fi

    # B intentionally has no DT_NEEDED edge to C.  Its undefined symbol is
    # supplied by C, a later sibling in the top requester's dependency list.
    cat > "$b_src" <<'C'
extern int sibling_provider(void);
static int constructor_value;
__attribute__((constructor)) static void sibling_b_ctor(void) {
    constructor_value = sibling_provider();
}
int sibling_consumer(void) { return constructor_value + 1; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_sibling_b.so \
            -o "$b" "$b_src"; then
        fail "direct-dlopen sibling scope" "consumer compile failed"
        rm -rf "$root"
        return
    fi
    if readelf -d "$b" 2>/dev/null |
            grep 'Shared library: \[libdlfrz_sibling_c.so\]' >/dev/null; then
        fail "direct-dlopen sibling scope" \
            "consumer unexpectedly has a direct dependency on provider"
        rm -rf "$root"
        return
    fi

    cat > "$top_src" <<'C'
extern int sibling_consumer(void);
extern int sibling_provider(void);
static int top_constructor_value;
__attribute__((constructor)) static void sibling_top_ctor(void) {
    top_constructor_value = sibling_consumer();
}
int sibling_top_value(void) {
    return top_constructor_value + sibling_provider();
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_sibling_top.so \
            -Wl,--no-as-needed -L"$root" -ldlfrz_sibling_b \
            -ldlfrz_sibling_c -Wl,--as-needed -Wl,-rpath,'$ORIGIN' \
            -o "$top" "$top_src"; then
        fail "direct-dlopen sibling scope" "requester compile failed"
        rm -rf "$root"
        return
    fi
    needed_order=$(readelf -d "$top" 2>/dev/null |
        sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
        head -n 2 | tr '\n' ' ')
    if [ "$needed_order" != \
         "libdlfrz_sibling_b.so libdlfrz_sibling_c.so " ]; then
        fail "direct-dlopen sibling scope" \
            "required B-then-C sibling order was not retained: $needed_order"
        rm -rf "$root"
        return
    fi

    top_abs=$(realpath "$top")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *h = dlopen("$top_abs", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*value)(void) = (int (*)(void))dlsym(h, "sibling_top_value");
    if (!value) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
    printf("sibling-result=%d\n", value());
    return 0;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen sibling scope" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect env -u LD_LIBRARY_PATH "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "sibling-result=111" ]; then
        fail "direct-dlopen sibling scope" \
            "native fixture failed (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen sibling scope" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen sibling scope" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct-dlopen sibling symbol scope"
    else
        fail "direct-dlopen sibling scope" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9e: breadth-first root/handle lookup and handle isolation
# ===================================================================
test_direct_dlopen_bfs_scope() {
    echo "--- direct dlopen breadth-first lookup scope ---"
    local root="$BUILD/dlopen_bfs_scope"
    local c_src="$root/c.c" c="$root/libdlfrz_bfs_c.so"
    local a_src="$root/a.c" a="$root/libdlfrz_bfs_a.so"
    local b_src="$root/b.c" b="$root/libdlfrz_bfs_b.so"
    local prior_src="$root/prior.c" prior="$root/libdlfrz_bfs_prior.so"
    local top_src="$root/top.c" top="$root/libdlfrz_bfs_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local prior_abs top_abs needed_order expect actual
    local freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"

    cat > "$c_src" <<'C'
int dlfrz_bfs_collision(void) { return 300; }
int dlfrz_bfs_c_anchor(void) { return 3; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_bfs_c.so \
            -o "$c" "$c_src"; then
        fail "direct-dlopen breadth-first scope" \
            "grandchild compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$a_src" <<'C'
extern int dlfrz_bfs_c_anchor(void);
int dlfrz_bfs_a_anchor(void) { return dlfrz_bfs_c_anchor() + 10; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_bfs_a.so \
            -Wl,--no-as-needed -L"$root" -ldlfrz_bfs_c \
            -Wl,--as-needed -Wl,-rpath,'$ORIGIN' -o "$a" "$a_src"; then
        fail "direct-dlopen breadth-first scope" "parent compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$b_src" <<'C'
int dlfrz_bfs_collision(void) { return 200; }
int dlfrz_bfs_b_anchor(void) { return 20; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_bfs_b.so \
            -o "$b" "$b_src"; then
        fail "direct-dlopen breadth-first scope" "sibling compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$prior_src" <<'C'
int dlfrz_bfs_committed_provider(void) { return 77; }
int dlfrz_bfs_unrelated_only(void) { return 99; }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_bfs_prior.so \
            -o "$prior" "$prior_src"; then
        fail "direct-dlopen breadth-first scope" \
            "prior provider compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$top_src" <<'C'
extern int dlfrz_bfs_collision(void);
extern int dlfrz_bfs_a_anchor(void);
extern int dlfrz_bfs_b_anchor(void);
extern int dlfrz_bfs_committed_provider(void);
int dlfrz_bfs_relocation_value(void) { return dlfrz_bfs_collision(); }
int dlfrz_bfs_committed_value(void) {
    return dlfrz_bfs_committed_provider();
}
int dlfrz_bfs_anchor_value(void) {
    return dlfrz_bfs_a_anchor() + dlfrz_bfs_b_anchor();
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_bfs_top.so \
            -Wl,--no-as-needed -L"$root" -ldlfrz_bfs_a -ldlfrz_bfs_b \
            -Wl,--as-needed -Wl,-rpath,'$ORIGIN' \
            -Wl,-rpath-link,"$root" -Wl,--allow-shlib-undefined \
            -o "$top" "$top_src"; then
        fail "direct-dlopen breadth-first scope" "requester compile failed"
        rm -rf "$root"
        return
    fi
    needed_order=$(readelf -d "$top" 2>/dev/null |
        sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
        head -n 2 | tr '\n' ' ')
    if [ "$needed_order" != \
         "libdlfrz_bfs_a.so libdlfrz_bfs_b.so " ] ||
       readelf -d "$top" 2>/dev/null |
            grep 'Shared library: \[libdlfrz_bfs_c.so\]' >/dev/null; then
        fail "direct-dlopen breadth-first scope" \
            "required root->A,B; A->C graph was not retained: $needed_order"
        rm -rf "$root"
        return
    fi

    prior_abs=$(realpath "$prior")
    top_abs=$(realpath "$top")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *prior = dlopen("$prior_abs", RTLD_NOW | RTLD_GLOBAL);
    if (!prior) { fprintf(stderr, "prior dlopen: %s\n", dlerror()); return 1; }
    void *top = dlopen("$top_abs", RTLD_NOW);
    if (!top) { fprintf(stderr, "top dlopen: %s\n", dlerror()); return 2; }
    int (*relocation_value)(void) =
        (int (*)(void))dlsym(top, "dlfrz_bfs_relocation_value");
    int (*committed_value)(void) =
        (int (*)(void))dlsym(top, "dlfrz_bfs_committed_value");
    int (*collision)(void) =
        (int (*)(void))dlsym(top, "dlfrz_bfs_collision");
    dlerror();
    void *leak = dlsym(top, "dlfrz_bfs_unrelated_only");
    if (!relocation_value || !committed_value || !collision) {
        fprintf(stderr, "required dlsym failed\n"); return 3;
    }
    printf("bfs-reloc=%d bfs-handle=%d committed=%d leak=%d\n",
           relocation_value(), collision(), committed_value(), leak != NULL);
    return 0;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen breadth-first scope" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect env -u LD_LIBRARY_PATH "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] ||
       [ "$expect" != \
         "bfs-reloc=200 bfs-handle=200 committed=77 leak=0" ]; then
        fail "direct-dlopen breadth-first scope" \
            "native fixture failed (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen breadth-first scope" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen breadth-first scope" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct-dlopen breadth-first lookup scope"
    else
        fail "direct-dlopen breadth-first scope" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# DT_SYMBOLIC and DF_SYMBOLIC change only the requesting DSO's relocation
# scope; they must not be approximated by link-time -Bsymbolic binding.  Keep
# real preemptible relocations in the fixture, derive the target libc's native
# policy from controls, and exercise both startup and traced-dlopen objects.
test_direct_symbolic_lookup_scope() {
    echo "--- direct DT_SYMBOLIC/DF_SYMBOLIC relocation scope ---"
    local root="$BUILD/direct_symbolic_scope"
    local lib_src="$root/library.c" mut_src="$root/mutate.c"
    local startup_src="$root/startup.c" dlopen_src="$root/dlopen.c"
    local mut="$root/mutate" dlopen_bin="$root/dlopen"
    local mode dir lib lib_abs bin out log actual expect
    local rc=0 rc_e=0 freeze_rc=0 startup_ready=0 dlopen_ready=0
    local normal_startup normal_dlopen legacy_expect flags_expect dynamic
    local -A native_startup=() native_dlopen=()

    rm -rf "$root"
    mkdir -p "$root"
    if ! command -v readelf >/dev/null 2>&1; then
        skip "direct symbolic relocation scope" "readelf not installed"
        return
    fi

    cat > "$lib_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>

__attribute__((noinline, visibility("default")))
int dlfrz_symbolic_collision(void) { return 22; }

/* Deliberately collide with a loader-owned shim as well as an ordinary
 * symbol.  A symbolic self-definition must win before shim substitution. */
__attribute__((noinline, visibility("default")))
int dladdr(const void *address, Dl_info *info) {
    (void)address;
    (void)info;
    return 22;
}

static int (* volatile collision_slot)(void) = dlfrz_symbolic_collision;

int dlfrz_symbolic_probe(void) {
    Dl_info info;
    return collision_slot() + dlfrz_symbolic_collision() +
           dladdr((const void *)&dlfrz_symbolic_collision, &info);
}
C

    cat > "$startup_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

extern int dlfrz_symbolic_probe(void);
int dlfrz_symbolic_collision(void) { return 11; }
int dladdr(const void *address, Dl_info *info) {
    (void)address;
    (void)info;
    return 11;
}

int main(void) {
    printf("symbolic=%d\n", dlfrz_symbolic_probe());
    return 0;
}
C

    cat > "$dlopen_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int dlfrz_symbolic_collision(void) { return 11; }
int dladdr(const void *address, Dl_info *info) {
    (void)address;
    (void)info;
    return 11;
}

int main(int argc, char **argv) {
    int (*probe)(void);
    void *handle;

    if (argc != 2)
        return 2;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    probe = (int (*)(void))dlsym(handle, "dlfrz_symbolic_probe");
    if (!probe) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 4;
    }
    printf("symbolic=%d\n", probe());
    return 0;
}
C

    cat > "$mut_src" <<'C'
#include <elf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DF_SYMBOLIC
#define DF_SYMBOLIC 0x00000002
#endif

int main(int argc, char **argv) {
    Elf64_Ehdr eh;
    Elf64_Phdr *phdrs = NULL;
    Elf64_Phdr dynamic_ph = {0};
    Elf64_Dyn *dynamic = NULL;
    FILE *file = NULL;
    long file_size;
    size_t dynamic_count;
    size_t null_index = SIZE_MAX;
    size_t flags_index = SIZE_MAX;
    size_t target_index;
    int dynamic_segments = 0;
    int result = 1;

    if (argc != 3 ||
        (strcmp(argv[1], "legacy") != 0 &&
         strcmp(argv[1], "flags") != 0))
        return 1;
    file = fopen(argv[2], "r+b");
    if (!file || fread(&eh, 1, sizeof(eh), file) != sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ident[EI_VERSION] != EV_CURRENT ||
        eh.e_type != ET_DYN || eh.e_version != EV_CURRENT ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum == PN_XNUM || eh.e_phoff > LONG_MAX)
        goto done;
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
        eh.e_phoff > (uint64_t)file_size ||
        eh.e_phnum > ((uint64_t)file_size - eh.e_phoff) / sizeof(*phdrs))
        goto done;
    phdrs = calloc(eh.e_phnum, sizeof(*phdrs));
    if (!phdrs || fseek(file, (long)eh.e_phoff, SEEK_SET) != 0 ||
        fread(phdrs, sizeof(*phdrs), eh.e_phnum, file) != eh.e_phnum)
        goto done;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dynamic_ph = phdrs[i];
            dynamic_segments++;
        }
    }
    if (dynamic_segments != 1 || dynamic_ph.p_filesz == 0 ||
        dynamic_ph.p_filesz % sizeof(Elf64_Dyn) != 0 ||
        dynamic_ph.p_offset > (uint64_t)file_size ||
        dynamic_ph.p_filesz > (uint64_t)file_size - dynamic_ph.p_offset ||
        dynamic_ph.p_offset > LONG_MAX)
        goto done;
    dynamic_count = (size_t)(dynamic_ph.p_filesz / sizeof(Elf64_Dyn));
    dynamic = calloc(dynamic_count, sizeof(*dynamic));
    if (!dynamic || fseek(file, (long)dynamic_ph.p_offset, SEEK_SET) != 0 ||
        fread(dynamic, sizeof(*dynamic), dynamic_count, file) != dynamic_count)
        goto done;
    for (size_t i = 0; i < dynamic_count; i++) {
        if (dynamic[i].d_tag == DT_NULL) {
            null_index = i;
            break;
        }
        if (dynamic[i].d_tag == DT_SYMBOLIC ||
            (dynamic[i].d_tag == DT_FLAGS &&
             (dynamic[i].d_un.d_val & DF_SYMBOLIC) != 0))
            goto done;
        if (dynamic[i].d_tag == DT_FLAGS) {
            if (flags_index != SIZE_MAX)
                goto done;
            flags_index = i;
        }
    }
    if (null_index == SIZE_MAX)
        goto done;

    if (strcmp(argv[1], "legacy") == 0) {
        if (null_index + 1 >= dynamic_count ||
            dynamic[null_index + 1].d_tag != DT_NULL)
            goto done;
        target_index = null_index;
        dynamic[target_index].d_tag = DT_SYMBOLIC;
        dynamic[target_index].d_un.d_val = 0;
    } else if (flags_index != SIZE_MAX) {
        target_index = flags_index;
        dynamic[target_index].d_un.d_val |= DF_SYMBOLIC;
    } else {
        if (null_index + 1 >= dynamic_count ||
            dynamic[null_index + 1].d_tag != DT_NULL)
            goto done;
        target_index = null_index;
        dynamic[target_index].d_tag = DT_FLAGS;
        dynamic[target_index].d_un.d_val = DF_SYMBOLIC;
    }

    if (dynamic_ph.p_offset > (uint64_t)LONG_MAX -
            target_index * sizeof(*dynamic) ||
        fseek(file, (long)(dynamic_ph.p_offset +
              target_index * sizeof(*dynamic)), SEEK_SET) != 0 ||
        fwrite(&dynamic[target_index], 1, sizeof(*dynamic), file) !=
            sizeof(*dynamic) || fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;
    result = 0;

done:
    if (file)
        fclose(file);
    free(dynamic);
    free(phdrs);
    return result;
}
C

    if ! gcc -std=c11 -Wall -Wextra -Werror -o "$mut" "$mut_src" ||
       ! gcc -rdynamic -o "$dlopen_bin" "$dlopen_src" -ldl; then
        fail "direct symbolic relocation scope" "fixture tools failed to compile"
        rm -rf "$root"
        return
    fi

    for mode in normal legacy flags; do
        dir="$root/lib-$mode"
        lib="$dir/libdlfrz_symbolic.so"
        bin="$root/startup-$mode"
        mkdir -p "$dir"
        if ! gcc -shared -fPIC -fsemantic-interposition \
                -Wl,-soname,libdlfrz_symbolic.so -o "$lib" "$lib_src"; then
            fail "direct symbolic relocation scope ($mode)" \
                "shared-object compile failed"
            rm -rf "$root"
            return
        fi
        if [ "$mode" != normal ] && ! "$mut" "$mode" "$lib"; then
            skip "direct symbolic relocation scope" \
                "toolchain PT_DYNAMIC has no spare bounded tag slot"
            rm -rf "$root"
            return
        fi
        dynamic=$(LC_ALL=C readelf -d "$lib" 2>/dev/null || true)
        case "$mode" in
            normal)
                if grep -Eq '\(SYMBOLIC\)|\(FLAGS\).*SYMBOLIC' \
                        <<<"$dynamic"; then
                    fail "direct symbolic relocation scope" \
                        "normal control unexpectedly has symbolic metadata"
                    rm -rf "$root"
                    return
                fi
                ;;
            legacy)
                if ! grep -q '\(SYMBOLIC\)' <<<"$dynamic"; then
                    fail "direct DT_SYMBOLIC relocation scope" \
                        "mutator did not emit DT_SYMBOLIC"
                    rm -rf "$root"
                    return
                fi
                ;;
            flags)
                if ! grep -Eq '\(FLAGS\).*SYMBOLIC' <<<"$dynamic"; then
                    fail "direct DF_SYMBOLIC relocation scope" \
                        "mutator did not emit DT_FLAGS/DF_SYMBOLIC"
                    rm -rf "$root"
                    return
                fi
                ;;
        esac
        if ! LC_ALL=C readelf -rW "$lib" 2>/dev/null |
                grep 'dlfrz_symbolic_collision' >/dev/null ||
           ! LC_ALL=C readelf -rW "$lib" 2>/dev/null |
                grep 'dladdr' >/dev/null; then
            fail "direct symbolic relocation scope ($mode)" \
                "linker eliminated the dynamic lookup fixture"
            rm -rf "$root"
            return
        fi
        if ! gcc -rdynamic -Wl,--no-as-needed -L"$dir" \
                -ldlfrz_symbolic -Wl,--as-needed \
                "-Wl,-rpath,\$ORIGIN/lib-$mode" \
                -o "$bin" "$startup_src"; then
            fail "direct symbolic relocation scope ($mode)" \
                "startup fixture compile failed"
            rm -rf "$root"
            return
        fi

        actual=""; rc_e=0
        capture_output actual env -u LD_LIBRARY_PATH "$bin" || rc_e=$?
        native_startup["$mode"]=$actual
        if [ "$rc_e" -ne 0 ]; then
            fail "native symbolic startup scope ($mode)" \
                "exit=$rc_e output=$actual"
            rm -rf "$root"
            return
        fi
        actual=""; rc_e=0
        lib_abs=$(realpath "$lib")
        capture_output actual env -u LD_LIBRARY_PATH "$dlopen_bin" \
            "$lib_abs" || rc_e=$?
        native_dlopen["$mode"]=$actual
        if [ "$rc_e" -ne 0 ]; then
            fail "native symbolic dlopen scope ($mode)" \
                "exit=$rc_e output=$actual"
            rm -rf "$root"
            return
        fi
    done

    normal_startup=${native_startup[normal]}
    normal_dlopen=${native_dlopen[normal]}
    legacy_expect=${native_startup[legacy]}
    flags_expect=${native_startup[flags]}
    if [ "$normal_startup" != "symbolic=33" ] ||
       [ "$normal_dlopen" != "$normal_startup" ]; then
        fail "native symbolic relocation scope" \
            "invalid normal controls: startup=$normal_startup dlopen=$normal_dlopen"
        rm -rf "$root"
        return
    fi
    if { [ "$legacy_expect" != "symbolic=33" ] &&
         [ "$legacy_expect" != "symbolic=66" ]; } ||
       [ "$flags_expect" != "$legacy_expect" ] ||
       [ "${native_dlopen[legacy]}" != "$legacy_expect" ] ||
       [ "${native_dlopen[flags]}" != "$flags_expect" ]; then
        fail "native symbolic relocation scope" \
            "encodings disagree: legacy=${native_startup[legacy]}/${native_dlopen[legacy]} flags=${native_startup[flags]}/${native_dlopen[flags]}"
        rm -rf "$root"
        return
    fi

    for mode in legacy flags; do
        dir="$root/lib-$mode"
        lib="$dir/libdlfrz_symbolic.so"
        lib_abs=$(realpath "$lib")
        bin="$root/startup-$mode"
        expect=${native_startup[$mode]}
        startup_ready=0
        dlopen_ready=0

        out="$root/startup-$mode.frozen"
        log="$root/startup-$mode.log"
        freeze_rc=0
        freeze_require_direct "direct symbolic startup scope ($mode)" \
            "$log" "$out" "$bin" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "direct symbolic startup scope ($mode)" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            startup_ready=1
        fi

        out="$root/dlopen-$mode.frozen"
        log="$root/dlopen-$mode.log"
        freeze_rc=0
        freeze_require_direct "direct symbolic dlopen scope ($mode)" \
            "$log" "$out" -t -- "$dlopen_bin" "$lib_abs" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "direct symbolic dlopen scope ($mode)" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            dlopen_ready=1
        fi

        mv "$lib" "$lib.removed"
        if [ "$startup_ready" -eq 1 ]; then
            out="$root/startup-$mode.frozen"
            actual=""; rc=0
            capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
                pass "direct symbolic startup scope ($mode)"
            else
                fail "direct symbolic startup scope ($mode)" \
                    "exit=$rc expected=$expect actual=$actual"
            fi
        fi
        if [ "$dlopen_ready" -eq 1 ]; then
            out="$root/dlopen-$mode.frozen"
            actual=""; rc=0
            capture_output actual env -u LD_LIBRARY_PATH "$out" \
                "$lib_abs" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
                pass "direct symbolic dlopen scope ($mode)"
            else
                fail "direct symbolic dlopen scope ($mode)" \
                    "exit=$rc expected=$expect actual=$actual"
            fi
        fi
    done
    rm -rf "$root"
}

# ===================================================================
# Test 9f: sibling IFUNC sees later-sibling ordinary data relocations
# ===================================================================
test_direct_dlopen_ifunc_data_order() {
    echo "--- direct dlopen IFUNC/data phase ordering ---"
    local root="$BUILD/dlopen_ifunc_data_order"
    local b_src="$root/b.c" b="$root/libdlfrz_ifunc_b.so"
    local c_src="$root/c.c" c="$root/libdlfrz_ifunc_c.so"
    local top_src="$root/top.c" top="$root/libdlfrz_ifunc_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local top_abs needed_order expect actual freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$c_src" <<'C'
int ifunc_data_target = 73;
int * volatile ifunc_data_pointer = &ifunc_data_target;

static int ifunc_good(void) { return *ifunc_data_pointer; }
static int ifunc_bad(void) { return -1; }
static void *ifunc_resolver(void) {
    int *pointer = ifunc_data_pointer;
    return pointer && *pointer == 73 ? (void *)ifunc_good : (void *)ifunc_bad;
}
int ifunc_data_selected(void) __attribute__((ifunc("ifunc_resolver")));
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_ifunc_c.so \
            -o "$c" "$c_src"; then
        if compiler_supports_gnu_ifunc "$root"; then
            fail "direct-dlopen IFUNC/data ordering" \
                "provider compile failed"
        else
            skip "direct-dlopen IFUNC/data ordering" \
                "target toolchain does not support GNU IFUNC"
        fi
        rm -rf "$root"
        return
    fi
    if ! readelf -r "$c" 2>/dev/null |
            grep 'ifunc_data_target' >/dev/null; then
        skip "direct-dlopen IFUNC/data ordering" \
            "toolchain did not emit the required data relocation"
        rm -rf "$root"
        return
    fi

    cat > "$b_src" <<'C'
extern int ifunc_data_selected(void);
int ifunc_sibling_call(void) { return ifunc_data_selected(); }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_ifunc_b.so \
            -o "$b" "$b_src"; then
        fail "direct-dlopen IFUNC/data ordering" "consumer compile failed"
        rm -rf "$root"
        return
    fi

    cat > "$top_src" <<'C'
extern int ifunc_sibling_call(void);
int ifunc_top_value(void) { return ifunc_sibling_call(); }
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_ifunc_top.so \
            -Wl,--no-as-needed -L"$root" -ldlfrz_ifunc_b \
            -ldlfrz_ifunc_c -Wl,--as-needed -Wl,-rpath,'$ORIGIN' \
            -Wl,--allow-shlib-undefined -o "$top" "$top_src"; then
        fail "direct-dlopen IFUNC/data ordering" "requester compile failed"
        rm -rf "$root"
        return
    fi
    needed_order=$(readelf -d "$top" 2>/dev/null |
        sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
        head -n 2 | tr '\n' ' ')
    if [ "$needed_order" != \
         "libdlfrz_ifunc_b.so libdlfrz_ifunc_c.so " ]; then
        fail "direct-dlopen IFUNC/data ordering" \
            "required B-then-C sibling order was not retained: $needed_order"
        rm -rf "$root"
        return
    fi

    top_abs=$(realpath "$top")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *h = dlopen("$top_abs", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*value)(void) = (int (*)(void))dlsym(h, "ifunc_top_value");
    if (!value) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
    printf("ifunc-data-result=%d\n", value());
    return 0;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen IFUNC/data ordering" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect env -u LD_LIBRARY_PATH "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "ifunc-data-result=73" ]; then
        fail "direct-dlopen IFUNC/data ordering" \
            "native fixture failed (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen IFUNC/data ordering" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen IFUNC/data ordering" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env -u LD_LIBRARY_PATH "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct-dlopen IFUNC sees relocated sibling data"
    else
        fail "direct-dlopen IFUNC/data ordering" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9f: executable COPY storage is initialized before IFUNC runs
# ===================================================================
test_direct_copy_ifunc_order() {
    echo "--- direct COPY/IFUNC phase ordering ---"
    local root="$BUILD/copy_ifunc_order"
    local lib_src="$root/lib.c" lib="$root/libdlfrz_copy_ifunc.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local expect actual relocs freeze_rc=0 rc_e=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$lib_src" <<'C'
int copy_ifunc_value = 7;
static int copy_ifunc_good(void) { return 73; }
static int copy_ifunc_bad(void) { return -1; }
static void *copy_ifunc_resolver(void) {
    return copy_ifunc_value == 7
        ? (void *)copy_ifunc_good : (void *)copy_ifunc_bad;
}
int copy_ifunc_selected(void)
    __attribute__((ifunc("copy_ifunc_resolver")));
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_copy_ifunc.so \
            -o "$lib" "$lib_src"; then
        if compiler_supports_gnu_ifunc "$root"; then
            fail "direct COPY/IFUNC ordering" "provider compile failed"
        else
            skip "direct COPY/IFUNC ordering" \
                "target toolchain does not support GNU IFUNC"
        fi
        rm -rf "$root"
        return
    fi

    cat > "$prog_src" <<'C'
#include <stdio.h>
extern int copy_ifunc_value;
extern int copy_ifunc_selected(void);
int main(void) {
    int selected = copy_ifunc_selected();
    printf("copy-ifunc=%d value=%d\n", selected, copy_ifunc_value);
    return selected == 73 && copy_ifunc_value == 7 ? 0 : 99;
}
C
    if ! gcc -fno-pie -no-pie -Wl,-z,now -o "$prog" "$prog_src" \
            -L"$root" -Wl,-rpath,'$ORIGIN' -ldlfrz_copy_ifunc; then
        fail "direct COPY/IFUNC ordering" "program compile failed"
        rm -rf "$root"
        return
    fi
    relocs=$(readelf -Wr "$prog" 2>/dev/null || true)
    if ! grep -q 'COPY.*copy_ifunc_value' <<<"$relocs"; then
        skip "direct COPY/IFUNC ordering" \
            "toolchain did not emit the required COPY relocation"
        rm -rf "$root"
        return
    fi
    capture_output expect "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "copy-ifunc=73 value=7" ]; then
        fail "direct COPY/IFUNC ordering" \
            "native fixture failed (exit $rc_e): $expect"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct COPY/IFUNC ordering" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct COPY/IFUNC ordering" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "direct COPY precedes IFUNC resolvers"
    else
        fail "direct COPY/IFUNC ordering" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9f: every public dlsym of an IFUNC performs fresh resolution
# ===================================================================
test_direct_dlsym_ifunc_repeated_resolution() {
    echo "--- direct repeated dlsym IFUNC resolution ---"
    local root="$BUILD/dlsym_ifunc_repeated"
    local src="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local expect actual freeze_rc=0 native_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! compiler_supports_gnu_ifunc "$root"; then
        skip "direct repeated dlsym IFUNC resolution" \
            "target toolchain/runtime does not support GNU IFUNC"
        rm -rf "$root"
        return
    fi

    cat > "$src" <<'C'
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdio.h>

typedef int (*ifunc_fn)(void);
static volatile unsigned int resolver_calls;

static int selected_implementation(void) { return 73; }
static ifunc_fn repeated_resolver(void)
{
    resolver_calls++;
    return selected_implementation;
}
__attribute__((visibility("default")))
int dlfreeze_repeated_ifunc(void)
    __attribute__((ifunc("repeated_resolver")));

static ifunc_fn lookup(void *handle)
{
    const char *error;
    ifunc_fn result;

    (void)dlerror();
    result = (ifunc_fn)dlsym(handle, "dlfreeze_repeated_ifunc");
    error = dlerror();
    if (error)
        fprintf(stderr, "dlsym: %s\n", error);
    return error ? NULL : result;
}

int main(void)
{
    void *self = dlopen(NULL, RTLD_NOW | RTLD_LOCAL);
    ifunc_fn functions[4];
    int values[4];
    int same;

    if (!self) {
        fprintf(stderr, "dlopen(NULL): %s\n", dlerror());
        return 2;
    }
    functions[0] = lookup(RTLD_DEFAULT);
    functions[1] = lookup(RTLD_DEFAULT);
    functions[2] = lookup(self);
    functions[3] = lookup(self);
    for (unsigned int i = 0; i < 4; i++) {
        if (!functions[i])
            return 3;
        values[i] = functions[i]();
    }
    same = functions[0] == functions[1] &&
           functions[0] == functions[2] &&
           functions[0] == functions[3];
    printf("calls=%u same=%d values=%d,%d,%d,%d\n",
           resolver_calls, same, values[0], values[1], values[2], values[3]);
    return same && values[0] == 73 && values[1] == 73 &&
           values[2] == 73 && values[3] == 73 ? 0 : 4;
}
C
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -rdynamic \
            -Wl,-z,now -o "$bin" "$src" -ldl; then
        fail "direct repeated dlsym IFUNC resolution" \
            "program compile failed after successful IFUNC probe"
        rm -rf "$root"
        return
    fi

    capture_output expect "$bin" || native_rc=$?
    if [ "$native_rc" -ne 0 ]; then
        fail "direct repeated dlsym IFUNC resolution" \
            "native fixture failed (exit=$native_rc output=$expect)"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct repeated dlsym IFUNC resolution" \
        "$log" "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct repeated dlsym IFUNC resolution" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "repeated RTLD_DEFAULT/global-handle dlsym resolves IFUNC anew"
    else
        fail "direct repeated dlsym IFUNC resolution" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# GNU/glibc gives binding-10 objects one owner across independent local
# groups.  TLS identity includes the canonical module ID, and public lookup
# APIs must return that same owner even when their handle first selects the
# other group's definition.
# ===================================================================
test_direct_gnu_unique_local_scopes() {
    echo "--- direct GNU-unique local-scope identity ---"
    local root="$BUILD/gnu_unique_local_scopes"
    local lib_src="$root/owner.cc" map="$root/owner.map"
    local lib_a="$root/libgnu_unique_a.so"
    local lib_b="$root/libgnu_unique_b.so"
    local main_src="$root/main.c" main="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local cxx expect actual freeze_rc=0 native_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cxx=$(command -v g++ || true)
    if [ -z "$cxx" ]; then
        skip "direct GNU-unique local-scope identity" "g++ not installed"
        return
    fi

    cat > "$lib_src" <<'CXX'
#define DLFRZ_JOIN_INNER(a, b) a##b
#define DLFRZ_JOIN(a, b) DLFRZ_JOIN_INNER(a, b)
extern "C" {
inline __attribute__((visibility("default")))
int dlfreeze_unique_object = OBJECT_INITIAL;
inline __attribute__((visibility("default"))) thread_local
int dlfreeze_unique_tls = TLS_INITIAL;

__attribute__((visibility("default")))
int *DLFRZ_JOIN(unique_object_address_, OWNER_SUFFIX)()
{
    return &dlfreeze_unique_object;
}
__attribute__((visibility("default")))
int *DLFRZ_JOIN(unique_tls_address_, OWNER_SUFFIX)()
{
    return &dlfreeze_unique_tls;
}
}
CXX
    cat > "$map" <<'MAP'
DLFREEZE_UNIQUE_1 {
    global:
        dlfreeze_unique_object;
        dlfreeze_unique_tls;
        unique_object_address_*;
        unique_tls_address_*;
    local: *;
};
MAP
    if ! "$cxx" -std=c++17 -Wall -Wextra -Werror -O2 -shared -fPIC \
            -DOWNER_SUFFIX=a -DOBJECT_INITIAL=11 -DTLS_INITIAL=31 \
            -Wl,-z,now -Wl,--version-script="$map" \
            -Wl,-soname,libgnu_unique_a.so -o "$lib_a" "$lib_src" ||
       ! "$cxx" -std=c++17 -Wall -Wextra -Werror -O2 -shared -fPIC \
            -DOWNER_SUFFIX=b -DOBJECT_INITIAL=22 -DTLS_INITIAL=41 \
            -Wl,-z,now -Wl,--version-script="$map" \
            -Wl,-soname,libgnu_unique_b.so -o "$lib_b" "$lib_src"; then
        fail "direct GNU-unique local-scope identity" \
            "C++ provider compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf -Ws "$lib_a" 2>/dev/null |
            grep -E 'OBJECT[[:space:]]+UNIQUE.*dlfreeze_unique_object' \
                >/dev/null ||
       ! readelf -Ws "$lib_a" 2>/dev/null |
            grep -E 'TLS[[:space:]]+UNIQUE.*dlfreeze_unique_tls' \
                >/dev/null; then
        skip "direct GNU-unique local-scope identity" \
            "toolchain did not emit STB_GNU_UNIQUE object and TLS definitions"
        rm -rf "$root"
        return
    fi

    cat > "$main_src" <<'C'
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

typedef int *(*address_fn)(void);
struct thread_args {
    void *a;
    void *b;
    address_fn tls_a;
    address_fn tls_b;
};

static void *thread_main(void *opaque)
{
    struct thread_args *args = opaque;
    int *accessor_a = args->tls_a();
    int *accessor_b = args->tls_b();
    int *dlsym_a = dlsym(args->a, "dlfreeze_unique_tls");
    int *dlsym_b = dlsym(args->b, "dlfreeze_unique_tls");
    int *dlvsym_a = dlvsym(args->a, "dlfreeze_unique_tls",
                           "DLFREEZE_UNIQUE_1");
    int *dlvsym_b = dlvsym(args->b, "dlfreeze_unique_tls",
                           "DLFREEZE_UNIQUE_1");

    return accessor_a && accessor_a == accessor_b &&
           accessor_a == dlsym_a && accessor_a == dlsym_b &&
           accessor_a == dlvsym_a && accessor_a == dlvsym_b &&
           *accessor_a == 31 ? NULL : (void *)1;
}

int main(int argc, char **argv)
{
    void *a;
    void *b;
    address_fn object_a;
    address_fn object_b;
    address_fn tls_a;
    address_fn tls_b;
    int *object_symbol_a;
    int *object_symbol_b;
    int *tls_symbol_a;
    int *tls_symbol_b;
    int *object_version_a;
    int *object_version_b;
    int *tls_version_a;
    int *tls_version_b;
    pthread_t thread;
    void *thread_result = (void *)1;
    struct thread_args args;
    int object_same;
    int tls_same;
    int api_object_same;
    int api_tls_same;
    int version_object_same;
    int version_tls_same;

    if (argc != 3)
        return 2;
    a = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    b = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!a || !b) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    object_a = (address_fn)dlsym(a, "unique_object_address_a");
    object_b = (address_fn)dlsym(b, "unique_object_address_b");
    tls_a = (address_fn)dlsym(a, "unique_tls_address_a");
    tls_b = (address_fn)dlsym(b, "unique_tls_address_b");
    if (!object_a || !object_b || !tls_a || !tls_b)
        return 4;

    object_symbol_a = dlsym(a, "dlfreeze_unique_object");
    object_symbol_b = dlsym(b, "dlfreeze_unique_object");
    tls_symbol_a = dlsym(a, "dlfreeze_unique_tls");
    tls_symbol_b = dlsym(b, "dlfreeze_unique_tls");
    object_version_a = dlvsym(a, "dlfreeze_unique_object",
                              "DLFREEZE_UNIQUE_1");
    object_version_b = dlvsym(b, "dlfreeze_unique_object",
                              "DLFREEZE_UNIQUE_1");
    tls_version_a = dlvsym(a, "dlfreeze_unique_tls",
                           "DLFREEZE_UNIQUE_1");
    tls_version_b = dlvsym(b, "dlfreeze_unique_tls",
                           "DLFREEZE_UNIQUE_1");
    object_same = object_a() == object_b() && *object_a() == 11;
    tls_same = tls_a() == tls_b() && *tls_a() == 31;
    api_object_same = object_symbol_a && object_symbol_a == object_symbol_b &&
                      object_symbol_a == object_a();
    api_tls_same = tls_symbol_a && tls_symbol_a == tls_symbol_b &&
                   tls_symbol_a == tls_a();
    version_object_same = object_version_a &&
                          object_version_a == object_version_b &&
                          object_version_a == object_a();
    version_tls_same = tls_version_a && tls_version_a == tls_version_b &&
                       tls_version_a == tls_a();
    args.a = a;
    args.b = b;
    args.tls_a = tls_a;
    args.tls_b = tls_b;
    if (pthread_create(&thread, NULL, thread_main, &args) != 0 ||
        pthread_join(thread, &thread_result) != 0)
        return 5;
    printf("object=%d tls=%d dlsym-object=%d dlsym-tls=%d "
           "dlvsym-object=%d dlvsym-tls=%d thread=%d\n",
           object_same, tls_same, api_object_same, api_tls_same,
           version_object_same, version_tls_same, thread_result == NULL);
    return object_same && tls_same && api_object_same && api_tls_same &&
           version_object_same && version_tls_same && thread_result == NULL
               ? 0 : 6;
}
C
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -pthread \
            -o "$main" "$main_src" -ldl; then
        fail "direct GNU-unique local-scope identity" \
            "program compile failed"
        rm -rf "$root"
        return
    fi
    if ! file "$main" 2>/dev/null | grep 'interpreter .*ld-linux' >/dev/null;
    then
        skip "direct GNU-unique local-scope identity" \
            "test compiler does not target glibc"
        rm -rf "$root"
        return
    fi

    capture_output expect "$main" "$lib_a" "$lib_b" || native_rc=$?
    if [ "$native_rc" -ne 0 ]; then
        fail "direct GNU-unique local-scope identity" \
            "native fixture failed (exit=$native_rc output=$expect)"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "direct GNU-unique local-scope identity" \
        "$log" "$out" -t -- "$main" "$lib_a" "$lib_b" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct GNU-unique local-scope identity" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$lib_a" "${lib_a}.source"
    mv "$lib_b" "${lib_b}.source"
    capture_output actual "$out" "$lib_a" "$lib_b" || rc=$?
    mv "${lib_a}.source" "$lib_a"
    mv "${lib_b}.source" "$lib_b"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "GNU-unique object identity crosses RTLD_LOCAL scopes"
        pass "GNU-unique TLS owner crosses RTLD_LOCAL scopes and threads"
        pass "dlsym/dlvsym preserve GNU-unique canonical ownership"
    else
        fail "direct GNU-unique local-scope identity" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# A failed group must not leave its staged GNU-unique owner pointing into an
# unmapped DSO.  A subsequent independent local group becomes the first
# successful canonical owner just as it does under native glibc.
test_direct_gnu_unique_transaction_rollback() {
    echo "--- direct GNU-unique transaction rollback ---"
    local root="$BUILD/gnu_unique_rollback"
    local unique_src="$root/failed-owner.cc"
    local bad_src="$root/bad.c" root_src="$root/root.c"
    local good_src="$root/good-owner.cc" main_src="$root/main.c"
    local failed_owner="$root/libunique_failed_owner.so"
    local bad="$root/libunique_bad.so" failed_root="$root/libunique_root.so"
    local good="$root/libunique_good_owner.so" main="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local cxx expect actual freeze_rc=0 native_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cxx=$(command -v g++ || true)
    if [ -z "$cxx" ]; then
        skip "direct GNU-unique transaction rollback" "g++ not installed"
        return
    fi
    cat > "$unique_src" <<'CXX'
extern "C" {
inline int dlfreeze_rollback_unique = 61;
int *failed_unique_address(void) { return &dlfreeze_rollback_unique; }
}
CXX
    cat > "$good_src" <<'CXX'
extern "C" {
inline int dlfreeze_rollback_unique = 71;
int *good_unique_address(void) { return &dlfreeze_rollback_unique; }
}
CXX
    cat > "$bad_src" <<'C'
extern int dlfreeze_rollback_missing_definition;
int unique_bad_value(void) { return dlfreeze_rollback_missing_definition; }
C
    cat > "$root_src" <<'C'
extern int *failed_unique_address(void);
extern int unique_bad_value(void);
int unique_root_value(void) {
    return *failed_unique_address() + unique_bad_value();
}
C
    if ! "$cxx" -std=c++17 -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-z,now -Wl,-soname,libunique_failed_owner.so \
            -o "$failed_owner" "$unique_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC -Wl,-z,now \
            -Wl,-soname,libunique_bad.so -o "$bad" "$bad_src" ||
       ! gcc -Wall -Wextra -Werror -O2 -shared -fPIC -Wl,-z,now \
            -Wl,-soname,libunique_root.so -Wl,--no-as-needed \
            -L"$root" -Wl,-rpath,'$ORIGIN' -o "$failed_root" "$root_src" \
            -lunique_failed_owner -lunique_bad ||
       ! "$cxx" -std=c++17 -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-z,now -Wl,-soname,libunique_good_owner.so \
            -o "$good" "$good_src"; then
        fail "direct GNU-unique transaction rollback" \
            "provider compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf -Ws "$failed_owner" 2>/dev/null |
            grep -E 'OBJECT[[:space:]]+UNIQUE.*dlfreeze_rollback_unique' \
                >/dev/null ||
       ! readelf -Ws "$good" 2>/dev/null |
            grep -E 'OBJECT[[:space:]]+UNIQUE.*dlfreeze_rollback_unique' \
                >/dev/null; then
        skip "direct GNU-unique transaction rollback" \
            "toolchain did not emit STB_GNU_UNIQUE definitions"
        rm -rf "$root"
        return
    fi
    cat > "$main_src" <<'C'
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
typedef int *(*address_fn)(void);
int main(int argc, char **argv) {
    void *failed;
    void *good;
    address_fn address;
    int *symbol;
    int saved_stderr;
    int nullfd;
    if (argc != 3)
        return 2;
    saved_stderr = dup(STDERR_FILENO);
    nullfd = open("/dev/null", O_WRONLY);
    if (saved_stderr < 0 || nullfd < 0 ||
        dup2(nullfd, STDERR_FILENO) < 0)
        return 7;
    close(nullfd);
    failed = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (dup2(saved_stderr, STDERR_FILENO) < 0)
        return 8;
    close(saved_stderr);
    if (failed) {
        puts("failed-group-loaded");
        return 3;
    }
    (void)dlerror();
    good = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!good) {
        fprintf(stderr, "good dlopen: %s\n", dlerror());
        return 4;
    }
    address = (address_fn)dlsym(good, "good_unique_address");
    symbol = dlsym(good, "dlfreeze_rollback_unique");
    if (!address || !symbol)
        return 5;
    printf("rollback=%d value=%d\n", address() == symbol, *address());
    return address() == symbol && *address() == 71 ? 0 : 6;
}
C
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
            -o "$main" "$main_src" -ldl; then
        fail "direct GNU-unique transaction rollback" \
            "program compile failed"
        rm -rf "$root"
        return
    fi
    if ! file "$main" 2>/dev/null | grep 'interpreter .*ld-linux' >/dev/null;
    then
        skip "direct GNU-unique transaction rollback" \
            "test compiler does not target glibc"
        rm -rf "$root"
        return
    fi

    capture_output expect env -u LD_LIBRARY_PATH "$main" \
        "$failed_root" "$good" || native_rc=$?
    if [ "$native_rc" -ne 0 ] || [ "$expect" != "rollback=1 value=71" ]; then
        fail "direct GNU-unique transaction rollback" \
            "native fixture failed (exit=$native_rc output=$expect)"
        rm -rf "$root"
        return
    fi
    freeze_require_direct "direct GNU-unique transaction rollback" \
        "$log" "$out" -t -- "$main" "$failed_root" "$good" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct GNU-unique transaction rollback" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    capture_output actual env -u LD_LIBRARY_PATH "$out" \
        "$failed_root" "$good" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "failed dlopen rolls back staged GNU-unique owners"
    else
        fail "direct GNU-unique transaction rollback" \
            "exit=$rc expected=$expect actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9g: reject executables and DF_1_NOOPEN objects in lazy loads
# ===================================================================
test_direct_dlopen_admission_flags() {
    echo "--- direct dlopen lazy-object admission ---"
    local root="$BUILD/dlopen_admission_flags"
    local noopen_src="$root/noopen.c" noopen="$root/libdlfrz_noopen.so"
    local execstack_src="$root/execstack.c" execstack="$root/libdlfrz_execstack.so"
    local missingstack="$root/libdlfrz_missingstack.so"
    local phdr_gate="$root/direct_phdr_gate"
    local interp_src="$root/interp.c" interp="$root/libdlfrz_interp.so"
    local pie_src="$root/pie.c" pie="$root/dlfrz-pie"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local noopen_abs execstack_abs missingstack_abs interp_abs pie_abs
    local noopen_native pie_native interp_native actual
    local noopen_native_rc=0 pie_native_rc=0 freeze_rc=0 rc=0
    local native_noopen=0 native_pie=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$noopen_src" <<'C'
#include <stdio.h>
__attribute__((constructor)) static void forbidden_ctor(void) {
    puts("NOOPEN-CONSTRUCTOR-RAN");
}
int noopen_value(void) { return 1; }
C
    cat > "$interp_src" <<'C'
__asm__(".section .interp,\"a\"\n"
        ".string \"/dlfreeze/nonexecuted-interpreter\"\n"
        ".previous");
int interp_value(void) { return 31; }
C
    cat > "$execstack_src" <<'C'
#include <stdio.h>
__attribute__((constructor)) static void execstack_ctor(void) {
    puts("EXECSTACK-CONSTRUCTOR-RAN");
}
int execstack_value(void) { return 1; }
C
    if ! gcc -shared -fPIC -Wl,-z,nodlopen \
            -Wl,-soname,libdlfrz_noopen.so -o "$noopen" "$noopen_src"; then
        skip "direct-dlopen lazy admission" "linker lacks -z nodlopen"
        rm -rf "$root"
        return
    fi
    if ! gcc -shared -fPIC -Wl,-z,execstack \
            -Wl,-soname,libdlfrz_execstack.so \
            -o "$execstack" "$execstack_src"; then
        skip "direct-dlopen executable-stack admission" \
            "linker lacks -z execstack"
        rm -rf "$root"
        return
    fi
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$phdr_gate" tests/direct_phdr_gate.c ||
       ! cp "$execstack" "$missingstack" ||
       ! "$phdr_gate" --raw-stack-missing "$missingstack"; then
        fail "direct-dlopen missing PT_GNU_STACK admission" \
            "could not construct legacy executable-stack DSO"
        rm -rf "$root"
        return
    fi
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_interp.so \
            -o "$interp" "$interp_src" ||
       ! readelf -Wl "$interp" 2>/dev/null | grep 'INTERP' >/dev/null ||
       readelf -dW "$interp" 2>/dev/null | grep 'FLAGS_1.*PIE' >/dev/null; then
        fail "direct-dlopen PT_INTERP-bearing DSO admission" \
            "linker did not create a non-PIE DSO with PT_INTERP"
        rm -rf "$root"
        return
    fi
    if ! readelf -Wl "$execstack" 2>/dev/null |
            grep -E 'GNU_STACK[[:space:]].*RWE' >/dev/null; then
        skip "direct-dlopen executable-stack admission" \
            "linker did not emit executable PT_GNU_STACK"
        rm -rf "$root"
        return
    fi
    if ! readelf -d "$noopen" 2>/dev/null |
            grep -E 'FLAGS_1.*NOOPEN' >/dev/null; then
        skip "direct-dlopen lazy admission" \
            "linker did not emit DF_1_NOOPEN"
        rm -rf "$root"
        return
    fi

    cat > "$pie_src" <<'C'
int main(void) { return 0; }
C
    if ! gcc -fPIE -pie -o "$pie" "$pie_src"; then
        fail "direct-dlopen lazy admission" "PIE compile failed"
        rm -rf "$root"
        return
    fi

    noopen_abs=$(realpath "$noopen")
    execstack_abs=$(realpath "$execstack")
    missingstack_abs=$(realpath "$missingstack")
    interp_abs=$(realpath "$interp")
    pie_abs=$(realpath "$pie")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *kind;
    const char *path;
    int should_succeed = 0;
    if (argc != 2)
        return 10;
    if (strcmp(argv[1], "noopen") == 0) {
        kind = "noopen";
        path = "$noopen_abs";
    } else if (strcmp(argv[1], "execstack") == 0) {
        kind = "execstack";
        path = "$execstack_abs";
    } else if (strcmp(argv[1], "missingstack") == 0) {
        kind = "missingstack";
        path = "$missingstack_abs";
    } else if (strcmp(argv[1], "interp") == 0) {
        kind = "interp";
        path = "$interp_abs";
        should_succeed = 1;
    } else if (strcmp(argv[1], "pie") == 0) {
        kind = "pie";
        path = "$pie_abs";
    } else {
        return 11;
    }
    dlerror();
    void *handle = dlopen(path, RTLD_NOW);
    const char *error = handle ? NULL : dlerror();
    if (should_succeed) {
        int (*value)(void) = handle ? (int (*)(void))dlsym(handle,
                                                           "interp_value")
                                    : NULL;
        int result = value ? value() : -1;
        printf("%s-value=%d\n", kind, result);
        return result != 31;
    }
    printf("%s-failed=%d\n", kind, error != NULL);
    return handle != NULL || error == NULL;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl; then
        fail "direct-dlopen lazy admission" "program compile failed"
        rm -rf "$root"
        return
    fi

    capture_output noopen_native env -u LD_LIBRARY_PATH "$prog" noopen ||
        noopen_native_rc=$?
    if [ "$noopen_native_rc" -eq 0 ] &&
       [ "$noopen_native" = "noopen-failed=1" ]; then
        native_noopen=1
    else
        skip "direct-dlopen DF_1_NOOPEN admission" \
            "native loader does not enforce DF_1_NOOPEN"
    fi

    capture_output pie_native env -u LD_LIBRARY_PATH "$prog" pie ||
        pie_native_rc=$?
    if [ "$pie_native_rc" -eq 0 ] &&
       [ "$pie_native" = "pie-failed=1" ]; then
        native_pie=1
    else
        skip "direct-dlopen PIE admission" \
            "native loader accepts PIE in dlopen"
    fi

    interp_native=""; rc=0
    capture_output interp_native env -u LD_LIBRARY_PATH "$prog" interp || rc=$?
    if [ "$rc" -ne 0 ] || [ "$interp_native" != "interp-value=31" ]; then
        fail "native PT_INTERP-bearing DSO dlopen control" \
            "exit=$rc output=$interp_native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct-dlopen lazy admission" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen lazy admission" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    if [ "$native_noopen" -eq 1 ]; then
        actual=""; rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" noopen || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "noopen-failed=1" ] &&
           [[ "$actual" != *"NOOPEN-CONSTRUCTOR-RAN"* ]]; then
            pass "direct-dlopen DF_1_NOOPEN admission"
        else
            fail "direct-dlopen DF_1_NOOPEN admission" \
                "exit=$rc actual=$actual"
        fi
    fi
    if [ "$native_pie" -eq 1 ]; then
        actual=""; rc=0
        capture_output actual env -u LD_LIBRARY_PATH "$out" pie || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "pie-failed=1" ]; then
            pass "direct-dlopen PIE admission"
        else
            fail "direct-dlopen PIE admission" \
                "exit=$rc actual=$actual"
        fi
    fi
    actual=""; rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" interp || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "interp-value=31" ]; then
        pass "direct-dlopen admits PT_INTERP-bearing non-PIE DSO"
    else
        fail "direct-dlopen PT_INTERP-bearing DSO admission" \
            "exit=$rc actual=$actual"
    fi
    actual=""; rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" execstack || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "execstack-failed=1" ] &&
       [[ "$actual" != *"EXECSTACK-CONSTRUCTOR-RAN"* ]]; then
        pass "direct-dlopen executable-stack admission"
    else
        fail "direct-dlopen executable-stack admission" \
            "exit=$rc actual=$actual"
    fi
    actual=""; rc=0
    capture_output actual env -u LD_LIBRARY_PATH "$out" missingstack || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "missingstack-failed=1" ] &&
       [[ "$actual" != *"EXECSTACK-CONSTRUCTOR-RAN"* ]]; then
        pass "direct-dlopen missing PT_GNU_STACK admission"
    else
        fail "direct-dlopen missing PT_GNU_STACK admission" \
            "exit=$rc actual=$actual"
    fi
    rm -rf "$root"
}

# Public dlopen mode bits must drive loader state rather than being ignored.
# The direct loader binds eagerly, never unloads, and supports one namespace,
# but it still preserves NOLOAD and LOCAL-to-GLOBAL visibility semantics.
test_direct_dlopen_mode_contract() {
    echo "--- direct dlopen mode contract ---"
    local root="$BUILD/dlopen_mode_contract"
    local dep_src="$root/dep.c" dep="$root/libmode_dep.so"
    local top_src="$root/top.c" top="$root/libmode_top.so"
    local prog_src="$root/main.c" prog="$root/main"
    local marker="$root/constructor.marker"
    local out="$root/main.frozen" log="$root/main.log"
    local actual="" rc=0 freeze_rc=0
    local cc="${DLFREEZE_TEST_LOCAL_SCOPE_CC:-gcc}"

    rm -rf "$root"
    mkdir -p "$root"
    if [ -z "${DLFREEZE_TEST_LOCAL_SCOPE_CC:-}" ] &&
       command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    fi

    cat > "$dep_src" <<'C'
int mode_dependency_value(void) { return 17; }
C
    cat > "$top_src" <<'C'
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
extern int mode_dependency_value(void);
__attribute__((constructor)) static void mode_constructor(void) {
    const char *marker = getenv("MODE_CONSTRUCTOR_MARKER");
    int fd;

    if (!marker || !marker[0])
        return;
    fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)write(fd, "constructed\n", 12);
        (void)close(fd);
    }
}
int mode_top_value(void) { return 100 + mode_dependency_value(); }
C
    cat > "$prog_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0x00008
#endif

typedef int (*value_fn)(void);

static int rejected(const char *path, int flags) {
    void *handle;

    (void)dlerror();
    handle = dlopen(path, flags);
    return handle == NULL && dlerror() != NULL;
}

static int default_absent(const char *name) {
    void *symbol;

    (void)dlerror();
    symbol = dlsym(RTLD_DEFAULT, name);
    return symbol == NULL && dlerror() != NULL;
}

int main(int argc, char **argv) {
    void *handle, *present, *promoted, *after_close, *self;
    value_fn top_value, dependency_value, global_top, global_dependency;

    if (argc != 4 || setenv("MODE_CONSTRUCTOR_MARKER", argv[3], 1) != 0)
        return 2;
    if (strcmp(argv[1], "trace") == 0) {
        handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
        top_value = handle ? (value_fn)dlsym(handle, "mode_top_value") : NULL;
        if (!top_value || top_value() != 117)
            return 3;
        puts("trace=117");
        return 0;
    }
    if (strcmp(argv[1], "check") != 0 || unlink(argv[3]) != 0 &&
        errno != ENOENT)
        return 4;

    self = dlopen(NULL, RTLD_LAZY | RTLD_NOW | RTLD_LOCAL);
    if (!self || dlerror() != NULL)
        return 5;
    if (!rejected(argv[2], RTLD_LOCAL) ||
        !rejected(argv[2], RTLD_NOW | 0x40000000) ||
        !rejected(argv[2], RTLD_NOW | RTLD_DEEPBIND))
        return 13;
    (void)dlerror();
    if (dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL) != NULL ||
        dlerror() == NULL || access(argv[3], F_OK) == 0 || errno != ENOENT ||
        !default_absent("mode_top_value") ||
        !default_absent("mode_dependency_value"))
        return 6;

    /* RTLD_LAZY is accepted for compatibility, but the direct loader
     * deliberately completes this dependency relocation eagerly. */
    handle = dlopen(argv[2], RTLD_LAZY | RTLD_LOCAL);
    top_value = handle ? (value_fn)dlsym(handle, "mode_top_value") : NULL;
    dependency_value = handle
        ? (value_fn)dlsym(handle, "mode_dependency_value") : NULL;
    if (!handle || !top_value || !dependency_value || top_value() != 117 ||
        dependency_value() != 17 || access(argv[3], F_OK) != 0 ||
        !default_absent("mode_top_value") ||
        !default_absent("mode_dependency_value"))
        return 7;

    present = dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    if (present != handle)
        return 8;
    promoted = dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL);
    if (promoted != handle)
        return 9;
    global_top = (value_fn)dlsym(RTLD_DEFAULT, "mode_top_value");
    global_dependency = (value_fn)dlsym(RTLD_DEFAULT,
                                        "mode_dependency_value");
    if (!global_top || !global_dependency || global_top() != 117 ||
        global_dependency() != 17)
        return 10;

    if (dlclose(handle) != 0 || dlclose(present) != 0 ||
        dlclose(promoted) != 0)
        return 11;
    after_close = dlopen(argv[2], RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    top_value = after_close
        ? (value_fn)dlsym(after_close, "mode_top_value") : NULL;
    if (after_close != handle || !top_value || top_value() != 117)
        return 12;

    puts("mode-contract-ok");
    return 0;
}
C

    if ! "$cc" -shared -fPIC -Wl,-soname,libmode_dep.so \
            -o "$dep" "$dep_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,libmode_top.so \
            -Wl,-rpath,'$ORIGIN' -Wl,--no-as-needed -L"$root" \
            -o "$top" "$top_src" -lmode_dep ||
       ! "$cc" -o "$prog" "$prog_src" -ldl; then
        fail "direct dlopen mode contract" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual "$prog" trace "$top" "$marker" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "trace=117" ] ||
       [ ! -f "$marker" ]; then
        fail "direct dlopen mode contract" \
            "native trace fixture exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi
    rm -f "$marker"

    freeze_require_direct "direct dlopen mode contract" "$log" "$out" \
        -t -- "$prog" trace "$top" "$marker" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dlopen mode contract" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rm -f "$top" "$dep" "$marker"
    actual=""; rc=0
    capture_output actual "$out" check "$top" "$marker" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "mode-contract-ok" ]; then
        pass "direct dlopen flags, NOLOAD, and scope promotion"
    else
        fail "direct dlopen mode contract" "exit=$rc output=$actual"
        tail -n 60 "$log" || true
    fi
    rm -rf "$root"
}

# A DSO loaded RTLD_LOCAL keeps a private lookup group.  glibc RTLD_NEXT walks
# the caller lookup scope, while musl starts at physical p->next and follows
# only that object's global syms_next link.  An unrelated local bridge before
# a later local provider distinguishes those contracts.
test_direct_dlopen_local_caller_scope() {
    echo "--- direct dlopen nested local caller scope ---"
    local root="$BUILD/dlopen_local_caller_scope"
    local provider_src="$root/provider.c"
    local provider="$root/liblocal_provider.so"
    local bridge_src="$root/bridge.c"
    local bridge="$root/liblocal_bridge.so"
    local caller_src="$root/caller.c"
    local caller="$root/liblocal_caller.so"
    local child_src="$root/child.c"
    local child="$root/liblocal_child.so"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local actual="" rc=0 freeze_rc=0 cc=gcc

    rm -rf "$root"
    mkdir -p "$root"
    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    fi

    cat > "$provider_src" <<'C'
int next_local_value(void) { return 31; }
C
    cat > "$child_src" <<'C'
int nested_child_value(void) { return 100; }
C
    cat > "$bridge_src" <<'C'
int local_bridge_value(void) { return 7; }
C
    cat > "$caller_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
typedef int (*value_fn)(void);

int inherited_local_value(void) { return 23; }

int run_local_scope(const char *child_path) {
    void *child;
    value_fn nested;
    value_fn next;
    value_fn local_default;

    child = dlopen(child_path, RTLD_NOW | RTLD_LOCAL);
    if (!child)
        return -1;
    nested = (value_fn)dlsym(child, "nested_child_value");
    if (!nested)
        return -2;
    next = (value_fn)dlsym(RTLD_NEXT, "next_local_value");
    local_default = (value_fn)dlsym(RTLD_DEFAULT,
                                    "inherited_local_value");
#ifdef __GLIBC__
    if (!next)
        return -3;
    if (!local_default)
        return -4;
    return local_default() + nested() + next();
#else
    if (next)
        return -3;
    if (local_default)
        return -4;
    return inherited_local_value() + nested() + 31;
#endif
}
C
    cat > "$prog_src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
typedef int (*run_fn)(const char *);

int main(int argc, char **argv) {
    void *caller;
    run_fn run;
    int value;

    if (argc != 3)
        return 2;
    caller = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    run = caller ? (run_fn)dlsym(caller, "run_local_scope") : NULL;
    if (!run)
        return 3;
    if (dlsym(RTLD_DEFAULT, "inherited_local_value") != NULL)
        return 4;
    value = run(argv[2]);
    if (value != 154) {
        printf("local-scope-value=%d\n", value);
        return 5;
    }
    puts("local-caller-scope-ok");
    return 0;
}
C

    if ! "$cc" -shared -fPIC -Wl,-soname,liblocal_provider.so \
            -o "$provider" "$provider_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,liblocal_bridge.so \
            -o "$bridge" "$bridge_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,liblocal_child.so \
            -o "$child" "$child_src" ||
       ! "$cc" -shared -fPIC -Wl,-soname,liblocal_caller.so \
            -Wl,-rpath,'$ORIGIN' -Wl,--no-as-needed -L"$root" \
            -o "$caller" "$caller_src" -llocal_bridge -llocal_provider -ldl ||
       ! "$cc" -o "$prog" "$prog_src" -ldl; then
        fail "direct dlopen local caller scope" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual "$prog" "$caller" "$child" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "local-caller-scope-ok" ]; then
        fail "direct dlopen local caller scope" \
            "native fixture exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct dlopen local caller scope" "$log" "$out" \
        -t -- "$prog" "$caller" "$child" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct dlopen local caller scope" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rm -f "$caller" "$bridge" "$provider" "$child"
    actual=""; rc=0
    capture_output actual "$out" "$caller" "$child" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "local-caller-scope-ok" ]; then
        pass "direct nested RTLD_LOCAL scope and RTLD_NEXT"
    else
        fail "direct dlopen local caller scope" "exit=$rc output=$actual"
        tail -n 60 "$log" || true
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9h: traced dlopen closures that require initial-exec TLS are
# mapped and assigned static TLS at startup, but remain semantically
# dormant until dlopen activates their exact dependency closure.
# ===================================================================
test_direct_dlopen_embedded_static_tls() {
    echo "--- direct traced dlopen static-TLS promotion ---"
    local root="$BUILD/dlopen_embedded_static_tls"
    local dep="$root/libdlfrz_early_tls_dep.so"
    local root_a="$root/libdlfrz_early_root_a.so"
    local root_b="$root/libdlfrz_early_root_b.so"
    local late="$root/libdlfrz_late_static_tls.so"
    local external_owner="$root/libdlfrz_external_ie_owner.so"
    local external_requester="$root/libdlfrz_external_ie_requester.so"
    local late_external_dir="$root/late-external"
    local late_external_owner="$late_external_dir/libdlfrz_late_external_ie_owner.so"
    local late_external_requester="$late_external_dir/libdlfrz_late_external_ie_requester.so"
    local prog="$root/main" parser_gate="$root/elf_parser_gate"
    local out="$root/main.frozen" log="$root/main.log"
    local dep_abs root_a_abs root_b_abs late_abs external_owner_abs
    local external_requester_abs
    local late_external_requester_abs
    local actual freeze_rc=0 rc=0 late_actual late_rc=0
    local late_external_actual late_external_rc=0
    local native_actual native_rc=0
    local root_relocs=""
    local have_ifunc=0
    local use_preloaded_trace=0
    local -a ifunc_cflags=()

    rm -rf "$root"
    mkdir -p "$root" "$late_external_dir"
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_early_tls_dep.so \
            -o "$dep" tests/direct_early_tls_dep.c; then
        fail "direct traced static-TLS promotion" \
            "dependency compile failed"
        rm -rf "$root"
        return
    fi
    if ! gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_external_ie_owner.so \
            -o "$external_owner" tests/direct_external_ie_owner.c ||
       ! gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_external_ie_requester.so \
            -Wl,-rpath,'$ORIGIN' -L"$root" \
            -o "$external_requester" tests/direct_external_ie_requester.c \
            -ldlfrz_external_ie_owner ||
       ! gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_late_external_ie_owner.so \
            -o "$late_external_owner" tests/direct_external_ie_owner.c ||
       ! gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_late_external_ie_requester.so \
            -Wl,-rpath,'$ORIGIN' -L"$late_external_dir" \
            -o "$late_external_requester" \
            tests/direct_external_ie_requester.c \
            -ldlfrz_late_external_ie_owner; then
        fail "direct traced external-IE TLS promotion" \
            "external-IE fixtures failed to compile"
        rm -rf "$root"
        return
    fi
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$parser_gate" tests/elf_parser_gate.c src/elf_parser.c ||
       ! "$parser_gate" "$dep" "$external_requester"; then
        fail "ELF parser static-TLS classification" \
            "self/external TPOFF or malformed-bound gate failed"
        rm -rf "$root"
        return
    fi
    pass "ELF parser static-TLS classification"

    if compiler_supports_gnu_ifunc "$root"; then
        have_ifunc=1
        ifunc_cflags=(-DDIRECT_EARLY_HAVE_IFUNC=1)
    else
        skip "direct traced dormant IRELATIVE timing" \
            "target toolchain does not support GNU IFUNC"
    fi

    if ! gcc "${ifunc_cflags[@]}" -shared -fPIC -DROOT_EVENT="'A'" \
            -Wl,-soname,libdlfrz_early_root_a.so -Wl,-rpath,'$ORIGIN' \
            -L"$root" -o "$root_a" tests/direct_early_tls_root.c \
            -ldlfrz_early_tls_dep ||
       ! gcc "${ifunc_cflags[@]}" -shared -fPIC -DROOT_EVENT="'B'" \
            -Wl,-soname,libdlfrz_early_root_b.so -Wl,-rpath,'$ORIGIN' \
            -L"$root" -o "$root_b" tests/direct_early_tls_root.c \
            -ldlfrz_early_tls_dep ||
       ! gcc -shared -fPIC -Wl,-soname,libdlfrz_late_static_tls.so \
            -o "$late" tests/direct_late_static_tls.c; then
        fail "direct traced static-TLS promotion" "root compile failed"
        rm -rf "$root"
        return
    fi
    if [ "$have_ifunc" -eq 1 ]; then
        root_relocs=$(readelf -rW "$root_a" 2>/dev/null || true)
    fi
    if [ "$have_ifunc" -eq 1 ] &&
       ! grep -q 'IRELATIVE' <<<"$root_relocs"; then
        fail "direct traced dormant IRELATIVE timing" \
            "IFUNC-capable toolchain emitted no IRELATIVE relocation"
        rm -rf "$root"
        return
    fi

    dep_abs=$(realpath "$dep")
    root_a_abs=$(realpath "$root_a")
    root_b_abs=$(realpath "$root_b")
    late_abs=$(realpath "$late")
    external_owner_abs=$(realpath "$external_owner")
    external_requester_abs=$(realpath "$external_requester")
    late_external_requester_abs=$(realpath "$late_external_requester")
    if ! gcc "${ifunc_cflags[@]}" -std=c11 -D_GNU_SOURCE -rdynamic -pthread \
            -DROOT_A_PATH="\"$root_a_abs\"" \
            -DROOT_B_PATH="\"$root_b_abs\"" \
            -DDEP_PATH="\"$dep_abs\"" \
            -DLATE_PATH="\"$late_abs\"" \
            -DEXTERNAL_IE_OWNER_PATH="\"$external_owner_abs\"" \
            -DEXTERNAL_IE_PATH="\"$external_requester_abs\"" \
            -DLATE_EXTERNAL_IE_PATH="\"$late_external_requester_abs\"" \
            -o "$prog" tests/direct_early_tls_main.c -ldl; then
        fail "direct traced static-TLS promotion" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output native_actual "$prog" || native_rc=$?
    if [ "$native_rc" -ne 0 ]; then
        if [[ "$native_actual" == *"initial-exec TLS resolves to dynamic definition"* ]]; then
            use_preloaded_trace=1
            echo "INFO: native libc rejects runtime initial-exec TLS; using the startup-preloaded trace fixture"
        elif [[ "$native_actual" == *"cannot allocate memory in static TLS block"* ]]; then
            skip "direct traced static-TLS promotion" \
                "native loader has no static-TLS surplus for the trace fixture"
            skip "direct traced external-IE TLS promotion" \
                "native loader has no static-TLS surplus for the trace fixture"
            skip "direct untraced static-TLS rejection" \
                "native trace fixture cannot run"
            skip "direct untraced external-IE rejection" \
                "native trace fixture cannot run"
            if [ "$have_ifunc" -eq 1 ]; then
                skip "direct traced dormant IRELATIVE timing" \
                    "native trace fixture cannot run"
            fi
            rm -rf "$root"
            return
        else
            fail "direct traced static-TLS promotion" \
                "native control exit=$native_rc output=$native_actual"
            rm -rf "$root"
            return
        fi
    fi

    if [ "$use_preloaded_trace" -eq 1 ]; then
        freeze_require_direct "direct traced static-TLS promotion" "$log" \
            "$out" -t "$prog" trace || freeze_rc=$?
    else
        freeze_require_direct "direct traced static-TLS promotion" "$log" \
            "$out" -t "$prog" -- || freeze_rc=$?
    fi
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct traced static-TLS promotion" "$DIRECT_FREEZE_REASON"
        skip "direct traced external-IE TLS promotion" "$DIRECT_FREEZE_REASON"
        skip "direct untraced static-TLS rejection" "$DIRECT_FREEZE_REASON"
        skip "direct untraced external-IE rejection" "$DIRECT_FREEZE_REASON"
        if [ "$have_ifunc" -eq 1 ]; then
            skip "direct traced dormant IRELATIVE timing" \
                "$DIRECT_FREEZE_REASON"
        fi
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$dep" "${dep}.bak"
    mv "$root_a" "${root_a}.bak"
    mv "$root_b" "${root_b}.bak"
    mv "$external_owner" "${external_owner}.bak"
    mv "$external_requester" "${external_requester}.bak"
    capture_output actual "$out" || rc=$?
    mv "${dep}.bak" "$dep"
    mv "${root_a}.bak" "$root_a"
    mv "${root_b}.bak" "$root_b"
    mv "${external_owner}.bak" "$external_owner"
    mv "${external_requester}.bak" "$external_requester"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] &&
       [ "$actual" = "promoted-static-tls-ok" ]; then
        pass "direct traced static-TLS promotion"
        pass "direct traced external-IE TLS promotion"
        if [ "$have_ifunc" -eq 1 ]; then
            pass "direct traced dormant IRELATIVE timing"
        fi
    else
        fail "direct traced static-TLS promotion" \
            "exit=$rc actual=$actual"
        fail "direct traced external-IE TLS promotion" \
            "exit=$rc actual=$actual"
        if [ "$have_ifunc" -eq 1 ]; then
            fail "direct traced dormant IRELATIVE timing" \
                "exit=$rc actual=$actual"
        fi
    fi

    capture_output late_actual "$out" late || late_rc=$?
    late_actual=$(printf '%s\n' "$late_actual" | strip_dlfreeze_warnings)
    if [ "$late_rc" -eq 0 ] &&
       [ "$late_actual" = "untraced-static-tls-rejected" ]; then
        pass "direct untraced static-TLS rejection"
    else
        fail "direct untraced static-TLS rejection" \
            "exit=$late_rc actual=$late_actual"
    fi

    capture_output late_external_actual "$out" external-late ||
        late_external_rc=$?
    late_external_actual=$(printf '%s\n' "$late_external_actual" | \
        strip_dlfreeze_warnings)
    if [ "$late_external_rc" -eq 0 ] &&
       [ "$late_external_actual" = "untraced-external-ie-rejected" ]; then
        pass "direct untraced external-IE rejection"
    else
        fail "direct untraced external-IE rejection" \
            "exit=$late_external_rc actual=$late_external_actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9i: a late initial-exec requester may use TLS that belongs to an
# ordinary startup object.  No new static allocation is needed in this
# case; the defining module already has a fixed TP offset in every thread.
# ===================================================================
test_direct_dlopen_startup_owned_ie() {
    echo "--- direct late initial-exec import from startup TLS owner ---"
    local root="$BUILD/dlopen_startup_owned_ie"
    local owner="$root/libdlfrz_external_ie_owner.so"
    local requester="$root/libdlfrz_external_ie_requester.so"
    local prog="$root/main" out="$root/main.frozen" log="$root/main.log"
    local requester_abs actual native_actual
    local native_rc=0 freeze_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_external_ie_owner.so \
            -o "$owner" tests/direct_external_ie_owner.c ||
       ! gcc -shared -fPIC \
            -Wl,-soname,libdlfrz_external_ie_requester.so \
            -Wl,-rpath,'$ORIGIN' -L"$root" -o "$requester" \
            tests/direct_external_ie_requester.c \
            -ldlfrz_external_ie_owner; then
        fail "direct startup-owned initial-exec import" \
            "TLS fixtures failed to compile"
        rm -rf "$root"
        return
    fi

    # Keep this proof independent of linker advisory flags.  The requester
    # itself must have no TLS template, while a real IE relocation imports
    # the owner's TLS symbol.
    if readelf -lW "$requester" 2>/dev/null | \
            grep -E '^[[:space:]]*TLS[[:space:]]' >/dev/null ||
       ! readelf -rW "$requester" 2>/dev/null | \
            grep -E 'R_(X86_64_TPOFF64|AARCH64_TLS_TPREL64)' >/dev/null; then
        fail "direct startup-owned initial-exec import" \
            "requester is not a no-PT_TLS initial-exec import fixture"
        rm -rf "$root"
        return
    fi

    requester_abs=$(realpath "$requester")
    if ! gcc -std=c11 -D_GNU_SOURCE -pthread \
            -DREQUESTER_PATH="\"$requester_abs\"" \
            -Wl,-rpath,'$ORIGIN' -L"$root" -o "$prog" \
            tests/direct_startup_ie_main.c \
            -ldlfrz_external_ie_owner -ldl; then
        fail "direct startup-owned initial-exec import" \
            "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output native_actual "$prog" || native_rc=$?
    if [ "$native_rc" -ne 0 ] ||
       [ "$native_actual" != "startup-owned-initial-exec-ok" ]; then
        fail "direct startup-owned initial-exec import" \
            "native control exit=$native_rc output=$native_actual"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "direct startup-owned initial-exec import" \
        "$log" "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct startup-owned initial-exec import" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    # The owner must come from the startup image.  Only the untraced
    # requester remains on disk for the late dlopen transaction.
    mv "$owner" "${owner}.bak"
    capture_output actual "$out" || rc=$?
    mv "${owner}.bak" "$owner"
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] &&
       [ "$actual" = "startup-owned-initial-exec-ok" ]; then
        pass "direct startup-owned initial-exec import"
    else
        fail "direct startup-owned initial-exec import" \
            "exit=$rc actual=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 9j: runtime dlopen consumes format-bounded PHDR/DYNAMIC tables
# ===================================================================
test_direct_runtime_parser_bounds() {
    echo "--- direct runtime ELF parser bounds ---"
    local root="$BUILD/direct_runtime_bounds"
    local lib="$root/libdirect_runtime_bounds.so"
    local large_dyn="$root/libdirect_large_dynamic.so"
    local pn_xnum="$root/libdirect_pn_xnum.so"
    local prog="$root/main" out="$root/main.frozen" log="$root/main.log"
    local stride_gate="$root/loader_section_stride_gate"
    local dynamic_gate="$root/runtime_dynamic_reader_gate"
    local load_gate="$root/load_segments_gate"
    local version_gate="$root/elf_version_stress_gate"
    local section_gate="$root/elf_sections_gate"
    local pn_pack_out="$root/pn-xnum.frozen"
    local phnum dyn_size expect actual freeze_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -Iinclude \
            -ffunction-sections -fdata-sections -fno-stack-protector \
            -Wl,--gc-sections -o "$dynamic_gate" \
            tests/runtime_dynamic_reader_gate.c -ldl -pthread ||
       ! run_with_timeout_seconds 10 "$dynamic_gate"; then
        fail "runtime dynamic/version metadata index" \
            "large-table, first-DT_NULL, truncation, or version-index gate failed"
        rm -rf "$root"
        return
    fi
    pass "runtime PT_DYNAMIC reads are chunk-bounded"
    pass "runtime PT_DYNAMIC first-terminator and truncation semantics"
    pass "runtime high-cardinality defined/needed versions use a paged index"
    pass "runtime version index rejects malformed chains and duplicate indices"
    pass "runtime startup source-owner indexing handles 65,535 aliases"
    pass "runtime GNU/SysV/version collision chains use bounded keyed name checks"

    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -ffunction-sections -fdata-sections -fno-stack-protector \
            -Wl,--gc-sections -o "$stride_gate" \
            tests/loader_section_stride_gate.c -ldl -pthread ||
       ! "$stride_gate"; then
        fail "loader bounded-table gates" "section/special-table gate failed"
        rm -rf "$root"
        return
    fi
    pass "loader section headers honor declared stride"
    pass "loader special-symbol insertion is capacity-bounded"
    pass "loader requires a valid kernel page-size contract"
    pass "loader libc-service provider/type/version/PT_LOAD gates"
    pass "loader private service symbols require one hash-consistent default"
    pass "loader embedded ELF mappings stop at the embedded file boundary"
    pass "loader RELRO protects only the native complete-page range"
    pass "loader prelinked weak and STN_UNDEF values are runtime-canonical"
    pass "loader prelinked zero-fill RELATIVE replay"
    pass "loader scalar relocations support unaligned destinations"
    pass "loader rejects misaligned typed ELF control tables"
    pass "loader GNU-hash chains remain file-backed"
    pass "loader ORIGIN parsing follows target token grammar"
    pass "loader detects system-wide glibc preload policy"
    pass "loader target-specific atfork registration backends"

    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -Iinclude \
            -o "$load_gate" tests/load_segments_gate.c; then
        fail "linear PT_LOAD validation" "gate compile failed"
        rm -rf "$root"
        return
    fi
    if ! run_with_timeout_seconds 5 "$load_gate"; then
        fail "linear PT_LOAD validation" \
            "65,535-entry disjoint table was rejected or timed out"
        rm -rf "$root"
        return
    fi
    pass "PT_LOAD order/overlap validation is linear"

    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -Iinclude \
            -o "$version_gate" tests/elf_version_stress_gate.c \
            src/elf_parser.c; then
        fail "ELF version parser complexity" "gate compile failed"
        rm -rf "$root"
        return
    fi
    if ! run_with_timeout_seconds 5 "$version_gate"; then
        fail "ELF version parser complexity" \
            "large valid control or reused-chain rejection timed out"
        rm -rf "$root"
        return
    fi
    pass "ELF version parsing remains file-size bounded"
    pass "ELF VA translation accepts 65,534 ordered program headers"

    if ! gcc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude \
            -o "$section_gate" tests/elf_sections_gate.c ||
       ! "$section_gate"; then
        fail "ELF extended section numbering" "encoding gate failed"
        rm -rf "$root"
        return
    fi
    pass "ELF extended section and symbol indices use standard encoding"

    if ! "$load_gate" --write-pn-xnum "$pn_xnum"; then
        fail "PN_XNUM rejection" "could not generate the stress DSO"
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    set +e
    run_with_timeout_seconds 5 "$DLFREEZE" -d -o "$pn_pack_out" -- \
        "$pn_xnum" >"$root/pn-pack.log" 2>&1
    rc=$?
    set -e
    actual=$(cat "$root/pn-pack.log")
    if [ "$rc" -ne 0 ] && [ ! -e "$pn_pack_out" ]; then
        pass "packer promptly rejects unsupported PN_XNUM"
    else
        fail "packer PN_XNUM rejection" \
            "exit=$rc output=$actual artifact=$([ -e "$pn_pack_out" ] && echo yes || echo no)"
        rm -rf "$root"
        return
    fi

    if ! command -v readelf >/dev/null 2>&1 ||
       ! gcc -shared -fPIC -nostdlib \
            -Wl,-T,tests/direct_runtime_bounds.ld \
            -Wl,-soname,libdirect_runtime_bounds.so \
            -o "$lib" tests/direct_runtime_bounds_lib.c ||
       ! gcc -Wall -Wextra -Werror -o "$prog" \
            tests/direct_runtime_bounds_main.c -ldl; then
        skip "direct runtime ELF parser bounds" \
            "toolchain does not support the bounded-table fixture"
        skip "runtime dlopen PN_XNUM rejection" \
            "toolchain does not support the runtime fixture"
        rm -rf "$root"
        return
    fi

    phnum=$(od -An -tu2 -j 56 -N2 "$lib" | tr -d '[:space:]')
    dyn_size=$(od -An -tu8 -j $((64 + 3 * 56 + 32)) -N8 "$lib" |
        tr -d '[:space:]')
    if ! [[ "$phnum" =~ ^[0-9]+$ && "$dyn_size" =~ ^[0-9]+$ ]] ||
       [ "$phnum" -le 64 ] || [ "$dyn_size" -le 65536 ]; then
        fail "direct runtime ELF parser bounds" \
            "fixture lacks large tables (phnum=$phnum dynamic=$dyn_size)"
        rm -rf "$root"
        return
    fi

    # Keep the same large PT_DYNAMIC but expose only the six functional
    # headers, so the second run tests dynamic-table streaming independently.
    cp "$lib" "$large_dyn"
    printf '\006\000' | dd of="$large_dyn" bs=1 seek=56 \
        conv=notrunc status=none

    expect="runtime-bounds=42"
    for candidate in "$lib" "$large_dyn"; do
        actual=""; rc=0
        capture_output actual "$prog" "$candidate" || rc=$?
        if [ "$rc" -ne 0 ] || [ "$actual" != "$expect" ]; then
            fail "native runtime ELF parser control" \
                "$(basename "$candidate") exit=$rc output=$actual"
            rm -rf "$root"
            return
        fi
    done

    freeze_require_direct "direct runtime ELF parser bounds" "$log" \
        "$out" "$prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "runtime dlopen accepts >64 program headers" \
            "$DIRECT_FREEZE_REASON"
        skip "runtime dlopen streams >64 KiB PT_DYNAMIC" \
            "$DIRECT_FREEZE_REASON"
        skip "runtime dlopen PN_XNUM rejection" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    actual=""; rc=0
    capture_output actual "$out" "$lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "runtime dlopen accepts >64 program headers"
    else
        fail "runtime dlopen >64 program headers" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual "$out" "$large_dyn" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "runtime dlopen streams >64 KiB PT_DYNAMIC"
    else
        fail "runtime dlopen >64 KiB PT_DYNAMIC" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    set +e
    run_with_timeout_seconds 5 "$out" "$pn_xnum" \
        >"$root/pn-runtime.log" 2>&1
    rc=$?
    set -e
    actual=$(cat "$root/pn-runtime.log")
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 3 ] && [[ "$actual" == *"dlopen:"* ]]; then
        pass "runtime dlopen promptly rejects unsupported PN_XNUM"
    else
        fail "runtime dlopen PN_XNUM rejection" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# ELF64 scalar relocation destinations need not be naturally aligned.
# Exercise both startup prelink writeback and a lazily mapped dlopen object.
# ===================================================================
test_unaligned_relocation_destinations() {
    echo "--- unaligned scalar relocation destinations ---"
    local root="$BUILD/unaligned_relocations"
    local startup_src="$root/startup.c" startup="$root/startup"
    local startup_out="$root/startup.frozen" startup_log="$root/startup.log"
    local lib_src="$root/plugin.c" lib="$root/libunaligned_reloc.so"
    local runner_src="$root/runner.c" runner="$root/runner"
    local runner_out="$root/runner.frozen" runner_log="$root/runner.log"
    local lib_abs reloc_off expect actual rc=0 freeze_rc=0
    local startup_unaligned=0 plugin_unaligned=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$startup_src" <<'C'
#include <stdio.h>
#include <string.h>
static int target = 41;
static struct __attribute__((packed)) {
    unsigned char tag;
    int *pointer;
} holder = { 0x5a, &target };
int main(void) {
    int *pointer = 0;
    memcpy(&pointer, &holder.pointer, sizeof(pointer));
    printf("startup-unaligned=%d\n", pointer ? *pointer : -1);
    return !pointer || *pointer != 41 || holder.tag != 0x5a;
}
C
    if ! gcc -fPIE -pie -Wall -Wextra -Werror \
            -o "$startup" "$startup_src"; then
        fail "startup unaligned relocation" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    while read -r reloc_off; do
        if [[ "$reloc_off" =~ ^[[:xdigit:]]+$ ]] &&
           [ $((16#$reloc_off % 8)) -ne 0 ]; then
            startup_unaligned=1
            break
        fi
    done < <(readelf -rW "$startup" 2>/dev/null |
        awk '$3 ~ /R_(X86_64_(RELATIVE|64)|AARCH64_(RELATIVE|ABS64))/ {print $1}')
    if [ "$startup_unaligned" -ne 1 ]; then
        skip "startup unaligned relocation" \
            "linker did not emit a packed scalar relocation"
    else
        freeze_require_direct "startup unaligned relocation" \
            "$startup_log" "$startup_out" "$startup" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "startup unaligned relocation" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            actual=""; rc=0
            capture_output actual env DLFREEZE_NO_FORK=1 \
                "$startup_out" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] &&
               [ "$actual" = "startup-unaligned=41" ] &&
               grep -Eq 'pre-linked[[:space:]]*:[[:space:]]*yes' \
                   "$startup_log"; then
                pass "startup prelinked unaligned relocation"
            else
                fail "startup unaligned relocation" \
                    "exit=$rc output=$actual or prelink did not commit"
            fi
        fi
    fi

    cat > "$lib_src" <<'C'
#include <string.h>
static int target = 73;
static struct __attribute__((packed)) {
    unsigned char tag;
    int *pointer;
} holder = { 0x6b, &target };
int unaligned_relocation_value(void) {
    int *pointer = 0;
    memcpy(&pointer, &holder.pointer, sizeof(pointer));
    return pointer && holder.tag == 0x6b ? *pointer : -1;
}
C
    if ! gcc -shared -fPIC -Wall -Wextra -Werror \
            -Wl,-soname,libunaligned_reloc.so -o "$lib" "$lib_src"; then
        fail "dlopen unaligned relocation" "plugin compile failed"
        rm -rf "$root"
        return
    fi
    while read -r reloc_off; do
        if [[ "$reloc_off" =~ ^[[:xdigit:]]+$ ]] &&
           [ $((16#$reloc_off % 8)) -ne 0 ]; then
            plugin_unaligned=1
            break
        fi
    done < <(readelf -rW "$lib" 2>/dev/null |
        awk '$3 ~ /R_(X86_64_(RELATIVE|64)|AARCH64_(RELATIVE|ABS64))/ {print $1}')
    if [ "$plugin_unaligned" -ne 1 ]; then
        skip "dlopen unaligned relocation" \
            "linker did not emit a packed scalar relocation"
        rm -rf "$root"
        return
    fi
    lib_abs=$(realpath "$lib")
    cat > "$runner_src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) return 3;
    int (*value)(void) = (int (*)(void))dlsym(
        handle, "unaligned_relocation_value");
    if (!value) return 4;
    printf("dlopen-unaligned=%d\n", value());
    return value() != 73;
}
C
    if ! gcc -Wall -Wextra -Werror -o "$runner" "$runner_src" -ldl; then
        fail "dlopen unaligned relocation" "runner compile failed"
        rm -rf "$root"
        return
    fi
    expect=""; rc=0
    capture_output expect "$runner" "$lib_abs" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$expect" != "dlopen-unaligned=73" ]; then
        fail "native dlopen unaligned relocation control" \
            "exit=$rc output=$expect"
        rm -rf "$root"
        return
    fi
    freeze_rc=0
    freeze_require_direct "dlopen unaligned relocation" \
        "$runner_log" "$runner_out" -t -- \
        "$runner" "$lib_abs" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlopen unaligned relocation" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        mv "$lib" "$lib.hidden"
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$runner_out" "$lib_abs" || rc=$?
        mv "$lib.hidden" "$lib"
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "dlopen runtime unaligned relocation"
        else
            fail "dlopen unaligned relocation" "exit=$rc output=$actual"
        fi
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 10: direct-mode dlopen fallback warning (lib not in image)
# ===================================================================
test_direct_dlopen_fallback() {
    echo "--- direct dlopen (fallback) ---"
    local shlib_src="$BUILD/fb2_lib.c"  shlib="$BUILD/libfb2.so"
    local prog_src="$BUILD/use_fb2.c"   prog="$BUILD/use_fb2"
    local out="$BUILD/use_fb2.frozen" log="$BUILD/use_fb2.log"
    local freeze_rc=0
    rm -f "$log"

    cat > "$shlib_src" <<'C'
int fb2_double(int x) { return x * 2; }
C
    gcc -shared -fPIC -o "$shlib" "$shlib_src"
    local shlib_abs
    shlib_abs=$(realpath "$shlib")

    # Program loads via absolute path — will NOT be captured during trace
    # because we trace with a different command that doesn't trigger this dlopen
    cat > "$prog_src" <<C
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    printf("before\n");
    void *h = dlopen("$shlib_abs", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*dbl)(int) = dlsym(h, "fb2_double");
    if (!dbl) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("double(21)=%d\n", dbl(21));
    dlclose(h);
    return 0;
}
C
    gcc -o "$prog" "$prog_src" -ldl

    local expect rc_e=0
    capture_output expect "$prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "direct-dlopen-fallback" "native fixture failed (exit $rc_e)"
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
    fi

    # Freeze with -d but WITHOUT -t — no dlopen tracing, lib won't be embedded
    freeze_require_direct "direct-dlopen-fallback" "$log" "$out" "$prog" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct-dlopen-fallback" "$DIRECT_FREEZE_REASON"
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
    fi

    # Run — should see warning on stderr but succeed
    local actual stderr_out rc=0
    capture_output_split actual stderr_out "$out" || rc=$?

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        if printf '%s\n' "$stderr_out" |
                grep "warning.*not in frozen image" >/dev/null 2>&1; then
            pass "direct-dlopen fallback+warning"
        else
            pass "direct-dlopen fallback (no warning)"
        fi
    else
        fail "direct-dlopen fallback" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
}

# A successful late filesystem dlopen must own an immutable copy of every
# mapped byte.  The constructor barrier makes truncation deterministic: once
# READY arrives, the DSO is mapped and executing, but its constructor cannot
# return until the parent has truncated the source and sent RELEASE.
run_direct_runtime_truncate_snapshot() {
    local family="$1" cc="$2"
    local root="$BUILD/direct_runtime_truncate_$family"
    local plugin="$root/libdirect_runtime_truncate.so"
    local live="$root/libdirect_runtime_truncate.live.so"
    local main="$root/main" out="$root/main.frozen" log="$root/main.log"
    local live_abs actual freeze_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! "$cc" -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libdirect_runtime_truncate.so \
            -o "$plugin" tests/direct_runtime_truncate_plugin.c ||
       ! "$cc" -Wall -Wextra -Werror -O2 -Wl,--export-dynamic \
            -o "$main" tests/direct_runtime_truncate_main.c -ldl; then
        fail "$family late filesystem DSO snapshot" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "$family late filesystem DSO snapshot" \
        "$log" "$out" -- "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$family late filesystem DSO snapshot" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    cp "$plugin" "$live"
    live_abs=$(realpath "$live")
    capture_output actual env DLFREEZE_NO_FORK=1 \
        "$out" "$live_abs" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] &&
       [ "$actual" = runtime-truncate-snapshot-ok ] &&
       [ ! -s "$live" ]; then
        pass "$family late filesystem DSO survives source truncation"
    else
        fail "$family late filesystem DSO snapshot" \
            "exit=$rc output=$actual source_size=$(stat -c %s "$live" 2>/dev/null || printf unknown)"
    fi
    rm -rf "$root"
}

test_direct_runtime_truncate_snapshot() {
    echo "--- direct late-filesystem DSO immutable snapshot ---"
    run_direct_runtime_truncate_snapshot GNU "$TEST_REAL_GCC"
    if command -v musl-gcc >/dev/null 2>&1; then
        run_direct_runtime_truncate_snapshot musl \
            "$(command -v musl-gcc)"
    else
        skip "musl late filesystem DSO snapshot" "musl-gcc unavailable"
    fi
}

run_direct_runtime_noexec_policy() {
    local family="$1" cc="$2"
    local root="$BUILD/direct_runtime_noexec_$family"
    local plugin="$root/libdirect_runtime_noexec.so"
    local main="$root/main" out="$root/main.frozen" log="$root/main.log"
    local candidate="/dev/shm/dlfreeze-runtime-noexec-$family-$$.so"
    local expect native actual freeze_rc=0 native_rc=0 rc=0

    rm -rf "$root"
    mkdir -p "$root"
    if [ ! -d /dev/shm ] || [ ! -w /dev/shm ]; then
        skip "$family late DSO noexec policy" "/dev/shm is not writable"
        rm -rf "$root"
        return
    fi
    if ! "$cc" -Wall -Wextra -Werror -O2 -shared -fPIC \
            -Wl,-soname,libdirect_runtime_noexec.so \
            -o "$plugin" tests/direct_runtime_bounds_lib.c ||
       ! "$cc" -Wall -Wextra -Werror -O2 \
            -o "$main" tests/direct_runtime_bounds_main.c -ldl; then
        fail "$family late DSO noexec policy" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect "$main" "$plugin" || native_rc=$?
    if [ "$native_rc" -ne 0 ] || [ "$expect" != runtime-bounds=42 ]; then
        fail "$family late DSO noexec policy" \
            "native executable-mount control failed: $expect"
        rm -rf "$root"
        return
    fi
    if ! cp "$plugin" "$candidate"; then
        skip "$family late DSO noexec policy" \
            "cannot materialize /dev/shm probe"
        rm -rf "$root"
        return
    fi
    native=""; native_rc=0
    capture_output native "$main" "$candidate" || native_rc=$?
    if [ "$native_rc" -eq 0 ]; then
        skip "$family late DSO noexec policy" \
            "native dlopen permits executable /dev/shm mappings"
        rm -f "$candidate"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "$family late DSO noexec policy" \
        "$log" "$out" -- "$main" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$family late DSO noexec policy" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$out" "$candidate" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -ne 0 ] &&
           [[ "$actual" == *"cannot populate segment"* ]] &&
           [[ "$actual" != *"runtime-bounds=42"* ]]; then
            pass "$family late DSO preserves native noexec policy"
        else
            fail "$family late DSO noexec policy" \
                "native_exit=$native_rc direct_exit=$rc output=$actual"
        fi
    fi
    rm -f "$candidate"
    rm -rf "$root"
}

test_direct_runtime_noexec_policy() {
    echo "--- direct late-filesystem DSO mmap policy ---"
    run_direct_runtime_noexec_policy GNU "$TEST_REAL_GCC"
    if command -v musl-gcc >/dev/null 2>&1; then
        run_direct_runtime_noexec_policy musl \
            "$(command -v musl-gcc)"
    else
        skip "musl late DSO noexec policy" "musl-gcc unavailable"
    fi
}

# ===================================================================
# Test 11: direct-mode python with C extensions (hashlib, sqlite3)
# ===================================================================
test_python3_direct() {
    echo "--- python3 direct-load ---"
    if ! command -v python3 &>/dev/null; then skip "python3-direct" "not installed"; return; fi

    local pypath out="$BUILD/python3d.frozen" log="$BUILD/python3d.log"
    local freeze_rc=0
    rm -f "$log"
    pypath=$(readlink -f "$(command -v python3)")

    # Freeze with -d (direct) and -t (trace dlopen) to capture C extensions
    freeze_require_direct "python3-direct" "$log" "$out" -t -- \
        "$pypath" -c \
        'import _blake2,hashlib,sqlite3; [getattr(hashlib,n)(b"hello").hexdigest() for n in ("md5","sha1","sha256","sha3_256")]; _blake2.blake2b(b"hello").hexdigest(); _blake2.blake2s(b"hello").hexdigest(); sqlite3.connect(":memory:").close(); print("traced")' ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "python3 direct hashlib" "$DIRECT_FREEZE_REASON"
        skip "python3 direct sqlite3" "$DIRECT_FREEZE_REASON"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$out" "$log"
        return
    fi

    # hashlib — C extension that loads libcrypto.so via DT_NEEDED
    local expect actual rc rc_e
    rc_e=0
    capture_output expect python3 -c \
        'import hashlib; print(hashlib.sha256(b"hello").hexdigest())' || rc_e=$?
    rc=0
    capture_output actual "$out" -c 'import hashlib; print(hashlib.sha256(b"hello").hexdigest())' || rc=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" -eq 0 ] && [ "$rc" -eq 0 ]; then
        pass "python3 direct hashlib"
    else
        fail "python3 direct hashlib" \
            "output or exit code differs (exit $rc_e vs $rc): expected=$expect actual=$actual"
    fi

    # sqlite3 — C extension that loads libsqlite3.so
    rc_e=0
    capture_output expect python3 -c \
        'import sqlite3; c=sqlite3.connect(":memory:"); c.execute("CREATE TABLE t(x)"); c.execute("INSERT INTO t VALUES(42)"); print(c.execute("SELECT x FROM t").fetchone()[0])' || rc_e=$?
    rc=0
    capture_output actual "$out" -c 'import sqlite3; c=sqlite3.connect(":memory:"); c.execute("CREATE TABLE t(x)"); c.execute("INSERT INTO t VALUES(42)"); print(c.execute("SELECT x FROM t").fetchone()[0])' || rc=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" -eq 0 ] && [ "$rc" -eq 0 ]; then
        pass "python3 direct sqlite3"
    else
        fail "python3 direct sqlite3" \
            "output or exit code differs (exit $rc_e vs $rc): expected=$expect actual=$actual"
    fi

    rm -f "$out" "$log"
}

test_python_repl_pty_direct() {
    echo "--- python3 interactive PTY direct-load ---"
    if ! command -v python3 >/dev/null 2>&1; then
        skip "Python REPL PTY direct-load" "python3 not installed"
        return
    fi
    if ! python3 -c \
            'import os,pty; master,slave=pty.openpty(); os.close(master); os.close(slave)' \
            >/dev/null 2>&1; then
        skip "Python REPL PTY direct-load" \
            "Python cannot create a PTY in this environment"
        return
    fi
    if [ ! -r tests/python_repl_pty.py ]; then
        fail "Python REPL PTY direct-load" "PTY test driver is missing"
        return
    fi

    local python work="$BUILD/python-repl-pty-work"
    local log="$BUILD/python-repl-pty.log"
    local total_timeout rc=0 reason
    python=$(readlink -f "$(command -v python3)")
    total_timeout=$((TEST_FREEZE_TIMEOUT + 2 * TEST_RUN_TIMEOUT + 30))
    rm -rf "$work"
    rm -f "$log"

    run_with_timeout_seconds "$total_timeout" env -u DLFREEZE_NO_FORK \
            "$python" tests/python_repl_pty.py \
            --dlfreeze "$DLFREEZE" --python "$python" \
            --work-dir "$work" \
            --freeze-timeout "$TEST_FREEZE_TIMEOUT" \
            --run-timeout "$TEST_RUN_TIMEOUT" >"$log" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "Python REPL PTY direct-load"
    elif [ "$rc" -eq 77 ]; then
        reason=$(grep -m1 '^SKIP: ' "$log" 2>/dev/null || true)
        reason=${reason#SKIP: }
        skip "Python REPL PTY direct-load" \
            "${reason:-target runtime does not support direct-load}"
    else
        fail "Python REPL PTY direct-load" \
            "interactive trace or frozen REPL protocol failed"
        tail -n 100 "$log" || true
    fi

    rm -rf "$work"
    rm -f "$log"
}

# ===================================================================
# Test 12: glibc direct-load keeps rseq below static TLS for threads
# ===================================================================
test_glibc_tls_dtor_direct() {
    echo "--- glibc tls-dtor direct-load ---"
    if ! command -v g++ &>/dev/null; then
        skip "glibc-tls-dtor-direct" "g++ not installed"
        return
    fi

    local lib_src="$BUILD/tls_dtor_lib.cpp" main_src="$BUILD/tls_dtor_main.cpp"
    local lib="$BUILD/libtls_dtor.so" bin="$BUILD/tls_dtor_main"
    local out="$BUILD/tls_dtor_main.frozen" log="$BUILD/tls_dtor_main.log"
    local freeze_rc=0
    rm -f "$log"

    cat > "$lib_src" <<'CPP'
struct Marker {
    int value;
    Marker() : value(0) {}
    ~Marker() {}
};

thread_local Marker marker;

extern "C" int tls_dtor_touch(void) {
    return ++marker.value;
}
CPP

    cat > "$main_src" <<'CPP'
#include <pthread.h>
#include <stdio.h>

extern "C" int tls_dtor_touch(void);

static void *run(void *arg) {
    (void)arg;
    printf("%d\n", tls_dtor_touch());
    return NULL;
}

int main(void) {
    pthread_t thread;

    if (pthread_create(&thread, NULL, run, NULL) != 0)
        return 1;
    if (pthread_join(thread, NULL) != 0)
        return 2;
    return 0;
}
CPP

    if ! g++ -shared -fPIC -o "$lib" "$lib_src"; then
        fail "glibc-tls-dtor-direct" "g++ failed building shared library"
        return
    fi
    if ! g++ -pthread -L"$BUILD" -Wl,-rpath,'$ORIGIN' -o "$bin" "$main_src" -ltls_dtor; then
        fail "glibc-tls-dtor-direct" "g++ failed building executable"
        return
    fi
    freeze_require_direct "glibc-tls-dtor-direct" "$log" "$out" -- \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "glibc-tls-dtor-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$lib_src" "$main_src" "$lib" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$lib_src" "$main_src" "$lib" "$bin" "$out" "$log"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    capture_output expect "$bin" || rc_e=$?
    capture_output actual "$out" || rc_a=$?

    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "glibc tls-dtor direct-load"
    else
        fail "glibc tls-dtor direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi

    rm -f "$lib_src" "$main_src" "$lib" "$bin" "$out" "$log"
}

# ===================================================================
# Test 13: host Ruby direct-load handles missing user gem directories
# ===================================================================
test_ruby_direct_host_run() {
    echo "--- ruby direct-load host-run ---"
    if ! command -v ruby &>/dev/null; then
        skip "ruby-direct-host-run" "ruby not installed"
        return
    fi

    local rubypath out home log
    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    if ! rubypath=$(resolve_ruby_elf); then
        skip "ruby-direct-host-run" "ruby command is not an ELF and no Ruby ELF interpreter was found"
        return
    fi
    out="$BUILD/ruby-host.frozen"
    log="$BUILD/ruby-host.log"
    home="$BUILD/ruby-home-missing"

    rm -rf "$home"
    rm -f "$log"

    capture_output expect env HOME="$home" "$rubypath" -e 'puts 1+2' || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "ruby-direct-host-run" "native ruby failed (exit $rc_e)"
        rm -rf "$home"
        return
    fi
    HOME="$home" freeze_require_direct "ruby-direct-host-run" "$log" \
        "$out" -t -f '/usr/*' -- "$rubypath" -e 'puts 1+2' ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "ruby-direct-host-run" "$DIRECT_FREEZE_REASON"
        rm -rf "$home"
        rm -f "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$home"
        rm -f "$out" "$log"
        return
    fi
    # Capture through a regular file, not the surrounding $() pipe.  Under
    # qemu-user/aarch64, frozen Ruby can leave a worker alive after timeout
    # kills the main process; if that worker inherited the pipe, bash waits
    # forever for EOF.  A regular file has no pipe EOF dependency.
    local outfile="$BUILD/ruby-host.out"
    rm -f "$outfile"
    run_with_timeout env HOME="$home" "$out" -e 'puts 1+2' >"$outfile" 2>&1 || rc_a=$?
    actual=$(cat "$outfile")
    rm -f "$outfile"

    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "ruby direct host-run"
    else
        fail "ruby direct host-run" "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi

    rm -rf "$home"
    rm -f "$out" "$log"
}

# ===================================================================
# Test 14: dlopen by bare soname in direct-load mode
#   Real-world: many programs do dlopen("libcrypto.so.3", ...) without an
#   absolute path, expecting the dynamic loader to search the standard
#   library directories.  In direct-load mode we must replicate that.
# ===================================================================
test_dlopen_soname_direct() {
    echo "--- dlopen by soname direct-load ---"
    local gate="$BUILD/gnu_cache_gate" cache_path="" soname="" interp=""
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -ffunction-sections -fdata-sections -fno-stack-protector \
            -Wl,--gc-sections -o "$gate" tests/gnu_cache_gate.c \
            -ldl -pthread || ! "$gate"; then
        fail "GNU runtime cache parser" \
            "synthetic cache/hwcaps gate failed"
        rm -f "$gate"
        return
    fi
    pass "GNU runtime cache parser validates legacy, bounds, OS tags, and hwcaps"

    interp=$(LC_ALL=C readelf -lW "$gate" 2>/dev/null |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' |
        head -n 1)
    if [ -z "$interp" ] || [ ! -r "$interp" ] ||
       ! command -v strings >/dev/null 2>&1; then
        skip "dlopen-soname-direct" \
            "target interpreter configuration cannot be inspected"
        rm -f "$gate"
        return
    fi
    cache_path=$(strings -a "$interp" |
        awk '/^\/.*\/ld[.]so[.]cache$/ {
                 if (seen && value != $0) { ambiguous = 1 }
                 value = $0; seen = 1
             }
             END { if (seen && !ambiguous) print value }')
    if [ -z "$cache_path" ]; then
        skip "dlopen-soname-direct" \
            "target glibc cache pathname is missing or ambiguous"
        rm -f "$gate"
        return
    fi

    for cand in libm.so.6 libcrypt.so.2 libcrypto.so.3 libz.so.1; do
        local selected_path=""
        selected_path=$("$gate" "$cache_path" "$cand" 2>/dev/null) || true
        if [ -n "$selected_path" ] && [ -e "$selected_path" ]; then
            soname="$cand"
            cache_path="$selected_path"
            break
        fi
        [ -n "$soname" ] && break
    done
    if [ -z "$soname" ]; then
        skip "dlopen-soname-direct" \
            "no compatible soname in the GNU runtime cache"
        rm -f "$gate"
        return
    fi

    local src="$BUILD/dlopen_soname.c" bin="$BUILD/dlopen_soname"
    local out="$BUILD/dlopen_soname.frozen" log="$BUILD/dlopen_soname.log"
    local freeze_rc=0
    rm -f "$log"
    cat > "$src" <<C
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    void *h = dlopen("$soname", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    if (argc == 2 && strcmp(argv[1], "native-path") == 0) {
        struct link_map *map = NULL;
        if (dlinfo(h, RTLD_DI_LINKMAP, &map) != 0 || !map || !map->l_name)
            return 2;
        puts(map->l_name);
        return 0;
    }
    printf("opened\n");
    return 0;
}
C
    gcc -o "$bin" "$src" -ldl

    local native_path="" cache_real="" native_real=""
    native_path=$("$bin" native-path 2>/dev/null) || true
    cache_real=$(readlink -f "$cache_path" 2>/dev/null || true)
    native_real=$(readlink -f "$native_path" 2>/dev/null || true)
    if [ -z "$cache_real" ] || [ "$cache_real" != "$native_real" ]; then
        fail "GNU runtime cache native oracle" \
            "cache=$cache_path native=$native_path"
        rm -f "$src" "$bin" "$out" "$log" "$gate"
        return
    fi
    pass "GNU runtime cache choice matches native loader"

    freeze_require_direct "dlopen-soname-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlopen-soname-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log" "$gate"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log" "$gate"
        return
    fi

    local actual rc=0
    capture_output actual "$out" || rc=$?
    # Allow the "loading from disk" warning that dlfreeze prints.
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "opened" ] && [ "$rc" = "0" ]; then
        pass "dlopen by soname direct-load"
    else
        fail "dlopen by soname direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log" "$gate"
}

# ===================================================================
# Test 15: dlopen with a relative slash path in direct-load mode
#   Per dlopen(3): if the name contains a slash it is interpreted as a
#   path (absolute or relative to cwd); only bare sonames are searched.
# ===================================================================
test_dlopen_relpath_direct() {
    echo "--- dlopen relative path direct-load ---"
    local libsrc="$BUILD/dlrel_lib.c"  lib="$BUILD/libdlrel.so"
    local src="$BUILD/dlrel_main.c"    bin="$BUILD/dlrel_main"
    local out="$BUILD/dlrel_main.frozen" log="$BUILD/dlrel_main.log"
    local freeze_rc=0
    rm -f "$log"

    cat > "$libsrc" <<'C'
int answer(void) { return 42; }
C
    gcc -shared -fPIC -o "$lib" "$libsrc"

    cat > "$src" <<'C'
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("./libdlrel.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    int (*answer)(void) = dlsym(h, "answer");
    if (!answer) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("%d\n", answer());
    return 0;
}
C
    gcc -o "$bin" "$src" -ldl

    freeze_require_direct "dlopen-relpath-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlopen-relpath-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    local actual rc=0 out_abs
    out_abs=$(readlink -f "$out")
    capture_output_in_dir actual "$BUILD" "$out_abs" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "42" ] && [ "$rc" = "0" ]; then
        pass "dlopen relative path direct-load"
    else
        fail "dlopen relative path direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
}

# The manifest keeps the caller's exact pathful request separate from the
# canonical source used for packing.  Exercise both an ordinary relative path
# and a symlink spelling after neither host lookup can succeed.
test_dlopen_exact_pathful_replay_direct() {
    echo "--- exact pathful dlopen replay direct-load ---"
    local root="$BUILD/dlopen_exact_pathful"
    local rel_dir="$root/relative" link_dir="$root/symlink"
    local libsrc="$root/lib.c" src="$root/main.c" bin="$root/main"
    local rel_lib="$rel_dir/libexact_relative.so"
    local real_lib="$link_dir/libexact_real.so"
    local alias_lib="$link_dir/libexact_alias.so"
    local rel_out="$root/relative.frozen" link_out="$root/symlink.frozen"
    local rel_log="$root/relative.log" link_log="$root/symlink.log"
    local freeze_rc=0 actual="" rc=0

    rm -rf "$root"
    mkdir -p "$rel_dir" "$link_dir"
    cat > "$libsrc" <<'C'
#ifndef EXACT_VALUE
#define EXACT_VALUE 0
#endif
int exact_pathful_value(void) { return EXACT_VALUE; }
C
    cat > "$src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3 || chdir(argv[1]) != 0)
        return 2;
    void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle,
                                               "exact_pathful_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -DEXACT_VALUE=71 \
            -Wl,-soname,libexact_relative.so -o "$rel_lib" "$libsrc" ||
       ! gcc -shared -fPIC -DEXACT_VALUE=72 \
            -Wl,-soname,libexact_real.so -o "$real_lib" "$libsrc" ||
       ! ln -s libexact_real.so "$alias_lib" ||
       ! gcc -o "$bin" "$src" -ldl; then
        fail "exact pathful dlopen replay" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "exact relative dlopen replay" "$rel_log" \
        "$rel_out" -t -- "$bin" "$rel_dir" ./libexact_relative.so ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "exact pathful dlopen replay" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    freeze_rc=0
    freeze_require_direct "exact symlink dlopen replay" "$link_log" \
        "$link_out" -t -- "$bin" "$link_dir" ./libexact_alias.so ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "exact symlink dlopen replay" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$rel_lib" "$rel_lib.host-unavailable"
    mv "$alias_lib" "$alias_lib.host-unavailable"
    mv "$real_lib" "$real_lib.host-unavailable"
    if run_with_timeout "$bin" "$rel_dir" ./libexact_relative.so \
            >/dev/null 2>&1 ||
       run_with_timeout "$bin" "$link_dir" ./libexact_alias.so \
            >/dev/null 2>&1; then
        fail "exact pathful dlopen replay" "host lookup unexpectedly succeeds"
        rm -rf "$root"
        return
    fi

    capture_output actual "$rel_out" "$rel_dir" ./libexact_relative.so || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -ne 0 ] || [ "$actual" != 71 ]; then
        fail "exact relative dlopen replay" "exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    actual=""; rc=0
    capture_output actual "$link_out" "$link_dir" ./libexact_alias.so || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = 72 ]; then
        pass "exact pathful dlopen replay without host DSO"
    else
        fail "exact symlink dlopen replay" "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# Two traced request spellings may identify one inode.  V4 retains both
# requests while keeping one map, constructor run, TLS module, and the first
# loader-visible l_name.
test_dlopen_same_source_aliases_direct() {
    echo "--- same-source dlopen aliases direct-load ---"
    local root="$BUILD/dlopen_same_source_aliases"
    local libsrc="$root/lib.c" src="$root/main.c"
    local real="$root/libalias_source.so"
    local first="$root/libalias_first.so" second="$root/libalias_second.so"
    local bin="$root/main" out="$root/main.frozen" log="$root/freeze.log"
    local root_abs expected actual="" rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat >"$libsrc" <<'C'
extern int dlfreeze_alias_ctor_count;
static __thread int dlfreeze_alias_tls = 91;
__attribute__((constructor))
static void dlfreeze_alias_init(void) { dlfreeze_alias_ctor_count++; }
int *dlfreeze_alias_tls_address(void) { return &dlfreeze_alias_tls; }
int dlfreeze_alias_value(void) { return dlfreeze_alias_tls; }
C
    cat >"$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int dlfreeze_alias_ctor_count;

int main(int argc, char **argv) {
    void *first_handle, *second_handle;
    int *(*first_tls)(void), *(*second_tls)(void);
    struct link_map *first_map = NULL, *second_map = NULL;
#ifdef RTLD_DI_TLS_MODID
    size_t first_modid = 0, second_modid = 0;
#endif
    int same_tls, same_tls_module;
    const char *expected = getenv("DLFREEZE_ALIAS_EXPECT_NAME");

    if (argc != 4 || chdir(argv[1]) != 0)
        return 2;
    first_handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    second_handle = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    if (!first_handle || !second_handle)
        return 3;
    first_tls = (int *(*)(void))dlsym(
        first_handle, "dlfreeze_alias_tls_address");
    second_tls = (int *(*)(void))dlsym(
        second_handle, "dlfreeze_alias_tls_address");
    if (!first_tls || !second_tls ||
        dlinfo(first_handle, RTLD_DI_LINKMAP, &first_map) != 0 ||
        dlinfo(second_handle, RTLD_DI_LINKMAP, &second_map) != 0 ||
        !first_map || !second_map || !first_map->l_name)
        return 4;
#ifdef RTLD_DI_TLS_MODID
    if (dlinfo(first_handle, RTLD_DI_TLS_MODID, &first_modid) != 0 ||
        dlinfo(second_handle, RTLD_DI_TLS_MODID, &second_modid) != 0)
        return 4;
#endif
    same_tls = first_tls() == second_tls();
    same_tls_module = same_tls;
#ifdef RTLD_DI_TLS_MODID
    same_tls_module = same_tls_module && first_modid != 0 &&
                      first_modid == second_modid;
#endif
    printf("%d:%d:%d:%d:%s\n", dlfreeze_alias_ctor_count,
           first_handle == second_handle, same_tls, same_tls_module,
           first_map->l_name);
    if (dlfreeze_alias_ctor_count != 1 || first_handle != second_handle ||
        !same_tls || !same_tls_module || first_map != second_map ||
        (expected && strcmp(first_map->l_name, expected) != 0))
        return 5;
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libalias_source.so \
            -o "$real" "$libsrc" ||
       ! ln -s libalias_source.so "$first" ||
       ! ln -s libalias_source.so "$second" ||
       ! gcc -Wl,--export-dynamic -o "$bin" "$src" -ldl; then
        fail "same-source dlopen aliases" "fixture compile failed"
        rm -rf "$root"
        return
    fi
    root_abs=$(readlink -f "$root")
    capture_output actual "$bin" "$root_abs" \
        ./libalias_first.so ./libalias_second.so || rc=$?
    if [ "$rc" -ne 0 ] || [[ "$actual" != 1:1:1:1:* ]]; then
        fail "native same-source dlopen aliases" \
            "exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "same-source dlopen aliases" "$log" "$out" \
        -t -- "$bin" "$root_abs" \
        ./libalias_first.so ./libalias_second.so || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "same-source dlopen aliases" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    rm -f "$first" "$second" "$real"
    expected="$root_abs/./libalias_first.so"
    actual=""; rc=0
    capture_output actual env DLFREEZE_ALIAS_EXPECT_NAME="$expected" \
        "$out" "$root_abs" ./libalias_first.so ./libalias_second.so || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "1:1:1:1:$expected" ]; then
        pass "same-source aliases share one map and first l_name"
    else
        fail "same-source dlopen aliases" "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# A traced dlopen root may already be a startup DT_NEEDED dependency.  The
# resolver deduplicates those two observations by source identity; the manifest
# must retain the request alias without reclassifying the object as dormant.
test_dlopen_startup_overlap_pathful_direct() {
    echo "--- startup-owned exact pathful dlopen replay ---"
    local root="$BUILD/dlopen_startup_overlap"
    local libsrc="$root/lib.c" lib="$root/libstartup_overlap.so"
    local src="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/freeze.log"
    local freeze_rc=0 actual="" expect="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
extern int startup_overlap_ctor_count;
static __thread int startup_overlap_tls = 83;
__attribute__((constructor))
static void startup_overlap_init(void) { startup_overlap_ctor_count++; }
int startup_overlap_value(void) { return startup_overlap_tls; }
int *startup_overlap_tls_address(void) { return &startup_overlap_tls; }
C
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <unistd.h>
extern int startup_overlap_value(void);
extern int *startup_overlap_tls_address(void);
int startup_overlap_ctor_count;
int main(int argc, char **argv) {
    struct link_map *linked_map = NULL, *alias_map = NULL;
#ifdef RTLD_DI_TLS_MODID
    size_t linked_modid = 0, alias_modid = 0;
#endif
    int same_tls, same_tls_module;
    if (argc != 3 || chdir(argv[1]) != 0)
        return 2;
    int linked_value = startup_overlap_value();
    void *linked = dlopen("libstartup_overlap.so",
                          RTLD_NOW | RTLD_NOLOAD | RTLD_LOCAL);
    void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!linked || !handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    int (*opened_value)(void) = (int (*)(void))dlsym(
        handle, "startup_overlap_value");
    int *(*opened_tls)(void) = (int *(*)(void))dlsym(
        handle, "startup_overlap_tls_address");
    if (!opened_value || !opened_tls ||
        dlinfo(linked, RTLD_DI_LINKMAP, &linked_map) != 0 ||
        dlinfo(handle, RTLD_DI_LINKMAP, &alias_map) != 0 ||
        !linked_map || !alias_map || !linked_map->l_name)
        return 4;
#ifdef RTLD_DI_TLS_MODID
    if (dlinfo(linked, RTLD_DI_TLS_MODID, &linked_modid) != 0 ||
        dlinfo(handle, RTLD_DI_TLS_MODID, &alias_modid) != 0)
        return 4;
#endif
    same_tls = startup_overlap_tls_address() == opened_tls();
    same_tls_module = same_tls;
#ifdef RTLD_DI_TLS_MODID
    same_tls_module = same_tls_module && linked_modid != 0 &&
                      linked_modid == alias_modid;
#endif
    printf("%d:%d:%d:%d:%d:%s\n", linked_value, opened_value(),
           startup_overlap_ctor_count, linked == handle,
           same_tls_module,
           linked_map->l_name);
    return linked_value == 83 && opened_value() == 83 &&
           startup_overlap_ctor_count == 1 && linked == handle &&
           linked_map == alias_map &&
           same_tls && same_tls_module ? 0 : 5;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libstartup_overlap.so \
            -o "$lib" "$libsrc" ||
       ! gcc -Wl,--export-dynamic -o "$bin" "$src" \
            -L"$root" -Wl,-rpath,'$ORIGIN' \
            -Wl,--no-as-needed -lstartup_overlap -ldl; then
        fail "startup-owned exact pathful dlopen replay" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi
    capture_output actual "$bin" "$root" ./libstartup_overlap.so || rc=$?
    expect="$actual"
    if [ "$rc" -ne 0 ] || [[ "$expect" != 83:83:1:1:1:* ]]; then
        fail "startup-owned exact pathful dlopen replay" \
            "native fixture exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "startup-owned exact pathful dlopen replay" \
        "$log" "$out" -t -- "$bin" "$root" ./libstartup_overlap.so ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "startup-owned exact pathful dlopen replay" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$lib" "$lib.host-unavailable"
    if run_with_timeout "$bin" "$root" ./libstartup_overlap.so \
            >/dev/null 2>&1; then
        fail "startup-owned exact pathful dlopen replay" \
            "native startup unexpectedly found the removed DSO"
        rm -rf "$root"
        return
    fi

    actual=""; rc=0
    capture_output actual "$out" "$root" ./libstartup_overlap.so || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "startup-owned aliases retain one map, TLS module, and l_name"
    else
        fail "startup-owned exact pathful dlopen replay" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# Every successful non-NULL dlopen must produce either a complete V4 record or
# an explicit terminal marker.  Interpose dlinfo to emulate a libc which does
# not expose RTLD_DI_LINKMAP for the returned handle.
test_successful_dlopen_trace_fails_closed() {
    echo "--- successful dlopen trace completeness ---"
    local root="$BUILD/dlopen_trace_completeness"
    local libsrc="$root/lib.c" lib="$root/libtrace_complete.so"
    local src="$root/main.c" bin="$root/main"
    local mocksrc="$root/mock_dlinfo.c" mock="$root/mock_dlinfo.so"
    local out="$root/main.frozen" log="$root/freeze.log"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
int trace_complete_value(void) { return 91; }
C
    cat > "$src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    int (*value)(void) = (int (*)(void))dlsym(
        handle, "trace_complete_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    cat > "$mocksrc" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
int dlinfo(void *handle, int request, void *info) {
    (void)handle;
    (void)request;
    (void)info;
    errno = ENOTSUP;
    return -1;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libtrace_complete.so \
            -o "$lib" "$libsrc" ||
       ! gcc -o "$bin" "$src" -ldl ||
       ! gcc -shared -fPIC -o "$mock" "$mocksrc"; then
        fail "successful dlopen trace completeness" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual "$bin" "$lib" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 91 ]; then
        fail "successful dlopen trace completeness" \
            "native fixture exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    if run_freeze env LD_PRELOAD="$mock" "$DLFREEZE" -t -o "$out" -- \
            "$bin" "$lib" >"$log" 2>&1; then
        fail "successful dlopen trace completeness" \
            "packaging unexpectedly succeeded"
    elif grep -Fq \
            'preload helper reported an incomplete dlopen trace: successful-dlopen-has-no-link-map' \
            "$log" && [ ! -e "$out" ]; then
        pass "successful unresolved dlopen trace fails closed"
    else
        fail "successful dlopen trace completeness" \
            "terminal trace diagnostic or output cleanup missing"
        tail -n 40 "$log" || true
    fi
    rm -rf "$root"
}

# Loader-specific dynamic-string expansion must not be frozen as though the
# request were an ordinary stable pathname.  Glibc supports $ORIGIN here;
# other libcs legitimately skip after the native capability probe.
test_dlopen_dynamic_token_refusal() {
    echo "--- dynamic-token dlopen trace refusal ---"
    local root="$BUILD/dlopen_dynamic_token"
    local libsrc="$root/lib.c" lib="$root/libtoken_request.so"
    local src="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/freeze.log"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
int token_request_value(void) { return 92; }
C
    cat > "$src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *handle = dlopen("$ORIGIN/libtoken_request.so",
                          RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    int (*value)(void) = (int (*)(void))dlsym(
        handle, "token_request_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libtoken_request.so \
            -o "$lib" "$libsrc" ||
       ! gcc -o "$bin" "$src" -ldl; then
        fail "dynamic-token dlopen trace refusal" "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual "$bin" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 92 ]; then
        skip "dynamic-token dlopen trace refusal" \
            "runtime does not expand \$ORIGIN in dlopen requests"
        rm -rf "$root"
        return
    fi

    if run_freeze "$DLFREEZE" -t -o "$out" -- "$bin" \
            >"$log" 2>&1; then
        fail "dynamic-token dlopen trace refusal" \
            "packaging unexpectedly succeeded"
        tail -n 40 "$log" || true
    elif grep -Fq \
            'preload helper reported an incomplete dlopen trace: dynamic-string-token-in-dlopen-request-is-unsupported' \
            "$log" && [ ! -e "$out" ]; then
        pass "dynamic-token dlopen trace fails at pack time"
    else
        fail "dynamic-token dlopen trace refusal" \
            "precise diagnostic or output cleanup missing"
        tail -n 40 "$log" || true
    fi
    rm -rf "$root"
}

# Extraction exposes one basename per packed DSO.  If a successful bare
# request used a different alias (for example a symlink), only direct replay
# can reproduce that exact lookup after the host alias disappears.
test_dlopen_bare_alias_requires_direct() {
    echo "--- bare dlopen alias requires direct-load ---"
    local root="$BUILD/dlopen_bare_alias"
    local libsrc="$root/lib.c" real_lib="$root/libbare_real.so"
    local alias_lib="$root/libbare_alias.so"
    local src="$root/main.c" bin="$root/main"
    local out="$root/main.frozen" log="$root/freeze.log"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
int bare_alias_value(void) { return 93; }
C
    cat > "$src" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *handle = dlopen("libbare_alias.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle,
                                                "bare_alias_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libbare_real.so \
            -o "$real_lib" "$libsrc" ||
       ! ln -s libbare_real.so "$alias_lib" ||
       ! gcc -o "$bin" "$src" -ldl; then
        fail "bare dlopen alias requires direct-load" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi

    capture_output actual env LD_LIBRARY_PATH="$root" "$bin" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 93 ]; then
        fail "bare dlopen alias requires direct-load" \
            "native fixture exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi

    if run_freeze env LD_LIBRARY_PATH="$root" "$DLFREEZE" -t -o "$out" \
            -- "$bin" >"$log" 2>&1; then
        fail "bare dlopen alias requires direct-load" \
            "extraction packaging unexpectedly succeeded"
    elif grep -Fq \
            'bare traced dlopen aliases require a supported direct-load mode' \
            "$log" && [ ! -e "$out" ]; then
        pass "bare dlopen alias extraction fails closed"
    else
        fail "bare dlopen alias requires direct-load" \
            "precise diagnostic or output cleanup missing"
        tail -n 40 "$log" || true
    fi
    rm -rf "$root"
}

# The trace helper may reproduce dlmopen only in the base namespace.  A
# successful isolated-namespace load must remain successful in the tracee but
# make the resulting trace terminally incomplete.
test_dlmopen_trace_namespaces() {
    echo "--- dlmopen trace namespaces ---"
    local root="$BUILD/dlmopen_trace_namespaces"
    local libsrc="$root/lib.c" lib="$root/libdlmtrace.so"
    local src="$root/main.c" bin="$root/main"
    local base_out="$root/base.frozen" base_log="$root/base.log"
    local new_out="$root/new.frozen" new_log="$root/new.log"
    local actual="" rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$libsrc" <<'C'
int dlmtrace_value(void) { return 94; }
C
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    Lmid_t namespace_id = strcmp(argv[1], "base") == 0
        ? LM_ID_BASE : LM_ID_NEWLM;
    void *handle = dlmopen(namespace_id, "libdlmtrace.so",
                           RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlmopen: %s\n", dlerror());
        return 3;
    }
    int (*value)(void) = (int (*)(void))dlsym(handle, "dlmtrace_value");
    if (!value)
        return 4;
    printf("%d\n", value());
    return 0;
}
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlmtrace.so \
            -o "$lib" "$libsrc" ||
       ! gcc -o "$bin" "$src" -ldl 2>/dev/null; then
        skip "dlmopen trace namespaces" \
            "compiler does not support dlmopen (likely musl)"
        rm -rf "$root"
        return
    fi

    capture_output actual env LD_LIBRARY_PATH="$root" "$bin" base || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 94 ]; then
        fail "dlmopen trace namespaces" \
            "native base namespace exit=$rc output=$actual"
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual env LD_LIBRARY_PATH="$root" "$bin" new || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != 94 ]; then
        skip "dlmopen trace namespaces" \
            "runtime does not support a new link-map namespace"
        rm -rf "$root"
        return
    fi

    if ! run_freeze env LD_LIBRARY_PATH="$root" "$DLFREEZE" -t \
            -o "$base_out" -- "$bin" base >"$base_log" 2>&1; then
        fail "base namespace dlmopen trace" "packaging failed"
        tail -n 40 "$base_log" || true
        rm -rf "$root"
        return
    fi

    if run_freeze env LD_LIBRARY_PATH="$root" "$DLFREEZE" -t \
            -o "$new_out" -- "$bin" new >"$new_log" 2>&1; then
        fail "non-base dlmopen trace refusal" \
            "packaging unexpectedly succeeded"
    elif grep -Fq \
            'preload helper reported an incomplete dlopen trace: successful-dlmopen-used-non-base-namespace' \
            "$new_log" && [ ! -e "$new_out" ]; then
        pass "non-base dlmopen trace fails closed"
    else
        fail "non-base dlmopen trace refusal" \
            "terminal trace diagnostic or output cleanup missing"
        tail -n 40 "$new_log" || true
    fi

    mv "$lib" "$lib.host-unavailable"
    actual=""; rc=0
    capture_output actual "$base_out" base || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = 94 ]; then
        pass "base namespace dlmopen trace is extraction-reproducible"
    else
        fail "base namespace dlmopen trace" "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 16: dlmopen supports the base namespace and rejects fake isolation
# ===================================================================
test_dlmopen_direct() {
    echo "--- dlmopen direct-load ---"
    local src="$BUILD/dlmopen_main.c" bin="$BUILD/dlmopen_main"
    local out="$BUILD/dlmopen_main.frozen" log="$BUILD/dlmopen_main.log"
    local freeze_rc=0
    rm -f "$log"
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *base = dlmopen(LM_ID_BASE, NULL, RTLD_NOW);
    if (!base) { fprintf(stderr, "base: %s\n", dlerror()); return 1; }
    if (dlmopen(LM_ID_NEWLM, NULL, RTLD_NOW) != NULL) {
        fprintf(stderr, "new namespace was silently aliased\n");
        return 2;
    }
    if (!dlerror()) { fprintf(stderr, "missing namespace error\n"); return 3; }
    puts("namespace-contract-ok");
    return 0;
}
C
    if ! gcc -o "$bin" "$src" -ldl 2>/dev/null; then
        skip "dlmopen-direct" "compiler does not support dlmopen (likely musl)"
        rm -f "$src" "$bin" "$out"
        return
    fi

    freeze_require_direct "dlmopen-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlmopen-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    local actual rc=0
    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "namespace-contract-ok" ] && [ "$rc" = "0" ]; then
        pass "dlmopen namespace contract direct-load"
    else
        fail "dlmopen direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 17: __thread variables in a dlopened shared library are
# per-thread (not shared across threads).
#   Repro for the bug: when glibc recycles a cached pthread stack it
#   calls _dl_allocate_tls_init without _dl_allocate_tls, so the DTV
#   block for a dlopened TLS module is reused.  Without re-initialising
#   it from the module's .tdata image, __thread state from the previous
#   thread leaks into the next one.
# ===================================================================
test_dlopen_tls_per_thread_direct() {
    echo "--- dlopen TLS per-thread direct-load ---"
    local libsrc="$BUILD/tlslib.c"  lib="$BUILD/libtlsperthread.so"
    local src="$BUILD/tlsuse.c"     bin="$BUILD/tlsuse"
    local out="$BUILD/tlsuse.frozen" log="$BUILD/tlsuse.log"
    local freeze_rc=0
    local tlsdesc_reloc=""
    local -a tls_cflags=()
    rm -f "$log"

    case "$(uname -m)" in
        x86_64)
            tls_cflags=(-mtls-dialect=gnu2)
            tlsdesc_reloc="R_X86_64_TLSDESC"
            ;;
        aarch64)
            tlsdesc_reloc="R_AARCH64_TLSDESC"
            ;;
    esac

    cat > "$libsrc" <<'C'
#include <stdint.h>
__thread int counter __attribute__((aligned(8192))) = 0;
int bump(void) { return ++counter; }
int tls_is_aligned(void) { return ((uintptr_t)&counter % 8192) == 0; }
C
    if ! gcc -shared -fPIC "${tls_cflags[@]}" -o "$lib" "$libsrc"; then
        # Old x86 compilers may not support the GNU2 dialect switch.  Keep
        # the per-thread regression there, but require TLSDESC whenever the
        # toolchain can deliberately emit it.
        tls_cflags=()
        tlsdesc_reloc=""
        if ! gcc -shared -fPIC -o "$lib" "$libsrc"; then
            fail "dlopen TLS per-thread direct-load" \
                "could not build TLS shared library fixture"
            rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
            return
        fi
    fi
    if ! readelf -W -l "$lib" | grep -E \
         'TLS[[:space:]].*0x2000([[:space:]]|$)' >/dev/null; then
        fail "dlopen TLS per-thread direct-load" \
            "fixture does not contain 8192-byte-aligned PT_TLS"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ -n "$tlsdesc_reloc" ] &&
       ! readelf -W -r "$lib" | grep "$tlsdesc_reloc" >/dev/null; then
        fail "dlopen TLS per-thread direct-load" \
            "fixture does not contain $tlsdesc_reloc"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    cat > "$src" <<C
#include <stdio.h>
#include <pthread.h>
#include <dlfcn.h>
static int (*bump)(void);
static int (*tls_is_aligned)(void);
static void *worker(void *arg) {
    long id = (long)arg;
    if (!tls_is_aligned()) return (void*)1L;
    for (int i = 0; i < 3; i++) printf("t%ld %d\n", id, bump());
    return NULL;
}
int main(void) {
    void *h = dlopen("$(realpath "$lib")", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    bump = dlsym(h, "bump");
    tls_is_aligned = dlsym(h, "tls_is_aligned");
    if (!bump || !tls_is_aligned || !tls_is_aligned()) {
        fprintf(stderr, "dlsym/alignment: %s\n", dlerror()); return 1;
    }
    pthread_t t1, t2;
    void *result = NULL;
    pthread_create(&t1, NULL, worker, (void*)1L); pthread_join(t1, &result);
    if (result) return 2;
    pthread_create(&t2, NULL, worker, (void*)2L); pthread_join(t2, &result);
    if (result) return 3;
    return 0;
}
C
    gcc -o "$bin" "$src" -ldl -lpthread

    freeze_require_direct "dlopen-tls-per-thread-direct" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlopen-tls-per-thread-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    capture_output expect "$bin" || rc_e=$?
    capture_output actual "$out" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$expect" = "$actual" ] &&
       [ "$rc_e" -eq 0 ] && [ "$rc_a" -eq 0 ]; then
        pass "dlopen TLS per-thread direct-load"
    else
        fail "dlopen TLS per-thread direct-load" \
            "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi
    rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
}

# glibc directly frees DTV to_free entries when reusing a cached stack, and
# asks rtld to release them when destroying a caller-provided stack.  Exercise
# the latter path repeatedly with a large late-loaded TLS block: a no-op
# _dl_deallocate_tls grows the address space by roughly one TLS block per
# thread, while correct target-allocator ownership remains bounded.
test_glibc_tls_teardown_direct() {
    echo "--- glibc dynamic TLS teardown direct-load ---"
    local root="$BUILD/glibc_tls_teardown"
    local lib="$root/libdirect_tls_teardown.so"
    local bin="$root/direct_tls_teardown"
    local out="$root/direct_tls_teardown.frozen"
    local log="$root/direct_tls_teardown.log"
    local original_lib actual="" native="" libc_banner="" rc=0 freeze_rc=0
    local -a tls_cflags=()

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eq 'GNU libc|GLIBC' <<<"$libc_banner"; then
        skip "glibc dynamic TLS teardown direct-load" \
            "host runtime is not glibc"
        return
    fi
    case "$(uname -m)" in
        x86_64) tls_cflags=(-mtls-dialect=gnu) ;;
        aarch64) tls_cflags=(-mtls-dialect=trad) ;;
        *)
            skip "glibc dynamic TLS teardown direct-load" \
                "unsupported architecture"
            return
            ;;
    esac

    rm -rf "$root"
    mkdir -p "$root"
    if ! gcc -shared -fPIC -ftls-model=global-dynamic \
            "${tls_cflags[@]}" -Wl,-soname,libdirect_tls_teardown.so \
            -o "$lib" tests/direct_tls_teardown_lib.c ||
       ! gcc -o "$bin" tests/direct_tls_teardown.c -ldl -lpthread; then
        fail "glibc dynamic TLS teardown direct-load" \
            "fixture compile failed"
        rm -rf "$root"
        return
    fi
    original_lib=$(realpath "$lib")
    capture_output native "$bin" "$original_lib" || rc=$?
    if [ "$rc" -eq 77 ]; then
        skip "glibc dynamic TLS teardown direct-load" \
            "/proc/self/statm is unavailable"
        rm -rf "$root"
        return
    fi
    if [ "$rc" -ne 0 ] || [ "$native" != "tls-teardown-ok" ]; then
        fail "glibc dynamic TLS teardown direct-load" \
            "native fixture exit=$rc output=$native"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "glibc-tls-teardown-direct" "$log" "$out" \
        -t -- "$bin" "$original_lib" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "glibc dynamic TLS teardown direct-load" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    mv "$lib" "$lib.host-unavailable"
    rc=0
    capture_output actual "$out" "$original_lib" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "tls-teardown-ok" ]; then
        pass "glibc dynamic TLS teardown direct-load"
    else
        fail "glibc dynamic TLS teardown direct-load" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 17b: a conservative glibc DTV capacity must bound every read from
# the old allocation.  Put a capacity-zero DTV at the end of a readable
# page and protect the following page; __tls_get_addr must grow the DTV
# and reconstruct the startup module's static slot without reading past
# the advertised generation entry.
# ===================================================================
test_glibc_dtv_capacity_direct() {
    echo "--- glibc DTV capacity direct-load ---"
    local libsrc="$BUILD/dtvcap-lib.c" lib="$BUILD/libdtvcap.so"
    local src="$BUILD/dtvcap-main.c" bin="$BUILD/dtvcap-main"
    local out="$BUILD/dtvcap-main.frozen" log="$BUILD/dtvcap-main.log"
    local actual="" libc_banner="" relocs="" rc=0 freeze_rc=0
    local -a tls_cflags=()

    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eq 'GNU libc|GLIBC' <<<"$libc_banner"; then
        skip "glibc DTV capacity direct-load" "host runtime is not glibc"
        return
    fi
    case "$(uname -m)" in
        x86_64) tls_cflags=(-mtls-dialect=gnu) ;;
        aarch64) tls_cflags=(-mtls-dialect=trad) ;;
        *)
            skip "glibc DTV capacity direct-load" "unsupported architecture"
            return
            ;;
    esac

    cat > "$libsrc" <<'C'
__thread int dtvcap_value = 37;
int dtvcap_read(void) { return dtvcap_value; }
C
    if ! gcc -shared -fPIC -ftls-model=global-dynamic \
            "${tls_cflags[@]}" -Wl,-soname,libdtvcap.so \
            -o "$lib" "$libsrc"; then
        skip "glibc DTV capacity direct-load" \
            "compiler cannot emit traditional global-dynamic TLS"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi
    if ! relocs=$(readelf -W -r "$lib" 2>&1) ||
       ! grep -q '__tls_get_addr' <<<"$relocs"; then
        fail "glibc DTV capacity direct-load" \
            "fixture does not call __tls_get_addr"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

extern int dtvcap_read(void);

static uintptr_t current_tp(void)
{
    uintptr_t tp;
#if defined(__x86_64__)
    __asm__ volatile("movq %%fs:0, %0" : "=r"(tp));
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
#endif
    return tp;
}

int main(void)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *map = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uintptr_t tp;
    uintptr_t **dtv_slot;
    uintptr_t *raw;

    if (map == MAP_FAILED ||
        mprotect(map + page, page, PROT_NONE) != 0)
        return 2;

    /* header entry + generation entry are the final 32 readable bytes. */
    raw = (uintptr_t *)(map + page) - 4;
    raw[0] = 0; /* advertised module capacity */
    raw[1] = 0;
    raw[2] = 1; /* generation */
    raw[3] = 0;

    tp = current_tp();
#if defined(__x86_64__)
    dtv_slot = (uintptr_t **)(tp + 8);
#else
    dtv_slot = (uintptr_t **)tp;
#endif
    *dtv_slot = raw + 2;

    if (dtvcap_read() != 37)
        return 3;
    if (*dtv_slot == raw + 2 || (*dtv_slot)[-2] == 0)
        return 4;
    puts("dtv-capacity-ok");
    return 0;
}
C
    if ! gcc -o "$bin" "$src" -L"$BUILD" -Wl,-rpath,'$ORIGIN' \
            -Wl,--no-as-needed -ldtvcap; then
        fail "glibc DTV capacity direct-load" \
            "could not build guarded-DTV fixture"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    freeze_require_direct "glibc-dtv-capacity-direct" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "glibc DTV capacity direct-load" "$DIRECT_FREEZE_REASON"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "dtv-capacity-ok" ]; then
        pass "glibc DTV capacity direct-load"
    else
        fail "glibc DTV capacity direct-load" "exit=$rc output=$actual"
    fi
    rm -f "$libsrc" "$lib" "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 18: direct mappings honor RELRO and leave reserved holes inaccessible
# ===================================================================
test_direct_memory_protections() {
    echo "--- direct memory protections ---"
    local src="$BUILD/direct_protections.c" bin="$BUILD/direct_protections"
    local out="$BUILD/direct_protections.frozen"
    local log="$BUILD/direct_protections.log" freeze_rc=0

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uintptr_t relro_addr;
static uintptr_t gap_addr;
static int captured_main;

static int capture_main(struct dl_phdr_info *info, size_t size, void *data) {
    uintptr_t load_end = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    (void)size;
    (void)data;
    if (captured_main || page_size <= 0) return 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD &&
            info->dlpi_addr + ph->p_vaddr + ph->p_memsz > load_end)
            load_end = info->dlpi_addr + ph->p_vaddr + ph->p_memsz;
        if (ph->p_type == PT_GNU_RELRO && ph->p_memsz)
            relro_addr = info->dlpi_addr + ph->p_vaddr;
    }
    gap_addr = (load_end + (uintptr_t)page_size - 1) &
               ~((uintptr_t)page_size - 1);
    captured_main = 1;
    return 0;
}

int main(void) {
    char line[512], perms[5];
    unsigned long lo, hi;
    int relro_readonly = 0, gap_none = 0, found_rwx = 0;
    FILE *maps;

    dl_iterate_phdr(capture_main, NULL);
    maps = fopen("/proc/self/maps", "r");
    if (!maps || !relro_addr || !gap_addr) return 1;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) != 3) continue;
        if (relro_addr >= lo && relro_addr < hi)
            relro_readonly = perms[1] != 'w';
        if (gap_addr >= lo && gap_addr < hi)
            gap_none = perms[0] == '-' && perms[1] == '-' && perms[2] == '-';
        if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x')
            found_rwx = 1;
    }
    fclose(maps);
    if (!relro_readonly || !gap_none || found_rwx) {
        fprintf(stderr, "relro=%d gap=%d rwx=%d\n",
                relro_readonly, gap_none, found_rwx);
        return 2;
    }
    puts("ok");
    return 0;
}
C
    if ! gcc -Wl,-z,relro,-z,now -o "$bin" "$src" -ldl; then
        fail "direct memory protections" "compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "direct memory protections" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct memory protections" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    local actual rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 DLFREEZE_PERF=1 "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "ok" ] && [ "$rc" -eq 0 ]; then
        pass "direct RELRO and mapping protections"
    else
        fail "direct RELRO and mapping protections" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 18b: definition addresses honor SHN_ABS, dynamic TLS, and bounds
# ===================================================================
test_direct_symbol_definition_addresses() {
    echo "--- direct symbol definition addresses ---"
    local root="$BUILD/symbol_definition_addresses"
    local lib_src="$root/lib.c" lib="$root/libdlfrz_symbols.so"
    local bad="$root/libdlfrz_symbols_bad.so" dynsym="$root/dynsym.bin"
    local prog_src="$root/main.c" prog="$root/main"
    local bad_src="$root/bad-main.c" bad_prog="$root/bad-main"
    local out="$root/main.frozen" bad_out="$root/bad-main.frozen"
    local log="$root/main.log" bad_log="$root/bad-main.log"
    local lib_abs bad_abs sym_index expect actual freeze_rc=0 rc_e=0 rc=0
    local native_definition_addresses=0

    rm -rf "$root"
    mkdir -p "$root"
    if ! command -v objcopy >/dev/null 2>&1 ||
       ! command -v readelf >/dev/null 2>&1; then
        skip "direct symbol definition addresses" \
            "readelf/objcopy not installed"
        rm -rf "$root"
        return
    fi

    cat > "$lib_src" <<'C'
extern char dlfrz_absolute_symbol;
void *dlfrz_absolute_anchor(void) { return &dlfrz_absolute_symbol; }
__thread int dlfrz_tls_symbol = 17;
int dlfrz_bounds_symbol = 23;
C
    if ! gcc -shared -fPIC -Wl,-soname,libdlfrz_symbols.so \
            -Wl,--defsym,dlfrz_absolute_symbol=0x1234 \
            -o "$lib" "$lib_src"; then
        fail "direct symbol definition addresses" "library compile failed"
        rm -rf "$root"
        return
    fi
    if ! readelf --dyn-syms -W "$lib" 2>/dev/null |
            grep -E '1234[[:space:]]+0[[:space:]]+NOTYPE.*ABS[[:space:]]+dlfrz_absolute_symbol$' \
                >/dev/null; then
        skip "direct symbol definition addresses" \
            "linker did not export the SHN_ABS fixture"
        rm -rf "$root"
        return
    fi

    lib_abs=$(realpath "$lib")
    cat > "$prog_src" <<C
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static int *main_tls;
static int thread_ok;
static void *thread_main(void *unused) {
    (void)unused;
    dlerror();
    int *value = (int *)dlsym(RTLD_DEFAULT, "dlfrz_tls_symbol");
    const char *error = dlerror();
    if (!error && value && value != main_tls && *value == 17) {
        *value = 73;
        thread_ok = *value == 73;
    }
    return NULL;
}

int main(void) {
    void *handle = dlopen("$lib_abs", RTLD_NOW | RTLD_GLOBAL);
    pthread_t thread;
    if (!handle) return 1;
    dlerror();
    void *absolute = dlsym(handle, "dlfrz_absolute_symbol");
    const char *absolute_error = dlerror();
    void *(*anchor)(void) = (void *(*)(void))
        dlsym(handle, "dlfrz_absolute_anchor");
    dlerror();
    main_tls = (int *)dlsym(RTLD_DEFAULT, "dlfrz_tls_symbol");
    const char *tls_error = dlerror();
    if (absolute_error || tls_error || !anchor || !main_tls ||
        (uintptr_t)absolute != 0x1234 ||
        (uintptr_t)anchor() != 0x1234 || *main_tls != 17)
        return 2;
    *main_tls = 41;
    if (pthread_create(&thread, NULL, thread_main, NULL) != 0 ||
        pthread_join(thread, NULL) != 0 || !thread_ok || *main_tls != 41)
        return 3;
    puts("symbol-addresses-ok");
    return 0;
}
C
    if ! gcc -o "$prog" "$prog_src" -ldl -pthread; then
        fail "direct symbol definition addresses" "program compile failed"
        rm -rf "$root"
        return
    fi
    capture_output expect "$prog" || rc_e=$?
    if [ "$rc_e" -eq 0 ] && [ "$expect" = "symbol-addresses-ok" ]; then
        native_definition_addresses=1
    else
        skip "direct SHN_ABS and TLS symbol addresses" \
            "native loader lacks the fixture's definition-address semantics"
    fi
    if [ "$native_definition_addresses" -eq 1 ]; then
        freeze_require_direct "direct symbol definition addresses" "$log" \
            "$out" "$prog" || freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "direct symbol definition addresses" "$DIRECT_FREEZE_REASON"
        elif [ "$freeze_rc" -eq 0 ]; then
            capture_output actual "$out" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
                pass "direct SHN_ABS and per-thread TLS symbol addresses"
            else
                fail "direct symbol definition addresses" \
                    "exit=$rc expected=$expect actual=$actual"
            fi
        fi
    fi

    cp "$lib" "$bad"
    if ! objcopy --dump-section .dynsym="$dynsym" "$bad" 2>/dev/null; then
        fail "out-of-range symbol definition rejection" \
            "could not extract .dynsym"
        rm -rf "$root"
        return
    fi
    sym_index=$(readelf --dyn-syms -W "$bad" 2>/dev/null |
        awk '$NF == "dlfrz_bounds_symbol" { gsub(":", "", $1); print $1; exit }')
    if ! [[ "$sym_index" =~ ^[0-9]+$ ]]; then
        fail "out-of-range symbol definition rejection" \
            "fixture symbol index not found"
        rm -rf "$root"
        return
    fi
    printf '\360\377\377\377\377\377\377\177' |
        dd of="$dynsym" bs=1 seek=$((sym_index * 24 + 8)) \
            conv=notrunc status=none
    if ! objcopy --update-section .dynsym="$dynsym" "$bad" 2>/dev/null; then
        fail "out-of-range symbol definition rejection" \
            "could not patch .dynsym"
        rm -rf "$root"
        return
    fi

    bad_abs=$(realpath "$bad")
    cat > "$bad_src" <<C
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void *handle = dlopen("$bad_abs", RTLD_NOW);
    if (!handle) return 1;
    dlerror();
    void *value = dlsym(handle, "dlfrz_bounds_symbol");
    const char *error = dlerror();
    printf("symbol-present=%d error=%d\n", value != NULL, error != NULL);
    return 0;
}
C
    if ! gcc -o "$bad_prog" "$bad_src" -ldl; then
        fail "out-of-range symbol definition rejection" \
            "program compile failed"
        rm -rf "$root"
        return
    fi
    expect=""; rc_e=0
    capture_output expect "$bad_prog" || rc_e=$?
    if [ "$rc_e" -ne 0 ] ||
       { [ "$expect" != "symbol-present=1 error=0" ] &&
         [ "$expect" != "symbol-present=0 error=1" ]; }; then
        skip "out-of-range symbol definition rejection" \
            "native loader cannot exercise the malformed symbol fixture"
        rm -rf "$root"
        return
    fi
    freeze_rc=0
    freeze_require_direct "out-of-range symbol definition rejection" \
        "$bad_log" "$bad_out" "$bad_prog" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "out-of-range symbol definition rejection" \
            "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual "$bad_out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "symbol-present=0 error=1" ]; then
        pass "out-of-range symbol definition rejected"
    else
        fail "out-of-range symbol definition rejection" \
            "exit=$rc output=$actual"
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 19: unsupported relocations fail closed in strict direct mode
# ===================================================================
test_unsupported_relocation_direct() {
    echo "--- unsupported relocation direct-load ---"
    if ! command -v objcopy >/dev/null 2>&1; then
        skip "unsupported relocation direct-load" "objcopy not installed"
        return
    fi

    local src="$BUILD/unsupported_reloc.c" bin="$BUILD/unsupported_reloc"
    local rela="$BUILD/unsupported_reloc.rela" out="$BUILD/unsupported_reloc.frozen"
    local log="$BUILD/unsupported_reloc.log" freeze_rc=0
    local rela_size rela_count=0 rela_records
    cat > "$src" <<'C'
static int value = 1;
int main(void) { return value != 1; }
C
    if ! gcc -o "$bin" "$src" ||
       ! objcopy --dump-section .rela.dyn="$rela" "$bin" 2>/dev/null ||
       [ ! -s "$rela" ]; then
        skip "unsupported relocation direct-load" "toolchain emitted no .rela.dyn"
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi

    rela_size=$(wc -c < "$rela")
    rela_count=$(readelf -d "$bin" 2>/dev/null |
        awk '/\(RELACOUNT\)/ { print $NF; exit }')
    rela_count=${rela_count:-0}
    if [ "$rela_size" -lt 24 ] || [ $((rela_size % 24)) -ne 0 ]; then
        skip "unsupported relocation direct-load" \
            "toolchain emitted a malformed .rela.dyn fixture"
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi
    rela_records=$((rela_size / 24))
    if [ "$rela_records" -le "$rela_count" ]; then
        skip "unsupported relocation direct-load" \
            "toolchain emitted no non-RELACOUNT relocation"
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi

    # Patch r_info in the final Rela record, which is outside the leading
    # DT_RELACOUNT range.  This preserves the RELACOUNT invariant and reaches
    # the unsupported-relocation diagnostic itself.
    printf '\376\377\000\000' | dd of="$rela" bs=1 \
        seek=$((rela_size - 16)) conv=notrunc status=none
    if ! objcopy --update-section .rela.dyn="$rela" "$bin" 2>/dev/null; then
        fail "unsupported relocation direct-load" "could not patch fixture"
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi
    freeze_require_direct "unsupported relocation direct-load" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "unsupported relocation direct-load" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$rela" "$out" "$log"
        return
    fi

    local actual rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       printf '%s\n' "$actual" | grep 'unsupported relocation' >/dev/null; then
        pass "unsupported relocation direct-load"
    else
        fail "unsupported relocation direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$rela" "$out" "$log"
}

# Dynamic-table, symbol, and relocation records are untrusted pack inputs.
# Relocation-only metadata can fall back to an un-prelinked artifact, which the
# runtime validator must refuse.  Metadata consumed again while constructing
# the profiler symbol table must instead abort the outer pack transaction.
test_malformed_prelink_metadata() {
    echo "--- malformed prelink input validation ---"
    local root="$BUILD/malformed_prelink_metadata"
    local src="$root/main.c" base="$root/main" gate="$root/gate"
    local semantic_gate="$root/dynamic_semantics_gate"
    local probe="$root/probe.frozen" probe_log="$root/probe.log"
    local cc mode bad out log actual rc freeze_rc gate_rc
    local label="malformed prelink input validation"
    local runtime_modes=(versym relocation-offset symbol-index audit depaudit \
                         auxiliary filter textrel-tag flags-textrel \
                         flags1-global flags1-group flags1-initfirst \
                         flags1-globaudit dynamic-relcount dynamic-shndx \
                         dynamic-posflag dynamic-feature dynamic-move \
                         dynamic-syminfo dynamic-config \
                         dynamic-android-rela dynamic-android-relr \
                         dynamic-gnu-prelinked dynamic-gnu-conflictsz \
                         dynamic-gnu-liblistsz dynamic-pltpadsz \
                         dynamic-gnu-conflict dynamic-gnu-liblist \
                         dynamic-pltpad)
    local profiler_modes=(syment sysv-hash symtab symbol-name gnu-hash \
                          gnu-count)

    rm -rf "$root"
    mkdir -p "$root"
    if command -v musl-gcc >/dev/null 2>&1; then
        cc=musl-gcc
    else
        cc=gcc
    fi
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) {
    puts("prelink-malformed-target-ran");
    return 0;
}
C
    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$semantic_gate" tests/dynamic_semantics_gate.c ||
       ! "$semantic_gate"; then
        fail "$label" "dynamic semantic classifier gate failed"
        rm -rf "$root"
        return
    fi
    if ! "$cc" -fPIE -pie -Wl,--hash-style=both -o "$base" "$src" ||
       ! readelf -l "$base" 2>/dev/null | grep 'ld-musl' >/dev/null ||
       ! readelf -d "$base" 2>/dev/null | grep '(HASH)' >/dev/null ||
       ! readelf -d "$base" 2>/dev/null | grep '(GNU_HASH)' >/dev/null ||
       ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$gate" tests/elf_prelink_gate.c; then
        skip "$label" "dynamic musl compiler is unavailable"
        rm -rf "$root"
        return
    fi

    freeze_rc=0
    freeze_require_direct "$label" "$probe_log" "$probe" "$base" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi
    actual=""; rc=0
    capture_output actual "$probe" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$actual" != "prelink-malformed-target-ran" ] ||
       ! grep -Eq '^[[:space:]]*pre-linked[[:space:]]*:[[:space:]]*yes' \
            "$probe_log"; then
        fail "$label" "valid prelink control failed (exit=$rc output=$actual)"
        rm -rf "$root"
        return
    fi

    for mode in "${runtime_modes[@]}"; do
        bad="$root/main.$mode"
        out="$bad.frozen"
        log="$bad.log"
        cp "$base" "$bad"
        set +e
        "$gate" "$mode" "$bad"
        gate_rc=$?
        set -e
        if [ "$gate_rc" -eq 77 ]; then
            skip "$label ($mode)" "fixture lacks required dynamic metadata"
            continue
        fi
        if [ "$gate_rc" -ne 0 ]; then
            fail "$label ($mode)" "could not mutate fixture"
            continue
        fi

        freeze_rc=0
        freeze_require_direct "$label ($mode)" "$log" "$out" "$bad" ||
            freeze_rc=$?
        if [ "$freeze_rc" -ne 0 ]; then
            if [ "$freeze_rc" -eq 77 ]; then
                skip "$label ($mode)" "$DIRECT_FREEZE_REASON"
            fi
            continue
        fi
        if ! grep -Fq 'dlfreeze: pre-linker failed' "$log" ||
           grep -Fq 'dlfreeze: pre-linker crashed' "$log"; then
            fail "$label ($mode)" \
                "prelink child did not report a clean failure"
            tail -n 40 "$log" || true
            continue
        fi

        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        if [ "$rc" -eq 127 ] && [[ "$actual" == *"malformed"* ]] &&
           [[ "$actual" != *"prelink-malformed-target-ran"* ]]; then
            pass "$label ($mode)"
        else
            fail "$label ($mode)" "exit=$rc output=$actual"
        fi
    done

    for mode in "${profiler_modes[@]}"; do
        bad="$root/main.$mode"
        out="$bad.frozen"
        log="$bad.log"
        cp "$base" "$bad"
        set +e
        "$gate" "$mode" "$bad"
        gate_rc=$?
        set -e
        if [ "$gate_rc" -eq 77 ]; then
            skip "$label profiler gate ($mode)" \
                "fixture lacks required dynamic metadata"
            continue
        fi
        if [ "$gate_rc" -ne 0 ]; then
            fail "$label profiler gate ($mode)" "could not mutate fixture"
            continue
        fi

        freeze_rc=0
        set +e
        run_freeze "$DLFREEZE" -d -o "$out" "$bad" >"$log" 2>&1
        freeze_rc=$?
        set -e
        if [ "$freeze_rc" -eq 0 ]; then
            fail "$label profiler gate ($mode)" \
                "malformed profiler metadata was packaged"
        elif [ "$freeze_rc" -eq 124 ] || [ "$freeze_rc" -eq 137 ]; then
            fail "$label profiler gate ($mode)" \
                "packer did not reject the input promptly (exit=$freeze_rc)"
        elif [ -e "$out" ]; then
            fail "$label profiler gate ($mode)" \
                "failed pack left a visible output"
        elif ! grep -Fq 'dlfreeze: pre-linker failed' "$log" ||
             grep -Fq 'dlfreeze: pre-linker crashed' "$log" ||
             ! grep -Fq 'dlfreeze: cannot append profiler symbol table' \
                  "$log"; then
            fail "$label profiler gate ($mode)" \
                "input did not reach a clean bounded profiler rejection"
            tail -n 40 "$log" || true
        else
            pass "$label profiler gate ($mode)"
        fi
    done
    rm -rf "$root"
}

# A RELR bitmap cannot be the first stream entry.  The pack-time prelinker
# must reject that grammar without dereferencing an uninitialized relocation
# cursor, and the runtime validator must refuse the non-prelinked artifact.
test_malformed_relr_prelink() {
    echo "--- malformed RELR prelink validation ---"
    local root="$BUILD/malformed_relr_prelink"
    local src="$root/main.c" bin="$root/main" bad="$root/main.bad"
    local gate="$root/elf_relr_gate" out="$root/main.frozen"
    local log="$root/freeze.log" actual="" rc=0 freeze_rc=0

    rm -rf "$root"
    mkdir -p "$root"
    cat > "$src" <<'C'
#include <stdio.h>
static void *relr_pointer = &relr_pointer;
int main(void) {
    printf("relr-target-ran:%p\n", relr_pointer);
    return 0;
}
C
    if ! gcc -fPIE -pie -Wl,-z,pack-relative-relocs -o "$bin" "$src" \
            >/dev/null 2>&1 ||
       ! readelf -d "$bin" 2>/dev/null | grep '(RELR)' >/dev/null ||
       ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
            -o "$gate" tests/elf_relr_gate.c; then
        skip "malformed RELR prelink validation" \
            "toolchain does not emit DT_RELR"
        rm -rf "$root"
        return
    fi
    if ! cp "$bin" "$bad" || ! "$gate" "$bad"; then
        fail "malformed RELR prelink validation" \
            "could not construct malformed RELR fixture"
        rm -rf "$root"
        return
    fi

    freeze_require_direct "malformed RELR prelink validation" "$log" \
        "$out" "$bad" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "malformed RELR prelink validation" "$DIRECT_FREEZE_REASON"
        rm -rf "$root"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -rf "$root"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"malformed relocation metadata"* ]] &&
       [[ "$actual" != *"relr-target-ran"* ]]; then
        pass "malformed RELR fails closed before target execution"
    else
        fail "malformed RELR prelink validation" \
            "exit=$rc output=$actual"
        tail -n 60 "$log" || true
    fi
    rm -rf "$root"
}

# ===================================================================
# Test 19b: dynamic-table pointers and relocation destinations must stay
# inside the embedded object's actual PT_LOAD segments.
# ===================================================================
test_malformed_dynamic_bounds_direct() {
    echo "--- malformed dynamic bounds direct-load ---"
    local src="$BUILD/malformed_dynamic.c" bin="$BUILD/malformed_dynamic"
    local out="$BUILD/malformed_dynamic.frozen"
    local bad_dyn="$BUILD/malformed_dynamic_bad_dyn.frozen"
    local bad_rel="$BUILD/malformed_dynamic_bad_rel.frozen"
    local log="$BUILD/malformed_dynamic.log" freeze_rc=0
    local size footer manifest main phoff phentsz phnum
    local dyn_off="" dyn_size="" rela_vaddr="" rela_file=""
    local p type poff pvaddr pfilesz pend d tag value actual rc

    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("malformed-target-ran"); return 0; }
C
    if ! gcc -o "$bin" "$src"; then
        fail "malformed dynamic bounds direct-load" "compile failed"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi
    freeze_require_direct "malformed dynamic bounds direct-load" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "malformed dynamic pointer rejection" "$DIRECT_FREEZE_REASON"
        skip "out-of-range relocation rejection" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi

    size=$(stat -c %s "$out" 2>/dev/null || true)
    if ! [[ "$size" =~ ^[0-9]+$ ]] || [ "$size" -lt 64 ]; then
        fail "malformed dynamic bounds direct-load" "invalid frozen footer"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi
    footer=$((size - 64))
    manifest=$(od -An -tu8 -j $((footer + 16)) -N8 "$out" |
        tr -d '[:space:]')
    main=$(od -An -tu8 -j "$manifest" -N8 "$out" | tr -d '[:space:]')
    phoff=$(od -An -tu8 -j $((main + 32)) -N8 "$out" |
        tr -d '[:space:]')
    phentsz=$(od -An -tu2 -j $((main + 54)) -N2 "$out" |
        tr -d '[:space:]')
    phnum=$(od -An -tu2 -j $((main + 56)) -N2 "$out" |
        tr -d '[:space:]')
    if ! [[ "$manifest" =~ ^[0-9]+$ && "$main" =~ ^[0-9]+$ &&
            "$phoff" =~ ^[0-9]+$ && "$phentsz" =~ ^[0-9]+$ &&
            "$phnum" =~ ^[0-9]+$ ]] || [ "$phentsz" -lt 56 ]; then
        fail "malformed dynamic bounds direct-load" "invalid embedded ELF"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi

    for ((p = 0; p < phnum; p++)); do
        poff=$((main + phoff + p * phentsz))
        type=$(od -An -tu4 -j "$poff" -N4 "$out" | tr -d '[:space:]')
        if [ "$type" = 2 ]; then
            dyn_off=$(od -An -tu8 -j $((poff + 8)) -N8 "$out" |
                tr -d '[:space:]')
            dyn_size=$(od -An -tu8 -j $((poff + 32)) -N8 "$out" |
                tr -d '[:space:]')
            dyn_off=$((main + dyn_off))
            break
        fi
    done
    if [ -z "$dyn_off" ] || [ -z "$dyn_size" ]; then
        fail "malformed dynamic bounds direct-load" "PT_DYNAMIC not found"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi
    for ((d = 0; d + 16 <= dyn_size; d += 16)); do
        tag=$(od -An -tu8 -j $((dyn_off + d)) -N8 "$out" |
            tr -d '[:space:]')
        [ "$tag" = 0 ] && break
        if [ "$tag" = 7 ]; then
            rela_vaddr=$(od -An -tu8 -j $((dyn_off + d + 8)) -N8 "$out" |
                tr -d '[:space:]')
            cp "$out" "$bad_dyn"
            printf '\360\377\377\377\377\377\377\377' |
                dd of="$bad_dyn" bs=1 seek=$((dyn_off + d + 8)) \
                    conv=notrunc status=none
            break
        fi
    done
    if [ -z "$rela_vaddr" ] || [ ! -f "$bad_dyn" ]; then
        fail "malformed dynamic bounds direct-load" "DT_RELA not found"
        rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
        return
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$bad_dyn" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"malformed dynamic metadata"* ]] &&
       [[ "$actual" != *"malformed-target-ran"* ]]; then
        pass "malformed dynamic pointer rejection"
    else
        fail "malformed dynamic pointer rejection" "exit=$rc output=$actual"
    fi

    for ((p = 0; p < phnum; p++)); do
        poff=$((main + phoff + p * phentsz))
        type=$(od -An -tu4 -j "$poff" -N4 "$out" | tr -d '[:space:]')
        [ "$type" = 1 ] || continue
        value=$(od -An -tu8 -j $((poff + 8)) -N8 "$out" |
            tr -d '[:space:]')
        pvaddr=$(od -An -tu8 -j $((poff + 16)) -N8 "$out" |
            tr -d '[:space:]')
        pfilesz=$(od -An -tu8 -j $((poff + 32)) -N8 "$out" |
            tr -d '[:space:]')
        pend=$((pvaddr + pfilesz))
        if [ "$rela_vaddr" -ge "$pvaddr" ] &&
           [ "$rela_vaddr" -lt "$pend" ]; then
            rela_file=$((main + value + rela_vaddr - pvaddr))
            break
        fi
    done
    if [ -z "$rela_file" ]; then
        fail "out-of-range relocation rejection" "RELA file range not found"
    else
        cp "$out" "$bad_rel"
        printf '\360\377\377\377\377\377\377\377' |
            dd of="$bad_rel" bs=1 seek="$rela_file" conv=notrunc status=none
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_rel" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"malformed relocation metadata"* ]] &&
           [[ "$actual" != *"malformed-target-ran"* ]]; then
            pass "out-of-range relocation rejection"
        else
            fail "out-of-range relocation rejection" "exit=$rc output=$actual"
        fi
    fi
    rm -f "$src" "$bin" "$out" "$bad_dyn" "$bad_rel" "$log"
}

# ===================================================================
# Test 20: dlvsym requires an exact GNU symbol version
# ===================================================================
test_dlvsym_direct() {
    echo "--- dlvsym direct-load ---"
    local src="$BUILD/dlv_main.c" bin="$BUILD/dlv_main"
    local out="$BUILD/dlv_main.frozen" log="$BUILD/dlv_main.log"
    local freeze_rc=0
    rm -f "$log"

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
#if defined(__aarch64__)
    const char *valid_version = "GLIBC_2.17";
#else
    const char *valid_version = "GLIBC_2.2.5";
#endif
    void *p = dlvsym(RTLD_DEFAULT, "pthread_self", valid_version);
    void *q = dlsym (RTLD_DEFAULT, "pthread_self");
    void *bad = dlvsym(RTLD_DEFAULT, "pthread_self", "GLIBC_999.0");
    if (!p) { fprintf(stderr, "dlvsym returned NULL\n"); return 1; }
    if (p != q) { fprintf(stderr, "dlvsym != dlsym\n"); return 2; }
    if (bad) { fprintf(stderr, "wrong version resolved\n"); return 3; }
    printf("ok\n");
    return 0;
}
C
    if ! gcc -o "$bin" "$src" -ldl -lpthread 2>"$BUILD/dlv_main.build.err"; then
        if grep -Eq 'undefined reference.*dlvsym|implicit declaration of function .dlvsym.' "$BUILD/dlv_main.build.err"; then
            skip "dlvsym direct-load" "host libc does not provide dlvsym"
        else
            fail "dlvsym direct-load" "compile failed"
            head -20 "$BUILD/dlv_main.build.err" || true
        fi
        rm -f "$src" "$bin" "$out" "$BUILD/dlv_main.build.err"
        return
    fi
    rm -f "$BUILD/dlv_main.build.err"

    freeze_require_direct "dlvsym direct-load" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlvsym direct-load" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    local actual rc=0
    capture_output actual "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$actual" = "ok" ] && [ "$rc" = "0" ]; then
        pass "dlvsym direct-load"
    else
        fail "dlvsym direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 20b: dlsym cache keys never retain caller-owned name storage
# ===================================================================
test_dlsym_cache_key_lifetime_direct() {
    echo "--- dlsym cache key lifetime direct-load ---"
    local src="$BUILD/dlsym_cache_key.c" bin="$BUILD/dlsym_cache_key"
    local out="$BUILD/dlsym_cache_key.frozen" log="$BUILD/dlsym_cache_key.log"
    local label="dlsym cache key lifetime direct-load"
    local expect actual rc_e=0 rc_a=0 freeze_rc=0
    rm -f "$log"

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline, visibility("default")))
int dlfrz_dynamic_name_target(void) { return 42; }

int main(void) {
    static const char symbol[] = "dlfrz_dynamic_name_target";
    long page_size = sysconf(_SC_PAGESIZE);
    char *name;
    int (*first)(void);
    int (*second)(void);
    const char *error;

    if (page_size <= 0)
        return 1;
    name = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (name == MAP_FAILED)
        return 2;
    memcpy(name, symbol, sizeof(symbol));

    (void)dlerror();
    first = (int (*)(void))dlsym(RTLD_DEFAULT, name);
    error = dlerror();
    if (error || !first || first() != 42)
        return 3;
    if (mprotect(name, (size_t)page_size, PROT_NONE) != 0)
        return 4;

    (void)dlerror();
    second = (int (*)(void))dlsym(RTLD_DEFAULT, symbol);
    error = dlerror();
    if (munmap(name, (size_t)page_size) != 0)
        return 5;
    if (error || second != first || second() != 42)
        return 6;
    puts("cache-key-ok");
    return 0;
}
C

    if ! gcc -rdynamic -o "$bin" "$src" -ldl; then
        fail "$label" "compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "cache-key-ok" ]; then
        fail "$label" "native fixture failed (exit $rc_e): $expect"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a output=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 20c: dlsym/dlvsym cannot bypass loader shims through libc handles
# ===================================================================
test_dlsym_special_consistency_direct() {
    echo "--- dlsym special consistency direct-load ---"
    local src="$BUILD/dlsym_special_consistency.c"
    local bin="$BUILD/dlsym_special_consistency"
    local out="$BUILD/dlsym_special_consistency.frozen"
    local log="$BUILD/dlsym_special_consistency.log"
    local label="dlsym special consistency direct-load"
    local expect actual reason rc_e=0 rc_a=0 freeze_rc=0
    rm -f "$log"

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    Dl_info info;
    void *global_puts;
    void *libc_handle;
    void *global_dlopen;
    void *handle_dlopen;
    void *global_dlsym;
    void *handle_dlsym;

    /* Taking puts directly may yield this executable's PLT entry, causing
     * dladdr to identify the PIE rather than libc.  Resolve the definition
     * through the native loader before constructing the libc handle. */
    global_puts = dlsym(RTLD_DEFAULT, "puts");
    if (!global_puts || !dladdr(global_puts, &info) || !info.dli_fname)
        return 1;
    libc_handle = dlopen(info.dli_fname, RTLD_NOW);
    if (!libc_handle)
        return 2;
    global_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    handle_dlopen = dlsym(libc_handle, "dlopen");
    global_dlsym = dlsym(RTLD_DEFAULT, "dlsym");
    handle_dlsym = dlsym(libc_handle, "dlsym");
    if (!global_dlopen || handle_dlopen != global_dlopen ||
        !global_dlsym || handle_dlsym != global_dlsym)
        return 3;

#if defined(__GLIBC__)
# if defined(__aarch64__)
    const char *version = "GLIBC_2.17";
# else
    const char *version = "GLIBC_2.2.5";
# endif
    if (dlvsym(RTLD_DEFAULT, "dlopen", version) != global_dlopen ||
        dlvsym(libc_handle, "dlopen", version) != global_dlopen ||
        dlvsym(RTLD_DEFAULT, "dlsym", version) != global_dlsym ||
        dlvsym(libc_handle, "dlsym", version) != global_dlsym)
        return 4;
#endif

    puts("special-consistency-ok");
    return 0;
}
C

    if ! gcc -o "$bin" "$src" -ldl; then
        fail "$label" "compile failed"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ge 1 ] && [ "$rc_e" -le 4 ]; then
        case "$rc_e" in
            1|2) reason="native loader could not construct a libc handle" ;;
            3|4) reason="native loader lacks the required libc-handle symbol semantics" ;;
        esac
        skip "$label" "$reason (exit $rc_e)"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "special-consistency-ok" ]; then
        fail "$label" "native fixture failed (exit $rc_e): $expect"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a output=$actual"
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 20d: a loader shim is not a substitute for an absent provider
# ===================================================================
test_dlsym_provider_admission_direct() {
    echo "--- dlsym provider admission direct-load ---"
    local src="$BUILD/dlsym_provider_admission.c"
    local bin="$BUILD/dlsym_provider_admission"
    local data="$BUILD/dlsym_provider_admission.data"
    local out="$BUILD/dlsym_provider_admission.frozen"
    local log="$BUILD/dlsym_provider_admission.log"
    local label="dlsym provider admission direct-load"
    local data_abs expect actual rc_e=0 rc_a=0 freeze_rc=0
    rm -f "$log"

    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    void *address;
    const char *error;
    FILE *file;

    if (argc != 2)
        return 1;
    file = fopen(argv[1], "rb");
    if (!file)
        return 2;
    fclose(file);

    (void)dlerror();
    address = dlsym(RTLD_DEFAULT, "newfstatat");
    error = dlerror();
    if (address || !error)
        puts("provider-present");
    else
        puts("provider-absent");
    return 0;
}
C
    cat > "$data" <<'DATA'
dlfreeze-provider-admission
DATA
    data_abs=$(realpath "$data")
    if ! gcc -o "$bin" "$src" -ldl; then
        fail "$label" "fixture compile failed"
        rm -f "$src" "$bin" "$data" "$out" "$log"
        return
    fi
    capture_output expect "$bin" "$data_abs" || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "$label" "native fixture failed (exit $rc_e): $expect"
        rm -f "$src" "$bin" "$data" "$out" "$log"
        return
    fi
    if [ "$expect" != "provider-absent" ]; then
        skip "$label" "host libc exports the provider probe symbol"
        rm -f "$src" "$bin" "$data" "$out" "$log"
        return
    fi

    freeze_require_direct "$label" "$log" "$out" \
        -t -f "$data_abs" "$bin" "$data_abs" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$data" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$data" "$out" "$log"
        return
    fi

    # Removing the source file proves the frozen run activated the VFS
    # override table that contains the otherwise provider-less probe name.
    rm -f "$data"
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" "$data_abs" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a expected=$expect actual=$actual"
    fi
    rm -f "$src" "$bin" "$data" "$out" "$log"
}

# ===================================================================
# Test 20e: loader-owned API shims replace only the selected libc provider.
# A plugin definition with the same name must survive handle, dlvsym, and
# RTLD_NEXT lookup.
# ===================================================================
test_dlsym_selected_provider_direct() {
    echo "--- dlsym selected-provider ownership direct-load ---"
    local provider="$BUILD/libdlsym_owner_provider.so"
    local caller="$BUILD/libdlsym_owner_caller.so"
    local bin="$BUILD/dlsym_owner_main"
    local out="$BUILD/dlsym_owner_main.frozen"
    local log="$BUILD/dlsym_owner_main.log"
    local expect actual provider_abs caller_abs
    local rc_e=0 rc_a=0 freeze_rc=0
    local label="dlsym selected-provider ownership direct-load"

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "fixture requires glibc symbol versioning"
        return
    fi
    if ! gcc -shared -fPIC -Wl,-Bsymbolic \
            -Wl,--version-script=tests/direct_dlsym_owner.map \
            -o "$provider" tests/direct_dlsym_owner_plugin.c ||
       ! gcc -shared -fPIC -o "$caller" \
            tests/direct_dlsym_owner_caller.c -L"$BUILD" \
            -Wl,--no-as-needed -ldlsym_owner_provider \
            -Wl,-rpath,'$ORIGIN' -ldl ||
       ! gcc -rdynamic \
            -Wl,--version-script=tests/direct_dlsym_owner_main.map \
            -o "$bin" tests/direct_dlsym_owner_main.c -ldl; then
        fail "$label" "fixture compile failed"
        rm -f "$provider" "$caller" "$bin" "$out" "$log"
        return
    fi
    provider_abs=$(realpath "$provider")
    caller_abs=$(realpath "$caller")
    capture_output expect "$bin" "$caller_abs" "$provider_abs" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "plugin-owner-ok" ]; then
        fail "$label" "native fixture failed (exit=$rc_e output=$expect)"
        rm -f "$provider" "$caller" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" -t -- \
        "$bin" "$caller_abs" "$provider_abs" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$provider" "$caller" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$provider" "$caller" "$bin" "$out" "$log"
        return
    fi
    mv "$provider" "$provider.hidden"
    mv "$caller" "$caller.hidden"
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" \
        "$caller_abs" "$provider_abs" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a expected=$expect actual=$actual"
    fi
    rm -f "$provider" "$provider.hidden" "$caller" "$caller.hidden" \
        "$bin" "$out" "$log"
}

# ===================================================================
# Test 20f: dlsym/__libc_dlsym use DL_LOOKUP_RETURN_NEWEST.  With two
# hidden compatibility definitions and no public default, unversioned lookup
# is ambiguous while dlvsym still resolves each exact version.
# ===================================================================
test_dlsym_return_newest_direct() {
    echo "--- dlsym return-newest direct-load ---"
    local lib="$BUILD/libdlsym_newest.so"
    local bin="$BUILD/dlsym_newest_main"
    local out="$BUILD/dlsym_newest_main.frozen"
    local log="$BUILD/dlsym_newest_main.log"
    local lib_abs expect actual rc_e=0 rc_a=0 freeze_rc=0
    local label="dlsym return-newest direct-load"

    if ! printf '#include <features.h>\n' |
            "$TEST_REAL_GCC" -dM -E - 2>/dev/null |
            grep '^#define __GLIBC__ ' >/dev/null; then
        skip "$label" "fixture requires glibc symbol versioning"
        return
    fi
    if ! gcc -shared -fPIC \
            -Wl,--version-script=tests/direct_dlsym_newest.map \
            -o "$lib" tests/direct_dlsym_newest_plugin.c ||
       ! gcc -o "$bin" tests/direct_dlsym_newest_main.c -ldl; then
        fail "$label" "fixture compile failed"
        rm -f "$lib" "$bin" "$out" "$log"
        return
    fi
    lib_abs=$(realpath "$lib")
    capture_output expect "$bin" "$lib_abs" || rc_e=$?
    if [ "$rc_e" -ne 0 ] || [ "$expect" != "return-newest-ok" ]; then
        fail "$label" "native fixture failed (exit=$rc_e output=$expect)"
        rm -f "$lib" "$bin" "$out" "$log"
        return
    fi
    freeze_require_direct "$label" "$log" "$out" -t -- \
        "$bin" "$lib_abs" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$lib" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$lib" "$bin" "$out" "$log"
        return
    fi
    mv "$lib" "$lib.hidden"
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" "$lib_abs" || rc_a=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc_a" -eq 0 ] && [ "$actual" = "$expect" ]; then
        pass "$label"
    else
        fail "$label" "exit=$rc_a expected=$expect actual=$actual"
    fi
    rm -f "$lib" "$lib.hidden" "$bin" "$out" "$log"
}

# ===================================================================
# Test 21: relocation lookup honors the requester's required version
# ===================================================================
test_versioned_relocation_direct() {
    echo "--- versioned relocation direct-load ---"
    local libsrc="$BUILD/versioned_lib.c" map="$BUILD/versioned.map"
    local src="$BUILD/versioned_main.c"
    local hash_style hash_tag label lib bin out log dynamic actual rc freeze_rc

    cat > "$libsrc" <<'C'
int value_v1(void) { return 11; }
int value_v2(void) { return 22; }
__asm__(".symver value_v1,value@VERS_1");
__asm__(".symver value_v2,value@@VERS_2");
C
    cat > "$map" <<'MAP'
VERS_1 {};
VERS_2 {} VERS_1;
MAP
    cat > "$src" <<'C'
#define _GNU_SOURCE
#include <stdio.h>
#if defined(__GLIBC__)
#include <dlfcn.h>
#endif
extern int old_value(void);
__asm__(".symver old_value,value@VERS_1");
extern int value(void);
int main(void) {
#if defined(__GLIBC__)
    typedef int (*value_fn)(void);
    value_fn exact_old = (value_fn)dlvsym(RTLD_DEFAULT, "value", "VERS_1");
    value_fn exact_new = (value_fn)dlvsym(RTLD_DEFAULT, "value", "VERS_2");
    if (!exact_old || !exact_new || exact_old() != 11 || exact_new() != 22)
        return 2;
    (void)dlerror();
    if (dlvsym(RTLD_DEFAULT, "value", "VERS_MISSING") != NULL ||
        dlerror() == NULL)
        return 3;
#endif
    printf("%d %d\n", old_value(), value());
    return 0;
}
C

    # Exercise both bounded GNU-hash and traditional SysV DT_HASH lookup.
    # Some linkers do not implement --hash-style, so each representation is
    # conditional.
    for hash_style in gnu sysv; do
        label="versioned relocation direct-load ($hash_style hash)"
        lib="$BUILD/libversioned_${hash_style}.so"
        bin="$BUILD/versioned_main_${hash_style}"
        out="$BUILD/versioned_main_${hash_style}.frozen"
        log="$BUILD/versioned_main_${hash_style}.log"
        rm -f "$log"
        hash_tag=GNU_HASH
        [ "$hash_style" = sysv ] && hash_tag=HASH

        if ! linker_supports_hash_style "$BUILD" "$hash_style"; then
            skip "$label" "linker does not support --hash-style=$hash_style"
            rm -f "$lib" "$bin" "$out"
            continue
        fi
        if ! gcc -shared -fPIC "-Wl,--hash-style=$hash_style" \
                -Wl,--version-script="$map" -o "$lib" "$libsrc"; then
            fail "$label" "shared versioned fixture compile failed"
            rm -f "$lib" "$bin" "$out"
            continue
        fi
        if command -v readelf >/dev/null 2>&1; then
            if ! dynamic=$(LC_ALL=C readelf -d "$lib"); then
                fail "$label" "could not inspect shared versioned fixture"
                rm -f "$lib" "$bin" "$out"
                continue
            fi
            if ! grep -qF "($hash_tag)" <<<"$dynamic"; then
                fail "$label" "shared fixture lacks requested hash table"
                rm -f "$lib" "$bin" "$out"
                continue
            fi
        fi
        if ! gcc -o "$bin" "$src" -L"$BUILD" \
                "-lversioned_${hash_style}" -Wl,-rpath,'$ORIGIN' -ldl; then
            fail "$label" "versioned executable fixture compile failed"
            rm -f "$lib" "$bin" "$out"
            continue
        fi
        freeze_rc=0
        freeze_require_direct "$label" "$log" "$out" "$bin" ||
            freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$label" "$DIRECT_FREEZE_REASON"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        actual="" rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$actual" = "11 22" ] && [ "$rc" -eq 0 ]; then
            pass "$label"
        else
            fail "$label" "rc=$rc out=$actual"
        fi
        rm -f "$lib" "$bin" "$out" "$log"
    done
    rm -f "$libsrc" "$map" "$src"
}

# ===================================================================
# Test 21a: an unversioned definition may interpose a default-version
# definition used by a relocation inside the defining DSO.  glibc treats the
# unversioned symbol as a fallback for a non-hidden version requirement.
# ===================================================================
test_default_version_interposition_direct() {
    echo "--- default-version definition interposition direct-load ---"
    local libsrc="$BUILD/default_version_interpose_lib.c"
    local map="$BUILD/default_version_interpose.map"
    local src="$BUILD/default_version_interpose_main.c"
    local hash_style lib bin out log label actual native
    local rc freeze_rc native_rc

    cat > "$libsrc" <<'C'
int probe_value_impl = 11;
__asm__(".symver probe_value_impl,probe_value@@PROBE_1");
extern int probe_value;
int read_probe_value(void) { return probe_value; }
int *probe_value_address(void) { return &probe_value; }
C
    cat > "$map" <<'MAP'
PROBE_1 {};
MAP
    cat > "$src" <<'C'
#include <stdio.h>
int probe_value = 99;
int read_probe_value(void);
int *probe_value_address(void);
int main(void) {
    int value = read_probe_value();
    int same = probe_value_address() == &probe_value;
    printf("%d %d\n", value, same);
    return value == 99 && same ? 0 : 3;
}
C

    for hash_style in gnu sysv; do
        label="default-version definition interposition direct-load ($hash_style hash)"
        lib="$BUILD/libdefault_version_interpose_${hash_style}.so"
        bin="$BUILD/default_version_interpose_${hash_style}"
        out="$BUILD/default_version_interpose_${hash_style}.frozen"
        log="$BUILD/default_version_interpose_${hash_style}.log"

        if ! linker_supports_hash_style "$BUILD" "$hash_style"; then
            skip "$label" "linker does not support --hash-style=$hash_style"
            continue
        fi
        if ! gcc -shared -fPIC "-Wl,--hash-style=$hash_style" \
                -Wl,--version-script="$map" \
                -Wl,-soname,"$(basename "$lib")" \
                -o "$lib" "$libsrc" ||
           ! gcc -o "$bin" "$src" -L"$BUILD" \
                "-l:$(basename "$lib")" -Wl,-rpath,'$ORIGIN'; then
            fail "$label" "fixture compile failed"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if command -v readelf >/dev/null 2>&1 &&
           ! readelf -Wr "$lib" 2>/dev/null |
                grep -E 'GLOB_DAT.*probe_value(@@)?PROBE_1' >/dev/null; then
            fail "$label" "fixture lacks the versioned self relocation"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        native=""; native_rc=0
        capture_output native "$bin" || native_rc=$?
        if [ "$native_rc" -ne 0 ] || [ "$native" != "99 1" ]; then
            skip "$label" "native runtime does not expose expected interposition"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        freeze_rc=0
        freeze_require_direct "$label" "$log" "$out" "$bin" ||
            freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$label" "$DIRECT_FREEZE_REASON"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "99 1" ]; then
            pass "$label"
        else
            fail "$label" "rc=$rc out=$actual"
        fi
        rm -f "$lib" "$bin" "$out" "$log"
    done
    rm -f "$libsrc" "$map" "$src"
}

# ===================================================================
# Test 21b: loader shims reject forged symbol versions
# ===================================================================
test_special_version_admission_direct() {
    echo "--- special-symbol version admission direct-load ---"
    local libsrc="$BUILD/special_version_lib.c"
    local map="$BUILD/special_version.map"
    local src="$BUILD/special_version_main.c"
    local lib="$BUILD/libspecial_version.so"
    local good="$BUILD/special_version_good"
    local bad="$BUILD/special_version_bad"
    local dynstr="$BUILD/special_version.dynstr"
    local hash_gate="$BUILD/special_version_hash_gate"
    local good_out="$BUILD/special_version_good.frozen"
    local bad_out="$BUILD/special_version_bad.frozen"
    local good_log="$BUILD/special_version_good.log"
    local bad_log="$BUILD/special_version_bad.log"
    local label="special-symbol version admission direct-load"
    local actual native_bad="" rc=0 native_bad_rc=0 freeze_rc=0

    if ! command -v readelf >/dev/null 2>&1 ||
       ! command -v objcopy >/dev/null 2>&1; then
        skip "$label" "readelf/objcopy not installed"
        return
    fi

    cat > "$libsrc" <<'C'
#include <stddef.h>
void *version_memcpy_impl(void *destination, const void *source, size_t size) {
    unsigned char *out = destination;
    const unsigned char *in = source;
    while (size-- != 0)
        *out++ = *in++;
    return destination;
}
__asm__(".symver version_memcpy_impl,memcpy@@GOOD_1");
C
    cat > "$map" <<'MAP'
GOOD_1 {};
MAP
    cat > "$src" <<'C'
#include <stddef.h>
#include <unistd.h>
extern void *version_memcpy(void *, const void *, size_t);
__asm__(".symver version_memcpy,memcpy@GOOD_1");
int main(void) {
    char output[19];
    version_memcpy(output, "memcpy-version-ok\n", sizeof(output));
    return write(STDOUT_FILENO, output, sizeof(output) - 1) ==
        (ssize_t)(sizeof(output) - 1) ? 0 : 2;
}
C

    if ! gcc -shared -fPIC -fno-builtin-memcpy \
            -Wl,--version-script="$map" \
            -Wl,-soname,libspecial_version.so \
            -o "$lib" "$libsrc" ||
       ! gcc -fno-builtin-memcpy -o "$good" "$src" -L"$BUILD" \
            -Wl,-rpath,'$ORIGIN' -lspecial_version; then
        skip "$label" "toolchain cannot build the versioned fixture"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good"
        return
    fi
    if ! readelf -Wr "$good" 2>/dev/null |
            grep 'memcpy@GOOD_1' >/dev/null; then
        skip "$label" "linker did not retain the versioned memcpy relocation"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good"
        return
    fi

    freeze_require_direct "$label (control)" "$good_log" "$good_out" \
        "$good" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$good_out" \
            "$good_log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$good_out" \
            "$good_log"
        return
    fi
    capture_output actual env DLFREEZE_NO_FORK=1 "$good_out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -ne 0 ] || [ "$actual" != "memcpy-version-ok" ]; then
        fail "$label (control)" "rc=$rc out=$actual"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$good_out" \
            "$good_log"
        return
    fi
    pass "$label (control)"

    if ! gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Iinclude \
            -o "$hash_gate" tests/elf_version_gate.c src/elf_parser.c; then
        fail "$label (forged)" "could not build the version metadata mutator"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$good_out" \
            "$good_log" "$hash_gate"
        return
    fi
    cp "$good" "$bad"
    rm -f "$dynstr"
    if ! objcopy --dump-section .dynstr="$dynstr" "$bad" 2>/dev/null ||
       ! sed -i 's/GOOD_1/FAKE_1/g' "$dynstr" ||
       ! objcopy --update-section .dynstr="$dynstr" "$bad" 2>/dev/null ||
       ! "$hash_gate" --rehash-requirement "$bad" \
            libspecial_version.so FAKE_1 ||
       ! readelf -Wr "$bad" 2>/dev/null |
            grep 'memcpy@FAKE_1' >/dev/null; then
        fail "$label (forged)" "could not forge the version requirement"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$bad" \
            "$dynstr" "$good_out" "$good_log" "$hash_gate"
        return
    fi

    capture_output native_bad env -u LD_LIBRARY_PATH "$bad" ||
        native_bad_rc=$?
    if { [ "$native_bad_rc" -eq 0 ] &&
         [ "$native_bad" != "memcpy-version-ok" ]; } ||
       { [ "$native_bad_rc" -ne 0 ] &&
         [[ "$native_bad" == *"memcpy-version-ok"* ]]; }; then
        fail "$label (forged native control)" \
            "incoherent exit=$native_bad_rc output=$native_bad"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$bad" \
            "$dynstr" "$good_out" "$good_log" "$hash_gate"
        return
    fi

    freeze_rc=0
    freeze_require_direct "$label (forged)" "$bad_log" "$bad_out" \
        "$bad" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label (forged)" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        actual="" rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_out" || rc=$?
        if [ "$native_bad_rc" -eq 0 ] && [ "$rc" -eq 0 ] &&
           [ "$actual" = "$native_bad" ]; then
            pass "$label (forged, name-only target runtime)"
        elif [ "$native_bad_rc" -ne 0 ] && [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"unresolved relocation symbol: memcpy"* ]] &&
           [[ "$actual" != *"memcpy-version-ok"* ]]; then
            pass "$label (forged)"
        else
            fail "$label (forged)" "rc=$rc out=$actual"
        fi
    fi

    rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$bad" "$dynstr" \
        "$good_out" "$bad_out" "$good_log" "$bad_log" "$hash_gate"
}

# ===================================================================
# Test 22: COPY-defined executable symbols retain VERNEED requirements
# ===================================================================
test_versioned_copy_relocation_direct() {
    echo "--- versioned COPY relocation direct-load ---"
    local libc_banner
    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc' <<<"$libc_banner"; then
        skip "versioned COPY relocation direct-load" "fixture requires glibc"
        return
    fi
    if ! command -v readelf >/dev/null 2>&1; then
        skip "versioned COPY relocation direct-load" "readelf not installed"
        return
    fi

    local libsrc="$BUILD/versioned_copy_lib.c"
    local map="$BUILD/versioned_copy.map"
    local src="$BUILD/versioned_copy_main.c"
    local hash_style lib bin out log label hash_tag dynamic relocs actual
    local rc=0 freeze_rc=0

    if ! compiler_supports_non_pie "$BUILD"; then
        for hash_style in gnu sysv; do
            skip "versioned COPY relocation direct-load ($hash_style hash)" \
                "compiler/linker does not support -fno-pie -no-pie"
        done
        return
    fi

    cat > "$libsrc" <<'C'
int copy_v1 = 11;
int copy_v2 = 22;
__asm__(".symver copy_v1,versioned_copy@COPY_1");
__asm__(".symver copy_v2,versioned_copy@@COPY_2");
extern int copy_v1_ref;
extern int copy_v2_ref;
__asm__(".symver copy_v1_ref,versioned_copy@COPY_1");
__asm__(".symver copy_v2_ref,versioned_copy@COPY_2");
int *copy_v1_addr(void) { return &copy_v1_ref; }
int *copy_v2_addr(void) { return &copy_v2_ref; }
int copy_v1_read(void) { return copy_v1_ref; }
int copy_v2_read(void) { return copy_v2_ref; }
C
    cat > "$map" <<'MAP'
COPY_1 {};
COPY_2 {} COPY_1;
MAP
    cat > "$src" <<'C'
#include <stdio.h>
extern int old_copy;
__asm__(".symver old_copy,versioned_copy@COPY_1");
extern int versioned_copy;
int *copy_v1_addr(void);
int *copy_v2_addr(void);
int copy_v1_read(void);
int copy_v2_read(void);
int main(void) {
    if (!stdout)
        return 2;
    if (old_copy != 11 || versioned_copy != 22 ||
        copy_v1_read() != 11 || copy_v2_read() != 22)
        return 3;
    if (copy_v1_addr() != &old_copy || copy_v2_addr() != &versioned_copy)
        return 4;
    old_copy = 31;
    versioned_copy = 42;
    if (copy_v1_read() != 31 || copy_v2_read() != 42)
        return 5;
    if (fprintf(stdout, "%d %d\n", old_copy, versioned_copy) < 0)
        return 6;
    return fflush(stdout) == 0 ? 0 : 7;
}
C

    for hash_style in gnu sysv; do
        label="versioned COPY relocation direct-load ($hash_style hash)"
        lib="$BUILD/libversioned_copy_${hash_style}.so"
        bin="$BUILD/versioned_copy_main_${hash_style}"
        out="$BUILD/versioned_copy_main_${hash_style}.frozen"
        log="$BUILD/versioned_copy_main_${hash_style}.log"
        hash_tag=GNU_HASH
        [ "$hash_style" = sysv ] && hash_tag=HASH

        if ! linker_supports_hash_style "$BUILD" "$hash_style"; then
            skip "$label" "linker does not support --hash-style=$hash_style"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if ! gcc -shared -fPIC "-Wl,--hash-style=$hash_style" \
                -Wl,--version-script="$map" -o "$lib" "$libsrc"; then
            fail "$label" "shared versioned COPY fixture compile failed"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if ! gcc -fno-pie -no-pie -o "$bin" "$src" -L"$BUILD" \
                "-l:libversioned_copy_${hash_style}.so" \
                -Wl,-rpath,'$ORIGIN'; then
            fail "$label" "non-PIE versioned COPY fixture compile failed"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if ! dynamic=$(LC_ALL=C readelf -d "$lib"); then
            fail "$label" "could not inspect shared versioned COPY fixture"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if ! grep -qF "($hash_tag)" <<<"$dynamic"; then
            fail "$label" "shared fixture lacks requested hash table"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        relocs=$(readelf -Wr "$bin" 2>/dev/null || true)
        if ! grep -q 'COPY.*stdout@' <<<"$relocs" ||
           ! grep -q 'COPY.*versioned_copy@COPY_' <<<"$relocs"; then
            skip "$label" "toolchain did not emit required COPY relocations"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        freeze_rc=0
        freeze_require_direct "$label" "$log" "$out" "$bin" ||
            freeze_rc=$?
        if [ "$freeze_rc" -eq 77 ]; then
            skip "$label" "$DIRECT_FREEZE_REASON"
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi
        if [ "$freeze_rc" -ne 0 ]; then
            rm -f "$lib" "$bin" "$out" "$log"
            continue
        fi

        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$actual" = "31 42" ] && [ "$rc" -eq 0 ]; then
            pass "$label"
        else
            fail "$label" "rc=$rc out=$actual"
        fi
        rm -f "$lib" "$bin" "$out" "$log"
    done
    rm -f "$libsrc" "$map" "$src"
}

# ===================================================================
# Test 22b: COPY sources supplied by the omitted native interpreter
# ===================================================================
test_interpreter_copy_object_direct() {
    echo "--- interpreter-owned COPY object direct-load ---"
    local src="$BUILD/interp_copy_object.c"
    local bin="$BUILD/interp_copy_object"
    local out="$BUILD/interp_copy_object.frozen"
    local log="$BUILD/interp_copy_object.log"
    local relocs expect="" actual="" rc_e=0 rc=0 freeze_rc=0
    local label="interpreter-owned COPY object direct-load"

    if ! command -v readelf >/dev/null 2>&1; then
        skip "$label" "readelf not installed"
        return
    fi
    if ! compiler_supports_non_pie "$BUILD"; then
        skip "$label" "compiler/linker does not support non-PIE output"
        return
    fi

    cat > "$src" <<'C'
#include <unistd.h>

__attribute__((noinline))
static int guarded_value(int value)
{
    volatile unsigned char bytes[16];
    bytes[0] = (unsigned char)value;
    return bytes[0];
}

int main(void)
{
    static const char message[] = "interpreter-copy-object-ok\n";

    if (guarded_value(7) != 7)
        return 2;
    return write(STDOUT_FILENO, message, sizeof(message) - 1) ==
        (ssize_t)(sizeof(message) - 1) ? 0 : 3;
}
C
    if ! gcc -fstack-protector-all -fno-pie -no-pie -o "$bin" "$src"; then
        fail "$label" "fixture compile failed"
        rm -f "$src" "$bin"
        return
    fi
    relocs=$(LC_ALL=C readelf -Wr "$bin" 2>/dev/null || true)
    if ! grep -Eq \
            'R_AARCH64_COPY[[:space:]]+.*__stack_chk_guard(@GLIBC_2[.]17)?' \
            <<<"$relocs"; then
        skip "$label" \
            "toolchain did not emit an interpreter-owned guard COPY"
        rm -f "$src" "$bin"
        return
    fi

    capture_output expect "$bin" || rc_e=$?
    if [ "$rc_e" -ne 0 ] ||
       [ "$expect" != "interpreter-copy-object-ok" ]; then
        fail "native interpreter-owned COPY control" \
            "exit=$rc_e output=$expect"
        rm -f "$src" "$bin"
        return
    fi

    freeze_require_direct "$label" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "$label" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "$expect" ]; then
            pass "$label"
        else
            fail "$label" "exit=$rc expected=$expect actual=$actual"
        fi
    fi
    rm -f "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 23: private musl layouts are admitted only by exact identity
# ===================================================================
test_musl_layout_gate() {
    echo "--- musl private runtime layout gate ---"
    local helper="$BUILD/musl_layout_gate"
    local decoder_helper
    local src="$BUILD/musl_layout_target.c"
    local bin="$BUILD/musl_layout_target"
    local bad_bin="$BUILD/musl_layout_target.unknown"
    local bad_interp="$BUILD/ld-musl-layout-unknown.so.1"
    local bad_out="$BUILD/musl_layout_unknown.frozen"
    local bad_log="$BUILD/musl_layout_unknown.log"
    local out="$BUILD/musl_layout_stale.frozen"
    local log="$BUILD/musl_layout_stale.log"
    local interp interp_abs bad_interp_abs libc_dir size meta_off actual
    local rc=0 freeze_rc=0

    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$helper" tests/musl_layout_gate.c; then
        fail "musl layout identity helper" "compile failed"
        return
    fi
    if "$helper" --selftest; then
        pass "musl layout identity helper"
    else
        fail "musl layout identity helper" \
            "known or unknown release identities were misclassified"
        rm -f "$helper"
        return
    fi

    if [ "$(uname -m)" = x86_64 ]; then
        decoder_helper="$BUILD/x86_64_musl_decoder_gate"
        if ! gcc -Wall -Wextra -D_GNU_SOURCE -Iinclude \
                -fno-stack-protector -ffunction-sections -fdata-sections \
                -Wl,--gc-sections -o "$decoder_helper" \
                tests/x86_64_musl_decoder_gate.c -ldl -pthread; then
            fail "x86-64 musl layout decoder" "compile failed"
        elif "$decoder_helper"; then
            pass "x86-64 musl layout decoder"
        else
            fail "x86-64 musl layout decoder" \
                "target startup/TLS mutation fixture was not decoded safely"
        fi
    elif [ "$(uname -m)" = aarch64 ]; then
        decoder_helper="$BUILD/aarch64_musl_decoder_gate"
        if ! gcc -Wall -Wextra -D_GNU_SOURCE -Iinclude \
                -fno-stack-protector -ffunction-sections -fdata-sections \
                -Wl,--gc-sections -o "$decoder_helper" \
                tests/aarch64_musl_decoder_gate.c -ldl -pthread; then
            fail "AArch64 musl layout decoder" "compile failed"
        elif "$decoder_helper"; then
            pass "AArch64 musl layout decoder"
        else
            fail "AArch64 musl layout decoder" \
                "hardened detach-state fixture was not decoded safely"
        fi
    fi

    if ! command -v musl-gcc >/dev/null 2>&1; then
        skip "musl layout integration gate" "musl-gcc not installed"
        rm -f "$helper"
        return
    fi
    if ! command -v readelf >/dev/null 2>&1; then
        skip "musl layout integration gate" "readelf not installed"
        rm -f "$helper"
        return
    fi

    cat > "$src" <<'C'
#include <stdio.h>
int main(void) {
    puts("musl-layout-target-ran");
    return 0;
}
C
    if ! musl-gcc -o "$bin" "$src"; then
        fail "musl layout integration gate" "target compile failed"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    if ! file "$bin" 2>/dev/null |
            grep 'interpreter .*ld-musl' >/dev/null; then
        skip "musl layout integration gate" \
            "musl-gcc did not produce a dynamic musl executable"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    interp=$(readelf -W -l "$bin" 2>/dev/null |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
    if [ -z "$interp" ] || [ ! -r "$interp" ]; then
        skip "musl layout integration gate" \
            "could not locate the target interpreter"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    interp_abs=$(readlink -f "$interp")
    libc_dir=$(dirname "$interp_abs")

    if ! cp "$interp" "$bad_interp" ||
       ! "$helper" --elf "$bad_interp"; then
        skip "musl layout integration gate" \
            "host musl release has no admitted private-layout profile"
        rm -f "$helper" "$src" "$bin" "$bad_interp"
        return
    fi
    bad_interp_abs=$(readlink -f "$bad_interp")
    if ! musl-gcc -Wl,--dynamic-linker="$bad_interp_abs" \
            -Wl,-rpath="$libc_dir" -o "$bad_bin" "$src"; then
        fail "unknown musl layout extraction gate" \
            "custom-interpreter target compile failed"
        rm -f "$helper" "$src" "$bin" "$bad_bin" "$bad_interp"
        return
    fi

    if ! run_freeze "$DLFREEZE" -d -o "$bad_out" "$bad_bin" \
            >"$bad_log" 2>&1; then
        fail "unknown musl layout extraction gate" "dlfreeze failed"
    else
        size=$(stat -c %s "$bad_out" 2>/dev/null || true)
        meta_off=""
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
            meta_off=$(od -An -tu8 -j $((size - 24)) -N8 "$bad_out" \
                2>/dev/null | tr -d '[:space:]')
        fi
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if grep -Eq \
               'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
               "$bad_log" &&
           [ "$meta_off" = 0 ] && [ "$rc" -eq 0 ] &&
           [ "$actual" = "musl-layout-target-ran" ]; then
            pass "unknown musl layout extraction gate"
        else
            fail "unknown musl layout extraction gate" \
                "metadata=$meta_off exit=$rc output=$actual"
        fi
    fi
    rm -f "$bad_bin" "$bad_interp" "$bad_out" "$bad_log"

    freeze_require_direct "stale direct musl layout refusal" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "stale direct musl layout strict refusal" \
            "$DIRECT_FREEZE_REASON"
        skip "stale direct musl layout helper refusal" \
            "$DIRECT_FREEZE_REASON"
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi
    if ! "$helper" --frozen "$out"; then
        fail "stale direct musl layout refusal" \
            "could not mutate the embedded interpreter identity"
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
       [[ "$actual" != *"musl-layout-target-ran"* ]]; then
        pass "stale direct musl layout strict refusal"
    else
        fail "stale direct musl layout strict refusal" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
       [[ "$actual" != *"musl-layout-target-ran"* ]]; then
        pass "stale direct musl layout helper refusal"
    else
        fail "stale direct musl layout helper refusal" \
            "exit=$rc output=$actual"
    fi

    rm -f "$helper" "$src" "$bin" "$out" "$log"
}

# ===================================================================
# Test 24: private glibc rtld layouts are admitted only by exact identity
# ===================================================================
test_glibc_layout_gate() {
    echo "--- glibc private rtld layout gate ---"
    local helper="$BUILD/glibc_layout_gate"
    local decoder_helper="$BUILD/glibc_tls_dtor_decoder_gate"
    local aarch64_rseq_helper="$BUILD/glibc_aarch64_rseq_gate"
    local src="$BUILD/glibc_layout_target.c"
    local bin="$BUILD/glibc_layout_target"
    local bad_bin="$BUILD/glibc_layout_target.unknown"
    local bad_interp="$BUILD/ld-linux-layout-unknown.so.2"
    local bad_out="$BUILD/glibc_layout_unknown.frozen"
    local bad_log="$BUILD/glibc_layout_unknown.log"
    local mismatch_bin="$BUILD/glibc_layout_target.mismatched"
    local mismatch_interp="$BUILD/ld-linux-release-mismatched.so.2"
    local mismatch_out="$BUILD/glibc_layout_mismatched.frozen"
    local mismatch_log="$BUILD/glibc_layout_mismatched.log"
    local out="$BUILD/glibc_layout_stale.frozen"
    local mismatched_libc_out="$BUILD/glibc_libc_release_mismatched.frozen"
    local hook_consumer_out="$BUILD/glibc_hook_consumer_mismatched.frozen"
    local tls_dtor_counter_out="$BUILD/glibc_tls_dtor_counter_mismatched.frozen"
    local dtv_descriptor_out="$BUILD/glibc_dtv_descriptor_mismatched.frozen"
    local aarch_contract_out=""
    local x86_cpu_contract_out=""
    local bad_service_reloc_out
    local missing_release_out="$BUILD/glibc_layout_release_missing.frozen"
    local missing_reloc_out="$BUILD/glibc_layout_relocation_missing.frozen"
    local log="$BUILD/glibc_layout_stale.log"
    local interp bad_interp_abs size meta_off actual libc_banner
    local rc=0 freeze_rc=0

    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$helper" tests/glibc_layout_gate.c; then
        fail "glibc layout identity helper" "compile failed"
        return
    fi
    if "$helper" --selftest; then
        pass "glibc layout identity helper"
    else
        fail "glibc layout identity helper" \
            "known, unknown, or development identities were misclassified"
        rm -f "$helper"
        return
    fi

    if ! gcc -Wall -Wextra -D_GNU_SOURCE -Iinclude \
            -fno-stack-protector -ffunction-sections -fdata-sections \
            -Wl,--gc-sections -o "$decoder_helper" \
            tests/glibc_tls_dtor_decoder_gate.c -ldl -pthread; then
        fail "glibc TLS-dtor counter decoder" "compile failed"
    elif "$decoder_helper"; then
        pass "glibc TLS-dtor counter decoder"
    else
        fail "glibc TLS-dtor counter decoder" \
            "target-code proof accepted a mutated instruction stream"
    fi
    rm -f "$decoder_helper"

    if [ "$(uname -m)" = aarch64 ]; then
        if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
                -fno-stack-protector -ffunction-sections -fdata-sections \
                -Wl,--gc-sections -o "$aarch64_rseq_helper" \
                tests/glibc_aarch64_rseq_gate.c -ldl -pthread; then
            fail "glibc AArch64 rseq control-flow decoder" \
                "compile failed"
            fail "glibc AArch64 code-view file provenance" \
                "compile failed"
        else
            if "$aarch64_rseq_helper" --rseq; then
                pass "glibc AArch64 rseq control-flow decoder"
            else
                fail "glibc AArch64 rseq control-flow decoder" \
                    "rooted CFG/provenance fixture was misclassified"
            fi
            if "$aarch64_rseq_helper" --file-backed; then
                pass "glibc AArch64 code-view file provenance"
            else
                fail "glibc AArch64 code-view file provenance" \
                    "executable zero-fill was accepted as target code"
            fi
        fi
        rm -f "$aarch64_rseq_helper"
    fi

    # Avoid a producer/grep -q pipeline under pipefail: grep may close the
    # pipe after the first matching line, making ldd's harmless SIGPIPE look
    # like a negative capability result.
    libc_banner=$(ldd --version 2>&1 || true)
    if ! grep -Eqi 'glibc|GNU libc' <<<"$libc_banner"; then
        skip "glibc layout integration gate" "fixture requires glibc"
        rm -f "$helper"
        return
    fi
    if ! command -v readelf >/dev/null 2>&1; then
        skip "glibc layout integration gate" "readelf not installed"
        rm -f "$helper"
        return
    fi

    cat > "$src" <<'C'
#include <stdio.h>
int main(void) {
    puts("layout-target-ran");
    return 0;
}
C
    if ! gcc -o "$bin" "$src"; then
        fail "glibc layout integration gate" "target compile failed"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    interp=$(readelf -W -l "$bin" 2>/dev/null |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
    if [ -z "$interp" ] || [ ! -r "$interp" ]; then
        skip "glibc layout integration gate" \
            "could not locate the target interpreter"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    if "$helper" --validate-family "$interp"; then
        pass "glibc structural family identity"
    else
        fail "glibc structural family identity" \
            "defined GLIBC_PRIVATE rtld objects were not recognized"
        rm -f "$helper" "$src" "$bin"
        return
    fi

    if ! cp "$interp" "$bad_interp" || ! "$helper" --elf "$bad_interp"; then
        fail "unknown glibc rtld layout extraction gate" \
            "could not construct an unknown-layout interpreter"
        rm -f "$helper" "$src" "$bin" "$bad_interp"
        return
    fi
    bad_interp_abs=$(readlink -f "$bad_interp")
    if ! gcc -Wl,--dynamic-linker="$bad_interp_abs" -o "$bad_bin" "$src";
    then
        fail "unknown glibc rtld layout extraction gate" \
            "custom-interpreter target compile failed"
        rm -f "$helper" "$src" "$bin" "$bad_bin" "$bad_interp"
        return
    fi

    if ! run_freeze "$DLFREEZE" -d -o "$bad_out" "$bad_bin" \
            >"$bad_log" 2>&1; then
        fail "unknown glibc rtld layout extraction gate" "dlfreeze failed"
    else
        size=$(stat -c %s "$bad_out" 2>/dev/null || true)
        meta_off=""
        if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
            meta_off=$(od -An -tu8 -j $((size - 24)) -N8 "$bad_out" \
                2>/dev/null | tr -d '[:space:]')
        fi
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 "$bad_out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if grep -Eq \
               'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
               "$bad_log" &&
           [ "$meta_off" = 0 ] && [ "$rc" -eq 0 ] &&
           [ "$actual" = "layout-target-ran" ]; then
            pass "unknown glibc rtld layout extraction gate"
        else
            fail "unknown glibc rtld layout extraction gate" \
                "metadata=$meta_off exit=$rc output=$actual"
        fi
    fi
    rm -f "$bad_bin" "$bad_interp" "$bad_out" "$bad_log"

    # Matching an rtld size tuple is insufficient if libc comes from a
    # different release.  Mutate only the copied interpreter's stable release
    # banner; the pair must be packaged for extraction, never direct-loaded.
    if ! cp "$interp" "$mismatch_interp"; then
        fail "mismatched glibc runtime extraction gate" \
            "could not copy the target interpreter"
    elif ! "$helper" --release-mismatch "$mismatch_interp"; then
        skip "mismatched glibc runtime extraction gate" \
            "interpreter has no mutable stable-release identity"
    else
        bad_interp_abs=$(readlink -f "$mismatch_interp")
        if ! gcc -Wl,--dynamic-linker="$bad_interp_abs" \
                -o "$mismatch_bin" "$src"; then
            fail "mismatched glibc runtime extraction gate" \
                "custom-interpreter target compile failed"
        elif ! run_freeze "$DLFREEZE" -d -o "$mismatch_out" \
                "$mismatch_bin" >"$mismatch_log" 2>&1; then
            fail "mismatched glibc runtime extraction gate" \
                "dlfreeze failed"
        else
            size=$(stat -c %s "$mismatch_out" 2>/dev/null || true)
            meta_off=""
            if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -ge 64 ]; then
                meta_off=$(od -An -tu8 -j $((size - 24)) -N8 \
                    "$mismatch_out" 2>/dev/null | tr -d '[:space:]')
            fi
            actual=""; rc=0
            capture_output actual env DLFREEZE_NO_FORK=1 \
                "$mismatch_out" || rc=$?
            actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
            if grep -Eq \
                   'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
                   "$mismatch_log" &&
               [ "$meta_off" = 0 ] && [ "$rc" -eq 0 ] &&
               [ "$actual" = "layout-target-ran" ]; then
                pass "mismatched glibc runtime extraction gate"
            else
                fail "mismatched glibc runtime extraction gate" \
                    "metadata=$meta_off exit=$rc output=$actual"
            fi
        fi
    fi
    rm -f "$mismatch_bin" "$mismatch_interp" "$mismatch_out" \
          "$mismatch_log"

    freeze_require_direct "stale direct glibc layout refusal" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "stale direct glibc layout strict refusal" \
            "$DIRECT_FREEZE_REASON"
        skip "stale direct glibc layout helper refusal" \
            "$DIRECT_FREEZE_REASON"
        rm -f "$helper" "$src" "$bin" "$out" "$log" \
            "$missing_reloc_out"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$helper" "$src" "$bin" "$out" "$log" \
            "$missing_reloc_out"
        return
    fi

    # Establish the unmodified artifact as a working direct-load control
    # before any refusal mutation.  Otherwise a target whose baseline private
    # contract is already rejected can make every mutation appear to fail
    # closed for the intended reason.
    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
    if [ "$rc" -eq 0 ] && [ "$actual" = "layout-target-ran" ]; then
        pass "direct glibc layout baseline"
    else
        fail "direct glibc layout baseline" \
            "exit=$rc output=$actual"
        rm -f "$helper" "$src" "$bin" "$out" "$log" \
            "$missing_reloc_out"
        return
    fi

    # The exported accessor, initializer layout writes, and CFG-rooted
    # generic-kind assignment are independent pieces of the x86 private CPU
    # contract.  Preserve the target release/size identity while corrupting
    # each witness and require runtime revalidation to stop before target
    # code, rather than trusting the packer's earlier admission.
    if [ "$(uname -m)" = x86_64 ]; then
        for mode in accessor layout kind-root; do
            x86_cpu_contract_out="$BUILD/glibc_x86_cpu_${mode//-/_}_mismatched.frozen"
            if ! cp "$out" "$x86_cpu_contract_out" ||
               ! "$helper" "--frozen-x86-cpu-$mode-mismatch" \
                    "$x86_cpu_contract_out"; then
                fail "glibc x86 CPU $mode contract refusal" \
                    "could not mutate the exact target-code witness"
            else
                actual=""; rc=0
                capture_output actual env DLFREEZE_NO_FORK=1 \
                    "$x86_cpu_contract_out" || rc=$?
                if [ "$rc" -eq 127 ] &&
                   [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
                   [[ "$actual" != *"layout-target-ran"* ]]; then
                    pass "glibc x86 CPU $mode contract strict refusal"
                else
                    fail "glibc x86 CPU $mode contract strict refusal" \
                        "exit=$rc output=$actual"
                fi
            fi
            rm -f "$x86_cpu_contract_out"
        done
    fi

    # Packer admission is not a runtime trust boundary.  Mutate only the
    # embedded libc banner after packaging and require the direct loader to
    # independently reject a libc/interpreter release mismatch before target
    # mapping or startup.
    if ! cp "$out" "$mismatched_libc_out" ||
       ! "$helper" --frozen-libc-release-mismatch \
            "$mismatched_libc_out"; then
        fail "stale glibc libc/interpreter pairing refusal" \
            "could not mutate the embedded libc release identity"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$mismatched_libc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"libc/interpreter release mismatch"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "stale glibc libc/interpreter pairing strict refusal"
        else
            fail "stale glibc libc/interpreter pairing strict refusal" \
                "exit=$rc output=$actual"
        fi

        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK \
            "$mismatched_libc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"libc/interpreter release mismatch"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "stale glibc libc/interpreter pairing helper refusal"
        else
            fail "stale glibc libc/interpreter pairing helper refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$mismatched_libc_out"

    # Keep the interpreter release and both private-object sizes unchanged,
    # but move libc's encoded _dl_dlfcn_hook field displacement by one slot.
    # The runtime must independently re-prove the consumer before startup.
    if ! cp "$out" "$hook_consumer_out" ||
       ! "$helper" --frozen-hook-consumer-mismatch "$hook_consumer_out";
    then
        fail "stale glibc dlfcn-hook consumer refusal" \
            "could not mutate the embedded libc consumer displacement"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$hook_consumer_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"libc/interpreter release mismatch"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "stale glibc dlfcn-hook consumer strict refusal"
        else
            fail "stale glibc dlfcn-hook consumer strict refusal" \
                "exit=$rc output=$actual"
        fi

        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK \
            "$hook_consumer_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"libc/interpreter release mismatch"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "stale glibc dlfcn-hook consumer helper refusal"
        else
            fail "stale glibc dlfcn-hook consumer helper refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$hook_consumer_out"

    # Keep libc's release and thread_db descriptors unchanged, but move only
    # __call_tls_dtors' atomic decrement to a different link_map field.  The
    # independently decoded registration/decrement witnesses must disagree
    # and direct loading must stop before target code.
    if ! cp "$out" "$tls_dtor_counter_out" ||
       ! "$helper" --frozen-tls-dtor-counter-mismatch \
            "$tls_dtor_counter_out"; then
        skip "glibc TLS-dtor counter mismatch refusal" \
            "target libc has no supported mutable decrement witness"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$tls_dtor_counter_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"target glibc thread-layout validation"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "glibc TLS-dtor counter mismatch strict refusal"
        else
            fail "glibc TLS-dtor counter mismatch strict refusal" \
                "exit=$rc output=$actual"
        fi

        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK \
            "$tls_dtor_counter_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"target glibc thread-layout validation"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "glibc TLS-dtor counter mismatch helper refusal"
        else
            fail "glibc TLS-dtor counter mismatch helper refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$tls_dtor_counter_out"

    # Preserve the target release and pthread size but corrupt the exact
    # thread_db descriptor which locates the TCB's DTV slot.  Both supported
    # architectures must refuse before target code can observe the stale slot.
    if ! cp "$out" "$dtv_descriptor_out" ||
       ! "$helper" --frozen-glibc-dtv-descriptor-mismatch \
            "$dtv_descriptor_out"; then
        fail "glibc DTV descriptor mismatch refusal" \
            "could not mutate the target thread_db descriptor"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$dtv_descriptor_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"target glibc thread-layout validation"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "glibc DTV descriptor mismatch strict refusal"
        else
            fail "glibc DTV descriptor mismatch strict refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$dtv_descriptor_out"

    # AArch64's initial-thread stackblock_size and rseq fields are private
    # target-libc contracts.  Corrupt each independent code witness after
    # packaging; release profiles and thread_db sizes remain unchanged.
    if [ "$(uname -m)" = aarch64 ]; then
        for mode in alloca-stack getattr-stack rseq; do
            aarch_contract_out="$BUILD/glibc_aarch64_${mode//-/_}_mismatched.frozen"
            if ! cp "$out" "$aarch_contract_out" ||
               ! "$helper" "--frozen-aarch64-$mode-mismatch" \
                    "$aarch_contract_out"; then
                skip "glibc AArch64 $mode contract refusal" \
                    "target libc has no supported mutable witness"
                rm -f "$aarch_contract_out"
                continue
            fi

            actual=""; rc=0
            capture_output actual env DLFREEZE_NO_FORK=1 \
                "$aarch_contract_out" || rc=$?
            if [ "$rc" -eq 127 ] &&
               [[ "$actual" == *"target glibc thread-layout validation"* ]] &&
               [[ "$actual" != *"layout-target-ran"* ]]; then
                pass "glibc AArch64 $mode contract strict refusal"
            else
                fail "glibc AArch64 $mode contract strict refusal" \
                    "exit=$rc output=$actual"
            fi
            rm -f "$aarch_contract_out"
        done
    fi

    # The private accessor is callable only after every relocation in its
    # isolated interpreter image was understood and bounded.  Unknown types
    # and malformed symbol references must decline direct mode cleanly.
    for mode in unsupported symbol; do
        bad_service_reloc_out="$BUILD/glibc_tunable_service_relocation_$mode.frozen"
        if ! cp "$out" "$bad_service_reloc_out" ||
           ! "$helper" "--frozen-tunable-reloc-$mode" \
                "$bad_service_reloc_out"; then
            skip "glibc tunable service relocation gate ($mode)" \
                "interpreter has no mutable non-layout relocation"
            rm -f "$bad_service_reloc_out"
            continue
        fi

        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$bad_service_reloc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"target interpreter lacks safe tunable defaults"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "glibc tunable service relocation gate ($mode)"
        else
            fail "glibc tunable service relocation gate ($mode)" \
                "exit=$rc output=$actual"
        fi
        rm -f "$bad_service_reloc_out"
    done

    for mode in callback-clobber self-loop fallthrough callback-bypass; do
        bad_service_reloc_out="$BUILD/glibc_tunable_accessor_$mode.frozen"
        if ! cp "$out" "$bad_service_reloc_out" ||
           ! "$helper" "--frozen-tunable-$mode" \
                "$bad_service_reloc_out"; then
            skip "glibc tunable accessor proof gate ($mode)" \
                "interpreter accessor lacks the selected mutation pattern"
            rm -f "$bad_service_reloc_out"
            continue
        fi

        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$bad_service_reloc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"target interpreter lacks safe tunable defaults"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "glibc tunable accessor proof gate ($mode)"
        else
            fail "glibc tunable accessor proof gate ($mode)" \
                "exit=$rc output=$actual"
        fi
        rm -f "$bad_service_reloc_out"
    done

    # Preserve the release banner and both private-object sizes, but remove
    # one relative relocation that positively identifies an overwritten
    # _rtld_global_ro function-pointer field.  Admission must fail before the
    # target is mapped or handed control.
    if ! cp "$out" "$missing_reloc_out" ||
       ! "$helper" --frozen-reloc-missing "$missing_reloc_out"; then
        skip "missing glibc GLRO relocation refusal" \
            "admitted profile has no relocated GLRO hook field"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$missing_reloc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "missing glibc GLRO relocation strict refusal"
        else
            fail "missing glibc GLRO relocation strict refusal" \
                "exit=$rc output=$actual"
        fi

        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK \
            "$missing_reloc_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "missing glibc GLRO relocation helper refusal"
        else
            fail "missing glibc GLRO relocation helper refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$missing_reloc_out"

    # A stale artifact must not substitute its highest GLIBC_2.* ABI symbol
    # version for the positive stable-release identity used at pack time.
    if ! cp "$out" "$missing_release_out" ||
       ! "$helper" --frozen-release-missing "$missing_release_out"; then
        fail "missing glibc release identity refusal" \
            "could not remove the embedded stable-release identity"
    else
        actual=""; rc=0
        capture_output actual env DLFREEZE_NO_FORK=1 \
            "$missing_release_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "missing glibc release identity strict refusal"
        else
            fail "missing glibc release identity strict refusal" \
                "exit=$rc output=$actual"
        fi

        actual=""; rc=0
        capture_output actual env -u DLFREEZE_NO_FORK \
            "$missing_release_out" || rc=$?
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
           [[ "$actual" != *"layout-target-ran"* ]]; then
            pass "missing glibc release identity helper refusal"
        else
            fail "missing glibc release identity helper refusal" \
                "exit=$rc output=$actual"
        fi
    fi
    rm -f "$missing_release_out"

    if ! "$helper" --frozen "$out"; then
        fail "stale direct glibc layout refusal" \
            "could not mutate the embedded interpreter identity"
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi

    actual=""; rc=0
    capture_output actual env DLFREEZE_NO_FORK=1 "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
       [[ "$actual" != *"layout-target-ran"* ]]; then
        pass "stale direct glibc layout strict refusal"
    else
        fail "stale direct glibc layout strict refusal" \
            "exit=$rc output=$actual"
    fi

    actual=""; rc=0
    capture_output actual env -u DLFREEZE_NO_FORK "$out" || rc=$?
    if [ "$rc" -eq 127 ] &&
       [[ "$actual" == *"direct-load artifact is incompatible"* ]] &&
       [[ "$actual" != *"layout-target-ran"* ]]; then
        pass "stale direct glibc layout helper refusal"
    else
        fail "stale direct glibc layout helper refusal" \
            "exit=$rc output=$actual"
    fi

    rm -f "$helper" "$src" "$bin" "$out" "$log" \
        "$missing_reloc_out" "$aarch_contract_out"
}

# ===================================================================
echo "======== dlfreeze test suite ========"
echo "build dir: $BUILD"
echo ""

test_hello
test_libc_semantics_gate
test_bootstrap_secure_gate
test_packer_alias_gate
test_packer_elf_alignment_gate
test_file_pattern_option_scaling
test_musl_hello_direct
test_glibc_tunable_environment_direct
test_glibc_tunable_defaults_direct
test_glibc_gmon_loader_policy
test_musl_ctor_direct
test_musl_copy_reloc_direct
test_musl_multibyte_direct
test_musl_shared_tls_direct
test_musl_target_contract_direct
test_renamed_runtime_identity
test_loader_post_tls_import_gate
test_direct_bootstrap_libc_independence
test_musl_layout_gate
test_glibc_gnu_hash_shift_gate
test_glibc_layout_gate
test_glibc_stack_end_direct
test_direct_constructor_stack_identity
test_direct_target_auxv_identity
test_glibc_private_exception_direct
test_glibc_internal_module_loading_direct
test_exit_code
test_upx_payload_mapping
test_captured_files_require_direct
test_runtime_relocation_vfs_fallthrough
test_captured_file_request_identity_direct
test_vfs_explicit_directory_kind
test_vfs_dir_handle_registry
test_direct_handoff_once
test_supervisor_signal_forwarding
test_supervisor_inherited_sigchld
test_direct_pty_interaction
test_preload_helper_compile_matrix
test_preload_fortified_open_entrypoints
test_preload_helper_initialization_race
test_preload_helper_constructor_order
test_trace_helper_symbol_version_compatibility
test_trace_helper_main_rpath_ancestry
test_aux_dependency_lookup_status
test_trace_helper_completeness
test_trace_helper_error_transparency
test_trace_exec_headers_and_open_errors
test_trace_ignores_deleted_out_of_scope_file
test_executable_path_empty_component
test_relative_executable_identity_extraction
test_exact_range_duplicate_extraction
test_direct_fork_lifecycle
test_direct_runtime_service_collisions
test_direct_runtime_loader_concurrency
test_direct_loader_introspection
test_external_program_headers_direct
test_direct_dladdr_visibility
test_direct_dladdr_layout
test_direct_vdso_namespace
test_direct_exit_lifecycle
test_direct_constructor_signal
test_direct_preinit_order
test_direct_constructor_prefix_collision
test_direct_metadata_validation
test_prelinked_runtime_fixup_canonical
test_aux_phdr_bounds_direct
test_static_tls_alignment_direct
test_tls_firstbyte_semantics_direct
test_nobits_tls_outside_load_direct
test_dependency_abi_validation
test_interpreter_prefix_dependencies
test_pack_search_semantics_gate
test_gnu_pack_dynamic_tokens
test_resolver_to_packer_snapshot_gate
test_dependency_search_semantics
test_first_opened_search_candidate
test_logical_load_path_identity
test_needed_source_alias_identity
test_pathful_glibc_direct_admission
test_gnu_pack_cache_contract
test_long_elf_metadata_strings
test_vfs_hash_complexity_gate
test_high_cardinality_data_manifest
test_ls
test_cat
test_negative_dot_path_manifest
test_direct_startup_elf_vfs
test_vfs_faccessat_flag_routing
test_vfs_environment_and_kernel_identity
test_direct_kernel_runtime_parameters
test_packer_main_detection
test_program_smoke_matrix
test_zig_cc_trace_direct
test_symlink_exe_identity_direct
test_dlopen_program
test_pathful_dlopen_requires_direct
test_dlopen_fallback
test_python3
test_python3_advanced
test_direct_dlopen_embedded
test_direct_dlopen_deps
test_direct_small_stack_dlopen_chain
test_direct_dlopen_runpath_origin
test_gnu_direct_runtime_search_ancestry
test_gnu_runtime_dynamic_token_gate
test_gnu_direct_runtime_dynamic_tokens
test_gnu_direct_runtime_hwcaps_paths
test_direct_dlopen_inode_alias
test_direct_dlopen_loaded_name_identity
test_musl_direct_runtime_search_semantics
test_direct_library_path_snapshot
test_musl_dual_search_tags
test_musl_direct_late_dlopen_ancestry
test_musl_direct_dlopen_head_scope
test_direct_dlopen_path_delimiters
test_direct_dlopen_long_search_path
test_direct_dlopen_name_storage_scaling
test_direct_dlopen_missing_needed
test_direct_dlopen_sibling_scope
test_direct_dlopen_bfs_scope
test_direct_symbolic_lookup_scope
test_direct_dlopen_ifunc_data_order
test_direct_copy_ifunc_order
test_direct_dlsym_ifunc_repeated_resolution
test_direct_gnu_unique_local_scopes
test_direct_gnu_unique_transaction_rollback
test_direct_dlopen_admission_flags
test_direct_dlopen_mode_contract
test_direct_dlopen_local_caller_scope
test_direct_dlopen_embedded_static_tls
test_direct_dlopen_startup_owned_ie
test_direct_runtime_parser_bounds
test_unaligned_relocation_destinations
test_direct_dlopen_fallback
test_direct_runtime_truncate_snapshot
test_direct_runtime_noexec_policy
test_python3_direct
test_python_repl_pty_direct
test_glibc_tls_dtor_direct
test_ruby_direct_host_run
test_dlopen_soname_direct
test_dlopen_relpath_direct
test_dlopen_exact_pathful_replay_direct
test_dlopen_same_source_aliases_direct
test_dlopen_startup_overlap_pathful_direct
test_successful_dlopen_trace_fails_closed
test_dlopen_dynamic_token_refusal
test_dlopen_bare_alias_requires_direct
test_dlmopen_trace_namespaces
test_dlmopen_direct
test_dlopen_tls_per_thread_direct
test_glibc_tls_teardown_direct
test_glibc_dtv_capacity_direct
test_direct_memory_protections
test_direct_symbol_definition_addresses
test_unsupported_relocation_direct
test_malformed_prelink_metadata
test_malformed_relr_prelink
test_malformed_dynamic_bounds_direct
test_dlvsym_direct
test_dlsym_cache_key_lifetime_direct
test_dlsym_special_consistency_direct
test_dlsym_provider_admission_direct
test_dlsym_selected_provider_direct
test_dlsym_return_newest_direct
test_versioned_relocation_direct
test_default_version_interposition_direct
test_special_version_admission_direct
test_versioned_copy_relocation_direct
test_interpreter_copy_object_direct

case "${DLFREEZE_REQUIRE_DIRECT:-${CI:-0}}" in
    1|true|TRUE|yes|YES)
        if [ "$DIRECT_ARTIFACTS" -eq 0 ]; then
            fail "direct-load CI coverage" \
                "no test produced a direct-load artifact"
        fi
        ;;
esac

echo ""
echo "======== ${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}, ${YLW}$SKIP skipped${RST}, $DIRECT_ARTIFACTS direct artifacts ========"
[ "$FAIL" -eq 0 ]
