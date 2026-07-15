#!/usr/bin/env bash
# dlfreeze test suite
# shellcheck disable=SC2016 # command snippets and $ORIGIN are intentionally literal
set -euo pipefail

BUILD="${1:-build}"
DLFREEZE="$BUILD/dlfreeze"

mkdir -p "$BUILD"

# Some host toolchains (gcc >= 16 on Arch) auto-inject -latomic_asneeded
# into musl-gcc's link line, but musl-gcc.specs uses -nostdlib and only
# adds -L/usr/lib/musl/lib so the system /usr/lib/libatomic_asneeded.a
# isn't found.  Make /usr/lib visible so linking succeeds without
# overriding musl's own libc.  Searched after gcc's -L paths so musl
# wins for -lc.
if [ -e /usr/lib/libatomic_asneeded.a ]; then
    export LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}/usr/lib"
fi

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

strip_dlfreeze_warnings() {
    grep -v '^dlfreeze: warning:' || true
}

# Distinguish a target/toolchain which does not implement GNU IFUNC from a
# broken test fixture.  Callers still fail if their real fixture does not
# compile after this minimal feature probe succeeds.
compiler_supports_gnu_ifunc() {
    local root="$1"
    local src="$root/.dlfreeze-ifunc-probe.c"
    local lib="$root/.dlfreeze-ifunc-probe.so"

    cat > "$src" <<'C'
static int probe_impl(void) { return 0; }
static void *probe_resolver(void) { return (void *)probe_impl; }
int dlfreeze_ifunc_probe(void)
    __attribute__((ifunc("probe_resolver")));
C
    if gcc -shared -fPIC -o "$lib" "$src" >/dev/null 2>&1; then
        rm -f "$src" "$lib"
        return 0
    fi
    rm -f "$src" "$lib"
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
# such an image a strict direct-load test.  Keep the packer log and raw footer
# checks together so direct regressions cannot silently pass via extraction.
DIRECT_FREEZE_REASON=""
DIRECT_META_OFF=""
freeze_require_direct() {
    local label="$1" log="$2" output="$3"
    local runtime_warning size footer_magic meta_off payload_end
    local direct_confirmed=0
    shift 3

    DIRECT_FREEZE_REASON=""
    DIRECT_META_OFF=""
    if ! run_freeze "$DLFREEZE" -d -o "$output" "$@" >"$log" 2>&1; then
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
    if [ "$expect" = "$actual" ] && [ "$rc_e" -eq "$rc_a" ]; then
        pass "musl hello direct-load"
    else
        fail "musl hello direct-load" \
            "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out" "$log"
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
# An unrecognized interpreter must produce a safe extraction-mode image
# instead of entering glibc-specific direct-loader paths.
# ===================================================================
test_unknown_runtime_fallback() {
    echo "--- unknown runtime extraction fallback ---"
    if ! command -v readelf &>/dev/null; then
        skip "unknown-runtime-fallback" "readelf not installed"
        return
    fi

    local src="$BUILD/unknown_runtime.c" probe="$BUILD/unknown_runtime_probe"
    local bin="$BUILD/unknown_runtime" out="$BUILD/unknown_runtime.frozen"
    local custom="$BUILD/custom-runtime.so" interp actual rc=0
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("unknown runtime fallback ok"); return 0; }
C
    gcc -o "$probe" "$src"
    interp=$(LC_ALL=C readelf -W -l "$probe" 2>/dev/null |
        sed -n 's@.*Requesting program interpreter: \([^]]*\).*@\1@p')
    if [ -z "$interp" ] || [[ "$(basename "$interp")" != ld-linux* ]]; then
        skip "unknown-runtime-fallback" "fixture requires a glibc host"
        rm -f "$src" "$probe"
        return
    fi
    cp -L "$interp" "$custom"
    gcc -Wl,--dynamic-linker="$custom" -o "$bin" "$src"
    if ! run_freeze "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "unknown-runtime-fallback" "dlfreeze failed"
    else
        # Force runtime startup through the bundled interpreter rather than
        # the byte-identical source path used while packaging.
        rm -f "$custom"
        capture_output actual "$out" || rc=$?
        actual=$(printf '%s\n' "$actual" | strip_dlfreeze_warnings)
        if [ "$rc" -eq 0 ] && [ "$actual" = "unknown runtime fallback ok" ]; then
            pass "unknown runtime extraction fallback"
        else
            fail "unknown runtime extraction fallback" "exit=$rc output=$actual"
        fi
    fi
    rm -f "$src" "$probe" "$bin" "$out" "$custom"
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
# Test 1h: glibc libc/rtld exception imports resolve exactly
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

    if ! gcc -D_GNU_SOURCE -Iinclude -fno-stack-protector \
            -ffunction-sections -fdata-sections -Wl,--gc-sections \
            -o "$helper" tests/glibc_exception_gate.c -ldl -pthread; then
        fail "glibc private exception success contract" \
            "helper compile failed"
        rm -f "$helper"
        return
    elif "$helper"; then
        pass "glibc private exception success contract"
    else
        fail "glibc private exception success contract" \
            "successful catch did not clear its result"
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
# Test 2b: direct-load never retries after application handoff
# ===================================================================
test_direct_handoff_once() {
    echo "--- direct handoff executes once ---"
    local src="$BUILD/handoff_once.c" bin="$BUILD/handoff_once"
    local out="$BUILD/handoff_once.frozen" marker="$BUILD/handoff_once.log"
    local pack_log="$BUILD/handoff_once.pack.log" freeze_rc=0
    rm -f "$pack_log"
    cat > "$src" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) return 2;
    FILE *f = fopen(argv[1], "a");
    if (!f) return 3;
    fputs("ran\n", f);
    fclose(f);
    if (argc == 3) raise(SIGTERM);
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
    rm -f "$src" "$bin" "$out" "$marker" "$pack_log"
}

# ===================================================================
# Test 2c: the direct supervisor forwards signals to the application
# ===================================================================
test_direct_signal_forwarding() {
    echo "--- direct supervisor signal forwarding ---"
    local src="$BUILD/direct_signal.c" bin="$BUILD/direct_signal"
    local out="$BUILD/direct_signal.frozen" marker="$BUILD/direct_signal.ready"
    local log="$BUILD/direct_signal.log" freeze_rc=0
    rm -f "$log"
    cat > "$src" <<'C'
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 3;
    if (write(fd, "ready\n", 6) != 6) return 4;
    close(fd);
    for (;;) pause();
}
C
    gcc -o "$bin" "$src"
    freeze_require_direct "direct signal forwarding" "$log" "$out" \
        "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "direct signal forwarding" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$marker" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$marker" "$log"
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
        fail "direct signal forwarding" "application child did not become ready"
    else
        kill -TERM "$wrapper"
        wait "$wrapper" || rc=$?
        local child_alive=0
        if kill -0 "$child" 2>/dev/null; then
            child_alive=1
            kill -KILL "$child" 2>/dev/null || true
        fi
        if [ "$rc" -eq 143 ] && [ "$child_alive" -eq 0 ]; then
            pass "direct signal forwarding"
        else
            fail "direct signal forwarding" \
                "wrapper exit=$rc child_alive=$child_alive"
        fi
    fi
    rm -f "$src" "$bin" "$out" "$marker" "$log"
}

# ===================================================================
# Test 2c2: controlling-terminal I/O and job-control signals survive
# both the direct supervisor and the strict in-process path.
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
        skip "supervised direct PTY interaction" "$DIRECT_FREEZE_REASON"
        skip "strict direct PTY interaction" "$DIRECT_FREEZE_REASON"
    elif [ "$freeze_rc" -eq 0 ]; then
        if "$helper" --run -- env -u DLFREEZE_NO_FORK \
                "$out" --target >"$supervised_log" 2>&1; then
            pass "supervised direct PTY interaction"
        else
            fail "supervised direct PTY interaction" \
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
            "$helper" --run -- "$DLFREEZE" -t \
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
        skip "direct constructor signal (no-fork)" "$DIRECT_FREEZE_REASON"
        skip "direct constructor signal (supervisor)" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi

    for mode in no-fork supervisor; do
        actual=""; rc=0
        if [ "$mode" = no-fork ]; then
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

# ===================================================================
# Test 2h: corrupt direct object metadata is rejected before mapping
# ===================================================================
test_direct_metadata_validation() {
    echo "--- direct object metadata validation ---"
    local src="$BUILD/direct_metadata.c" bin="$BUILD/direct_metadata"
    local out="$BUILD/direct_metadata.frozen"
    local prelinked="$BUILD/direct_metadata_prelinked.frozen"
    local early_invalid="$BUILD/direct_metadata_early_invalid.frozen"
    local log="$BUILD/direct_metadata.log"
    local size meta_off meta_flags actual rc=0 freeze_rc=0

    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("metadata-target-ran"); return 0; }
C
    if ! gcc -fPIE -pie -o "$bin" "$src"; then
        fail "direct metadata validation" "compile failed"
        rm -f "$src" "$bin" "$out" "$prelinked" "$early_invalid" "$log"
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
        rm -f "$src" "$bin" "$out" "$prelinked" "$early_invalid" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$prelinked" "$early_invalid" "$log"
        return
    fi

    size=$(stat -c %s "$out")
    meta_off=$DIRECT_META_OFF
    if [ "$meta_off" -gt $((size - 64 - 48)) ]; then
        fail "direct metadata validation" "metadata field lies outside payload"
        rm -f "$src" "$bin" "$out" "$prelinked" "$early_invalid" "$log"
        return
    fi

    # A prelinked artifact contains relocated PT_LOAD bytes and must never be
    # retried through the system dynamic linker after an unmarked child
    # failure.  Zeroing a PIE main's base keeps metadata structurally valid,
    # but makes the child's fixed-address reservation fail before handoff.
    meta_flags=$(od -An -tu4 -j $((meta_off + 48)) -N4 "$out" \
        2>/dev/null | tr -d '[:space:]')
    if [[ "$meta_flags" =~ ^[0-9]+$ ]] &&
       [ $((meta_flags & 16)) -ne 0 ]; then
        cp "$out" "$prelinked"
        dd if=/dev/zero of="$prelinked" bs=1 seek="$meta_off" count=8 \
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
    rm -f "$src" "$bin" "$out" "$prelinked" "$early_invalid" "$log"
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
    local log="$BUILD/direct_phdr_target.log"
    local actual rc=0 freeze_rc=0

    if ! gcc -Wall -Wextra -Werror -D_GNU_SOURCE -Iinclude \
            -o "$helper" tests/direct_phdr_gate.c; then
        fail "direct auxiliary program-header bounds" "helper compile failed"
        return
    fi
    cat > "$src" <<'C'
#include <stdio.h>
int main(void) { puts("phdr-target-ran"); return 0; }
C
    if ! gcc -fPIE -pie -Wl,-z,relro,-z,now -o "$bin" "$src"; then
        fail "direct auxiliary program-header bounds" "target compile failed"
        rm -f "$helper" "$src" "$bin"
        return
    fi
    freeze_require_direct "direct auxiliary program-header bounds" "$log" \
        "$out" "$bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "malformed PT_GNU_RELRO rejection" "$DIRECT_FREEZE_REASON"
        skip "malformed PT_GNU_EH_FRAME rejection" "$DIRECT_FREEZE_REASON"
        rm -f "$helper" "$src" "$bin" "$out" "$log"
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

    rm -f "$helper" "$src" "$bin" "$out" "$bad_relro" "$bad_eh" "$log"
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
# Test 2f: dependency search skips wrong-ABI candidates and fails closed
# ===================================================================
test_dependency_abi_validation() {
    echo "--- dependency ABI validation ---"
    local lib_src="$BUILD/abi_dep.c" main_src="$BUILD/abi_main.c"
    local good="$BUILD/abi-good" bad="$BUILD/abi-bad"
    local lib="$good/libdlfreeze_abi_fixture.so"
    local bin="$BUILD/abi_main" out="$BUILD/abi_main.frozen" actual rc=0
    mkdir -p "$good" "$bad"
    cat > "$lib_src" <<'C'
int abi_fixture_value(void) { return 42; }
C
    cat > "$main_src" <<'C'
#include <stdio.h>
int abi_fixture_value(void);
int main(void) { printf("%d\n", abi_fixture_value()); return 0; }
C
    gcc -shared -fPIC -Wl,-soname,libdlfreeze_abi_fixture.so -o "$lib" "$lib_src"
    gcc -Wl,-rpath,"$good" -L"$good" -o "$bin" "$main_src" \
        -ldlfreeze_abi_fixture
    cp "$lib" "$bad/libdlfreeze_abi_fixture.so"
    case "$(uname -m)" in
        x86_64)  printf '\267\000' | dd of="$bad/libdlfreeze_abi_fixture.so" \
                     bs=1 seek=18 conv=notrunc status=none ;;
        aarch64) printf '\076\000' | dd of="$bad/libdlfreeze_abi_fixture.so" \
                     bs=1 seek=18 conv=notrunc status=none ;;
    esac

    if ! run_freeze env LD_LIBRARY_PATH="$bad" "$DLFREEZE" -o "$out" "$bin" \
            >/dev/null 2>&1; then
        fail "dependency ABI candidate" "dlfreeze rejected valid fallback"
    else
        capture_output actual "$out" || rc=$?
        if [ "$rc" -eq 0 ] && [ "$actual" = 42 ]; then
            pass "dependency ABI candidate"
        else
            fail "dependency ABI candidate" "exit=$rc output=$actual"
        fi
    fi

    rm -f "$out" "$lib"
    if run_freeze "$DLFREEZE" -o "$out" "$bin" >/dev/null 2>&1; then
        fail "missing dependency is fatal" "packaging unexpectedly succeeded"
    else
        pass "missing dependency is fatal"
    fi
    rm -rf "$good" "$bad"
    rm -f "$lib_src" "$main_src" "$bin" "$out"
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
    local root="$BUILD/vfs_negative_dot"
    local existing="$root/existing"
    local missing="$root/missing.txt"
    local probe="$existing/../missing.txt"
    local src="$BUILD/vfs_negative_dot.c"
    local bin="$BUILD/vfs_negative_dot"
    local out="$BUILD/vfs_negative_dot.frozen"
    local log="$BUILD/vfs_negative_dot.log"
    local actual rc=0 freeze_rc=0

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
# Test 4b: packer proves direct-main ownership or falls back cleanly
# ===================================================================
test_packer_main_detection() {
    echo "--- packer main detection ---"
    local pos_src="$BUILD/main_detect_positive.c"
    local neg_src="$BUILD/main_detect_opaque.c"
    local pos_bin="$BUILD/main_detect_positive"
    local neg_bin="$BUILD/main_detect_opaque"
    local pos_out="$BUILD/main_detect_positive.frozen"
    local neg_out="$BUILD/main_detect_opaque.frozen"
    local log="$BUILD/main_detect.log" size meta rc=0 freeze_rc=0

    cat > "$pos_src" <<'C'
int main(void) { return 37; }
C
    cat > "$neg_src" <<'C'
#include <unistd.h>
__attribute__((noreturn)) void opaque_start(void) { _exit(23); }
C

    gcc -O2 -o "$pos_bin" "$pos_src"
    gcc -O2 -nostartfiles -Wl,-e,opaque_start -o "$neg_bin" "$neg_src"
    strip --strip-all "$pos_bin" "$neg_bin"

    freeze_require_direct "packer stripped main detection" "$log" \
        "$pos_out" "$pos_bin" || freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "packer stripped main detection" "$DIRECT_FREEZE_REASON"
        skip "packer unknown-main fallback" \
            "runtime capability check precedes main detection"
        rm -f "$pos_src" "$neg_src" "$pos_bin" "$neg_bin" \
              "$pos_out" "$neg_out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$pos_src" "$neg_src" "$pos_bin" "$neg_bin" \
              "$pos_out" "$neg_out" "$log"
        return
    fi

    meta=$DIRECT_META_OFF
    rc=0
    run_with_timeout env DLFREEZE_NO_FORK=1 "$pos_out" \
        >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 37 ]; then
        pass "packer stripped main detection"
    else
        fail "packer stripped main detection" "meta=$meta exit=$rc"
    fi

    if ! run_freeze "$DLFREEZE" -d -o "$neg_out" "$neg_bin" >"$log" 2>&1; then
        fail "packer unknown-main fallback" "dlfreeze failed"
    else
        size=$(stat -c %s "$neg_out")
        meta=$(od -An -tu8 -j $((size - 24)) -N8 "$neg_out" |
            tr -d '[:space:]')
        rc=0
        run_with_timeout env DLFREEZE_NO_FORK=1 "$neg_out" >/dev/null 2>&1 || rc=$?
        if [[ "$meta" =~ ^[0-9]+$ ]] && [ "$meta" -eq 0 ] &&
           [ "$rc" -eq 23 ] &&
           grep -q 'cannot establish main address' "$log"; then
            pass "packer unknown-main fallback"
        else
            fail "packer unknown-main fallback" "meta=$meta exit=$rc"
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

    local pypath out="$BUILD/python3.frozen"
    pypath=$(readlink -f "$(command -v python3)")

    if ! run_freeze "$DLFREEZE" -v -t -o "$out" -- "$pypath" -c 'import json; print("ok")'; then
        fail "python3" "dlfreeze failed"; return
    fi

    # simple print
    local expect actual
    capture_output expect python3 -c 'print("Hello from Python!")'
    capture_output actual "$out" -c 'print("Hello from Python!")'
    if [ "$expect" = "$actual" ]; then pass "python3 print"; else
        fail "python3 print" "output differs"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    # math
    capture_output expect python3 -c 'import math; print(math.pi)'
    capture_output actual "$out" -c 'import math; print(math.pi)'
    if [ "$expect" = "$actual" ]; then pass "python3 math"; else
        fail "python3 math" "output differs"
    fi

    # json (pure-python module)
    capture_output expect python3 -c 'import json; print(json.dumps({"a":1}))'
    capture_output actual "$out" -c 'import json; print(json.dumps({"a":1}))'
    if [ "$expect" = "$actual" ]; then pass "python3 json"; else
        fail "python3 json" "output differs"
    fi

    rm -f "$out"
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
    local expect actual
    capture_output expect env LD_LIBRARY_PATH="$BUILD" "$prog"

    # Freeze with dlopen tracing — LD_LIBRARY_PATH is needed during trace
    if ! run_freeze env LD_LIBRARY_PATH="$BUILD" "$DLFREEZE" -v -t -o "$out" "$prog" \
            -- 2>&1; then
        fail "dlopen" "dlfreeze failed"; return
    fi

    # The frozen binary should work without LD_LIBRARY_PATH
    capture_output actual env -u LD_LIBRARY_PATH "$out"

    if [ "$expect" = "$actual" ]; then pass "dlopen (traced)"; else
        fail "dlopen (traced)" "output differs"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out"
}

# ===================================================================
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
    local expect actual
    capture_output expect "$prog"
    capture_output actual "$out"

    if [ "$expect" = "$actual" ]; then pass "dlopen fallback (system lib)"; else
        fail "dlopen fallback" "output differs"
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

    local pypath out="$BUILD/python3a.frozen"
    pypath=$(readlink -f "$(command -v python3)")

    # Trace with a broader import set
    if ! run_freeze "$DLFREEZE" -t -o "$out" -- "$pypath" -c \
         'import os,sys,json,hashlib,socket,ssl,sqlite3; print("traced")' 2>/dev/null; then
        fail "python3-adv" "dlfreeze failed"; return
    fi

    # os module
    local expect actual
    capture_output expect python3 -c 'import os; print(os.getpid.__name__)'
    capture_output actual "$out" -c 'import os; print(os.getpid.__name__)'
    if [ "$expect" = "$actual" ]; then pass "python3 os"; else
        fail "python3 os" "output differs: $expect vs $actual"; fi

    # hashlib
    capture_output expect python3 -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())'
    capture_output actual "$out" -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())'
    if [ "$expect" = "$actual" ]; then pass "python3 hashlib"; else
        fail "python3 hashlib" "output differs"; fi

    # sqlite3
    capture_output expect python3 -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])'
    capture_output actual "$out" -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])'
    if [ "$expect" = "$actual" ]; then pass "python3 sqlite3"; else
        fail "python3 sqlite3" "output differs: expected=$expect actual=$actual"; fi

    rm -f "$out"
}

# ===================================================================
# Test 8: direct-mode dlopen from frozen image (embedded loading)
# ===================================================================
test_direct_dlopen_embedded() {
    echo "--- direct dlopen (embedded) ---"
    local shlib_src="$BUILD/emb_lib.c"  shlib="$BUILD/libemb.so"
    local prog_src="$BUILD/use_emb.c"   prog="$BUILD/use_emb"
    local out="$BUILD/use_emb.frozen" log="$BUILD/use_emb.log"
    local freeze_rc=0
    rm -f "$log"

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
        rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
        return
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

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" "$log"
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
# Test 9g: reject executables and DF_1_NOOPEN objects in lazy loads
# ===================================================================
test_direct_dlopen_admission_flags() {
    echo "--- direct dlopen lazy-object admission ---"
    local root="$BUILD/dlopen_admission_flags"
    local noopen_src="$root/noopen.c" noopen="$root/libdlfrz_noopen.so"
    local pie_src="$root/pie.c" pie="$root/dlfrz-pie"
    local prog_src="$root/main.c" prog="$root/main"
    local out="$root/main.frozen" log="$root/main.log"
    local noopen_abs pie_abs noopen_native pie_native actual
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
    if ! gcc -shared -fPIC -Wl,-z,nodlopen \
            -Wl,-soname,libdlfrz_noopen.so -o "$noopen" "$noopen_src"; then
        skip "direct-dlopen lazy admission" "linker lacks -z nodlopen"
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
    pie_abs=$(realpath "$pie")
    cat > "$prog_src" <<C
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *kind;
    const char *path;
    if (argc != 2)
        return 10;
    if (strcmp(argv[1], "noopen") == 0) {
        kind = "noopen";
        path = "$noopen_abs";
    } else if (strcmp(argv[1], "pie") == 0) {
        kind = "pie";
        path = "$pie_abs";
    } else {
        return 11;
    }
    dlerror();
    void *handle = dlopen(path, RTLD_NOW);
    const char *error = handle ? NULL : dlerror();
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

    if [ "$native_noopen" -eq 0 ] && [ "$native_pie" -eq 0 ]; then
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
    local soname=""
    for cand in libm.so.6 libcrypt.so.2 libcrypto.so.3 libz.so.1; do
        for d in /lib /lib64 /usr/lib /usr/lib64 \
                 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu \
                 /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu; do
            if [ -e "$d/$cand" ]; then soname="$cand"; break; fi
        done
        [ -n "$soname" ] && break
    done
    if [ -z "$soname" ]; then
        skip "dlopen-soname-direct" "no system soname found"
        return
    fi

    local src="$BUILD/dlopen_soname.c" bin="$BUILD/dlopen_soname"
    local out="$BUILD/dlopen_soname.frozen" log="$BUILD/dlopen_soname.log"
    local freeze_rc=0
    rm -f "$log"
    cat > "$src" <<C
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlopen("$soname", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    printf("opened\n");
    return 0;
}
C
    gcc -o "$bin" "$src" -ldl

    freeze_require_direct "dlopen-soname-direct" "$log" "$out" "$bin" ||
        freeze_rc=$?
    if [ "$freeze_rc" -eq 77 ]; then
        skip "dlopen-soname-direct" "$DIRECT_FREEZE_REASON"
        rm -f "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$src" "$bin" "$out" "$log"
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
    rm -f "$src" "$bin" "$out" "$log"
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
    local good_out="$BUILD/special_version_good.frozen"
    local bad_out="$BUILD/special_version_bad.frozen"
    local good_log="$BUILD/special_version_good.log"
    local bad_log="$BUILD/special_version_bad.log"
    local label="special-symbol version admission direct-load"
    local actual rc=0 freeze_rc=0

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

    cp "$good" "$bad"
    rm -f "$dynstr"
    if ! objcopy --dump-section .dynstr="$dynstr" "$bad" 2>/dev/null ||
       ! sed -i 's/GOOD_1/FAKE_1/g' "$dynstr" ||
       ! objcopy --update-section .dynstr="$dynstr" "$bad" 2>/dev/null ||
       ! readelf -Wr "$bad" 2>/dev/null |
            grep 'memcpy@FAKE_1' >/dev/null; then
        fail "$label (forged)" "could not forge the version requirement"
        rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$bad" \
            "$dynstr" "$good_out" "$good_log"
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
        if [ "$rc" -eq 127 ] &&
           [[ "$actual" == *"unresolved relocation symbol: memcpy"* ]] &&
           [[ "$actual" != *"memcpy-version-ok"* ]]; then
            pass "$label (forged)"
        else
            fail "$label (forged)" "rc=$rc out=$actual"
        fi
    fi

    rm -f "$libsrc" "$map" "$src" "$lib" "$good" "$bad" "$dynstr" \
        "$good_out" "$bad_out" "$good_log" "$bad_log"
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
                "old register-flag fixture was not decoded safely"
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
    local missing_release_out="$BUILD/glibc_layout_release_missing.frozen"
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
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi
    if [ "$freeze_rc" -ne 0 ]; then
        rm -f "$helper" "$src" "$bin" "$out" "$log"
        return
    fi

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

    rm -f "$helper" "$src" "$bin" "$out" "$log"
}

# ===================================================================
echo "======== dlfreeze test suite ========"
echo "build dir: $BUILD"
echo ""

test_hello
test_musl_hello_direct
test_musl_ctor_direct
test_musl_copy_reloc_direct
test_musl_multibyte_direct
test_musl_shared_tls_direct
test_unknown_runtime_fallback
test_musl_layout_gate
test_glibc_layout_gate
test_glibc_stack_end_direct
test_glibc_private_exception_direct
test_exit_code
test_direct_handoff_once
test_direct_signal_forwarding
test_direct_pty_interaction
test_direct_fork_lifecycle
test_direct_exit_lifecycle
test_direct_constructor_signal
test_direct_preinit_order
test_direct_metadata_validation
test_aux_phdr_bounds_direct
test_static_tls_alignment_direct
test_nobits_tls_outside_load_direct
test_dependency_abi_validation
test_ls
test_cat
test_negative_dot_path_manifest
test_packer_main_detection
test_program_smoke_matrix
test_symlink_exe_identity_direct
test_dlopen_program
test_dlopen_fallback
test_python3
test_python3_advanced
test_direct_dlopen_embedded
test_direct_dlopen_deps
test_direct_dlopen_runpath_origin
test_direct_dlopen_path_delimiters
test_direct_dlopen_missing_needed
test_direct_dlopen_sibling_scope
test_direct_dlopen_bfs_scope
test_direct_dlopen_ifunc_data_order
test_direct_copy_ifunc_order
test_direct_dlopen_admission_flags
test_direct_dlopen_embedded_static_tls
test_direct_dlopen_startup_owned_ie
test_direct_dlopen_fallback
test_python3_direct
test_python_repl_pty_direct
test_glibc_tls_dtor_direct
test_ruby_direct_host_run
test_dlopen_soname_direct
test_dlopen_relpath_direct
test_dlmopen_direct
test_dlopen_tls_per_thread_direct
test_glibc_dtv_capacity_direct
test_direct_memory_protections
test_direct_symbol_definition_addresses
test_unsupported_relocation_direct
test_malformed_dynamic_bounds_direct
test_dlvsym_direct
test_dlsym_cache_key_lifetime_direct
test_dlsym_special_consistency_direct
test_dlsym_provider_admission_direct
test_versioned_relocation_direct
test_special_version_admission_direct
test_versioned_copy_relocation_direct

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
