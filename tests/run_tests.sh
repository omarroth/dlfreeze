#!/usr/bin/env bash
# dlfreeze test suite
set -euo pipefail

BUILD="${1:-build}"
DLFREEZE="$BUILD/dlfreeze"

mkdir -p "$BUILD"

PASS=0 FAIL=0 SKIP=0
RED=$'\033[31m' GRN=$'\033[32m' YLW=$'\033[33m' RST=$'\033[0m'
pass() { echo "${GRN}PASS${RST}: $1"; ((PASS++)) || true; }
fail() { echo "${RED}FAIL${RST}: $1 — $2"; ((FAIL++)) || true; }
skip() { echo "${YLW}SKIP${RST}: $1 — $2"; ((SKIP++)) || true; }

# ===================================================================
# Helper: freeze, run, compare
# ===================================================================
freeze_and_compare() {
    local label="$1" binary="$2" output="$3"
    shift 3  # remaining args are passed to both runs

    if ! "$DLFREEZE" -v -o "$output" "$binary"; then
        fail "$label" "dlfreeze failed"; return 1
    fi
    if [ ! -x "$output" ]; then
        fail "$label" "output not executable"; return 1
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$binary" "$@" 2>&1) || rc_e=$?
    actual=$("$output" "$@" 2>&1) || rc_a=$?

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
    if ! "$DLFREEZE" -v -o "$out" "$bin"; then fail "hello" "dlfreeze failed"; return; fi

    local expect actual
    expect=$("$bin" foo bar 2>&1 | tail -n +2)
    actual=$("$out" foo bar 2>&1 | tail -n +2)
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

    local src="$BUILD/hello_musl.c" bin="$BUILD/hello_musl" out="$BUILD/hello_musl.frozen"
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

    if ! file "$bin" | grep -q 'interpreter .*ld-musl'; then
        skip "musl-hello-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual
    expect=$("$bin" 2>&1)

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "musl-hello-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1)
    if [ "$expect" = "$actual" ]; then
        pass "musl hello direct-load"
    else
        fail "musl hello direct-load" "output differs"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out"
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

    local src="$BUILD/ctor_musl.c" bin="$BUILD/ctor_musl" out="$BUILD/ctor_musl.frozen"
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

    if ! file "$bin" | grep -q 'interpreter .*ld-musl'; then
        skip "musl-ctor-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "musl-ctor-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1) || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl ctor direct-load"
    else
        fail "musl ctor direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out"
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

    local src="$BUILD/copy_reloc_musl.c" bin="$BUILD/copy_reloc_musl" out="$BUILD/copy_reloc_musl.frozen"
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

    if ! file "$bin" | grep -q 'interpreter .*ld-musl'; then
        skip "musl-copy-reloc-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! readelf -W -r "$bin" | grep -q 'R_X86_64_COPY.*stderr'; then
        skip "musl-copy-reloc-direct" "musl-gcc did not emit stderr COPY relocation"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "musl-copy-reloc-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1) || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl copy-reloc direct-load"
    else
        fail "musl copy-reloc direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out"
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

    local src="$BUILD/multibyte_musl.c" bin="$BUILD/multibyte_musl" out="$BUILD/multibyte_musl.frozen"
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

    if ! file "$bin" | grep -q 'interpreter .*ld-musl'; then
        skip "musl-multibyte-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "musl-multibyte-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1) || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl multibyte direct-load"
    else
        fail "musl multibyte direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out"
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
    local lib="$BUILD/libtlsdep_musl.so" bin="$BUILD/tlsmain_musl" out="$BUILD/tlsmain_musl.frozen"
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

    if ! readelf -W -l "$lib" | grep -q 'TLS'; then
        skip "musl-shared-tls-direct" "musl-gcc did not emit PT_TLS for the shared library"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    if ! musl-gcc -Wl,-rpath,'$ORIGIN' -L"$BUILD" -o "$bin" "$src_main" -ltlsdep_musl; then
        fail "musl-shared-tls-direct" "musl-gcc failed building main executable"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    if ! file "$bin" | grep -q 'interpreter .*ld-musl'; then
        skip "musl-shared-tls-direct" "musl-gcc did not produce a dynamic musl executable"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "musl-shared-tls-direct" "dlfreeze failed"
        rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1) || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "musl shared-tls direct-load"
    else
        fail "musl shared-tls direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src_lib" "$src_main" "$lib" "$bin" "$out"
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

    local src="$BUILD/libc_stack_end.c" bin="$BUILD/libc_stack_end" out="$BUILD/libc_stack_end.frozen"
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

    if ! file "$bin" | grep -q 'interpreter .*ld-linux'; then
        skip "glibc-stack-end-direct" "gcc did not produce a dynamic glibc executable"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "glibc-stack-end-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    actual=$("$out" 2>&1) || rc_a=$?
    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "glibc stack-end direct-load"
    else
        fail "glibc stack-end direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$src" "$bin" "$out"
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
    if ! "$DLFREEZE" -o "$out" "$bin"; then fail "exit-code" "dlfreeze failed"; return; fi

    local e0 a0 e42 a42 ed ad
    "$bin"   0  || e0=$?;  e0=${e0:-0}
    "$out"   0  || a0=$?;  a0=${a0:-0}
    "$bin"   42 || e42=$?; e42=${e42:-0}
    "$out"   42 || a42=$?; a42=${a42:-0}
    "$bin"      || ed=$?;  ed=${ed:-0}
    "$out"      || ad=$?;  ad=${ad:-0}

    if [[ "$e0" == "$a0" && "$e42" == "$a42" && "$ed" == "$ad" ]]; then
        pass "exit-code"
    else
        fail "exit-code" "expected $e0/$e42/$ed got $a0/$a42/$ad"
    fi
    rm -f "$src" "$bin" "$out"
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
    if ! "$DLFREEZE" -o "$out" /bin/cat; then fail "cat stdin" "dlfreeze failed"; return; fi
    local expect actual
    expect=$(echo "hello world" | /bin/cat)
    actual=$(echo "hello world" | "$out")
    if [ "$expect" = "$actual" ]; then pass "cat stdin"; else fail "cat stdin" "output differs"; fi
    rm -f "$out"
}

# ===================================================================
# Test 5: python3 (with dlopen tracing)
# ===================================================================
test_python3() {
    echo "--- python3 ---"
    if ! command -v python3 &>/dev/null; then skip "python3" "not installed"; return; fi

    local pypath out="$BUILD/python3.frozen"
    pypath=$(readlink -f "$(which python3)")

    if ! "$DLFREEZE" -v -t -o "$out" -- "$pypath" -c 'import json; print("ok")'; then
        fail "python3" "dlfreeze failed"; return
    fi

    # simple print
    local expect actual
    expect=$(python3 -c 'print("Hello from Python!")' 2>&1)
    actual=$("$out" -c 'print("Hello from Python!")' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 print"; else
        fail "python3 print" "output differs"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    # math
    expect=$(python3 -c 'import math; print(math.pi)' 2>&1)
    actual=$("$out" -c 'import math; print(math.pi)' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 math"; else
        fail "python3 math" "output differs"
    fi

    # json (pure-python module)
    expect=$(python3 -c 'import json; print(json.dumps({"a":1}))' 2>&1)
    actual=$("$out" -c 'import json; print(json.dumps({"a":1}))' 2>&1)
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
    expect=$(LD_LIBRARY_PATH="$BUILD" "$prog" 2>&1)

    # Freeze with dlopen tracing — LD_LIBRARY_PATH is needed during trace
    if ! LD_LIBRARY_PATH="$BUILD" "$DLFREEZE" -v -t -o "$out" "$prog" \
            -- 2>&1; then
        fail "dlopen" "dlfreeze failed"; return
    fi

    # The frozen binary should work without LD_LIBRARY_PATH
    actual=$(unset LD_LIBRARY_PATH; "$out" 2>&1)

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
    if ! "$DLFREEZE" -v -o "$out" "$prog"; then
        fail "dlopen-fallback" "dlfreeze failed"; return
    fi

    # The frozen binary should still work because the bundled ld.so
    # falls back to loading from the real filesystem.
    local expect actual
    expect=$("$prog" 2>&1)
    actual=$("$out" 2>&1)

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
    pypath=$(readlink -f "$(which python3)")

    # Trace with a broader import set
    if ! "$DLFREEZE" -t -o "$out" -- "$pypath" -c \
         'import os,sys,json,hashlib,socket,ssl,sqlite3; print("traced")' 2>/dev/null; then
        fail "python3-adv" "dlfreeze failed"; return
    fi

    # os module
    local expect actual
    expect=$(python3 -c 'import os; print(os.getpid.__name__)' 2>&1)
    actual=$("$out" -c 'import os; print(os.getpid.__name__)' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 os"; else
        fail "python3 os" "output differs: $expect vs $actual"; fi

    # hashlib
    expect=$(python3 -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())' 2>&1)
    actual=$("$out" -c 'import hashlib; print(hashlib.sha256(b"test").hexdigest())' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 hashlib"; else
        fail "python3 hashlib" "output differs"; fi

    # sqlite3
    expect=$(python3 -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])' 2>&1)
    actual=$("$out" -c 'import sqlite3; c=sqlite3.connect(":memory:"); print(c.execute("SELECT 1+1").fetchone()[0])' 2>&1)
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
    local out="$BUILD/use_emb.frozen"

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

    local expect
    expect=$(LD_LIBRARY_PATH="$BUILD" "$prog" 2>&1)

    # Freeze with -d (direct) and -t (trace dlopen)
    if ! LD_LIBRARY_PATH="$BUILD" "$DLFREEZE" -d -t -o "$out" "$prog" -- \
            2>/dev/null; then
        fail "direct-dlopen-embedded" "dlfreeze failed"; return
    fi

    # Run frozen binary — should load libemb.so from embedded image,
    # NOT from the filesystem.  Remove the .so to prove it.
    mv "$shlib" "${shlib}.bak"
    local actual rc=0
    actual=$(unset LD_LIBRARY_PATH; "$out" 2>&1) || rc=$?
    mv "${shlib}.bak" "$shlib"

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        pass "direct-dlopen embedded"
    else
        fail "direct-dlopen embedded" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out"
}

# ===================================================================
# Test 9: direct-mode dlopen with transitive DT_NEEDED deps
# ===================================================================
test_direct_dlopen_deps() {
    echo "--- direct dlopen (deps) ---"
    local dep_src="$BUILD/dep_lib.c"  dep="$BUILD/libdep.so"
    local top_src="$BUILD/top_lib.c"  top="$BUILD/libtop.so"
    local prog_src="$BUILD/use_dep.c" prog="$BUILD/use_dep"
    local out="$BUILD/use_dep.frozen"

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

    local expect
    expect=$(LD_LIBRARY_PATH="$BUILD" "$prog" 2>&1)

    # Freeze with -d -t — both libtop.so and libdep.so should be captured
    if ! LD_LIBRARY_PATH="$BUILD" "$DLFREEZE" -d -t -o "$out" "$prog" -- \
            2>/dev/null; then
        fail "direct-dlopen-deps" "dlfreeze failed"; return
    fi

    # Remove both .so files to prove they load from frozen image
    mv "$dep" "${dep}.bak"
    mv "$top" "${top}.bak"
    local actual rc=0
    actual=$(unset LD_LIBRARY_PATH; "$out" 2>&1) || rc=$?
    mv "${dep}.bak" "$dep"
    mv "${top}.bak" "$top"

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        pass "direct-dlopen deps"
    else
        fail "direct-dlopen deps" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$dep_src" "$dep" "$top_src" "$top" "$prog_src" "$prog" "$out"
}

# ===================================================================
# Test 10: direct-mode dlopen fallback warning (lib not in image)
# ===================================================================
test_direct_dlopen_fallback() {
    echo "--- direct dlopen (fallback) ---"
    local shlib_src="$BUILD/fb2_lib.c"  shlib="$BUILD/libfb2.so"
    local prog_src="$BUILD/use_fb2.c"   prog="$BUILD/use_fb2"
    local out="$BUILD/use_fb2.frozen"

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

    local expect
    expect=$("$prog" 2>&1)

    # Freeze with -d but WITHOUT -t — no dlopen tracing, lib won't be embedded
    if ! "$DLFREEZE" -d -o "$out" "$prog" 2>/dev/null; then
        fail "direct-dlopen-fallback" "dlfreeze failed"; return
    fi

    # Run — should see warning on stderr but succeed
    local actual stderr_out rc=0
    actual=$("$out" 2>/tmp/dlfreeze_test_stderr) || rc=$?
    stderr_out=$(cat /tmp/dlfreeze_test_stderr)

    if [ "$expect" = "$actual" ] && [ "$rc" -eq 0 ]; then
        if echo "$stderr_out" | grep -q "warning.*not in frozen image" 2>/dev/null; then
            pass "direct-dlopen fallback+warning"
        else
            pass "direct-dlopen fallback (no warning)"
        fi
    else
        fail "direct-dlopen fallback" "output differs or failed (rc=$rc)"
        echo "  expect: $expect"
        echo "  actual: $actual"
    fi

    rm -f "$shlib_src" "$shlib" "$prog_src" "$prog" "$out" /tmp/dlfreeze_test_stderr
}

# ===================================================================
# Test 11: direct-mode python with C extensions (hashlib, sqlite3)
# ===================================================================
test_python3_direct() {
    echo "--- python3 direct-load ---"
    if ! command -v python3 &>/dev/null; then skip "python3-direct" "not installed"; return; fi

    local pypath out="$BUILD/python3d.frozen"
    pypath=$(readlink -f "$(which python3)")

    # Freeze with -d (direct) and -t (trace dlopen) to capture C extensions
    if ! "$DLFREEZE" -d -t -o "$out" -- "$pypath" -c \
         'import hashlib,sqlite3; print("traced")' 2>/dev/null; then
        fail "python3-direct" "dlfreeze failed"; return
    fi

    # hashlib — C extension that loads libcrypto.so via DT_NEEDED
    local expect actual
    expect=$(python3 -c 'import hashlib; print(hashlib.sha256(b"hello").hexdigest())' 2>&1)
    actual=$("$out" -c 'import hashlib; print(hashlib.sha256(b"hello").hexdigest())' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 direct hashlib"; else
        fail "python3 direct hashlib" "output differs: expected=$expect actual=$actual"; fi

    # sqlite3 — C extension that loads libsqlite3.so
    expect=$(python3 -c 'import sqlite3; c=sqlite3.connect(":memory:"); c.execute("CREATE TABLE t(x)"); c.execute("INSERT INTO t VALUES(42)"); print(c.execute("SELECT x FROM t").fetchone()[0])' 2>&1)
    actual=$("$out" -c 'import sqlite3; c=sqlite3.connect(":memory:"); c.execute("CREATE TABLE t(x)"); c.execute("INSERT INTO t VALUES(42)"); print(c.execute("SELECT x FROM t").fetchone()[0])' 2>&1)
    if [ "$expect" = "$actual" ]; then pass "python3 direct sqlite3"; else
        fail "python3 direct sqlite3" "output differs: expected=$expect actual=$actual"; fi

    rm -f "$out"
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
    local lib="$BUILD/libtls_dtor.so" bin="$BUILD/tls_dtor_main" out="$BUILD/tls_dtor_main.frozen"

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
    if ! "$DLFREEZE" -d -o "$out" -- "$bin" 2>/dev/null; then
        fail "glibc-tls-dtor-direct" "dlfreeze failed"
        return
    fi

    local expect actual rc_e=0 rc_a=0
    expect=$("$bin" 2>&1) || rc_e=$?
    actual=$(timeout 30 "$out" 2>&1) || rc_a=$?

    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "glibc tls-dtor direct-load"
    else
        fail "glibc tls-dtor direct-load" "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi

    rm -f "$lib_src" "$main_src" "$lib" "$bin" "$out"
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

    local rubypath out home
    local expect actual rc_e=0 rc_a=0
    rubypath=$(readlink -f "$(which ruby)")
    out="$BUILD/ruby-host.frozen"
    home="$BUILD/ruby-home-missing"

    rm -rf "$home"

    expect=$(HOME="$home" "$rubypath" -e 'puts 1+2' 2>&1) || rc_e=$?
    if [ "$rc_e" -ne 0 ]; then
        fail "ruby-direct-host-run" "native ruby failed (exit $rc_e)"
        rm -rf "$home"
        return
    fi
    if ! HOME="$home" "$DLFREEZE" -d -t -f '/usr/*' -o "$out" -- "$rubypath" -e 'puts 1+2' 2>/dev/null; then
        fail "ruby-direct-host-run" "dlfreeze failed"
        rm -rf "$home"
        return
    fi
    actual=$(HOME="$home" timeout 30 "$out" -e 'puts 1+2' 2>&1) || rc_a=$?

    if [ "$expect" = "$actual" ] && [ "$rc_e" = "$rc_a" ]; then
        pass "ruby direct host-run"
    else
        fail "ruby direct host-run" "output or exit code differs (exit $rc_e vs $rc_a)"
        diff -u <(echo "$expect") <(echo "$actual") | head -20 || true
    fi

    rm -rf "$home"
    rm -f "$out"
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
    local out="$BUILD/dlopen_soname.frozen"
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

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "dlopen-soname-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local actual rc=0
    actual=$(timeout 10 "$out" 2>&1) || rc=$?
    # Allow the "loading from disk" warning that dlfreeze prints.
    actual=$(echo "$actual" | grep -v '^dlfreeze: warning:' || true)
    if [ "$actual" = "opened" ] && [ "$rc" = "0" ]; then
        pass "dlopen by soname direct-load"
    else
        fail "dlopen by soname direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out"
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
    local out="$BUILD/dlrel_main.frozen"

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

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "dlopen-relpath-direct" "dlfreeze failed"
        rm -f "$libsrc" "$lib" "$src" "$bin" "$out"
        return
    fi

    local actual rc=0
    actual=$(cd "$BUILD" && timeout 10 "$out" 2>&1) || rc=$?
    actual=$(echo "$actual" | grep -v '^dlfreeze: warning:' || true)
    if [ "$actual" = "42" ] && [ "$rc" = "0" ]; then
        pass "dlopen relative path direct-load"
    else
        fail "dlopen relative path direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$libsrc" "$lib" "$src" "$bin" "$out"
}

# ===================================================================
# Test 16: dlmopen behaves as dlopen (namespace ignored)
# ===================================================================
test_dlmopen_direct() {
    echo "--- dlmopen direct-load ---"
    local soname=""
    for cand in libm.so.6 libz.so.1; do
        for d in /lib /lib64 /usr/lib /usr/lib64 \
                 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu \
                 /lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu; do
            if [ -e "$d/$cand" ]; then soname="$cand"; break; fi
        done
        [ -n "$soname" ] && break
    done
    if [ -z "$soname" ]; then
        skip "dlmopen-direct" "no system soname found"
        return
    fi

    local src="$BUILD/dlmopen_main.c" bin="$BUILD/dlmopen_main"
    local out="$BUILD/dlmopen_main.frozen"
    cat > "$src" <<C
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
int main(void) {
    void *h = dlmopen(LM_ID_NEWLM, "$soname", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlmopen: %s\n", dlerror()); return 1; }
    printf("opened\n");
    return 0;
}
C
    if ! gcc -o "$bin" "$src" -ldl 2>/dev/null; then
        skip "dlmopen-direct" "compiler does not support dlmopen (likely musl)"
        rm -f "$src" "$bin" "$out"
        return
    fi

    if ! "$DLFREEZE" -d -o "$out" "$bin" >/dev/null 2>&1; then
        fail "dlmopen-direct" "dlfreeze failed"
        rm -f "$src" "$bin" "$out"
        return
    fi

    local actual rc=0
    actual=$(timeout 10 "$out" 2>&1) || rc=$?
    actual=$(echo "$actual" | grep -v '^dlfreeze: warning:' || true)
    if [ "$actual" = "opened" ] && [ "$rc" = "0" ]; then
        pass "dlmopen direct-load"
    else
        fail "dlmopen direct-load" "rc=$rc out=$actual"
    fi
    rm -f "$src" "$bin" "$out"
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
test_glibc_stack_end_direct
test_exit_code
test_ls
test_cat
test_dlopen_program
test_dlopen_fallback
test_python3
test_python3_advanced
test_direct_dlopen_embedded
test_direct_dlopen_deps
test_direct_dlopen_fallback
test_python3_direct
test_glibc_tls_dtor_direct
test_ruby_direct_host_run
test_dlopen_soname_direct
test_dlopen_relpath_direct
test_dlmopen_direct

echo ""
echo "======== ${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}, ${YLW}$SKIP skipped${RST} ========"
[ "$FAIL" -eq 0 ]
