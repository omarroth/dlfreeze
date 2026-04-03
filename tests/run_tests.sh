#!/usr/bin/env bash
# dlfreeze test suite
set -euo pipefail

BUILD="${1:-build}"
DLFREEZE="$BUILD/dlfreeze"

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
        diff --color=auto <(echo "$expect") <(echo "$actual") | head -20 || true
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
        diff --color=auto <(echo "$expect") <(echo "$actual") | head -20 || true
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

    if ! "$DLFREEZE" -v -t -o "$out" "$pypath" -- -c 'import json; print("ok")'; then
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
    if ! "$DLFREEZE" -t -o "$out" "$pypath" -- -c \
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
echo "======== dlfreeze test suite ========"
echo "build dir: $BUILD"
echo ""

test_hello
test_exit_code
test_ls
test_cat
test_dlopen_program
test_dlopen_fallback
test_python3
test_python3_advanced

echo ""
echo "======== ${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}, ${YLW}$SKIP skipped${RST} ========"
[ "$FAIL" -eq 0 ]
