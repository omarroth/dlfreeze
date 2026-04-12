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

docker_usable() {
    command -v docker &>/dev/null && docker info >/dev/null 2>&1
}

docker_alpine_run() {
    local repo_root build_abs

    repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    build_abs=$(readlink -f "$BUILD")
    docker run --rm \
        -v "$repo_root":/work \
        -v "$build_abs":/dlfreeze-build \
        -w /work \
        alpine:3.20 sh -lc "$1"
}

    docker_alpine_edge_run() {
        local repo_root build_abs

        repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
        build_abs=$(readlink -f "$BUILD")
        docker run --rm \
        -v "$repo_root":/work \
        -v "$build_abs":/dlfreeze-build \
        -w /work \
        alpine:edge sh -lc "$1"
    }

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
# Test 1g: Alpine musl direct-load supports Python threading
# ===================================================================
test_alpine_python_thread_direct() {
    echo "--- alpine python thread direct-load ---"
    if ! docker_usable; then
        skip "alpine-python-thread-direct" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache python3 >/dev/null; /dlfreeze-build/dlfreeze -o /tmp/python312-thread.frozen -d -- python3 -c '\''import threading; out=[]; t=threading.Thread(target=lambda: out.append(7)); t.start(); t.join(); print(out[0])'\'' >/dev/null 2>&1; timeout 30 /tmp/python312-thread.frozen -c '\''import threading; out=[]; t=threading.Thread(target=lambda: out.append(7)); t.start(); t.join(); print(out[0])'\'''

    actual=$(docker_alpine_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "7" ]; then
        pass "alpine python thread direct-load"
    else
        fail "alpine python thread direct-load" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1h: Alpine musl direct-load supports Python sqlite fallback imports
# ===================================================================
test_alpine_python_sqlite_direct() {
    echo "--- alpine python sqlite direct-load ---"
    if ! docker_usable; then
        skip "alpine-python-sqlite-direct" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache python3 >/dev/null; /dlfreeze-build/dlfreeze -o /tmp/python312-sqlite.frozen -d -- python3 -c '\''import sqlite3; conn=sqlite3.connect(":memory:"); print(conn.execute("select 42").fetchone()[0])'\'' >/dev/null 2>&1; timeout 30 /tmp/python312-sqlite.frozen -c '\''import sqlite3; conn=sqlite3.connect(":memory:"); print(conn.execute("select 42").fetchone()[0])'\'' 2>/tmp/python312-sqlite.err'

    actual=$(docker_alpine_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "42" ]; then
        pass "alpine python sqlite direct-load"
    else
        fail "alpine python sqlite direct-load" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1i: Alpine edge musl direct-load supports Python cryptography imports
# ===================================================================
test_alpine_python_cryptography_direct() {
    echo "--- alpine python cryptography direct-load ---"
    if ! docker_usable; then
        skip "alpine-python-cryptography-direct" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache python3 py3-cryptography >/dev/null; printf "from cryptography.fernet import Fernet\nmsg = b\"hello\"\ncipher = Fernet(Fernet.generate_key())\nprint(cipher.decrypt(cipher.encrypt(msg)).decode())\n" > /tmp/crypt.py; /dlfreeze-build/dlfreeze -d -o /tmp/python314-crypt.frozen -- python3 /tmp/crypt.py >/dev/null 2>&1; timeout 60 /tmp/python314-crypt.frozen /tmp/crypt.py 2>/tmp/python314-crypt.err'

    actual=$(docker_alpine_edge_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "hello" ]; then
        pass "alpine python cryptography direct-load"
    else
        fail "alpine python cryptography direct-load" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1j: Alpine edge traced/data direct-load supports Python cryptography
# ===================================================================
test_alpine_python_cryptography_captured() {
    echo "--- alpine python cryptography traced direct-load ---"
    if ! docker_usable; then
        skip "alpine-python-cryptography-captured" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache python3 py3-cryptography strace >/dev/null; printf "from cryptography.fernet import Fernet\nmsg = b\"hello\"\ncipher = Fernet(Fernet.generate_key())\nprint(cipher.decrypt(cipher.encrypt(msg)).decode())\n" > /tmp/crypt.py; /dlfreeze-build/dlfreeze -d -t -f "/usr/*" -o /tmp/python314-crypt-vfs.frozen -- python3 /tmp/crypt.py >/dev/null 2>&1; timeout 60 /tmp/python314-crypt-vfs.frozen /tmp/crypt.py'

    actual=$(docker_alpine_edge_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "hello" ]; then
        pass "alpine python cryptography traced direct-load"
    else
        fail "alpine python cryptography traced direct-load" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1k: Alpine musl extracted mode preserves clang self-reexec helpers
# ===================================================================
test_alpine_clang_compile() {
    echo "--- alpine clang compile ---"
    if ! docker_usable; then
        skip "alpine-clang-compile" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache clang17 build-base >/dev/null; printf "int main(void){return 0;}\n" > /tmp/hello.c; /dlfreeze-build/dlfreeze -o /tmp/clang17.frozen -- $(command -v clang-17) >/dev/null 2>&1; timeout 45 /tmp/clang17.frozen /tmp/hello.c -o /tmp/hello; /tmp/hello; echo ok'

    actual=$(docker_alpine_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "ok" ]; then
        pass "alpine clang compile"
    else
        fail "alpine clang compile" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1l: Alpine edge musl direct-load supports clang21 compilation
# ===================================================================
test_alpine_clang_direct_compile() {
    echo "--- alpine clang direct compile ---"
    if ! docker_usable; then
        skip "alpine-clang-direct-compile" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache clang21 build-base >/dev/null; printf "#include <stdio.h>\nint main(void){puts(\"ok\");return 0;}\n" > /tmp/hello.c; /dlfreeze-build/dlfreeze -d -o /tmp/clang21d.frozen -- $(command -v clang-21) >/dev/null 2>&1; timeout 45 /tmp/clang21d.frozen /tmp/hello.c -o /tmp/hello; /tmp/hello'

    actual=$(docker_alpine_edge_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "ok" ]; then
        pass "alpine clang direct compile"
    else
        fail "alpine clang direct compile" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
}

# ===================================================================
# Test 1m: Alpine edge captures linker archives via -f tracing
# ===================================================================
test_alpine_clang_captured_static_libs() {
    echo "--- alpine clang captured static libs ---"
    if ! docker_usable; then
        skip "alpine-clang-captured-static-libs" "docker unavailable"
        return
    fi

    local script actual rc=0
    script='set -e; apk add --no-cache clang21 build-base strace >/dev/null; printf "#include <stdio.h>\nint main(void){puts(\"ok\");return 0;}\n" > /tmp/hello.c; /dlfreeze-build/dlfreeze -d -t -f "/usr/*" -o /tmp/clang21vfs.frozen -- $(command -v clang-21) /tmp/hello.c -o /tmp/hello.freeze >/dev/null 2>&1; rm -f /tmp/hello.freeze; mv /usr/lib/libssp_nonshared.a /tmp/libssp_nonshared.a.hide; trap "mv /tmp/libssp_nonshared.a.hide /usr/lib/libssp_nonshared.a" EXIT; timeout 45 /tmp/clang21vfs.frozen -resource-dir /usr/lib/llvm21/lib/clang/21 /tmp/hello.c -o /tmp/hello; /tmp/hello'

    actual=$(docker_alpine_edge_run "$script" 2>&1) || rc=$?
    if [ "$rc" = 0 ] && [ "$actual" = "ok" ]; then
        pass "alpine clang captured static libs"
    else
        fail "alpine clang captured static libs" "output or exit code differs (exit $rc)"
        echo "  actual: $actual"
    fi
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
echo "======== dlfreeze test suite ========"
echo "build dir: $BUILD"
echo ""

test_hello
test_musl_hello_direct
test_musl_ctor_direct
test_musl_copy_reloc_direct
test_musl_multibyte_direct
test_musl_shared_tls_direct
test_alpine_python_thread_direct
test_alpine_python_sqlite_direct
test_alpine_python_cryptography_direct
test_alpine_python_cryptography_captured
test_alpine_clang_compile
test_alpine_clang_direct_compile
test_alpine_clang_captured_static_libs
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

echo ""
echo "======== ${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}, ${YLW}$SKIP skipped${RST} ========"
[ "$FAIL" -eq 0 ]
