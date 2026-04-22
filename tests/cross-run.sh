#!/bin/sh
# tests/cross-run.sh — Run frozen binaries from every build environment and
# verify output.  Called inside Docker containers by the cross-platform CI
# workflow's cross-run job.
set -eu

# ── Colours ────────────────────────────────────────────────────────
RED=$(printf '\033[31m')
GRN=$(printf '\033[32m')
YLW=$(printf '\033[33m')
RST=$(printf '\033[0m')

PASS=0 FAIL=0 SKIP=0
pass() { echo "${GRN}PASS${RST}: $1"; PASS=$((PASS + 1)); }
fail() { echo "${RED}FAIL${RST}: $1 — $2"; FAIL=$((FAIL + 1)); }
skip() { echo "${YLW}SKIP${RST}: $1 — $2"; SKIP=$((SKIP + 1)); }

RUN_TIMEOUT="${RUN_TIMEOUT:-15}"

run_capture() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$RUN_TIMEOUT" "$@"
    else
        "$@"
    fi
}

run_quiet() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "$RUN_TIMEOUT" "$@"
    else
        "$@"
    fi
}

distro_name() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$PRETTY_NAME"
    else
        echo "unknown"
    fi
}

echo "========================================================"
echo "Cross-run: $(uname -m) | $(distro_name)"
echo "========================================================"
echo ""

FROZEN_DIR="${FROZEN_DIR:-/work/frozen-all}"
FROZEN_GLOB="${FROZEN_GLOB:-$FROZEN_DIR/frozen-*}"
IS_ALPINE_TARGET=0
if [ -f /etc/alpine-release ]; then
    IS_ALPINE_TARGET=1
fi

if [ ! -d "$FROZEN_DIR" ]; then
    echo "ERROR: $FROZEN_DIR not found"
    exit 1
fi

# ── Iterate over each source environment's frozen artifacts ────────
for src_dir in $FROZEN_GLOB; do
    [ -d "$src_dir" ] || continue
    src_env=$(basename "$src_dir")
    if [ ! -e "$src_dir/hello.frozen" ] \
        && [ ! -e "$src_dir/exitcode.frozen" ] \
        && [ ! -e "$src_dir/python3.frozen" ] \
        && [ ! -e "$src_dir/ruby.frozen" ]; then
        echo "--- Source: $src_env ---"
        skip "$src_env" "no artifacts found"
        echo ""
        continue
    fi
    echo "--- Source: $src_env ---"

    # ── hello.frozen ───────────────────────────────────────────────
    frozen="$src_dir/hello.frozen"
    expected="$src_dir/hello.expected"
    if [ -f "$frozen" ] && [ -f "$expected" ]; then
        chmod +x "$frozen" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen" foo bar 2>&1) || rc=$?
        exp=$(cat "$expected")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/hello.frozen"
        else
            fail "$src_env/hello.frozen" "output differs or rc=$rc"
            echo "  expected: $(echo "$exp" | head -3)"
            echo "  actual:   $(echo "$actual" | head -3)"
        fi
    else
        skip "$src_env/hello.frozen" "artifact not found"
    fi

    # ── hello.upx.frozen (UPX-compressed) ──────────────────────────
    frozen_upx="$src_dir/hello.upx.frozen"
    if [ -f "$frozen_upx" ] && [ -f "$expected" ]; then
        chmod +x "$frozen_upx" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen_upx" foo bar 2>&1) || rc=$?
        exp=$(cat "$expected")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/hello.upx.frozen"
        else
            fail "$src_env/hello.upx.frozen" "output differs or rc=$rc"
            echo "  expected: $(echo "$exp" | head -3)"
            echo "  actual:   $(echo "$actual" | head -3)"
        fi
    else
        skip "$src_env/hello.upx.frozen" "artifact or expectation not found"
    fi

    # ── exitcode.frozen ────────────────────────────────────────────
    frozen_ec="$src_dir/exitcode.frozen"
    if [ -f "$frozen_ec" ]; then
        chmod +x "$frozen_ec" 2>/dev/null || true

        # Test exit code 0
        rc=0
        run_quiet "$frozen_ec" 0 >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne 0 ]; then
            fail "$src_env/exitcode(0)" "expected rc=0, got rc=$rc"
        else
            # Test exit code 42
            rc=0
            run_quiet "$frozen_ec" 42 >/dev/null 2>&1 || rc=$?
            if [ "$rc" -eq 42 ]; then
                pass "$src_env/exitcode.frozen"
            else
                fail "$src_env/exitcode(42)" "expected rc=42, got rc=$rc"
            fi
        fi
    else
        skip "$src_env/exitcode.frozen" "artifact not found"
    fi

    # ── exitcode.upx.frozen ────────────────────────────────────────
    frozen_ec_upx="$src_dir/exitcode.upx.frozen"
    if [ -f "$frozen_ec_upx" ]; then
        chmod +x "$frozen_ec_upx" 2>/dev/null || true

        rc=0
        run_quiet "$frozen_ec_upx" 0 >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ne 0 ]; then
            fail "$src_env/exitcode.upx(0)" "expected rc=0, got rc=$rc"
        else
            rc=0
            run_quiet "$frozen_ec_upx" 42 >/dev/null 2>&1 || rc=$?
            if [ "$rc" -eq 42 ]; then
                pass "$src_env/exitcode.upx.frozen"
            else
                fail "$src_env/exitcode.upx(42)" "expected rc=42, got rc=$rc"
            fi
        fi
    else
        skip "$src_env/exitcode.upx.frozen" "UPX not available at build time"
    fi

    # ── python3.frozen ─────────────────────────────────────────────
    frozen_py="$src_dir/python3.frozen"
    expected_py="$src_dir/python3.expected"
    if [ -f "$frozen_py" ] && [ -f "$expected_py" ]; then
        if [ "$IS_ALPINE_TARGET" -eq 0 ] && echo "$src_env" | grep -q '^frozen-alpine-'; then
            skip "$src_env/python3.frozen" "alpine musl python cross-target on glibc is not yet supported"
        else
        chmod +x "$frozen_py" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen_py" -c 'print(1+2)' 2>&1) || rc=$?
        exp=$(cat "$expected_py")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/python3.frozen"
        else
            fail "$src_env/python3.frozen" "output differs or rc=$rc"
        fi
        fi
    else
        skip "$src_env/python3.frozen" "artifact not found"
    fi

    # ── python3.upx.frozen ─────────────────────────────────────────
    frozen_py_upx="$src_dir/python3.upx.frozen"
    if [ -f "$frozen_py_upx" ] && [ -f "$expected_py" ]; then
        if [ "$IS_ALPINE_TARGET" -eq 0 ] && echo "$src_env" | grep -q '^frozen-alpine-'; then
            skip "$src_env/python3.upx.frozen" "alpine musl python cross-target on glibc is not yet supported"
        else
        chmod +x "$frozen_py_upx" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen_py_upx" -c 'print(1+2)' 2>&1) || rc=$?
        exp=$(cat "$expected_py")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/python3.upx.frozen"
        else
            fail "$src_env/python3.upx.frozen" "output differs or rc=$rc"
        fi
        fi
    else
        skip "$src_env/python3.upx.frozen" "artifact or expectation not found"
    fi

    # ── ruby.frozen ────────────────────────────────────────────────
    frozen_rb="$src_dir/ruby.frozen"
    expected_rb="$src_dir/ruby.expected"
    if [ -f "$frozen_rb" ] && [ -f "$expected_rb" ]; then
        if [ "$IS_ALPINE_TARGET" -eq 0 ] && echo "$src_env" | grep -q '^frozen-alpine-'; then
            skip "$src_env/ruby.frozen" "alpine musl ruby cross-target on glibc is not yet supported"
        else
        chmod +x "$frozen_rb" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen_rb" -e 'puts 1+2' 2>&1) || rc=$?
        exp=$(cat "$expected_rb")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/ruby.frozen"
        else
            fail "$src_env/ruby.frozen" "output differs or rc=$rc"
        fi
        fi
    else
        skip "$src_env/ruby.frozen" "artifact not found"
    fi

    # ── ruby.upx.frozen ────────────────────────────────────────────
    frozen_rb_upx="$src_dir/ruby.upx.frozen"
    if [ -f "$frozen_rb_upx" ] && [ -f "$expected_rb" ]; then
        if [ "$IS_ALPINE_TARGET" -eq 0 ] && echo "$src_env" | grep -q '^frozen-alpine-'; then
            skip "$src_env/ruby.upx.frozen" "alpine musl ruby cross-target on glibc is not yet supported"
        else
        chmod +x "$frozen_rb_upx" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen_rb_upx" -e 'puts 1+2' 2>&1) || rc=$?
        exp=$(cat "$expected_rb")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/ruby.upx.frozen"
        else
            fail "$src_env/ruby.upx.frozen" "output differs or rc=$rc"
        fi
        fi
    else
        skip "$src_env/ruby.upx.frozen" "artifact or expectation not found"
    fi

    echo ""
done

echo "========================================================"
echo "${GRN}$PASS passed${RST}, ${RED}$FAIL failed${RST}, ${YLW}$SKIP skipped${RST}"
echo "========================================================"

[ "$FAIL" -eq 0 ]
