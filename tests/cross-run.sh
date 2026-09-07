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
RUN_TIMEOUT_KILL_AFTER="${RUN_TIMEOUT_KILL_AFTER:-5}"

run_with_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        if timeout --help 2>&1 | grep -- '--kill-after' >/dev/null; then
            timeout --kill-after="$RUN_TIMEOUT_KILL_AFTER" "$RUN_TIMEOUT" "$@"
        else
            timeout "$RUN_TIMEOUT" "$@"
        fi
    else
        "$@"
    fi
}

run_capture() {
    tmp=$(mktemp)
    set +e
    run_with_timeout "$@" >"$tmp" 2>&1
    rc=$?
    set -e
    cat "$tmp"
    rm -f "$tmp"
    return "$rc"
}

run_capture_stdout() {
    tmp=$(mktemp)
    set +e
    run_with_timeout "$@" >"$tmp" 2>/dev/null
    rc=$?
    set -e
    cat "$tmp"
    rm -f "$tmp"
    return "$rc"
}

run_quiet() {
    run_with_timeout "$@"
}

run_direct_contract() {
    contract_run_artifact=$1
    contract_run_expected=$2
    contract_run_label=$3
    contract_run_output=$(mktemp)
    contract_run_rc=0

    set +e
    run_with_timeout env DLFREEZE_NO_FORK=1 "$contract_run_artifact" \
        >"$contract_run_output" 2>&1
    contract_run_rc=$?
    set -e
    # Appending a non-newline sentinel before command substitution preserves
    # trailing newlines, while avoiding a dependency on cmp/diff in the bare
    # Fedora and Arch cross-run images.
    contract_run_expected_cmp=$(cat "$contract_run_expected"; printf .)
    contract_run_actual_cmp=$(cat "$contract_run_output"; printf .)

    if [ "$contract_run_rc" -eq 0 ] &&
       [ "$contract_run_expected_cmp" = "$contract_run_actual_cmp" ]; then
        pass "$contract_run_label"
    else
        fail "$contract_run_label" \
            "strict generic contract differs or rc=$contract_run_rc"
        contract_run_exp=$(cat "$contract_run_expected")
        contract_run_actual=$(cat "$contract_run_output")
        diagnose_failure "$contract_run_artifact" "$contract_run_exp" \
            "$contract_run_actual" env DLFREEZE_DEBUG=1 \
            DLFREEZE_NO_FORK=1 "$contract_run_artifact"
    fi
    rm -f "$contract_run_output"
}

artifact_info() {
    path="$1"

    echo "  artifact: $path"
    if command -v stat >/dev/null 2>&1; then
        stat -c '  stat: mode=%a size=%s mtime=%y' "$path" 2>/dev/null || true
    fi
    if command -v file >/dev/null 2>&1; then
        file "$path" 2>/dev/null | sed 's/^/  file: /' || true
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" 2>/dev/null | sed 's/^/  sha256: /' || true
    fi
}

diagnose_failure() {
    artifact="$1"
    expected="$2"
    actual="$3"
    shift 3

    artifact_info "$artifact"
    echo "  expected: $(printf '%s\n' "$expected" | head -3)"
    if [ -n "$actual" ]; then
        echo "  actual:"
        printf '%s\n' "$actual" | sed -n '1,20p' | sed 's/^/    /'
    else
        echo "  actual: <empty>"
    fi

    tmp=$(mktemp)
    set +e
    run_with_timeout "$@" >"$tmp" 2>&1
    dbg_rc=$?
    set -e
    echo "  debug retry rc=$dbg_rc (first 120 lines):"
    sed -n '1,120p' "$tmp" | sed 's/^/    /'
    rm -f "$tmp"
}

distro_name() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
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

if [ ! -d "$FROZEN_DIR" ]; then
    echo "ERROR: $FROZEN_DIR not found"
    exit 1
fi

# Each producer describes every distinct glibc/musl runtime it found in a
# small, non-executable status file.  A `direct` entry must have a generic C
# artifact and expectation; `unsupported` is an explicit capability result.
# The legacy environment-variable name is retained for workflow compatibility,
# but Python and Ruby artifacts are no longer part of this coverage contract.
require_direct_contracts=${DLFREEZE_REQUIRE_DIRECT_CONTRACTS:-${DLFREEZE_REQUIRE_RUNTIME_ARTIFACTS:-0}}
case "$require_direct_contracts" in
    0|1) ;;
    *)
        echo "ERROR: DLFREEZE_REQUIRE_DIRECT_CONTRACTS must be 0 or 1"
        exit 2
        ;;
esac
contract_source_count=0
contract_direct_total=0
contract_upx_total=0
contract_error=0
for src_dir in $FROZEN_GLOB; do
    [ -d "$src_dir" ] || continue
    contract_source_count=$((contract_source_count + 1))
    if [ ! -f "$src_dir/hello.frozen" ] ||
       [ ! -f "$src_dir/hello.expected" ]; then
        echo "ERROR: $src_dir lacks the mandatory hello artifact pair"
        contract_error=1
    fi
    if [ ! -f "$src_dir/exitcode.frozen" ]; then
        echo "ERROR: $src_dir lacks the mandatory exitcode artifact"
        contract_error=1
    fi
    contract_status="$src_dir/direct-contracts.v1"
    if [ ! -f "$contract_status" ]; then
        if [ "$require_direct_contracts" = 1 ]; then
            echo "ERROR: $src_dir has no generic direct-contract status"
            contract_error=1
        fi
        continue
    fi

    contract_runtime_count=0
    contract_seen_runtime=
    contract_version=
    contract_runtime=
    contract_state=
    contract_variant=
    contract_extra=
    while IFS='|' read -r contract_version contract_runtime \
            contract_state contract_variant contract_extra ||
          [ -n "$contract_version$contract_runtime$contract_state$contract_variant$contract_extra" ]; do
        contract_runtime_count=$((contract_runtime_count + 1))
        if [ "$contract_version" != 1 ] || [ -n "$contract_extra" ]; then
            echo "ERROR: malformed generic direct-contract entry in $contract_status"
            contract_error=1
            continue
        fi
        case "$contract_runtime" in
            ''|*[!a-z0-9_-]*)
                echo "ERROR: invalid runtime name in $contract_status: $contract_runtime"
                contract_error=1
                continue
                ;;
        esac
        case " $contract_seen_runtime " in
            *" $contract_runtime "*)
                echo "ERROR: duplicate runtime in $contract_status: $contract_runtime"
                contract_error=1
                continue
                ;;
        esac
        contract_seen_runtime="$contract_seen_runtime $contract_runtime"

        contract_artifact="$src_dir/direct-$contract_runtime.frozen"
        contract_expected="$src_dir/direct-$contract_runtime.expected"
        contract_upx="$src_dir/direct-$contract_runtime.upx.frozen"
        case "$contract_state|$contract_variant" in
            direct\|plain)
                contract_direct_total=$((contract_direct_total + 1))
                if [ ! -f "$contract_artifact" ] ||
                   [ ! -f "$contract_expected" ] ||
                   [ -e "$contract_upx" ]; then
                    echo "ERROR: $src_dir lacks its declared $contract_runtime direct contract"
                    contract_error=1
                fi
                ;;
            direct\|upx)
                contract_direct_total=$((contract_direct_total + 1))
                contract_upx_total=$((contract_upx_total + 1))
                if [ ! -f "$contract_artifact" ] ||
                   [ ! -f "$contract_expected" ] ||
                   [ ! -f "$contract_upx" ]; then
                    echo "ERROR: $src_dir lacks its declared $contract_runtime plain+UPX contract"
                    contract_error=1
                fi
                ;;
            unsupported\|none)
                if [ -e "$contract_artifact" ] ||
                   [ -e "$contract_expected" ] ||
                   [ -e "$contract_upx" ]; then
                    echo "ERROR: $src_dir published $contract_runtime artifacts while declaring it unsupported"
                    contract_error=1
                fi
                ;;
            *)
                echo "ERROR: invalid state in $contract_status: $contract_state|$contract_variant"
                contract_error=1
                ;;
        esac
    done < "$contract_status"
    if [ "$contract_runtime_count" -eq 0 ]; then
        echo "ERROR: $contract_status contains no runtime entries"
        contract_error=1
    fi
done

if [ "$contract_error" -ne 0 ]; then
    exit 1
fi
if [ "$contract_source_count" -eq 0 ]; then
    echo "ERROR: no frozen producer directories matched $FROZEN_GLOB"
    exit 1
fi
if [ "$require_direct_contracts" = 1 ]; then
    if [ "$contract_source_count" -eq 0 ] ||
       [ "$contract_direct_total" -eq 0 ] ||
       [ "$contract_upx_total" -eq 0 ]; then
        echo "ERROR: aggregate artifacts lack required generic direct coverage"
        echo "  sources=$contract_source_count direct=$contract_direct_total upx=$contract_upx_total"
        exit 1
    fi
fi

# ── Iterate over each source environment's frozen artifacts ────────
for src_dir in $FROZEN_GLOB; do
    [ -d "$src_dir" ] || continue
    src_env=$(basename "$src_dir")
    if [ ! -e "$src_dir/hello.frozen" ] \
        && [ ! -e "$src_dir/exitcode.frozen" ] \
        && [ ! -e "$src_dir/direct-contracts.v1" ] \
        && [ ! -e "$src_dir/python3.frozen" ] \
        && [ ! -e "$src_dir/ruby.frozen" ]; then
        echo "--- Source: $src_env ---"
        skip "$src_env" "no artifacts found"
        echo ""
        continue
    fi
    echo "--- Source: $src_env ---"

    # ── generic strict-direct contracts ─────────────────────────────
    contract_status="$src_dir/direct-contracts.v1"
    if [ -f "$contract_status" ]; then
        contract_version=
        contract_runtime=
        contract_state=
        contract_variant=
        contract_extra=
        while IFS='|' read -r contract_version contract_runtime \
                contract_state contract_variant contract_extra ||
              [ -n "$contract_version$contract_runtime$contract_state$contract_variant$contract_extra" ]; do
            # The validation pass above already checked version, spelling,
            # uniqueness, and file presence.
            if [ "$contract_state" = unsupported ]; then
                skip "$src_env/direct-$contract_runtime" \
                    "producer runtime was not admitted for direct loading"
                continue
            fi

            contract_artifact="$src_dir/direct-$contract_runtime.frozen"
            contract_expected="$src_dir/direct-$contract_runtime.expected"
            chmod +x "$contract_artifact" 2>/dev/null || true
            run_direct_contract "$contract_artifact" "$contract_expected" \
                "$src_env/direct-$contract_runtime.frozen"

            if [ "$contract_variant" = upx ]; then
                contract_upx="$src_dir/direct-$contract_runtime.upx.frozen"
                chmod +x "$contract_upx" 2>/dev/null || true
                run_direct_contract "$contract_upx" "$contract_expected" \
                    "$src_env/direct-$contract_runtime.upx.frozen"
            fi
        done < "$contract_status"
    elif [ "$require_direct_contracts" = 1 ]; then
        fail "$src_env/direct-contract" "status file not found"
    else
        skip "$src_env/direct-contract" "status file not found"
    fi

    # ── hello.frozen ───────────────────────────────────────────────
    frozen="$src_dir/hello.frozen"
    expected="$src_dir/hello.expected"
    if [ -f "$frozen" ] && [ -f "$expected" ]; then
        chmod +x "$frozen" 2>/dev/null || true
        rc=0
        actual=$(run_capture "$frozen" foo bar) || rc=$?
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
        actual=$(run_capture "$frozen_upx" foo bar) || rc=$?
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
        fail "$src_env/exitcode.frozen" "mandatory artifact not found"
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
        chmod +x "$frozen_py" 2>/dev/null || true
        rc=0
        actual=$(run_capture_stdout env DLFREEZE_NO_FORK=1 \
            "$frozen_py" -c 'print(1+2)') || rc=$?
        exp=$(cat "$expected_py")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/python3.frozen"
        else
            fail "$src_env/python3.frozen" "output differs or rc=$rc"
            diagnose_failure "$frozen_py" "$exp" "$actual" \
                env DLFREEZE_DEBUG=1 DLFREEZE_NO_FORK=1 \
                "$frozen_py" -c 'print(1+2)'
        fi
    else
        skip "$src_env/python3.frozen" "artifact not found"
    fi

    # ── python3.upx.frozen ─────────────────────────────────────────
    frozen_py_upx="$src_dir/python3.upx.frozen"
    if [ -f "$frozen_py_upx" ] && [ -f "$expected_py" ]; then
        chmod +x "$frozen_py_upx" 2>/dev/null || true
        rc=0
        actual=$(run_capture_stdout env DLFREEZE_NO_FORK=1 \
            "$frozen_py_upx" -c 'print(1+2)') || rc=$?
        exp=$(cat "$expected_py")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/python3.upx.frozen"
        else
            fail "$src_env/python3.upx.frozen" "output differs or rc=$rc"
            diagnose_failure "$frozen_py_upx" "$exp" "$actual" \
                env DLFREEZE_DEBUG=1 DLFREEZE_NO_FORK=1 \
                "$frozen_py_upx" -c 'print(1+2)'
        fi
    else
        skip "$src_env/python3.upx.frozen" "artifact or expectation not found"
    fi

    # ── ruby.frozen ────────────────────────────────────────────────
    frozen_rb="$src_dir/ruby.frozen"
    expected_rb="$src_dir/ruby.expected"
    if [ -f "$frozen_rb" ] && [ -f "$expected_rb" ]; then
        chmod +x "$frozen_rb" 2>/dev/null || true
        rc=0
        actual=$(run_capture_stdout env DLFREEZE_NO_FORK=1 \
            "$frozen_rb" -e 'puts 1+2') || rc=$?
        exp=$(cat "$expected_rb")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/ruby.frozen"
        else
            fail "$src_env/ruby.frozen" "output differs or rc=$rc"
            diagnose_failure "$frozen_rb" "$exp" "$actual" \
                env DLFREEZE_DEBUG=1 DLFREEZE_NO_FORK=1 \
                "$frozen_rb" -e 'puts 1+2'
        fi
    else
        skip "$src_env/ruby.frozen" "artifact not found"
    fi

    # ── ruby.upx.frozen ────────────────────────────────────────────
    frozen_rb_upx="$src_dir/ruby.upx.frozen"
    if [ -f "$frozen_rb_upx" ] && [ -f "$expected_rb" ]; then
        chmod +x "$frozen_rb_upx" 2>/dev/null || true
        rc=0
        actual=$(run_capture_stdout env DLFREEZE_NO_FORK=1 \
            "$frozen_rb_upx" -e 'puts 1+2') || rc=$?
        exp=$(cat "$expected_rb")
        if [ "$actual" = "$exp" ] && [ "$rc" -eq 0 ]; then
            pass "$src_env/ruby.upx.frozen"
        else
            fail "$src_env/ruby.upx.frozen" "output differs or rc=$rc"
            diagnose_failure "$frozen_rb_upx" "$exp" "$actual" \
                env DLFREEZE_DEBUG=1 DLFREEZE_NO_FORK=1 \
                "$frozen_rb_upx" -e 'puts 1+2'
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
