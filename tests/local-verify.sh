#!/usr/bin/env bash
# Local helper: build, run tests, and reproduce Ruby/Python freeze behavior quickly.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build-host}"
RUN_SUITE=1
RUN_SMOKE=1
RUN_CROSS=1
CROSS_ARCH=""
CROSS_ENV=""

TEST_RUN_TIMEOUT="${TEST_RUN_TIMEOUT:-30}"
TEST_FREEZE_TIMEOUT="${TEST_FREEZE_TIMEOUT:-180}"
TEST_SUITE_TIMEOUT="${TEST_SUITE_TIMEOUT:-1200}"
TEST_TIMEOUT_KILL_AFTER="${TEST_TIMEOUT_KILL_AFTER:-5}"

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

run_suite() {
    run_with_timeout_seconds "$TEST_SUITE_TIMEOUT" "$@"
}

run_direct_data_smoke() {
    local label="$1" output="$2" target="$3" log rc=0
    shift 3

    log=$(mktemp)
    if run_freeze "$BUILD_DIR"/dlfreeze -d -t -f '/usr/*' \
            -o "$output" -- "$target" "$@" >"$log" 2>&1; then
        cat "$log"
        rm -f "$log"
        run_with_timeout "$output" "$@"
        return
    else
        rc=$?
    fi
    if grep -Eq \
            'requires a supported direct-load runtime|requires a supported direct-load mode' \
            "$log"; then
        echo "[local-verify] SKIP: $label — target runtime is not admitted for direct loading"
        rm -f "$log"
        return 0
    fi
    cat "$log" >&2
    rm -f "$log"
    return "$rc"
}

usage() {
    cat <<'EOF'
Usage: tests/local-verify.sh [options]

Options:
  --build-dir DIR        Build directory to use (default: build-host)
  --skip-suite           Skip tests/run_tests.sh
  --skip-smoke           Skip local Ruby/Python freeze smoke checks
  --skip-cross           Skip full cross-distro build/run matrix
  --cross-arch ARCH      Arch for cross matrix Docker platform (amd64|arm64)
  --cross-env NAME       Limit the matrix to one CI environment
  -h, --help             Show this help

Examples:
  tests/local-verify.sh
  tests/local-verify.sh --skip-suite --skip-cross
  tests/local-verify.sh --cross-arch arm64
  tests/local-verify.sh --cross-env ubuntu-24.04
  BUILD_DIR=build tests/local-verify.sh
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir)
            if [[ $# -lt 2 ]]; then
                echo "--build-dir requires a value" >&2
                usage >&2
                exit 2
            fi
            BUILD_DIR="$2"
            shift 2
            ;;
        --skip-suite)
            RUN_SUITE=0
            shift
            ;;
        --skip-smoke)
            RUN_SMOKE=0
            shift
            ;;
        --skip-cross)
            RUN_CROSS=0
            shift
            ;;
        --cross-arch)
            if [[ $# -lt 2 ]]; then
                echo "--cross-arch requires a value" >&2
                usage >&2
                exit 2
            fi
            CROSS_ARCH="$2"
            shift 2
            ;;
        --cross-env)
            if [[ $# -lt 2 ]]; then
                echo "--cross-env requires a value" >&2
                usage >&2
                exit 2
            fi
            CROSS_ENV="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

echo "[local-verify] build dir: $BUILD_DIR"
make BUILD="$BUILD_DIR" -j"$(nproc)"

if [[ "$RUN_SUITE" -eq 1 ]]; then
    echo "[local-verify] running full test suite"
    run_suite bash tests/run_tests.sh "$BUILD_DIR"
fi

if [[ "$RUN_SMOKE" -eq 1 ]]; then
    echo "[local-verify] Ruby gems-enabled freeze smoke"
    run_direct_data_smoke Ruby /tmp/ruby.local.frozen ruby -e 'puts 1+2'

    echo "[local-verify] Python freeze smoke"
    run_direct_data_smoke Python /tmp/python.local.frozen \
        python3 -c 'print(1+2)'
fi

if [[ "$RUN_CROSS" -eq 1 ]]; then
    echo "[local-verify] running full cross-distro matrix"
    matrix_args=()
    [[ -z "$CROSS_ARCH" ]] || matrix_args+=(--arch "$CROSS_ARCH")
    [[ -z "$CROSS_ENV" ]] || matrix_args+=(--env "$CROSS_ENV")
    bash tests/local-cross-matrix.sh "${matrix_args[@]}"
fi

echo "[local-verify] done"
