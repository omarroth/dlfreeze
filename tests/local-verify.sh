#!/usr/bin/env bash
# Local helper: build, run tests, and reproduce Ruby/Python freeze behavior quickly.
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build-host}"
RUN_SUITE=1
RUN_SMOKE=1
RUN_CROSS=1
CROSS_ARCH=""

usage() {
    cat <<'EOF'
Usage: tests/local-verify.sh [options]

Options:
  --build-dir DIR        Build directory to use (default: build-host)
  --skip-suite           Skip tests/run_tests.sh
  --skip-smoke           Skip local Ruby/Python freeze smoke checks
    --skip-cross           Skip full cross-distro build/run matrix
    --cross-arch ARCH      Arch for cross matrix docker platform (amd64|arm64)
  --ubuntu24             Also run Ubuntu 24.04 Ruby smoke repro in Docker
  -h, --help             Show this help

Examples:
  tests/local-verify.sh
    tests/local-verify.sh --skip-suite --skip-cross --ubuntu24
    tests/local-verify.sh --cross-arch arm64
  BUILD_DIR=build tests/local-verify.sh
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir)
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
            CROSS_ARCH="$2"
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
    bash tests/run_tests.sh "$BUILD_DIR"
fi

if [[ "$RUN_SMOKE" -eq 1 ]]; then
    echo "[local-verify] Ruby gems-enabled freeze smoke"
    "$BUILD_DIR"/dlfreeze -t -f '/usr/*' -o /tmp/ruby.local.frozen -- ruby -e 'puts 1+2'
    /tmp/ruby.local.frozen -e 'puts 1+2'

    echo "[local-verify] Python freeze smoke"
    "$BUILD_DIR"/dlfreeze -t -f '/usr/*' -o /tmp/python.local.frozen -- python3 -c 'print(1+2)'
    /tmp/python.local.frozen -c 'print(1+2)'
fi

if [[ "$RUN_CROSS" -eq 1 ]]; then
    echo "[local-verify] running full cross-distro matrix"
    if [[ -n "$CROSS_ARCH" ]]; then
        ARCH="$CROSS_ARCH" bash tests/local-cross-matrix.sh
    else
        bash tests/local-cross-matrix.sh
    fi
fi

echo "[local-verify] done"
