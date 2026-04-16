#!/usr/bin/env bash
# Run CI-like cross matrix locally:
# 1) Build artifacts in each distro image
# 2) Run every source artifact set on every target distro image
set -euo pipefail

ARCH="${ARCH:-}"
DO_BUILD=1
DO_RUN=1

usage() {
    cat <<'EOF'
Usage: tests/local-cross-matrix.sh [options]

Options:
  --arch ARCH            Target architecture for Docker platform (amd64|arm64)
  --build-only           Only build artifacts in each distro image
  --run-only             Only run cross-run matrix (expects frozen-all populated)
  -h, --help             Show this help

Examples:
  tests/local-cross-matrix.sh
  tests/local-cross-matrix.sh --arch arm64
  tests/local-cross-matrix.sh --build-only
EOF
}

if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported host arch: $(uname -m). Use --arch." >&2; exit 2 ;;
    esac
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --build-only)
            DO_BUILD=1
            DO_RUN=0
            shift
            ;;
        --run-only)
            DO_BUILD=0
            DO_RUN=1
            shift
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

case "$ARCH" in
    amd64|arm64) ;;
    *) echo "Unsupported arch: $ARCH (expected amd64|arm64)" >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for cross matrix" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="$ROOT/frozen-all"
mkdir -p "$FROZEN_ROOT"

# Keep names aligned with CI workflow naming.
ENVS=(
    "ubuntu-18.04|ubuntu:18.04"
    "ubuntu-20.04|ubuntu:20.04"
    "ubuntu-24.04|ubuntu:24.04"
    "alpine-3.20|alpine:3.20"
)

run_in_image() {
    local image="$1"
    local cmd="$2"

    docker run --rm --platform "linux/$ARCH" \
        -v "$ROOT":/work -w /work \
        "$image" \
        sh -lc "$cmd"
}

if [[ "$DO_BUILD" -eq 1 ]]; then
    echo "[cross-matrix] build stage (arch=$ARCH)"
    for pair in "${ENVS[@]}"; do
        name="${pair%%|*}"
        image="${pair##*|}"
        out_dir="/work/frozen-all/frozen-${name}-${ARCH}"
        host_out="$FROZEN_ROOT/frozen-${name}-${ARCH}"

        rm -rf "$host_out"
        mkdir -p "$host_out"

        echo "[cross-matrix] build in $image -> frozen-${name}-${ARCH}"
        run_in_image "$image" "OUTDIR=$out_dir sh /work/tests/cross-build.sh"
    done
fi

if [[ "$DO_RUN" -eq 1 ]]; then
    echo "[cross-matrix] run stage (arch=$ARCH)"
    for pair in "${ENVS[@]}"; do
        name="${pair%%|*}"
        image="${pair##*|}"
        echo "[cross-matrix] run on $image against all frozen-*-${ARCH}"
        run_in_image "$image" "FROZEN_DIR=/work/frozen-all FROZEN_GLOB='/work/frozen-all/frozen-*-${ARCH}' sh /work/tests/cross-run.sh"
    done
fi

echo "[cross-matrix] done"
