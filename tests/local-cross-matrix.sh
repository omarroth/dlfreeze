#!/usr/bin/env bash
# Run CI-like cross matrix locally:
# 1) Build artifacts in each distro image
# 2) Run every source artifact set on every target distro image
set -euo pipefail

ARCH="${ARCH:-}"
ENV_FILTER="${ENV_FILTER:-}"
DO_BUILD=1
DO_RUN=1

usage() {
    cat <<'EOF'
Usage: tests/local-cross-matrix.sh [options]

Options:
  --arch ARCH            Target architecture for Docker platform (amd64|arm64)
  --env NAME             Run one CI environment (for example arch-latest)
  --build-only           Only build artifacts in each distro image
  --run-only             Only run cross-run matrix (expects frozen-all populated)
  -h, --help             Show this help

Examples:
  tests/local-cross-matrix.sh
  tests/local-cross-matrix.sh --arch arm64
  tests/local-cross-matrix.sh --arch arm64 --env arch-latest --build-only
  FROZEN_ROOT=/tmp/dlfreeze-artifacts tests/local-cross-matrix.sh --run-only
  tests/local-cross-matrix.sh --build-only
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            if [[ $# -lt 2 ]]; then
                echo "--arch requires a value" >&2
                usage >&2
                exit 2
            fi
            ARCH="$2"
            shift 2
            ;;
        --env)
            if [[ $# -lt 2 ]]; then
                echo "--env requires a value" >&2
                usage >&2
                exit 2
            fi
            ENV_FILTER="$2"
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

if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "Unsupported host arch: $(uname -m). Use --arch." >&2; exit 2 ;;
    esac
fi

case "$ARCH" in
    amd64|arm64) ;;
    *) echo "Unsupported arch: $ARCH (expected amd64|arm64)" >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for cross matrix" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="${FROZEN_ROOT:-$ROOT/frozen-all}"
mkdir -p "$FROZEN_ROOT"
FROZEN_ROOT="$(cd "$FROZEN_ROOT" && pwd -P)"

# Keep names aligned with CI workflow naming.
ENVS=(
    "ubuntu-18.04|ubuntu:18.04"
    "ubuntu-20.04|ubuntu:20.04"
    "ubuntu-24.04|ubuntu:24.04"
    "alpine-3.20|alpine:3.20"
    "debian-12|debian:12"
    "debian-trixie|debian:trixie"
    "fedora-41|fedora:41"
    "fedora-rawhide|fedora:rawhide"
)
# Arch's official image is amd64-only; use the community arm64 fork on arm64.
if [[ "$ARCH" == "arm64" ]]; then
    ENVS+=("arch-latest|menci/archlinuxarm:base")
else
    ENVS+=("arch-latest|archlinux:latest")
fi

if [[ -n "$ENV_FILTER" ]]; then
    FILTERED_ENVS=()
    for pair in "${ENVS[@]}"; do
        if [[ "${pair%%|*}" == "$ENV_FILTER" ]]; then
            FILTERED_ENVS+=("$pair")
        fi
    done
    if [[ "${#FILTERED_ENVS[@]}" -eq 0 ]]; then
        echo "Unknown environment: $ENV_FILTER" >&2
        printf 'Available:' >&2
        for pair in "${ENVS[@]}"; do
            printf ' %s' "${pair%%|*}" >&2
        done
        printf '\n' >&2
        exit 2
    fi
    ENVS=("${FILTERED_ENVS[@]}")
fi

run_in_image() {
    local image="$1"
    local cmd="$2"
    local host_uid host_gid
    host_uid=$(id -u)
    host_gid=$(id -g)

    docker run --rm --platform "linux/$ARCH" \
        -v "$ROOT":/work -w /work \
        -v "$FROZEN_ROOT":/frozen-all \
        -e DLFREEZE_HOST_UID="$host_uid" \
        -e DLFREEZE_HOST_GID="$host_gid" \
        "$image" \
        sh -lc '
            status=0
            sh -lc "$1" || status=$?
            chown -R "$DLFREEZE_HOST_UID:$DLFREEZE_HOST_GID" \
                /work/build /frozen-all 2>/dev/null || true
            exit "$status"
        ' sh "$cmd"
}

if [[ "$DO_BUILD" -eq 1 ]]; then
    echo "[cross-matrix] build stage (arch=$ARCH)"
    for pair in "${ENVS[@]}"; do
        name="${pair%%|*}"
        image="${pair##*|}"
        out_dir="/frozen-all/frozen-${name}-${ARCH}"
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
        run_in_image "$image" "FROZEN_DIR=/frozen-all FROZEN_GLOB='/frozen-all/frozen-*-${ARCH}' sh /work/tests/cross-run.sh"
    done
fi

echo "[cross-matrix] done"
