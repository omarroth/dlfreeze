#!/usr/bin/env bash
# Run CI-like cross matrix locally:
# 1) Build artifacts in each distro image
# 2) Run every source artifact set on every target distro image
set -euo pipefail

ARCH="${ARCH:-}"
ENV_FILTER="${ENV_FILTER:-}"
DO_BUILD=1
DO_RUN=1
if [[ -n "${DLFREEZE_REQUIRE_DIRECT_CONTRACTS+x}" ||
      -n "${DLFREEZE_REQUIRE_RUNTIME_ARTIFACTS+x}" ]]; then
    REQUIRE_DIRECT_CONTRACTS_EXPLICIT=1
else
    REQUIRE_DIRECT_CONTRACTS_EXPLICIT=0
fi
REQUIRE_DIRECT_CONTRACTS="${DLFREEZE_REQUIRE_DIRECT_CONTRACTS:-${DLFREEZE_REQUIRE_RUNTIME_ARTIFACTS:-1}}"

case "$REQUIRE_DIRECT_CONTRACTS" in
    0|1) ;;
    *)
        echo "DLFREEZE_REQUIRE_DIRECT_CONTRACTS must be 0 or 1" >&2
        exit 2
        ;;
esac

usage() {
    cat <<'EOF'
Usage: tests/local-cross-matrix.sh [options]

Options:
  --arch ARCH            Target architecture for Docker platform (amd64|arm64)
  --env NAME             Run one CI environment (for example arch-latest)
  --build-only           Only build artifacts in each distro image
  --run-only             Only run cross-run matrix (expects frozen-all populated)
  -h, --help             Show this help

Environment:
  DLFREEZE_REQUIRE_DIRECT_CONTRACTS=0
                         Allow a targeted run without aggregate direct+UPX
                         artifacts. Aggregate runs require them by default;
                         one-environment runs do not unless explicitly set.
  TEST_SUITE_TIMEOUT=N   Per-image test-suite limit in seconds. Defaults to
                         3600 for an emulated architecture and 1200 natively.

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

case "$(uname -m)" in
    x86_64|amd64) HOST_ARCH=amd64 ;;
    aarch64|arm64) HOST_ARCH=arm64 ;;
    *) HOST_ARCH=unknown ;;
esac
if [[ "$HOST_ARCH" == "$ARCH" ]]; then
    DEFAULT_TEST_SUITE_TIMEOUT=1200
else
    # User-mode emulation is substantially slower, especially for the many
    # compiler-heavy direct-loader fixtures.  Keep a finite bound without
    # making the native GitHub-equivalent timeout spuriously fail locally.
    DEFAULT_TEST_SUITE_TIMEOUT=3600
fi
TEST_RUN_TIMEOUT="${TEST_RUN_TIMEOUT:-30}"
TEST_FREEZE_TIMEOUT="${TEST_FREEZE_TIMEOUT:-180}"
TEST_SUITE_TIMEOUT="${TEST_SUITE_TIMEOUT:-$DEFAULT_TEST_SUITE_TIMEOUT}"
TEST_TIMEOUT_KILL_AFTER="${TEST_TIMEOUT_KILL_AFTER:-5}"

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
    # A single producer can legitimately expose only a runtime outside the
    # admitted direct-loader contract (for example an older glibc).  Still
    # validate every artifact it does publish, but do not require that one
    # targeted producer to satisfy the aggregate direct+UPX coverage rule.
    if [[ "$REQUIRE_DIRECT_CONTRACTS_EXPLICIT" -eq 0 ]]; then
        REQUIRE_DIRECT_CONTRACTS=0
    fi
fi

run_in_image() {
    local image="$1"
    local cmd="$2"
    local host_uid host_gid
    host_uid=$(id -u)
    host_gid=$(id -g)

    docker run --rm --platform "linux/$ARCH" \
        -v "$ROOT":/source:ro -w /work \
        -v "$FROZEN_ROOT":/frozen-all \
        -e DLFREEZE_HOST_UID="$host_uid" \
        -e DLFREEZE_HOST_GID="$host_gid" \
        -e TEST_RUN_TIMEOUT="$TEST_RUN_TIMEOUT" \
        -e TEST_FREEZE_TIMEOUT="$TEST_FREEZE_TIMEOUT" \
        -e TEST_SUITE_TIMEOUT="$TEST_SUITE_TIMEOUT" \
        -e TEST_TIMEOUT_KILL_AFTER="$TEST_TIMEOUT_KILL_AFTER" \
        -e RUN_TIMEOUT="$TEST_RUN_TIMEOUT" \
        -e RUN_TIMEOUT_KILL_AFTER="$TEST_TIMEOUT_KILL_AFTER" \
        "$image" \
        sh -lc '
            # Build and test in the container filesystem.  cross-build.sh
            # deliberately replaces /work/build; a writable bind mount here
            # would otherwise destroy or contaminate the caller local
            # build while reproducing CI.
            if ! cp -a /source/Makefile /source/LICENSE /source/README.md \
                    /source/include /source/src /source/tests /work/; then
                echo "ERROR: could not create isolated source snapshot" >&2
                exit 1
            fi
            status=0
            sh -lc "$1" || status=$?
            chown -R "$DLFREEZE_HOST_UID:$DLFREEZE_HOST_GID" \
                /frozen-all 2>/dev/null || true
            exit "$status"
        ' sh "$cmd"
}

if [[ "$DO_BUILD" -eq 1 ]]; then
    echo "[cross-matrix] build stage (arch=$ARCH, suite-timeout=${TEST_SUITE_TIMEOUT}s)"
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
    source_glob="/frozen-all/frozen-*-${ARCH}"
    if [[ -n "$ENV_FILTER" ]]; then
        # Match workflow_dispatch semantics: a targeted environment builds
        # and consumes only that producer's artifacts.  Otherwise an older
        # frozen-* directory left in FROZEN_ROOT could falsely satisfy the
        # aggregate direct/UPX contract or introduce unrelated stale failures.
        source_glob="/frozen-all/frozen-${ENV_FILTER}-${ARCH}"
    fi
    for pair in "${ENVS[@]}"; do
        name="${pair%%|*}"
        image="${pair##*|}"
        echo "[cross-matrix] run on $image against $source_glob"
        run_in_image "$image" "DLFREEZE_REQUIRE_DIRECT_CONTRACTS=$REQUIRE_DIRECT_CONTRACTS DLFREEZE_REQUIRE_RUNTIME_ARTIFACTS=$REQUIRE_DIRECT_CONTRACTS FROZEN_DIR=/frozen-all FROZEN_GLOB='$source_glob' sh /work/tests/cross-run.sh"
    done
fi

echo "[cross-matrix] done"
