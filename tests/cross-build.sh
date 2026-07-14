#!/bin/sh
# tests/cross-build.sh — Build dlfreeze, run test suite, freeze cross-test
# binaries.  Called inside Docker containers by the cross-platform CI workflow.
set -eu

TEST_RUN_TIMEOUT="${TEST_RUN_TIMEOUT:-30}"
TEST_FREEZE_TIMEOUT="${TEST_FREEZE_TIMEOUT:-180}"
TEST_SUITE_TIMEOUT="${TEST_SUITE_TIMEOUT:-1200}"
TEST_TIMEOUT_KILL_AFTER="${TEST_TIMEOUT_KILL_AFTER:-5}"

run_with_timeout_seconds() {
    limit="$1"
    shift

    if command -v timeout >/dev/null 2>&1; then
        if timeout --help 2>&1 | grep -q -- '--kill-after'; then
            timeout --kill-after="$TEST_TIMEOUT_KILL_AFTER" "$limit" "$@"
        else
            timeout "$limit" "$@"
        fi
    else
        "$@"
    fi
}

run_freeze() {
    run_with_timeout_seconds "$TEST_FREEZE_TIMEOUT" "$@"
}

run_suite() {
    run_with_timeout_seconds "$TEST_SUITE_TIMEOUT" "$@"
}

distro_name() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$PRETTY_NAME"
    else
        echo "unknown"
    fi
}

path_is_elf() {
    command -v file >/dev/null 2>&1 && file -b "$1" 2>/dev/null | grep -q 'ELF'
}

resolve_ruby_elf() {
    path=$(command -v ruby 2>/dev/null || true)
    if [ -n "$path" ]; then
        path=$(readlink -f "$path")
        if path_is_elf "$path"; then
            printf '%s\n' "$path"
            return 0
        fi
    fi

    for candidate in ruby-mri ruby3.4 ruby3.3 ruby3.2 ruby3.1 ruby3.0 ruby2.7; do
        path=$(command -v "$candidate" 2>/dev/null || true)
        if [ -n "$path" ]; then
            path=$(readlink -f "$path")
            if path_is_elf "$path"; then
                printf '%s\n' "$path"
                return 0
            fi
        fi
    done

    return 1
}

link_musl_gcc_to_host_cc() {
    host_cc=$(command -v gcc 2>/dev/null || true)
    if [ -z "$host_cc" ]; then
        echo "ERROR: cannot create musl-gcc fallback: gcc is not installed" >&2
        return 1
    fi
    ln -sf "$host_cc" /usr/local/bin/musl-gcc
}

# Fetch a modern UPX from GitHub when the distro lacks one (Fedora has
# no upx in core repos) or ships one too old to compress our binaries
# (older Debian/Ubuntu).  No-op when a sufficiently new UPX is present.
fetch_upx_from_github() {
    if command -v upx >/dev/null 2>&1; then
        upx_ver=$(upx --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        case "$upx_ver" in
            [4-9].*|[1-9][0-9]*.*) return 0 ;;  # already modern enough
        esac
    fi
    case "$(uname -m)" in
        x86_64)  upx_arch=amd64 ;;
        aarch64) upx_arch=arm64 ;;
        *)       upx_arch=$(uname -m) ;;
    esac
    fetcher=
    if command -v curl >/dev/null 2>&1; then fetcher=curl;
    elif command -v wget >/dev/null 2>&1; then fetcher=wget;
    else echo "WARNING: no curl/wget for UPX download"; return 1; fi
    url="https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-${upx_arch}_linux.tar.xz"
    if [ "$fetcher" = curl ]; then
        curl -fsSL "$url" -o /tmp/upx.tar.xz || { echo "WARNING: UPX download failed"; return 1; }
    else
        wget -q "$url" -O /tmp/upx.tar.xz || { echo "WARNING: UPX download failed"; return 1; }
    fi
    if tar -xJf /tmp/upx.tar.xz -C /tmp &&
       cp "/tmp/upx-4.2.4-${upx_arch}_linux/upx" /usr/local/bin/upx &&
       chmod +x /usr/local/bin/upx &&
       ln -sf /usr/local/bin/upx /usr/bin/upx; then
        echo "Installed UPX $(/usr/local/bin/upx --version 2>/dev/null | head -1)"
    else
        echo "WARNING: failed to install UPX"
        return 1
    fi
}

echo "========================================================"
echo "Cross-build: $(uname -m) | $(distro_name)"
echo "========================================================"

# ── Install build dependencies ─────────────────────────────────────
if [ -f /etc/alpine-release ]; then
    apk add --no-cache \
        gcc g++ musl-dev make linux-headers bash python3 file binutils strace diffutils \
        git openssl sqlite
    apk add --no-cache upx 2>/dev/null || true
    apk add --no-cache ruby 2>/dev/null || true
    # Alpine's gcc IS musl-gcc; create symlink so tests that check
    # for the musl-gcc command still work.
    if ! command -v musl-gcc >/dev/null 2>&1; then
        link_musl_gcc_to_host_cc
    fi
elif [ -f /etc/arch-release ]; then
    # Arch is a rolling distro and forbids partial upgrades.  Using
    # `pacman -Sy` to install fresh packages on top of a stale base
    # image will pull in a new bash that requires readline symbols
    # (e.g. `rl_completion_rewrite_hook`) that the image's older
    # readline does not yet provide, breaking /bin/sh for the rest
    # of the script.  Always do a full `-Syu` first.
    # New pacman versions sandbox downloads with Landlock/seccomp.  Those
    # syscalls may be unavailable when the container runs through qemu-user;
    # use pacman's supported opt-out in this already-isolated CI container.
    pacman_sandbox_opt=
    if pacman -S --help 2>&1 | grep -q -- '--disable-sandbox'; then
        pacman_sandbox_opt=--disable-sandbox
    fi
    pacman_log=/tmp/dlfreeze-pacman.log
    if ! pacman $pacman_sandbox_opt -Syu --noconfirm --needed \
        gcc musl make bash python file binutils strace diffutils \
        git openssl sqlite >"$pacman_log" 2>&1; then
        echo "ERROR: required package installation failed" >&2
        tail -50 "$pacman_log" >&2
        exit 1
    fi
    tail -3 "$pacman_log"
    pacman $pacman_sandbox_opt -S --noconfirm --needed upx 2>/dev/null || true
    pacman $pacman_sandbox_opt -S --noconfirm --needed ruby 2>/dev/null || true
    # Arch ships musl as a separate package providing /usr/bin/musl-gcc
    if ! command -v musl-gcc >/dev/null 2>&1; then
        # fall back to plain gcc; static-musl link will be dropped
        link_musl_gcc_to_host_cc
    fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG=$(command -v dnf || command -v yum)
    pkg_log=/tmp/dlfreeze-rpm-install.log
    if ! "$PKG" install -y -q \
        gcc gcc-c++ make bash python3 file binutils diffutils glibc-static \
        git openssl sqlite >"$pkg_log" 2>&1; then
        echo "ERROR: required package installation failed" >&2
        tail -50 "$pkg_log" >&2
        exit 1
    fi
    tail -3 "$pkg_log"
    "$PKG" install -y -q strace 2>/dev/null || true
    "$PKG" install -y -q ruby 2>/dev/null || true
    # Fedora's core repos do not include UPX, so the package install is
    # expected to fail.  Fall through to the GitHub fetch helper below.
    "$PKG" install -y -q upx 2>/dev/null || true
    "$PKG" install -y -q curl tar xz 2>/dev/null || true
    fetch_upx_from_github || true
    # Fedora doesn't ship musl-gcc in repos — fall back to plain gcc.
    # The Makefile uses musl-gcc for the static bootstrap; on glibc-only
    # systems we link statically against glibc instead.
    if ! command -v musl-gcc >/dev/null 2>&1; then
        link_musl_gcc_to_host_cc
    fi
elif [ -f /etc/debian_version ]; then
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update -qq 2>/dev/null; then
        # Older Ubuntu releases may have moved to old-releases.ubuntu.com
        sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
        sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
        apt-get update -qq
    fi
    apt_log=/tmp/dlfreeze-apt-install.log
    if ! apt-get install -y -qq gcc g++ musl-tools make bash file binutils diffutils \
        git openssl sqlite3 >"$apt_log" 2>&1; then
        echo "ERROR: required package installation failed" >&2
        tail -50 "$apt_log" >&2
        exit 1
    fi
    tail -1 "$apt_log"
    apt-get install -y -qq strace 2>/dev/null || true
    apt-get install -y -qq python3 2>/dev/null || true
    apt-get install -y -qq ruby 2>/dev/null || true
    # Prefer UPX ≥ 4.x — the system package may be too old (e.g. 3.95 on
    # 20.04 doesn't support our binaries).  Try to fetch a recent release.
    if ! apt-get install -y -qq upx-ucl 2>/dev/null; then
        apt-get install -y -qq upx 2>/dev/null || true
    fi
    apt-get install -y -qq wget xz-utils ca-certificates 2>/dev/null || true
    fetch_upx_from_github || true
fi

echo ""
echo "Toolchain:"
gcc --version | head -1
command -v musl-gcc >/dev/null 2>&1 && musl-gcc --version 2>&1 | head -1 || echo "musl-gcc: not found"
echo ""

# ── Build dlfreeze from source ─────────────────────────────────────
cd /work
rm -rf build
make -j"$(nproc)" 2>&1
echo ""
echo "Build artifacts:"
ls -la build/dlfreeze build/dlfreeze-bootstrap build/dlfreeze-preload.so
echo ""

# ── Run test suite (Docker-dependent tests auto-skip) ──────────────
echo "--- Test suite ---"
# The test suite skips tests whose prerequisites are missing (Docker,
# specific relocation types, etc.), but real failures must fail the build.
# Development-snapshot libc jobs intentionally exercise the extraction
# admission path.  Every stable matrix image must prove that at least one
# fixture actually contained and executed direct-load metadata.
case "$(distro_name)" in
    *Rawhide*|*rawhide*) DLFREEZE_REQUIRE_DIRECT=0 ;;
    *)                   DLFREEZE_REQUIRE_DIRECT=1 ;;
esac
export DLFREEZE_REQUIRE_DIRECT
if run_suite bash tests/run_tests.sh build; then
    echo "Test suite: all passed"
else
    echo "ERROR: test suite failed"
    exit 1
fi
echo ""

# ── Freeze cross-test programs ─────────────────────────────────────
OUTDIR="${OUTDIR:-/work/build/cross-test}"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# 1. Hello world — deterministic output for cross-environment comparison
cat > /tmp/cross_hello.c <<'EOF'
#include <stdio.h>
#include <math.h>
#include <string.h>
int main(int argc, char **argv) {
    printf("hello from dlfreeze\n");
    printf("sqrt(2)=%.6f\n", sqrt(2.0));
    printf("strlen(test)=%zu\n", strlen("test"));
    for (int i = 1; i < argc; i++)
        printf("arg[%d]=%s\n", i, argv[i]);
    return 0;
}
EOF
gcc -o /tmp/cross_hello /tmp/cross_hello.c -lm
/tmp/cross_hello foo bar > "$OUTDIR/hello.expected"
run_freeze /work/build/dlfreeze -v -d -o "$OUTDIR/hello.frozen" /tmp/cross_hello
chmod +x "$OUTDIR/hello.frozen"

# 2. Exit code preservation
cat > /tmp/cross_exit.c <<'EOF'
#include <stdlib.h>
int main(int argc, char **argv) {
    return argc > 1 ? atoi(argv[1]) : 42;
}
EOF
gcc -o /tmp/cross_exit /tmp/cross_exit.c
run_freeze /work/build/dlfreeze -v -d -o "$OUTDIR/exitcode.frozen" /tmp/cross_exit
chmod +x "$OUTDIR/exitcode.frozen"

# 3. UPX-compressed variants (best effort)
if command -v upx >/dev/null 2>&1; then
    for f in "$OUTDIR"/*.frozen; do
        base=$(basename "$f" .frozen)
        rm -f "$OUTDIR/${base}.upx.frozen"
        if upx --best -o "$OUTDIR/${base}.upx.frozen" "$f" 2>/dev/null; then
            chmod +x "$OUTDIR/${base}.upx.frozen"
        fi
    done
    echo "UPX compression: done"
else
    echo "UPX: not available, skipping compressed variants"
fi

# 4. Python3 — freeze a simple deterministic script (best effort)
if command -v python3 >/dev/null 2>&1; then
    if run_freeze /work/build/dlfreeze -v -d -t -f '/usr/*' -o "$OUTDIR/python3.frozen" -- python3 -c 'print(1+2)' 2>/dev/null; then
        chmod +x "$OUTDIR/python3.frozen"
        echo "3" > "$OUTDIR/python3.expected"
        if command -v upx >/dev/null 2>&1; then
            upx --best -o "$OUTDIR/python3.upx.frozen" "$OUTDIR/python3.frozen" 2>/dev/null && \
                chmod +x "$OUTDIR/python3.upx.frozen" || true
        fi
    else
        echo "WARNING: failed to freeze python3 (skipping)"
    fi
else
    echo "python3: not available, skipping"
fi

# 5. Ruby — freeze a simple deterministic script (best effort)
if command -v ruby >/dev/null 2>&1; then
    ruby_elf=$(resolve_ruby_elf || true)
    if [ -n "$ruby_elf" ] && run_freeze /work/build/dlfreeze -v -d -t -f '/usr/*' -o "$OUTDIR/ruby.frozen" -- "$ruby_elf" -e 'puts 1+2' 2>/dev/null; then
        chmod +x "$OUTDIR/ruby.frozen"
        echo "3" > "$OUTDIR/ruby.expected"
        if command -v upx >/dev/null 2>&1; then
            upx --best -o "$OUTDIR/ruby.upx.frozen" "$OUTDIR/ruby.frozen" 2>/dev/null && \
                chmod +x "$OUTDIR/ruby.upx.frozen" || true
        fi
    else
        echo "WARNING: failed to freeze ruby (skipping)"
    fi
else
    echo "ruby: not available, skipping"
fi

echo ""
echo "Cross-test artifacts:"
ls -la "$OUTDIR/"
echo ""
echo "Cross-build: DONE"
