#!/bin/sh
# tests/cross-build.sh — Build dlfreeze, run test suite, freeze cross-test
# binaries.  Called inside Docker containers by the cross-platform CI workflow.
set -eu

distro_name() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$PRETTY_NAME"
    else
        echo "unknown"
    fi
}

echo "========================================================"
echo "Cross-build: $(uname -m) | $(distro_name)"
echo "========================================================"

# ── Install build dependencies ─────────────────────────────────────
if [ -f /etc/alpine-release ]; then
    apk add --no-cache \
        gcc musl-dev make linux-headers bash python3 file binutils
    apk add --no-cache upx 2>/dev/null || true
    apk add --no-cache ruby 2>/dev/null || true
    # Alpine's gcc IS musl-gcc; create symlink so tests that check
    # for the musl-gcc command still work.
    if ! command -v musl-gcc >/dev/null 2>&1; then
        ln -sf "$(command -v gcc)" /usr/local/bin/musl-gcc
    fi
elif [ -f /etc/debian_version ]; then
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update -qq 2>/dev/null; then
        # Older Ubuntu releases may have moved to old-releases.ubuntu.com
        sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
        sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list
        apt-get update -qq
    fi
    apt-get install -y -qq gcc musl-tools make bash file binutils 2>&1 | tail -1
    apt-get install -y -qq python3 2>/dev/null || true
    apt-get install -y -qq ruby 2>/dev/null || true
    # Prefer UPX ≥ 4.x — the system package may be too old (e.g. 3.95 on
    # 20.04 doesn't support our binaries).  Try to fetch a recent release.
    if ! apt-get install -y -qq upx-ucl 2>/dev/null; then
        apt-get install -y -qq upx 2>/dev/null || true
    fi
    # Verify the installed UPX can actually compress; if not, fetch a
    # modern static binary from GitHub.
    if command -v upx >/dev/null 2>&1; then
        upx_ver=$(upx --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1)
        case "$upx_ver" in
            3.*|"")
                echo "System UPX ($upx_ver) too old, fetching UPX 4.2.4…"
                apt-get install -y -qq wget xz-utils 2>&1 | tail -1
                # UPX release uses amd64/arm64 naming, not x86_64/aarch64
                case "$(uname -m)" in
                    x86_64)  upx_arch=amd64 ;;
                    aarch64) upx_arch=arm64 ;;
                    *)       upx_arch=$(uname -m) ;;
                esac
                wget -q "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-${upx_arch}_linux.tar.xz" -O /tmp/upx.tar.xz 2>/dev/null \
                    && tar -xJf /tmp/upx.tar.xz -C /tmp \
                    && cp /tmp/upx-4.2.4-${upx_arch}_linux/upx /usr/local/bin/upx \
                    && chmod +x /usr/local/bin/upx \
                    && ln -sf /usr/local/bin/upx /usr/bin/upx \
                    && echo "Installed UPX $(/usr/local/bin/upx --version 2>/dev/null | head -1)" \
                    || echo "WARNING: failed to fetch newer UPX"
                ;;
        esac
    fi
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
# specific relocation types, etc.).  We run it for coverage but do not
# gate the build on it — the cross-run job is the hard compatibility gate.
if bash tests/run_tests.sh build; then
    echo "Test suite: all passed"
else
    echo "WARNING: test suite had failures (may be expected in this environment)"
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
/work/build/dlfreeze -v -d -o "$OUTDIR/hello.frozen" /tmp/cross_hello
chmod +x "$OUTDIR/hello.frozen"

# 2. Exit code preservation
cat > /tmp/cross_exit.c <<'EOF'
#include <stdlib.h>
int main(int argc, char **argv) {
    return argc > 1 ? atoi(argv[1]) : 42;
}
EOF
gcc -o /tmp/cross_exit /tmp/cross_exit.c
/work/build/dlfreeze -v -d -o "$OUTDIR/exitcode.frozen" /tmp/cross_exit
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
    if /work/build/dlfreeze -v -d -t -f '/usr/*' -o "$OUTDIR/python3.frozen" -- python3 -c 'print(1+2)' 2>/dev/null; then
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
    if /work/build/dlfreeze -v -d -t -f '/usr/*' -o "$OUTDIR/ruby.frozen" -- ruby -e 'puts 1+2' 2>/dev/null; then
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
