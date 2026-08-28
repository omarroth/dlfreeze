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
        if timeout --help 2>&1 | grep -- '--kill-after' >/dev/null; then
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

verify_frozen_artifact() {
    verify_artifact=$1
    verify_expected_rc=$2
    verify_expected_file=$3
    verify_output_mode=$4
    shift 4

    verify_output=$(mktemp)
    verify_stderr=$(mktemp)
    verify_rc=0
    case "$verify_output_mode" in
        stdout)
            run_with_timeout_seconds "$TEST_RUN_TIMEOUT" \
                env DLFREEZE_NO_FORK=1 "$verify_artifact" "$@" \
                >"$verify_output" 2>"$verify_stderr" || verify_rc=$?
            ;;
        combined)
            run_with_timeout_seconds "$TEST_RUN_TIMEOUT" \
                env DLFREEZE_NO_FORK=1 "$verify_artifact" "$@" \
                >"$verify_output" 2>&1 || verify_rc=$?
            ;;
        *)
            echo "ERROR: unknown smoke-test output mode: $verify_output_mode" >&2
            rm -f "$verify_output" "$verify_stderr"
            return 1
            ;;
    esac

    if [ "$verify_rc" -ne "$verify_expected_rc" ] ||
       { [ "$verify_expected_file" != - ] &&
         ! cmp -s "$verify_expected_file" "$verify_output"; }; then
        echo "ERROR: artifact smoke test failed: $verify_artifact" >&2
        echo "  expected exit: $verify_expected_rc" >&2
        echo "  actual exit:   $verify_rc" >&2
        if [ "$verify_expected_file" != - ]; then
            echo "  expected output:" >&2
            sed -n '1,40p' "$verify_expected_file" >&2
            echo "  actual output:" >&2
            sed -n '1,40p' "$verify_output" >&2
        fi
        if [ -s "$verify_stderr" ]; then
            echo "  actual stderr:" >&2
            sed -n '1,40p' "$verify_stderr" >&2
        fi
        rm -f "$verify_output" "$verify_stderr"
        return 1
    fi

    rm -f "$verify_output" "$verify_stderr"
    return 0
}

# Print the final packer diagnostic only when a failed direct-data freeze was
# refused solely because the target runtime cannot provide direct loading.
# These messages are emitted by mutually exclusive, fail-fast checks in
# pack_frozen().  Requiring an exact final non-empty line avoids treating an
# earlier target-program message, or a later genuine packer failure, as a
# capability skip.
classify_direct_capability_refusal() {
    capability_rc=$1
    capability_log=$2
    [ "$capability_rc" -eq 1 ] 2>/dev/null || return 1
    capability_last=$(awk 'NF { last = $0 } END { if (last != "") print last }' \
        "$capability_log") || return 1

    case "$capability_last" in
        'dlfreeze: pathful DT_NEEDED entries require a supported direct-load mode'|\
        'dlfreeze: pathful traced dlopen entries require a supported direct-load mode'|\
        'dlfreeze: bare traced dlopen aliases require a supported direct-load mode'|\
        'dlfreeze: captured files require a supported direct-load runtime')
            printf '%s\n' "$capability_last"
            return 0
            ;;
    esac
    return 1
}

# A successful pack may still be an intentional extraction fallback when the
# filter matched no data.  The runtime path is variable, so validate the whole
# diagnostic grammar and require exactly one such line.
classify_direct_extraction_fallback() {
    fallback_log=$1
    awk '
        /^dlfreeze: warning: direct-load is unavailable for runtime [^;[:cntrl:]]+; creating an extraction-mode binary$/ {
            count++
            reason = $0
        }
        END {
            if (count == 1) {
                print reason
                exit 0
            }
            exit 1
        }
    ' "$fallback_log"
}

cross_build_classifier_selftest() {
    classifier_log=$(mktemp)
    classifier_reasons='dlfreeze: pathful DT_NEEDED entries require a supported direct-load mode
dlfreeze: pathful traced dlopen entries require a supported direct-load mode
dlfreeze: bare traced dlopen aliases require a supported direct-load mode
dlfreeze: captured files require a supported direct-load runtime'

    while IFS= read -r classifier_reason; do
        printf 'unrelated trace output\n%s\n' "$classifier_reason" \
            > "$classifier_log"
        classifier_actual=$(classify_direct_capability_refusal \
            1 "$classifier_log" || true)
        if [ "$classifier_actual" != "$classifier_reason" ]; then
            echo "classifier selftest rejected: $classifier_reason" >&2
            rm -f "$classifier_log"
            return 1
        fi
    done <<EOF
$classifier_reasons
EOF

    printf '%s: unrelated suffix\n' \
        'dlfreeze: captured files require a supported direct-load runtime' \
        > "$classifier_log"
    if classify_direct_capability_refusal 1 "$classifier_log" >/dev/null; then
        echo "classifier selftest accepted an inexact diagnostic" >&2
        rm -f "$classifier_log"
        return 1
    fi

    printf '%s\ndlfreeze: packing failed\n' \
        'dlfreeze: captured files require a supported direct-load runtime' \
        > "$classifier_log"
    if classify_direct_capability_refusal 1 "$classifier_log" >/dev/null; then
        echo "classifier selftest hid a later packer failure" >&2
        rm -f "$classifier_log"
        return 1
    fi

    printf '%s\n' \
        'dlfreeze: captured files require a supported direct-load runtime' \
        > "$classifier_log"
    if classify_direct_capability_refusal 124 "$classifier_log" >/dev/null; then
        echo "classifier selftest hid a timeout" >&2
        rm -f "$classifier_log"
        return 1
    fi

    classifier_fallback='dlfreeze: warning: direct-load is unavailable for runtime /lib/ld-test.so; creating an extraction-mode binary'
    printf 'trace output\n%s\npack summary\n' "$classifier_fallback" \
        > "$classifier_log"
    classifier_actual=$(classify_direct_extraction_fallback \
        "$classifier_log" || true)
    if [ "$classifier_actual" != "$classifier_fallback" ]; then
        echo "classifier selftest rejected an exact extraction fallback" >&2
        rm -f "$classifier_log"
        return 1
    fi
    printf '%s: unrelated suffix\n' "$classifier_fallback" > "$classifier_log"
    if classify_direct_extraction_fallback "$classifier_log" >/dev/null; then
        echo "classifier selftest accepted an inexact extraction fallback" >&2
        rm -f "$classifier_log"
        return 1
    fi
    printf '%s\n%s\n' "$classifier_fallback" "$classifier_fallback" \
        > "$classifier_log"
    if classify_direct_extraction_fallback "$classifier_log" >/dev/null; then
        echo "classifier selftest accepted duplicate extraction diagnostics" >&2
        rm -f "$classifier_log"
        return 1
    fi

    rm -f "$classifier_log"
    echo "cross-build direct-capability classifier: PASS"
}

if [ "${1:-}" = --selftest-capability-classifier ]; then
    if [ "$#" -ne 1 ]; then
        echo "--selftest-capability-classifier takes no arguments" >&2
        exit 2
    fi
    cross_build_classifier_selftest
    exit $?
fi

# Return 0 when a compressed artifact was created and smoke-tested, 1 when
# UPX cannot compress this ELF (best-effort coverage), and 2 when UPX produced
# an executable that does not preserve the source artifact's behavior.
make_upx_artifact() {
    upx_source=$1
    upx_output=$2
    upx_label=$3
    upx_expected_rc=$4
    upx_expected_file=$5
    upx_output_mode=$6
    shift 6

    rm -f "$upx_output"
    # UPX --best can spend an unbounded amount of time on large runtime
    # artifacts.  Compression is optional coverage, but it must not stall the
    # entire producer job; use the same finite budget as artifact creation.
    if ! run_with_timeout_seconds "$TEST_FREEZE_TIMEOUT" \
            upx --best -o "$upx_output" "$upx_source" 2>/dev/null; then
        echo "UPX: cannot compress $upx_label (skipping)"
        rm -f "$upx_output"
        return 1
    fi
    chmod +x "$upx_output"
    if ! verify_frozen_artifact "$upx_output" "$upx_expected_rc" \
            "$upx_expected_file" "$upx_output_mode" "$@"; then
        rm -f "$upx_output"
        return 2
    fi
    return 0
}

# A coarse image probe cannot certify an individual runtime.  Capture the
# final pack log and footer so an artifact is published as a direct-load test
# only when that exact executable received direct-loader metadata.  Extraction
# mode cannot generically virtualize arbitrary captured absolute paths.
freeze_cross_direct_data_artifact() {
    direct_label=$1
    direct_output=$2
    shift 2
    direct_log="${direct_output}.pack.log"

    rm -f "$direct_output" "$direct_log"
    direct_rc=0
    run_freeze /work/build/dlfreeze -v -d -o "$direct_output" "$@" \
        >"$direct_log" 2>&1 || direct_rc=$?
    if [ "$direct_rc" -ne 0 ]; then
        if direct_reason=$(classify_direct_capability_refusal \
                "$direct_rc" "$direct_log"); then
            echo "SKIP: $direct_label — $direct_reason"
            rm -f "$direct_output" "$direct_log"
            return 77
        fi
        echo "ERROR: failed to freeze $direct_label (exit $direct_rc)" >&2
        sed -n '1,160p' "$direct_log" >&2
        rm -f "$direct_output" "$direct_log"
        return 1
    fi

    direct_size=$(stat -c %s "$direct_output" 2>/dev/null || true)
    direct_magic=
    direct_meta=
    if [ -n "$direct_size" ] && [ "$direct_size" -ge 64 ] 2>/dev/null; then
        direct_magic=$(od -An -tx1 -j $((direct_size - 64)) -N8 \
            "$direct_output" 2>/dev/null | tr -d '[:space:]')
        direct_meta=$(od -An -tu8 -j $((direct_size - 24)) -N8 \
            "$direct_output" 2>/dev/null | tr -d '[:space:]')
    fi

    direct_confirmed=0
    if grep -Eq \
            '^[[:space:]]*mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)[[:space:]]*$' \
            "$direct_log"; then
        direct_confirmed=1
    fi
    direct_reason=$(classify_direct_extraction_fallback "$direct_log" || true)

    if [ "$direct_confirmed" -eq 1 ] &&
       [ -z "$direct_reason" ] &&
       [ "$direct_magic" = 444c465245455a00 ] &&
       [ -n "$direct_meta" ] && [ "$direct_meta" != 0 ]; then
        cat "$direct_log"
        rm -f "$direct_log"
        chmod +x "$direct_output"
        return 0
    fi

    if [ "$direct_confirmed" -eq 0 ] && [ -n "$direct_reason" ] &&
       [ "$direct_magic" = 444c465245455a00 ] &&
       [ "$direct_meta" = 0 ]; then
        echo "SKIP: $direct_label — $direct_reason"
        rm -f "$direct_output" "$direct_log"
        return 77
    fi

    echo "ERROR: $direct_label packer output did not unambiguously contain valid direct metadata" >&2
    sed -n '1,160p' "$direct_log" >&2
    rm -f "$direct_output" "$direct_log"
    return 1
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

path_is_elf() {
    command -v file >/dev/null 2>&1 &&
        file -b "$1" 2>/dev/null | grep 'ELF' >/dev/null
}

# Return 0 when at least one distinct, dynamic host runtime is admitted for
# direct loading, 1 when every available runtime cleanly falls back to
# extraction, and 2 for a compiler/packer failure.  CI coverage should depend
# on the capability being exercised, not on distro names (rolling and
# prerelease images frequently change their PRETTY_NAME).
probe_direct_runtime_admission() {
    probe_dir=/tmp/dlfreeze-direct-admission
    probe_src="$probe_dir/probe.c"
    probe_seen=
    probe_index=0

    rm -rf "$probe_dir"
    mkdir -p "$probe_dir"
    if ! command -v readelf >/dev/null 2>&1; then
        echo "ERROR: readelf is required for the direct-runtime capability probe" >&2
        rm -rf "$probe_dir"
        return 2
    fi
    cat > "$probe_src" <<'EOF'
int main(void) { return 0; }
EOF

    for probe_cc in gcc musl-gcc; do
        probe_cc_path=$(command -v "$probe_cc" 2>/dev/null || true)
        [ -n "$probe_cc_path" ] || continue
        probe_cc_path=$(readlink -f "$probe_cc_path")
        case " $probe_seen " in
            *" $probe_cc_path "*) continue ;;
        esac
        probe_seen="$probe_seen $probe_cc_path"
        probe_index=$((probe_index + 1))
        probe_bin="$probe_dir/probe-$probe_index"
        probe_out="$probe_dir/probe-$probe_index.frozen"
        probe_log="$probe_dir/probe-$probe_index.log"
        probe_compile_log="$probe_dir/probe-$probe_index.compile.log"

        if ! "$probe_cc" -o "$probe_bin" "$probe_src" \
                >"$probe_compile_log" 2>&1; then
            echo "ERROR: direct-runtime probe compilation failed with $probe_cc" >&2
            cat "$probe_compile_log" >&2
            rm -rf "$probe_dir"
            return 2
        fi
        if ! readelf -W -l "$probe_bin" 2>/dev/null |
                grep 'Requesting program interpreter:' >/dev/null; then
            continue
        fi
        if ! run_freeze ./build/dlfreeze -d -o "$probe_out" "$probe_bin" \
                >"$probe_log" 2>&1; then
            echo "ERROR: dlfreeze failed during direct-runtime capability probe ($probe_cc)" >&2
            cat "$probe_log" >&2
            rm -rf "$probe_dir"
            return 2
        fi
        if [ ! -x "$probe_out" ]; then
            echo "ERROR: direct-runtime probe produced no executable ($probe_cc)" >&2
            cat "$probe_log" >&2
            rm -rf "$probe_dir"
            return 2
        fi

        if grep -Eq \
                '^[[:space:]]*mode[[:space:]]*:[[:space:]]*direct-load \(in-process loader\)[[:space:]]*$' \
                "$probe_log"; then
            if grep -Eq \
                    'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
                    "$probe_log"; then
                echo "ERROR: contradictory direct-runtime probe result ($probe_cc)" >&2
                cat "$probe_log" >&2
                rm -rf "$probe_dir"
                return 2
            fi
            rm -rf "$probe_dir"
            return 0
        fi
        if grep -Eq \
                'direct-load is unavailable for runtime .*creating an extraction-mode binary' \
                "$probe_log"; then
            continue
        fi

        echo "ERROR: unrecognized direct-runtime probe result ($probe_cc)" >&2
        cat "$probe_log" >&2
        rm -rf "$probe_dir"
        return 2
    done

    rm -rf "$probe_dir"
    return 1
}

# Build one application-independent strict-direct contract for every distinct
# host libc exposed by the available compilers.  The fixture covers startup,
# an embedded data file, a traced dlopen object, constructors, library TLS, and
# pthread TLS.  Its status file is the machine-readable producer contract used
# by cross-run.sh; Python and Ruby remain useful smoke tests but do not decide
# whether direct-loader coverage exists.
build_generic_direct_contracts() {
    contract_outdir=$1
    contract_status="$contract_outdir/direct-contracts.v1"
    contract_seen_cc=
    contract_seen_runtime=
    contract_runtime_count=0

    : > "$contract_status"
    contract_compilers=${DLFREEZE_CONTRACT_COMPILERS:-"gcc musl-gcc"}
    # Compiler commands are whitespace-delimited command names/paths.  This is
    # deliberately configurable so a renamed or additional target toolchain
    # can participate without teaching the contract about libc filenames.
    # shellcheck disable=SC2086
    set -- $contract_compilers
    for contract_cc do
        contract_cc_path=$(command -v "$contract_cc" 2>/dev/null || true)
        [ -n "$contract_cc_path" ] || continue
        contract_cc_path=$(readlink -f "$contract_cc_path")
        case " $contract_seen_cc " in
            *" $contract_cc_path "*) continue ;;
        esac
        contract_seen_cc="$contract_seen_cc $contract_cc_path"

        contract_probe_dir="/tmp/dlfreeze-cross-contract-probe-$$"
        rm -rf "$contract_probe_dir"
        mkdir -p "$contract_probe_dir"
        cat > "$contract_probe_dir/probe.c" <<'EOF'
int main(void) { return 0; }
EOF
        if ! "$contract_cc" -o "$contract_probe_dir/probe" \
                "$contract_probe_dir/probe.c"; then
            echo "ERROR: generic direct contract probe failed with $contract_cc" >&2
            rm -rf "$contract_probe_dir"
            return 1
        fi
        contract_interp=$(readelf -W -l "$contract_probe_dir/probe" 2>/dev/null |
            sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
        rm -rf "$contract_probe_dir"
        if [ -z "$contract_interp" ]; then
            echo "SKIP: generic direct contract ($contract_cc) — no dynamic interpreter"
            continue
        fi
        contract_interp_real=$(readlink -f "$contract_interp" 2>/dev/null || true)
        contract_runtime_hash=$(
            [ -n "$contract_interp_real" ] &&
            [ -f "$contract_interp_real" ] &&
            sha256sum "$contract_interp_real" 2>/dev/null | awk '{print $1}'
        )
        case "$contract_runtime_hash" in
            ''|*[!0-9a-f]*)
                echo "ERROR: generic direct contract ($contract_cc) cannot identify interpreter content: $contract_interp" >&2
                return 1
                ;;
        esac
        if [ "${#contract_runtime_hash}" -ne 64 ]; then
            echo "ERROR: generic direct contract ($contract_cc) produced a non-SHA256 runtime identity" >&2
            return 1
        fi
        contract_runtime="runtime-$contract_runtime_hash"
        case " $contract_seen_runtime " in
            *" $contract_runtime "*) continue ;;
        esac
        contract_seen_runtime="$contract_seen_runtime $contract_runtime"
        contract_runtime_count=$((contract_runtime_count + 1))

        contract_root="/tmp/dlfreeze-cross-direct-$contract_runtime"
        contract_root_abs="$contract_root"
        contract_asset="$contract_root/asset.txt"
        contract_lib="$contract_root/libdlfreeze_contract.so"
        contract_lib_src="$contract_root/library.c"
        contract_main_src="$contract_root/main.c"
        contract_main="$contract_root/main"
        contract_artifact="$contract_outdir/direct-$contract_runtime.frozen"
        contract_expected="$contract_outdir/direct-$contract_runtime.expected"
        contract_upx="$contract_outdir/direct-$contract_runtime.upx.frozen"

        rm -rf "$contract_root"
        rm -f "$contract_artifact" "$contract_expected" "$contract_upx"
        mkdir -p "$contract_root"
        cat > "$contract_lib_src" <<'EOF'
static __thread int contract_tls = 40;
static int constructor_ready;

__attribute__((constructor))
static void contract_constructor(void)
{
    constructor_ready = 1;
}

int dlfreeze_contract_value(void)
{
    return constructor_ready + ++contract_tls;
}
EOF
        cat > "$contract_main_src" <<'EOF'
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifndef CONTRACT_ASSET
#error CONTRACT_ASSET is required
#endif
#ifndef CONTRACT_LIBRARY
#error CONTRACT_LIBRARY is required
#endif

static __thread int main_tls = 20;

static void *contract_worker(void *unused)
{
    (void)unused;
    if (main_tls != 20)
        return (void *)1;
    main_tls = 21;
    return main_tls == 21 ? NULL : (void *)2;
}

int main(void)
{
    char asset[64];
    void *handle;
    void *worker_result = NULL;
    int (*value)(void);
    FILE *stream;
    pthread_t thread;

    stream = fopen(CONTRACT_ASSET, "r");
    if (!stream || !fgets(asset, sizeof(asset), stream))
        return 2;
    fclose(stream);
    asset[strcspn(asset, "\r\n")] = '\0';

    handle = dlopen(CONTRACT_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 3;
    value = (int (*)(void))dlsym(handle, "dlfreeze_contract_value");
    if (!value || value() != 42)
        return 4;
    if (pthread_create(&thread, NULL, contract_worker, NULL) != 0 ||
        pthread_join(thread, &worker_result) != 0 || worker_result != NULL ||
        main_tls != 20)
        return 5;
    puts(asset);
    dlclose(handle);
    return 0;
}
EOF
        printf '%s\n' 'generic-direct-contract-ok' > "$contract_asset"
        if ! "$contract_cc" -shared -fPIC \
                -Wl,-soname,libdlfreeze_contract.so \
                -o "$contract_lib" "$contract_lib_src" ||
           ! "$contract_cc" -pthread -o "$contract_main" \
                "-DCONTRACT_ASSET=\"$contract_asset\"" \
                "-DCONTRACT_LIBRARY=\"$contract_lib\"" \
                "$contract_main_src" -ldl; then
            echo "ERROR: generic $contract_runtime direct contract compile failed" >&2
            rm -rf "$contract_root"
            return 1
        fi
        if ! run_with_timeout_seconds "$TEST_RUN_TIMEOUT" "$contract_main" \
                > "$contract_expected" 2>&1; then
            echo "ERROR: native generic $contract_runtime contract failed" >&2
            rm -rf "$contract_root"
            rm -f "$contract_expected"
            return 1
        fi

        contract_freeze_rc=0
        if freeze_cross_direct_data_artifact \
                "generic $contract_runtime direct contract" "$contract_artifact" \
                -t -f "$contract_root_abs/*" -- "$contract_main"; then
            rm -rf "$contract_root"
            if ! verify_frozen_artifact "$contract_artifact" 0 \
                    "$contract_expected" combined; then
                echo "ERROR: generic $contract_runtime direct contract failed its producer smoke test" >&2
                rm -f "$contract_artifact" "$contract_expected"
                return 1
            fi

            contract_upx_state=plain
            if command -v upx >/dev/null 2>&1; then
                if make_upx_artifact "$contract_artifact" "$contract_upx" \
                        "generic-$contract_runtime" 0 "$contract_expected" \
                        combined; then
                    contract_upx_state=upx
                else
                    contract_upx_rc=$?
                    [ "$contract_upx_rc" -eq 1 ] || return 1
                fi
            fi
            printf '1|%s|direct|%s\n' \
                "$contract_runtime" "$contract_upx_state" >> "$contract_status"
        else
            contract_freeze_rc=$?
            rm -rf "$contract_root"
            rm -f "$contract_artifact" "$contract_expected" "$contract_upx"
            if [ "$contract_freeze_rc" -eq 77 ]; then
                printf '1|%s|unsupported|none\n' \
                    "$contract_runtime" >> "$contract_status"
            else
                return 1
            fi
        fi
    done

    if [ "$contract_runtime_count" -eq 0 ]; then
        echo "ERROR: no dynamic runtime was available for the generic direct contract" >&2
        return 1
    fi
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
    if pacman -S --help 2>&1 | grep -- '--disable-sandbox' >/dev/null; then
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
    pacman $pacman_sandbox_opt -S --noconfirm --needed zig 2>/dev/null || true
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
    "$PKG" install -y -q zig 2>/dev/null || true
    # Fedora exposes a real musl compiler wrapper in current releases.  Use it
    # when available so the static bootstrap has the audited post-handoff TLS
    # runtime required by direct mode; older releases may lack these packages.
    "$PKG" install -y -q musl-gcc musl-libc-static 2>/dev/null || true
    # Fedora's core repos do not include UPX, so the package install is
    # expected to fail.  Fall through to the GitHub fetch helper below.
    "$PKG" install -y -q upx 2>/dev/null || true
    "$PKG" install -y -q curl tar xz 2>/dev/null || true
    fetch_upx_from_github || true
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
make WERROR=1 -j"$(nproc)" 2>&1
echo ""
echo "Build artifacts:"
ls -la build/dlfreeze build/dlfreeze-bootstrap \
    build/dlfreeze-preload.so build/dlfreeze-preload-static.so
echo ""

# ── Run test suite (Docker-dependent tests auto-skip) ──────────────
echo "--- Test suite ---"
# The test suite skips tests whose prerequisites are missing (Docker,
# specific relocation types, etc.), but real failures must fail the build.
# Require direct-loader coverage exactly when this image has an admitted host
# runtime.  A clean extraction fallback is a capability result; compiler,
# packer, and ambiguous-output failures from the probe remain fatal.
if probe_direct_runtime_admission; then
    DLFREEZE_REQUIRE_DIRECT=1
else
    probe_rc=$?
    if [ "$probe_rc" -ne 1 ]; then
        exit 1
    fi
    DLFREEZE_REQUIRE_DIRECT=0
fi
export DLFREEZE_REQUIRE_DIRECT
echo "direct coverage required: $DLFREEZE_REQUIRE_DIRECT"
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

# The generic contract is the strict direct-loader coverage signal.  Every
# recognized producer libc gets its own artifact; unsupported runtimes are
# recorded explicitly so consumers can distinguish a capability result from a
# missing or silently downgraded test.
build_generic_direct_contracts "$OUTDIR"

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
    if make_upx_artifact "$OUTDIR/hello.frozen" \
            "$OUTDIR/hello.upx.frozen" hello 0 "$OUTDIR/hello.expected" \
            combined foo bar; then
        :
    else
        upx_rc=$?
        [ "$upx_rc" -eq 1 ] || exit 1
    fi
    if make_upx_artifact "$OUTDIR/exitcode.frozen" \
            "$OUTDIR/exitcode.upx.frozen" exitcode 0 - combined 0; then
        if ! verify_frozen_artifact "$OUTDIR/exitcode.upx.frozen" \
                42 - combined 42; then
            rm -f "$OUTDIR/exitcode.upx.frozen"
            exit 1
        fi
    else
        upx_rc=$?
        [ "$upx_rc" -eq 1 ] || exit 1
    fi
    echo "UPX compression: done"
else
    echo "UPX: not available, skipping compressed variants"
fi

# 4. Python3 — freeze a simple deterministic script (best effort)
if command -v python3 >/dev/null 2>&1; then
    if freeze_cross_direct_data_artifact python3 "$OUTDIR/python3.frozen" \
            -t -f '/usr/*' -- python3 -c 'print(1+2)'; then
        if ! python3 -c 'print(1+2)' >"$OUTDIR/python3.expected" 2>/dev/null ||
           ! verify_frozen_artifact "$OUTDIR/python3.frozen" 0 \
                "$OUTDIR/python3.expected" stdout -c 'print(1+2)'; then
            echo "ERROR: python3 direct artifact failed its producer smoke test" >&2
            exit 1
        fi
        if command -v upx >/dev/null 2>&1; then
            if make_upx_artifact "$OUTDIR/python3.frozen" \
                    "$OUTDIR/python3.upx.frozen" python3 0 \
                    "$OUTDIR/python3.expected" stdout -c 'print(1+2)'; then
                :
            else
                upx_rc=$?
                [ "$upx_rc" -eq 1 ] || exit 1
            fi
        fi
    else
        freeze_rc=$?
        [ "$freeze_rc" -eq 77 ] || exit 1
    fi
else
    echo "python3: not available, skipping"
fi

# 5. Ruby — freeze a simple deterministic script (best effort)
if command -v ruby >/dev/null 2>&1; then
    ruby_elf=$(resolve_ruby_elf || true)
    if [ -n "$ruby_elf" ] &&
       freeze_cross_direct_data_artifact ruby "$OUTDIR/ruby.frozen" \
            -t -f '/usr/*' -- "$ruby_elf" -e 'puts 1+2'; then
        # Ruby emits host-version/default-gem warnings on stderr which are
        # intentionally not a stable cross-distribution program result.
        # Preserve exit status and compare deterministic stdout; failures
        # still print a combined diagnostic retry in cross-run.sh.
        if ! "$ruby_elf" -e 'puts 1+2' \
                >"$OUTDIR/ruby.expected" 2>/dev/null ||
           ! verify_frozen_artifact "$OUTDIR/ruby.frozen" 0 \
                "$OUTDIR/ruby.expected" stdout -e 'puts 1+2'; then
            echo "ERROR: ruby direct artifact failed its producer smoke test" >&2
            exit 1
        fi
        if command -v upx >/dev/null 2>&1; then
            if make_upx_artifact "$OUTDIR/ruby.frozen" \
                    "$OUTDIR/ruby.upx.frozen" ruby 0 \
                    "$OUTDIR/ruby.expected" stdout -e 'puts 1+2'; then
                :
            else
                upx_rc=$?
                [ "$upx_rc" -eq 1 ] || exit 1
            fi
        fi
    else
        freeze_rc=$?
        if [ -z "$ruby_elf" ]; then
            echo "ruby: installed command has no ELF interpreter (skipping)"
        elif [ "$freeze_rc" -ne 77 ]; then
            exit 1
        fi
    fi
else
    echo "ruby: not available, skipping"
fi

echo ""
echo "Cross-test artifacts:"
ls -la "$OUTDIR/"
echo ""
echo "Cross-build: DONE"
