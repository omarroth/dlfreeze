#!/usr/bin/env bash
set -euo pipefail

# Use this file as all three mock executables. The frozen mock has a footer
# appended after the script; each mock branch exits before reading that data.
case "${0##*/}" in
    dlfreeze)
        [[ "$#" == 3 && "$1" == -o && "$3" == "$BENCH_GATE_BIN" ]]
        out="$2"
        cp "$3" "$out"
        {
            if [[ "$BENCH_GATE_MODE" == bad-magic ]]; then
                printf 'BADMAGIC'
            else
                printf 'DLFREEZ\0'
            fi
            printf '\0%.0s' {1..32}
            case "$BENCH_GATE_MODE" in
                direct)     printf '\1\0\0\0\0\0\0\0' ;;
                bad-offset) printf '\377%.0s' {1..8} ;;
                *)          printf '\0%.0s' {1..8} ;;
            esac
            printf '\0%.0s' {1..16}
        } >> "$out"
        exit 0
        ;;
    workload|*.frozen)
        [[ "$#" == 1 && "$1" == --version ]]
        [[ "$QT_QPA_PLATFORM" == benchmark-env-sentinel ]]
        printf '%s\t%s\t%s\n' "${0##*/}" "$1" "$QT_QPA_PLATFORM" >> "$BENCH_GATE_LOG"
        printf 'generic version fixture\n'
        exit 0
        ;;
    perf)
        [[ "$1" == stat ]]
        shift
        csv=0 out=""
        while [[ "$#" -gt 0 ]]; do
            case "$1" in
                -x,) csv=1; shift ;;
                -o) out="$2"; shift 2 ;;
                -e) shift 2 ;;
                --no-big-num) shift ;;
                --) shift; break ;;
                *) exit 1 ;;
            esac
        done
        [[ -n "$out" && "$#" -gt 0 ]]
        factor=1
        [[ "$1" != *.frozen ]] || factor=2
        "$@"
        if [[ "$csv" == 1 ]]; then
            printf '%d,,cycles,\n%d,,page-faults,\n%d,nsec,task-clock,\n' \
                "$((100 * factor))" "$((10 * factor))" "$((1000000 * factor))" > "$out"
        else
            printf '0.00%d seconds time elapsed\n' "$((2 * factor))" > "$out"
        fi
        exit 0
        ;;
esac

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/bin" "$root/build dir"
script="$(realpath "$0")"
for mock in perf workload; do
    cp "$script" "$root/bin/$mock"
    chmod +x "$root/bin/$mock"
done
cp "$script" "$root/build dir/dlfreeze"
chmod +x "$root/build dir/dlfreeze"

run_mock() {
    PATH="$root/bin:$PATH" BENCH_GATE_BIN="$root/bin/workload" \
        BENCH_GATE_MODE="$1" BENCH_GATE_LOG="$root/calls" \
        QT_QPA_PLATFORM=benchmark-env-sentinel \
        KMAIL_BIN="${2:-$root/bin/workload}" BENCH_CASES=kmail BENCH_RUNS=2 \
        BENCH_DIR="$root/results $1" bash tests/run_benchmarks.sh "$root/build dir"
}

for mode in direct extraction; do
    : > "$root/calls"
    run_mock "$mode" > "$root/$mode.log" 2>&1
    awk -F '\t' -v mode="$mode" '
        NR == 1 { if (NF != 14 || $14 != "artifact_mode") exit 1; next }
        NR == 2 {
            if (NF != 14 || $1 != "kmail --version" ||
                $2 != 100 || $3 != 200 || $4 != "2.00x" ||
                $5 != 10 || $6 != 20 || $7 != "2.00x" ||
                $8 != 1 || $9 != 2 || $10 != "2.00x" ||
                $11 != 2 || $12 != 4 || $13 != "2.00x" || $14 != mode)
                exit 1;
        }
        END { if (NR != 2) exit 1 }
    ' "$root/results $mode/startup-bench.tsv"
    [[ "$(wc -l < "$root/calls")" -eq 10 ]]
    [[ "$(awk -F '\t' '$1 == "workload" {n++} END {print n+0}' "$root/calls")" -eq 5 ]]
    [[ "$(awk -F '\t' '$1 == "kmail.frozen" {n++} END {print n+0}' "$root/calls")" -eq 5 ]]
done

for mode in bad-magic bad-offset; do
    : > "$root/calls"
    if run_mock "$mode" > "$root/$mode.log" 2>&1; then
        printf 'benchmark accepted %s artifact\n' "$mode" >&2
        exit 1
    fi
    [[ ! -s "$root/calls" ]]
    grep -Eq '^error: artifact (has invalid footer magic|metadata offset lies outside payload):' \
        "$root/$mode.log"
done

: > "$root/calls"
run_mock missing "$root/no-such-binary" > "$root/missing.log" 2>&1
grep -q '^SKIP: kmail (missing binary:' "$root/missing.log"
[[ "$(wc -l < "$root/results missing/startup-bench.tsv")" -eq 1 ]]
[[ ! -s "$root/calls" ]]

printf 'benchmark workload, environment, metric and artifact-mode gates passed\n'
