#!/usr/bin/env bash
set -euo pipefail

BUILD="${1:-build}"
DLFREEZE="$BUILD/dlfreeze"
BENCH_DIR="${BENCH_DIR:-$BUILD/bench}"
BENCH_RUNS="${BENCH_RUNS:-1}"
BENCH_WARM_CACHE="${BENCH_WARM_CACHE:-1}"
BENCH_CASES_RAW="${BENCH_CASES:-ls python clang ffmpeg ffmpeg-traced}"
SUMMARY_FILE="$BENCH_DIR/startup-bench.tsv"

find_first_binary() {
    local candidate
    for candidate in "$@"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

LS_BIN="${LS_BIN:-$(find_first_binary /bin/ls ls || true)}"
PYTHON_BIN="${PYTHON_BIN:-$(find_first_binary python3 || true)}"
CLANG_BIN="${CLANG_BIN:-$(find_first_binary clang clang-22 clang-21 clang-20 clang-19 clang-18 clang-17 clang-16 clang-15 || true)}"
FFMPEG_BIN="${FFMPEG_BIN:-$(find_first_binary ffmpeg || true)}"

if [[ "${BUILD}" == "-h" || "${BUILD}" == "--help" ]]; then
    cat <<'EOF'
Usage: tests/run_benchmarks.sh [build-dir]

Environment overrides:
  BENCH_CASES        Space- or comma-separated cases to run.
                     Default: ls python clang ffmpeg ffmpeg-traced
  BENCH_RUNS         Number of measured perf runs to average. Default: 1
  BENCH_WARM_CACHE   Run one untimed warm-up before measuring. Default: 1
  BENCH_DIR          Output directory for frozen binaries/results.
  LS_BIN             Native ls path.
  PYTHON_BIN         Native python path.
  CLANG_BIN          Native clang path.
  FFMPEG_BIN         Native ffmpeg path.

Examples:
  make bench
  BENCH_CASES=ffmpeg make bench
  BENCH_RUNS=5 BENCH_CASES='clang ffmpeg' make bench
EOF
    exit 0
fi

die() {
    echo "error: $*" >&2
    exit 1
}

note() {
    echo "$*"
}

skip_case() {
    echo "SKIP: $1"
}

normalize_task_clock_ms() {
    local value="$1"
    local unit="$2"
    case "$unit" in
        msec) printf '%s\n' "$value" ;;
        usec) awk -v v="$value" 'BEGIN { printf "%.6f\n", v / 1000.0 }' ;;
        sec)  awk -v v="$value" 'BEGIN { printf "%.6f\n", v * 1000.0 }' ;;
        nsec) awk -v v="$value" 'BEGIN { printf "%.6f\n", v / 1000000.0 }' ;;
        *)    printf '%s\n' "$value" ;;
    esac
}

parse_perf_file() {
    local perf_file="$1"
    local cycles=""
    local page_faults=""
    local task_clock_ms=""
    local value unit event _rest

    while IFS=, read -r value unit event _rest; do
        case "$event" in
            cycles*)
                cycles="$value"
                ;;
            page-faults*)
                page_faults="$value"
                ;;
            task-clock*)
                task_clock_ms="$(normalize_task_clock_ms "$value" "$unit")"
                ;;
        esac
    done < "$perf_file"

    [[ -n "$cycles" && -n "$page_faults" && -n "$task_clock_ms" ]] || \
        die "failed to parse perf output from $perf_file"

    printf '%s\t%s\t%s\n' "$cycles" "$page_faults" "$task_clock_ms"
}

measure_command() {
    local perf_file samples metrics
    local -a cmd=("$@")

    perf_file="$(mktemp)"
    samples="$(mktemp)"

    if [[ "$BENCH_WARM_CACHE" != "0" ]]; then
        "${cmd[@]}" >/dev/null 2>&1 || die "warm-up failed: ${cmd[*]}"
    fi

    for ((run = 1; run <= BENCH_RUNS; run++)); do
        : > "$perf_file"
        if ! perf stat -x, --no-big-num -o "$perf_file" \
            -e cycles,page-faults,task-clock -- \
            "${cmd[@]}" >/dev/null 2>/dev/null; then
            rm -f "$perf_file" "$samples"
            die "perf stat failed: ${cmd[*]}"
        fi
        parse_perf_file "$perf_file" >> "$samples"
    done

    metrics="$(awk -F '\t' '
        { cycles += $1; faults += $2; clock += $3; runs += 1 }
        END {
            if (runs == 0) exit 1;
            printf "%.0f\t%.0f\t%.6f\n", cycles / runs, faults / runs, clock / runs;
        }
    ' "$samples")"

    rm -f "$perf_file" "$samples"
    printf '%s\n' "$metrics"
}

ratio_string() {
    local lhs="$1"
    local rhs="$2"
    awk -v lhs="$lhs" -v rhs="$rhs" 'BEGIN {
        if (rhs == 0) {
            print "n/a";
        } else {
            printf "%.2fx", lhs / rhs;
        }
    }'
}

run_case() {
    local case_id="$1"
    local desc=""
    local bin=""
    local out=""
    local native_metrics frozen_metrics
    local native_cycles native_faults native_ms
    local frozen_cycles frozen_faults frozen_ms
    local cycles_ratio faults_ratio ms_ratio
    local -a freeze_cmd=()
    local -a native_cmd=()
    local -a frozen_cmd=()

    case "$case_id" in
        ls)
            desc="ls"
            bin="$LS_BIN"
            out="$BENCH_DIR/ls.frozen"
            freeze_cmd=("$DLFREEZE" -d -o "$out" "$bin")
            native_cmd=("$bin")
            frozen_cmd=("$out")
            ;;
        python)
            desc="python3 --version"
            bin="$PYTHON_BIN"
            out="$BENCH_DIR/python3.frozen"
            freeze_cmd=("$DLFREEZE" -d -o "$out" "$bin")
            native_cmd=("$bin" --version)
            frozen_cmd=("$out" --version)
            ;;
        clang)
            desc="clang --version"
            bin="$CLANG_BIN"
            out="$BENCH_DIR/clang.frozen"
            freeze_cmd=("$DLFREEZE" -d -o "$out" "$bin")
            native_cmd=("$bin" --version)
            frozen_cmd=("$out" --version)
            ;;
        ffmpeg)
            desc="ffmpeg -version"
            bin="$FFMPEG_BIN"
            out="$BENCH_DIR/ffmpeg.frozen"
            freeze_cmd=("$DLFREEZE" -d -o "$out" "$bin")
            native_cmd=("$bin" -version)
            frozen_cmd=("$out" -version)
            ;;
        ffmpeg-traced)
            desc="ffmpeg -version (traced)"
            bin="$FFMPEG_BIN"
            out="$BENCH_DIR/ffmpeg-traced.frozen"
            freeze_cmd=("$DLFREEZE" -d -t -o "$out" -- "$bin" -version)
            native_cmd=("$bin" -version)
            frozen_cmd=("$out" -version)
            ;;
        *)
            die "unknown benchmark case: $case_id"
            ;;
    esac

    if [[ -z "$bin" || ! -x "$bin" ]]; then
        skip_case "$case_id (missing binary: $bin)"
        return 0
    fi

    note "--- $case_id ---"
    note "freezing: $bin -> $out"
    "${freeze_cmd[@]}"

    native_metrics="$(measure_command "${native_cmd[@]}")"
    frozen_metrics="$(measure_command "${frozen_cmd[@]}")"

    IFS=$'\t' read -r native_cycles native_faults native_ms <<< "$native_metrics"
    IFS=$'\t' read -r frozen_cycles frozen_faults frozen_ms <<< "$frozen_metrics"

    cycles_ratio="$(ratio_string "$frozen_cycles" "$native_cycles")"
    faults_ratio="$(ratio_string "$frozen_faults" "$native_faults")"
    ms_ratio="$(ratio_string "$frozen_ms" "$native_ms")"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$desc" \
        "$native_cycles" "$frozen_cycles" "$cycles_ratio" \
        "$native_faults" "$frozen_faults" "$faults_ratio" \
        "$native_ms" "$frozen_ms" "$ms_ratio" \
        >> "$SUMMARY_FILE"
}

[[ -x "$DLFREEZE" ]] || die "missing executable: $DLFREEZE (run make first)"
command -v perf >/dev/null 2>&1 || die "perf is required for benchmarks"

mkdir -p "$BENCH_DIR"

if ! perf stat -x, --no-big-num -o /dev/null -e cycles,page-faults,task-clock -- true >/dev/null 2>/dev/null; then
    die "perf stat failed; check perf permissions on this system"
fi

printf 'workload\tnative_cycles\tfrozen_cycles\tcycles_ratio\tnative_faults\tfrozen_faults\tfaults_ratio\tnative_ms\tfrozen_ms\tms_ratio\n' > "$SUMMARY_FILE"

note "======== dlfreeze startup benchmarks ========"
note "build dir       : $BUILD"
note "bench dir       : $BENCH_DIR"
note "runs per case   : $BENCH_RUNS"
note "warm cache      : $([[ "$BENCH_WARM_CACHE" == "0" ]] && echo no || echo yes)"

BENCH_CASES_EXPANDED="${BENCH_CASES_RAW//,/ }"
for case_id in $BENCH_CASES_EXPANDED; do
    run_case "$case_id"
done

note
note "Summary"
awk -F '\t' '
    NR == 1 {
        printf "%-24s %14s %14s %10s %14s %14s %10s %11s %11s %10s\n",
            "workload",
            "native cycles", "frozen cycles", "ratio",
            "native faults", "frozen faults", "ratio",
            "native ms", "frozen ms", "ratio";
        next;
    }
    {
        printf "%-24s %14s %14s %10s %14s %14s %10s %11.3f %11.3f %10s\n",
            $1, $2, $3, $4, $5, $6, $7, $8 + 0.0, $9 + 0.0, $10;
    }
' "$SUMMARY_FILE"

note
note "Wrote $SUMMARY_FILE"