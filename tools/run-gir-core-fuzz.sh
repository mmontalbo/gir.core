#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GIR_CORE_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

PROJECT_PATH="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/SourceFuncFuzzer.csproj"
PROPS_FILE="${REPO_ROOT}/properties/GirCore.Fuzzing.props"
GENERATED_IMPORT_RESOLVER="${REPO_ROOT}/src/Libs/GObject-2.0/Internal/ImportResolver.Generated.cs"
PUBLISH_ROOT="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release"
PUBLISH_DIR="${PUBLISH_ROOT}/publish"
INSTRUMENTED_DIR="${PUBLISH_ROOT}/instrumented"
ASSEMBLY_NAME="SourceFuncFuzzer.dll"
ASSEMBLY_PATH="${INSTRUMENTED_DIR}/${ASSEMBLY_NAME}"
DEFAULT_CORPUS_DIR="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/corpus"
DEFAULT_FINDINGS_DIR_BASE="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/findings"

usage() {
  cat <<EOF
Usage: $(basename "$0") [instrument|afl] [options] [-- [afl-fuzz options]]

Commands:
  instrument           Build and instrument the SourceFunc harness (default).
  afl                  Instrument the harness (unless --skip-instrument) and launch AFL++.

Options:
  --skip-instrument    Skip rebuilding the harness when running the 'afl' command.
  --single             Launch a single AFL++ instance instead of a multi-core campaign.
  --workers <count>    Override the number of AFL++ instances (defaults to detected cores, capped at 32).
  --memory <mb|none>   Override the AFL++ memory limit (-m). Use 'none' to disable the cap.
  --testcache <mb>     Set AFL_TESTCACHE_SIZE when launching AFL++ (default: 200 MB).
  -h, --help           Show this help text and exit.

When running 'afl' without extra options, a seed corpus is created in
${DEFAULT_CORPUS_DIR} and AFL++ writes findings to a timestamped folder under
${DEFAULT_FINDINGS_DIR_BASE}. The helper launches a primary master instance and
secondary workers with varied schedules so the harness is fuzzed across multiple
CPU cores. Pass --single to revert to the legacy one-worker behaviour, or append
custom AFL++ parameters after "--" to take full control of the invocation.

The harness command "dotnet ${ASSEMBLY_NAME}" is appended automatically and
AFL++ streams inputs to the harness via STDIN.
EOF
}

COMMAND="instrument"
SKIP_INSTRUMENT=0
SERIOUS_MODE=1
FORCE_SINGLE=0
REQUESTED_WORKERS=""
REQUESTED_MEMORY=""
REQUESTED_TESTCACHE=""
WORKER_COUNT_VALUE=""
TESTCACHE_VALUE=""
MEMORY_LIMIT_VALUE=""
declare -a AFL_ARGS=()
declare -a AFL_SECONDARY_PIDS=()

cleanup_secondaries() {
  if [[ ${#AFL_SECONDARY_PIDS[@]} -eq 0 ]]; then
    return
  fi

  echo "Stopping secondary AFL++ instances..." >&2
  kill "${AFL_SECONDARY_PIDS[@]}" 2>/dev/null || true
  wait "${AFL_SECONDARY_PIDS[@]}" 2>/dev/null || true
  AFL_SECONDARY_PIDS=()
}

if [[ ! -f "${PROJECT_PATH}" ]]; then
  echo "Unable to locate the SourceFuncFuzzer project at ${PROJECT_PATH}." >&2
  exit 1
fi

if [[ ! -f "${PROPS_FILE}" ]]; then
  echo "Unable to locate ${PROPS_FILE}." >&2
  exit 1
fi

parse_args() {
  if [[ $# -gt 0 ]]; then
    case "$1" in
      instrument|afl)
        COMMAND="$1"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        echo "The '--' separator is only valid with the 'afl' command." >&2
        usage >&2
        exit 1
        ;;
      *)
        echo "Unknown command: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-instrument)
        SKIP_INSTRUMENT=1
        shift
        ;;
      --single)
        FORCE_SINGLE=1
        SERIOUS_MODE=0
        shift
        ;;
      --serious)
        SERIOUS_MODE=1
        FORCE_SINGLE=0
        shift
        ;;
      --workers)
        if [[ $# -lt 2 ]]; then
          echo "--workers requires a count" >&2
          usage >&2
          exit 1
        fi
        REQUESTED_WORKERS="$2"
        shift 2
        ;;
      --memory)
        if [[ $# -lt 2 ]]; then
          echo "--memory requires a value in megabytes or 'none'" >&2
          usage >&2
          exit 1
        fi
        REQUESTED_MEMORY="$2"
        shift 2
        ;;
      --testcache)
        if [[ $# -lt 2 ]]; then
          echo "--testcache requires a size in megabytes" >&2
          usage >&2
          exit 1
        fi
        REQUESTED_TESTCACHE="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        AFL_ARGS=("$@")
        break
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

maybe_warn_core_pattern() {
  local core_pattern_path="/proc/sys/kernel/core_pattern"

  if [[ ! -r "${core_pattern_path}" ]]; then
    return
  fi

  local core_pattern
  core_pattern="$(<"${core_pattern_path}")"

  if [[ "${core_pattern}" == \|* ]]; then
    echo "Warning: ${core_pattern_path} pipes core dumps to an external handler." >&2
    echo "         AFL++ may treat crashes as timeouts until this is adjusted." >&2

    if [[ -z "${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-}" ]]; then
      export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
      echo "         Setting AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 for this session." >&2
      echo "         To handle crashes immediately instead, run 'echo core | sudo tee ${core_pattern_path}' before fuzzing." >&2
    else
      echo "         AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES}." >&2
      echo "         Consider adjusting ${core_pattern_path} to write core files directly." >&2
    fi
  fi
}

instrument_harness() {
  if [[ ! -f "${GENERATED_IMPORT_RESOLVER}" ]]; then
    echo "Generated bindings are required but ${GENERATED_IMPORT_RESOLVER} was not found." >&2
    echo "Run 'dotnet fsi scripts/GenerateLibs.fsx' before instrumenting the harness." >&2
    exit 1
  fi

  local sharpfuzz_version
  sharpfuzz_version=$(sed -n 's/.*<SharpFuzzVersion>\(.*\)<\/SharpFuzzVersion>.*/\1/p' "${PROPS_FILE}" | head -n 1)

  if [[ -z "${sharpfuzz_version}" ]]; then
    echo "Failed to read SharpFuzzVersion from ${PROPS_FILE}." >&2
    exit 1
  fi

  if ! command -v dotnet >/dev/null 2>&1; then
    echo "The dotnet CLI is required. Install the .NET SDK (9.0 or later) and ensure 'dotnet' is on your PATH." >&2
    exit 1
  fi

  if ! command -v sharpfuzz >/dev/null 2>&1; then
    echo "SharpFuzz.CommandLine is required. Install or update it with 'dotnet tool update --global SharpFuzz.CommandLine --version ${sharpfuzz_version}' (run with 'install' instead of 'update' if needed)." >&2
    exit 1
  fi

  echo "Building SourceFuncFuzzer harness..."
  dotnet publish "${PROJECT_PATH}" -c Release -o "${PUBLISH_DIR}"

  echo "Preparing instrumented output directory..."
  rm -rf "${INSTRUMENTED_DIR}"
  mkdir -p "${INSTRUMENTED_DIR}"
  cp -a "${PUBLISH_DIR}/." "${INSTRUMENTED_DIR}"

  if [[ ! -f "${ASSEMBLY_PATH}" ]]; then
    echo "The published assembly could not be found at ${ASSEMBLY_PATH}." >&2
    exit 1
  fi

  echo "Instrumenting ${ASSEMBLY_NAME} with SharpFuzz..."
  if ! sharpfuzz "${ASSEMBLY_PATH}" GirCore.Fuzzing.SourceFuncFuzzer; then
    echo "SharpFuzz instrumentation failed." >&2
    exit 1
  fi

  echo "Instrumentation complete."
  echo "Instrumented assembly: ${ASSEMBLY_PATH}"
  echo "Use the files in ${INSTRUMENTED_DIR} as the harness when running your fuzzer."

  if [[ "${COMMAND}" != "afl" ]]; then
    echo "Run '$(basename "$0") afl' to start AFL++ with the default configuration."
  fi
}

run_afl() {
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "The dotnet CLI is required to execute the harness. Install the .NET SDK (9.0 or later)." >&2
    exit 1
  fi

  local dotnet_path
  dotnet_path="$(command -v dotnet)"

  if ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "afl-fuzz was not found on PATH. Install AFL++ or enter the provided Nix shell." >&2
    exit 1
  fi

  : "${AFL_SKIP_CPUFREQ:=1}"
  export AFL_SKIP_CPUFREQ

  if [[ -z "${AFL_SKIP_BIN_CHECK:-}" ]]; then
    export AFL_SKIP_BIN_CHECK=1
    echo "Setting AFL_SKIP_BIN_CHECK=1 so AFL++ accepts the managed harness." >&2
  fi

  if [[ -z "${AFL_IMPORT_FIRST:-}" ]]; then
    export AFL_IMPORT_FIRST=1
    echo "Setting AFL_IMPORT_FIRST=1 so synchronized queues are imported first." >&2
  fi

  if [[ -z "${AFL_IGNORE_SEED_PROBLEMS:-}" ]]; then
    export AFL_IGNORE_SEED_PROBLEMS=1
    echo "Setting AFL_IGNORE_SEED_PROBLEMS=1 to skip crashing seeds during warmup." >&2
  fi

  if [[ -z "${AFL_INPUT_LEN_MIN:-}" ]]; then
    export AFL_INPUT_LEN_MIN=1
    echo "Setting AFL_INPUT_LEN_MIN=1 so SourceFunc inputs remain non-empty." >&2
  fi

  if [[ -z "${AFL_TESTCACHE_SIZE:-}" ]]; then
    local cache_target=""

    if [[ -n "${TESTCACHE_VALUE}" ]]; then
      cache_target="${TESTCACHE_VALUE}"
    else
      cache_target=200
    fi

    if [[ -n "${cache_target}" && ${cache_target} -gt 0 ]]; then
      export AFL_TESTCACHE_SIZE="${cache_target}"
      echo "Setting AFL_TESTCACHE_SIZE=${cache_target} to cache test cases in memory." >&2
    fi
  fi

  maybe_warn_core_pattern

  if [[ ${SKIP_INSTRUMENT} -eq 0 ]]; then
    instrument_harness
  elif [[ ! -f "${ASSEMBLY_PATH}" ]]; then
    echo "--skip-instrument was specified but ${ASSEMBLY_PATH} does not exist." >&2
    echo "Build and instrument the harness first by running '$(basename "$0") instrument'." >&2
    exit 1
  fi

  local corpus_dir="${DEFAULT_CORPUS_DIR}"
  local findings_dir="${DEFAULT_FINDINGS_DIR_BASE}/run-$(date +%Y%m%d-%H%M%S)"
  local default_seed="${corpus_dir}/seed-default"

  mkdir -p "${corpus_dir}" "${findings_dir}"

  if [[ ! -s "${default_seed}" ]]; then
    printf 'seed' >"${default_seed}"
  fi

  local -a harness_tail=( "--" "${dotnet_path}" "${ASSEMBLY_PATH}" )

  if [[ ${#AFL_ARGS[@]} -gt 0 ]]; then
    echo "Launching AFL++ with custom arguments: ${AFL_ARGS[*]}"
    local -a afl_cmd=( "afl-fuzz" )

    if [[ -n "${MEMORY_LIMIT_VALUE}" ]]; then
      if [[ "${MEMORY_LIMIT_VALUE}" == "none" ]]; then
        echo "Disabling AFL++ memory limit (-m none)."
      else
        echo "Setting AFL++ memory limit to ${MEMORY_LIMIT_VALUE} MB."
      fi
      afl_cmd+=( "-m" "none" )
    fi

    afl_cmd+=( "${AFL_ARGS[@]}" "${harness_tail[@]}" )
    exec "${afl_cmd[@]}"
  fi

  local cpu_count_raw=""

  if command -v getconf >/dev/null 2>&1; then
    cpu_count_raw="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  fi

  if [[ -z "${cpu_count_raw}" ]] && command -v nproc >/dev/null 2>&1; then
    cpu_count_raw="$(nproc 2>/dev/null || true)"
  fi

  local cpu_count=1

  if [[ "${cpu_count_raw}" =~ ^[0-9]+$ ]]; then
    cpu_count=$((10#${cpu_count_raw}))
  fi

  if (( cpu_count < 1 )); then
    cpu_count=1
  fi

  local worker_count=1

  if [[ -n "${WORKER_COUNT_VALUE}" ]]; then
    worker_count=${WORKER_COUNT_VALUE}
  elif (( FORCE_SINGLE )); then
    worker_count=1
  elif (( SERIOUS_MODE )); then
    worker_count=${cpu_count}

    if (( worker_count > 32 )); then
      worker_count=32
    fi
  fi

  if (( worker_count < 1 )); then
    worker_count=1
  fi

  local -a base_cmd=( "afl-fuzz" "-i" "${corpus_dir}" "-o" "${findings_dir}" )

  if [[ -n "${MEMORY_LIMIT_VALUE}" ]]; then
    if [[ "${MEMORY_LIMIT_VALUE}" == "none" ]]; then
      echo "Disabling AFL++ memory limit (-m none)."
    else
      echo "Setting AFL++ memory limit to ${MEMORY_LIMIT_VALUE} MB."
    fi
    base_cmd+=( "-m" "${MEMORY_LIMIT_VALUE}" )
  fi

  if (( worker_count == 1 )); then
    echo "Launching AFL++ with seed corpus at ${corpus_dir}."
    echo "Findings will be written to ${findings_dir}."
    local -a afl_cmd=( "${base_cmd[@]}" "${harness_tail[@]}" )
    exec "${afl_cmd[@]}"
  fi

  local secondary_count=$((worker_count - 1))
  local host_tag

  host_tag="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)"
  host_tag="${host_tag//[^A-Za-z0-9_-]/}" 

  if [[ -z "${host_tag}" ]]; then
    host_tag="host"
  fi

  local main_name="main-${host_tag}"
  local logs_dir="${findings_dir}/logs"
  mkdir -p "${logs_dir}"

  echo "Launching AFL++ campaign with ${worker_count} workers (1 master, ${secondary_count} secondary)."
  echo "Seed corpus: ${corpus_dir}"
  echo "Findings directory: ${findings_dir}"

  local -a secondary_variants=(
    "mopt|-L 0 -p fast|"
    "trim-explore|-p explore|AFL_DISABLE_TRIM=1"
    "trim-exploit|-p exploit|AFL_DISABLE_TRIM=1"
    "trim-rare|-p rare|AFL_DISABLE_TRIM=1"
    "trim-lin|-p lin|AFL_DISABLE_TRIM=1"
    "oldqueue|-Z -p coe|AFL_DISABLE_TRIM=1"
    "ascii|-a ascii -p explore|"
    "binary|-a binary -p exploit|"
    "fast|-p fast|AFL_DISABLE_TRIM=1"
    "quad|-p quad|"
  )

  AFL_SECONDARY_PIDS=()

  local variant_count=${#secondary_variants[@]}

  for ((i = 0; i < secondary_count; i++)); do
    local variant="${secondary_variants[i % variant_count]}"
    local variant_name=""
    local variant_opts=""
    local variant_env=""

    IFS='|' read -r variant_name variant_opts variant_env <<<"${variant}"

    if [[ -z "${variant_name}" ]]; then
      variant_name="sec"
    fi

    local fuzzer_name
    fuzzer_name="${variant_name}-$((i + 1))-${host_tag}"
    fuzzer_name="${fuzzer_name//[^A-Za-z0-9_-]/-}"

    local -a cmd=( "${base_cmd[@]}" "-S" "${fuzzer_name}" )

    if [[ -n "${variant_opts}" ]]; then
      read -r -a variant_opts_array <<<"${variant_opts}"
      cmd+=( "${variant_opts_array[@]}" )
    fi

    local -a env_prefix=( "env" )

    if [[ -n "${variant_env}" ]]; then
      IFS=',' read -r -a variant_env_array <<<"${variant_env}"
      for env_entry in "${variant_env_array[@]}"; do
        if [[ -n "${env_entry}" ]]; then
          env_prefix+=( "${env_entry}" )
        fi
      done
    fi

    cmd+=( "${harness_tail[@]}" )

    local log_file="${logs_dir}/${fuzzer_name}.log"
    echo "  Secondary ${fuzzer_name}: ${variant_opts:-default schedule}${variant_env:+ (env: ${variant_env})} -> ${log_file}"
    env_prefix+=( "${cmd[@]}" )
    "${env_prefix[@]}" >>"${log_file}" 2>&1 &
    AFL_SECONDARY_PIDS+=($!)
  done

  trap cleanup_secondaries EXIT

  echo "Master ${main_name} running in the foreground. Press Ctrl+C to stop the campaign."

  local -a main_cmd=( "${base_cmd[@]}" "-M" "${main_name}" "-p" "explore" "${harness_tail[@]}" )

  env AFL_FINAL_SYNC=1 "${main_cmd[@]}"
  local main_status=$?

  trap - EXIT
  cleanup_secondaries

  return ${main_status}
}

main() {
  parse_args "$@"

  if [[ "${COMMAND}" != "afl" && ${SKIP_INSTRUMENT} -ne 0 ]]; then
    echo "--skip-instrument is only valid with the 'afl' command." >&2
    usage >&2
    exit 1
  fi

  if [[ "${COMMAND}" != "afl" && ${#AFL_ARGS[@]} -gt 0 ]]; then
    echo "Additional arguments are only supported with the 'afl' command." >&2
    usage >&2
    exit 1
  fi

  if [[ "${COMMAND}" != "afl" ]]; then
    if (( FORCE_SINGLE )); then
      echo "--single is only available with the 'afl' command." >&2
      usage >&2
      exit 1
    fi

    if [[ -n "${REQUESTED_WORKERS}" ]]; then
      echo "--workers is only available with the 'afl' command." >&2
      usage >&2
      exit 1
    fi

    if [[ -n "${REQUESTED_TESTCACHE}" ]]; then
      echo "--testcache is only available with the 'afl' command." >&2
      usage >&2
      exit 1
    fi

    if [[ -n "${REQUESTED_MEMORY}" ]]; then
      echo "--memory is only available with the 'afl' command." >&2
      usage >&2
      exit 1
    fi
  fi

  if [[ -n "${REQUESTED_WORKERS}" ]]; then
    if [[ ! "${REQUESTED_WORKERS}" =~ ^[0-9]+$ ]]; then
      echo "--workers requires a positive integer." >&2
      exit 1
    fi

    WORKER_COUNT_VALUE=$((10#${REQUESTED_WORKERS}))

    if (( WORKER_COUNT_VALUE < 1 )); then
      echo "--workers must be at least 1." >&2
      exit 1
    fi
  fi

  if [[ -n "${REQUESTED_TESTCACHE}" ]]; then
    if [[ ! "${REQUESTED_TESTCACHE}" =~ ^[0-9]+$ ]]; then
      echo "--testcache requires a non-negative integer." >&2
      exit 1
    fi

    TESTCACHE_VALUE=$((10#${REQUESTED_TESTCACHE}))
  fi

  if [[ -n "${REQUESTED_MEMORY}" ]]; then
    if [[ "${REQUESTED_MEMORY}" == "none" ]]; then
      MEMORY_LIMIT_VALUE="none"
    elif [[ "${REQUESTED_MEMORY}" =~ ^[0-9]+$ ]]; then
      MEMORY_LIMIT_VALUE=$((10#${REQUESTED_MEMORY}))
      if (( MEMORY_LIMIT_VALUE < 0 )); then
        echo "--memory requires a non-negative integer or 'none'." >&2
        exit 1
      fi
    else
      echo "--memory requires a non-negative integer or 'none'." >&2
      exit 1
    fi
  fi

  if (( FORCE_SINGLE )); then
    if [[ -n "${WORKER_COUNT_VALUE}" ]] && (( WORKER_COUNT_VALUE > 1 )); then
      echo "--single cannot be combined with --workers values greater than 1." >&2
      exit 1
    fi
  fi

  case "${COMMAND}" in
    instrument)
      instrument_harness
      ;;
    afl)
      run_afl
      ;;
    *)
      echo "Unexpected command: ${COMMAND}" >&2
      exit 1
      ;;
  esac
}

main "$@"
