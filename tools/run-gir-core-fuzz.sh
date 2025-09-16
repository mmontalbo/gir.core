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
  instrument         Build and instrument the SourceFunc harness (default).
  afl                Instrument the harness (unless --skip-instrument) and launch AFL++.

Options:
  --skip-instrument  Skip rebuilding the harness when running the 'afl' command.
  -h, --help         Show this help text and exit.

When running 'afl' without extra options, a seed corpus is created in
${DEFAULT_CORPUS_DIR} and AFL++ writes findings to a timestamped folder under
${DEFAULT_FINDINGS_DIR_BASE}.

To provide custom AFL++ options (for example, to reuse an existing corpus),
append them after "--". The harness command "dotnet ${ASSEMBLY_NAME} @@" is
appended automatically.
EOF
}

COMMAND="instrument"
SKIP_INSTRUMENT=0
declare -a AFL_ARGS=()

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

  maybe_warn_core_pattern

  if [[ ${SKIP_INSTRUMENT} -eq 0 ]]; then
    instrument_harness
  elif [[ ! -f "${ASSEMBLY_PATH}" ]]; then
    echo "--skip-instrument was specified but ${ASSEMBLY_PATH} does not exist." >&2
    echo "Build and instrument the harness first by running '$(basename "$0") instrument'." >&2
    exit 1
  fi

  local -a afl_cmd

  if [[ ${#AFL_ARGS[@]} -eq 0 ]]; then
    local corpus_dir="${DEFAULT_CORPUS_DIR}"
    local findings_dir="${DEFAULT_FINDINGS_DIR_BASE}/run-$(date +%Y%m%d-%H%M%S)"

    mkdir -p "${corpus_dir}"

    local default_seed="${corpus_dir}/seed-default"

    if [[ ! -s "${default_seed}" ]]; then
      printf 'seed' >"${default_seed}"
    fi

    mkdir -p "${findings_dir}"

    echo "Launching AFL++ with seed corpus at ${corpus_dir}."
    echo "Findings will be written to ${findings_dir}."

    afl_cmd=("afl-fuzz" "-i" "${corpus_dir}" "-o" "${findings_dir}" "--" "${dotnet_path}" "${ASSEMBLY_PATH}" "@@")
  else
    echo "Launching AFL++ with custom arguments: ${AFL_ARGS[*]}"
    afl_cmd=("afl-fuzz" "${AFL_ARGS[@]}" "--" "${dotnet_path}" "${ASSEMBLY_PATH}" "@@")
  fi

  exec "${afl_cmd[@]}"
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
