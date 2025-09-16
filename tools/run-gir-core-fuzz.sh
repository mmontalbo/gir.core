#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GIR_CORE_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
PROJECT_PATH="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/SourceFuncFuzzer.csproj"
PROPS_FILE="${REPO_ROOT}/properties/GirCore.Fuzzing.props"
PUBLISH_DIR="${REPO_ROOT}/src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release/net8.0/publish"
INSTRUMENTED_DIR="${PUBLISH_DIR}/instrumented"
ASSEMBLY_NAME="SourceFuncFuzzer.dll"
ASSEMBLY_PATH="${INSTRUMENTED_DIR}/${ASSEMBLY_NAME}"

if [[ ! -f "${PROJECT_PATH}" ]]; then
  echo "Unable to locate the SourceFuncFuzzer project at ${PROJECT_PATH}." >&2
  exit 1
fi

if [[ ! -f "${PROPS_FILE}" ]]; then
  echo "Unable to locate ${PROPS_FILE}." >&2
  exit 1
fi

SHARPFUZZ_VERSION=$(sed -n 's/.*<SharpFuzzVersion>\(.*\)<\/SharpFuzzVersion>.*/\1/p' "${PROPS_FILE}" | head -n 1)

if [[ -z "${SHARPFUZZ_VERSION}" ]]; then
  echo "Failed to read SharpFuzzVersion from ${PROPS_FILE}." >&2
  exit 1
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "The dotnet CLI is required. Install the .NET 8 SDK and ensure 'dotnet' is on your PATH." >&2
  exit 1
fi

if ! command -v sharpfuzz >/dev/null 2>&1; then
  echo "SharpFuzz.CommandLine is required. Install it with 'dotnet tool install --global SharpFuzz.CommandLine --version ${SHARPFUZZ_VERSION}'." >&2
  exit 1
fi

echo "Building SourceFuncFuzzer harness..."
dotnet publish "${PROJECT_PATH}" -c Release >/dev/null

echo "Preparing instrumented output directory..."
rm -rf "${INSTRUMENTED_DIR}"
mkdir -p "${INSTRUMENTED_DIR}"
cp -a "${PUBLISH_DIR}/." "${INSTRUMENTED_DIR}"

if [[ ! -f "${ASSEMBLY_PATH}" ]]; then
  echo "The published assembly could not be found at ${ASSEMBLY_PATH}." >&2
  exit 1
fi

echo "Instrumenting ${ASSEMBLY_NAME} with SharpFuzz..."
if ! sharpfuzz "${ASSEMBLY_PATH}" GirCore.Fuzzing.SourceFuncFuzzer >/dev/null; then
  echo "SharpFuzz instrumentation failed." >&2
  exit 1
fi

echo "Instrumentation complete."
echo "Instrumented assembly: ${ASSEMBLY_PATH}"
echo "Use the files in ${INSTRUMENTED_DIR} as the harness when running your fuzzer."
