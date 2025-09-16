# Fuzzing Gir.Core

Gir.Core ships with a SharpFuzz-based harness that exercises the GLib `SourceFunc`
callback marshalers. The harness can be instrumented and executed with any AFL-
compatible engine once the repository is built locally.

## Prerequisites

To follow the steps below you will need:

- The [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) available on
  your `PATH` so the `dotnet` CLI is accessible.
- The SharpFuzz command-line tool version `2.2.0` installed (or updated) globally
  with the .NET 9 SDK:

  ```bash
  dotnet tool update --global SharpFuzz.CommandLine --version 2.2.0
  ```

  If the tool has not been installed before, run the same command with
  `install` instead of `update`. Installing or updating with the .NET 9 SDK
  ensures the CLI uses the same runtime as the harness. The same version is
  consumed by the harness via the central
  `SharpFuzzVersion` property in
  [`properties/GirCore.Fuzzing.props`](../properties/GirCore.Fuzzing.props).
- A local clone of this repository (including submodules) with the generated
  bindings available. If you have not already generated the bindings, run:

  ```bash
  dotnet fsi scripts/GenerateLibs.fsx
  ```

If you are using [Nix](https://nixos.org), a development shell is provided that
installs the .NET 9 SDK, the matching SharpFuzz CLI, and
[AFL++](https://github.com/AFLplusplus/AFLplusplus) locally. Enter it from the
repository root by running:

```bash
nix-shell
```

The shell hook provisions a local `.dotnet` tools directory and installs or
updates `SharpFuzz.CommandLine` to the version pinned in
[`properties/GirCore.Fuzzing.props`](../properties/GirCore.Fuzzing.props),
ensuring the CLI targets .NET 9 while exposing the `afl-fuzz` binary on your
`PATH`.

## Instrumenting the SourceFunc harness

After the prerequisites have been met, the harness can be built and
instrumented using the helper script:

```bash
./tools/run-gir-core-fuzz.sh
```

The script verifies that both the `dotnet` CLI and the SharpFuzz tool are
available, ensures the generated bindings are present, builds the
`SourceFuncFuzzer` target in `Release` mode, and copies the published output to
`src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release/instrumented`. `sharpfuzz` is
then invoked against `SourceFuncFuzzer.dll` so the instrumented assembly is
ready for use with AFL or libFuzzer drivers.

The script may be executed from outside of the repository by pointing
`GIR_CORE_ROOT` at your checkout:

```bash
GIR_CORE_ROOT=/path/to/gir.core ./tools/run-gir-core-fuzz.sh
```

Once instrumentation succeeds, use the binaries within the `instrumented`
folder as the harness payload for your fuzzer. You can re-run the script at any
time to rebuild the harness after making changes.

## Running AFL++

To instrument the harness and immediately start fuzzing with AFL++, run:

```bash
./tools/run-gir-core-fuzz.sh afl
```

If instrumentation is required, the script rebuilds the harness before launching
`afl-fuzz`. A seed corpus containing a single empty input is created in
`src/Tests/Fuzzing/SourceFuncFuzzer/corpus`, and findings are written to a
timestamped directory under `src/Tests/Fuzzing/SourceFuncFuzzer/findings`.

The helper sets `AFL_SKIP_CPUFREQ=1` automatically and inspects
`/proc/sys/kernel/core_pattern`. If the kernel is configured to pipe core dumps
to another process, the script exports
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` so AFL++ continues to run. Adjust the
core pattern to `core` before fuzzing if you would rather collect crash dumps
immediately:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```

To reuse existing instrumented binaries, pass `--skip-instrument`. Additional
`afl-fuzz` flags can be forwarded by appending them after `--`. For example, to
resume from an existing corpus:

```bash
./tools/run-gir-core-fuzz.sh afl --skip-instrument -- -i src/Tests/Fuzzing/SourceFuncFuzzer/corpus -o /tmp/source-func-findings \
  -m none
```

`afl-fuzz` must be available on your `PATH`. The provided `nix-shell`
environment automatically installs AFL++ and exposes the `afl-fuzz` command so
the script works without additional setup.

### Running AFL++ manually

The instrumented harness can also be fuzzed without the helper script. After
running `./tools/run-gir-core-fuzz.sh` (or `./tools/run-gir-core-fuzz.sh
instrument`), execute the following commands from the repository root:

```bash
mkdir -p src/Tests/Fuzzing/SourceFuncFuzzer/corpus
printf '' > src/Tests/Fuzzing/SourceFuncFuzzer/corpus/empty
afl-fuzz -i src/Tests/Fuzzing/SourceFuncFuzzer/corpus \
  -o src/Tests/Fuzzing/SourceFuncFuzzer/findings \
  -- "$(command -v dotnet)" \
  src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release/instrumented/SourceFuncFuzzer.dll \
  @@
```

Using the fully qualified `dotnet` path suppresses AFL++'s warning about an
unqualified binary name. If `/proc/sys/kernel/core_pattern` pipes crash dumps to
an external handler, either set `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` or
temporarily switch the core pattern to `core` as shown above.
