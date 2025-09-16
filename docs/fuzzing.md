# Fuzzing Gir.Core

Gir.Core ships with a SharpFuzz-based harness that exercises the GLib `SourceFunc`
callback marshalers. The harness can be instrumented and executed with any AFL-
compatible engine once the repository is built locally.

## Prerequisites

To follow the steps below you will need:

- The [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) available on
  your `PATH` so the `dotnet` CLI is accessible.
- The SharpFuzz command-line tool version `2.2.0` installed globally:

  ```bash
  dotnet tool install --global SharpFuzz.CommandLine --version 2.2.0
  ```

  The same version is consumed by the harness via the central
  `SharpFuzzVersion` property in
  [`properties/GirCore.Fuzzing.props`](../properties/GirCore.Fuzzing.props).
- A local clone of this repository (including submodules) with the generated
  bindings available. If you have not already generated the bindings, run:

  ```bash
  dotnet fsi scripts/GenerateLibs.fsx
  ```

If you are using [Nix](https://nixos.org), a development shell is provided that
installs the required SDK and configures the SharpFuzz CLI locally. Enter it by
running:

```bash
nix-shell
```

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
