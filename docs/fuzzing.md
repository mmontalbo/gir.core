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
`afl-fuzz`. A seed corpus containing a small default input is created in
`src/Tests/Fuzzing/SourceFuncFuzzer/corpus`, and findings are written to a
timestamped directory under `src/Tests/Fuzzing/SourceFuncFuzzer/findings`. The
placeholder seed ensures AFL++ always has a non-empty test case to mutate; when
the stream is empty the harness returns immediately, and AFL++ trims the queue
back to an empty seed otherwise.

By default the helper starts a "serious" campaign that uses the available CPU
cores (capped at 32) by running a foreground master instance and multiple
secondary fuzzers with varied schedules and mutation modes. Secondary workers
write their console output to `findings/logs/<name>.log` while the master keeps
the interactive TUI in the invoking terminal. Use `--workers <count>` to set an
explicit total, or `--single` to fall back to the legacy one-instance launch.

The script also applies several recommended environment tweaks when they are
not already present:

- `AFL_SKIP_CPUFREQ=1` to ignore CPU frequency scaling checks.
- `AFL_SKIP_BIN_CHECK=1` so AFL++ accepts the managed SharpFuzz harness.
- `AFL_IMPORT_FIRST=1` to prioritise importing synced queue entries from other
  fuzzers.
- `AFL_IGNORE_SEED_PROBLEMS=1` to skip crashing or hanging seeds during warmup.
- `AFL_INPUT_LEN_MIN=1` so AFL++ keeps at least one byte in every testcase; the
  `SourceFunc` harness exits immediately on empty inputs, and zero-length seeds
  collapse coverage.
- `AFL_TESTCACHE_SIZE=200` (megabytes) to cache test cases in RAM; override the
  value with `--testcache <mb>` or by exporting `AFL_TESTCACHE_SIZE` manually.

Override any of these by exporting the environment variable before launching
the helper. For example, set `AFL_INPUT_LEN_MIN=0` explicitly if you need to fuzz the
empty-input path.

`/proc/sys/kernel/core_pattern` is inspected before fuzzing. If the kernel is
configured to pipe core dumps to another process, the helper exports
`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` so AFL++ continues to run. Adjust the
core pattern to `core` before fuzzing if you would rather collect crash dumps
immediately:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```

To reuse existing instrumented binaries, pass `--skip-instrument`. Additional
`afl-fuzz` flags can be forwarded by appending them after `--`; in that mode the
helper does not spawn the multi-core campaign and simply relays the options you
provide. For example, to resume from an existing corpus:

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
printf 'seed' > src/Tests/Fuzzing/SourceFuncFuzzer/corpus/seed-default
AFL_SKIP_BIN_CHECK=1 AFL_INPUT_LEN_MIN=1 afl-fuzz -i src/Tests/Fuzzing/SourceFuncFuzzer/corpus \
  -o src/Tests/Fuzzing/SourceFuncFuzzer/findings \
  -- "$(command -v dotnet)" \
  src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release/instrumented/SourceFuncFuzzer.dll \
  @@
```

Ensure the corpus directory always contains at least one non-empty seed; AFL++
aborts when the input directory only has empty files. Setting `AFL_INPUT_LEN_MIN=1`
prevents the queue from being trimmed back to the zero-byte case.

Using the fully qualified `dotnet` path suppresses AFL++'s warning about an
unqualified binary name. If `/proc/sys/kernel/core_pattern` pipes crash dumps to
an external handler, either set `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` or
temporarily switch the core pattern to `core` as shown above.
