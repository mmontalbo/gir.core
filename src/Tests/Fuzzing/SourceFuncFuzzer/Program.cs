using System.Collections.Generic;
using SharpFuzz;

namespace GirCore.Fuzzing;

public static class Program
{
    public static void Main(string[] args)
    {
        GLib.Module.Initialize();
        GObject.Module.Initialize();

        var disablePersistent =
            string.Equals(
                Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_DISABLE_PERSISTENT"),
                "1",
                StringComparison.Ordinal);

        var traceRaw = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_TRACE");
        var trace = string.Equals(traceRaw, "1", StringComparison.Ordinal);

        var envLogPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SourceFuncFuzzer-env.txt");

        try
        {
            System.IO.File.WriteAllText(envLogPath, traceRaw ?? "<null>");
        }
        catch
        {
            // Ignore environment logging failures, this is diagnostic only.
        }

        var validateDirectory = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_VALIDATE_DIR");

        if (!string.IsNullOrEmpty(validateDirectory))
        {
            var seedsRaw = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_VALIDATE_SEEDS");
            var runsRaw = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_VALIDATE_RUNS");
            var runs = 5;

            if (!string.IsNullOrEmpty(runsRaw) && int.TryParse(runsRaw, out var parsedRuns) && parsedRuns > 1)
            {
                runs = parsedRuns;
            }

            var seeds = new List<string>();

            if (!string.IsNullOrEmpty(seedsRaw))
            {
                var split = seedsRaw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                seeds.AddRange(split);
            }

            ReplayHarness.ValidateDeterministic(validateDirectory, seeds, runs);
            return;
        }

        var replayDirectory = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_REPLAY_DIR");

        if (!string.IsNullOrEmpty(replayDirectory))
        {
            ReplayHarness.Run(replayDirectory);
            return;
        }

        var replayRandom = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_REPLAY_RANDOM");

        if (!string.IsNullOrEmpty(replayRandom) &&
            int.TryParse(replayRandom, out var randomIterations) &&
            randomIterations > 0)
        {
            ReplayHarness.RunRandom(randomIterations);
            return;
        }

        var logPath = trace
            ? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SourceFuncFuzzer.log")
            : null;

        var forkLogPath = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_FORK_LOG");

        void Log(string message)
        {
            if (!trace)
            {
                return;
            }

            var formatted = $"[sourcefunc] {message}{System.Environment.NewLine}";

            try
            {
                System.Console.Error.Write(formatted);

                if (logPath is not null)
                {
                    System.IO.File.AppendAllText(logPath, formatted);
                }
            }
            catch
            {
                // Ignore logging failures while tracing.
            }
        }

        Log($"persistent disabled: {disablePersistent}");
        try
        {
            if (disablePersistent)
            {
                Fuzzer.RunOnce(SourceFuncFuzzer.Run);
            }
            else
            {
                if (!string.IsNullOrEmpty(forkLogPath))
                {
                    ForkServerLogger.Run(SourceFuncFuzzer.Run, forkLogPath);
                }
                else
                {
                    Fuzzer.Run(SourceFuncFuzzer.Run);
                }
            }

            Log("fuzzer run returned");
        }
        catch (System.Exception ex) when (trace)
        {
            Log($"fuzzer threw: {ex}");
            throw;
        }
    }
}
