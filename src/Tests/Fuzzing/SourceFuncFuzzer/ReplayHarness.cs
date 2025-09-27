using System;
using System.Collections.Generic;
using System.IO;

namespace GirCore.Fuzzing;

internal static class ReplayHarness
{
    public static void Run(string directory)
    {
        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"[replay] directory not found: {directory}");
            return;
        }

        var files = Directory.GetFiles(directory, "*", SearchOption.TopDirectoryOnly);

        if (files.Length == 0)
        {
            Console.Error.WriteLine($"[replay] no inputs in {directory}");
            return;
        }

        Console.Error.WriteLine($"[replay] running {files.Length} inputs from {directory}");

        var index = 0;

        foreach (var path in files)
        {
            index++;

            try
            {
                using var memory = new MemoryStream(File.ReadAllBytes(path));
                memory.Position = 0;
                SourceFuncFuzzer.BeginProfilingInput(Path.GetFileName(path), (int)memory.Length);

                try
                {
                    SourceFuncFuzzer.Run(memory);
                }
                finally
                {
                    SourceFuncFuzzer.EndProfilingInput();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[replay] input {index}/{files.Length} '{Path.GetFileName(path)}' threw: {ex}");
                throw;
            }
        }

        Console.Error.WriteLine("[replay] completed without error");
        SourceFuncFuzzer.EmitProfilingSummary();
    }

    public static void ValidateDeterministic(string directory, IReadOnlyCollection<string> seeds, int runs)
    {
        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"[determinism] directory not found: {directory}");
            return;
        }

        var effectiveRuns = Math.Max(runs, 2);
        var targets = ResolveTargets(directory, seeds);

        if (targets.Count == 0)
        {
            Console.Error.WriteLine("[determinism] no matching seeds to validate");
            return;
        }

        foreach (var target in targets)
        {
            var bytes = File.ReadAllBytes(target.Path);
            var span = new ReadOnlySpan<byte>(bytes);
            var baseline = SourceFuncFuzzer.RunWithFingerprint(span);
            var unstableRuns = new List<string>();

            for (var i = 1; i < effectiveRuns; i++)
            {
                var result = SourceFuncFuzzer.RunWithFingerprint(span);

                if (result.HashCode == baseline.HashCode && result.EdgeCount == baseline.EdgeCount)
                {
                    continue;
                }

                var diff = DescribeDifference(baseline.Edges, result.Edges);
                unstableRuns.Add($"run={i + 1} hash=0x{result.HashCode:x8} edges={result.EdgeCount} {diff}");
            }

            if (unstableRuns.Count == 0)
            {
                Console.Out.WriteLine(
                    $"[determinism] seed={target.Name} stable hash=0x{baseline.HashCode:x8} edges={baseline.EdgeCount}");
            }
            else
            {
                Console.Out.WriteLine(
                    $"[determinism] seed={target.Name} unstable baseline_hash=0x{baseline.HashCode:x8} edges={baseline.EdgeCount}");

                foreach (var line in unstableRuns)
                {
                    Console.Out.WriteLine($"[determinism]   {line}");
                }
            }
        }
    }

    private static List<(string Name, string Path)> ResolveTargets(string directory, IReadOnlyCollection<string> seeds)
    {
        if (seeds.Count == 0)
        {
            return new List<(string Name, string Path)>();
        }

        var targets = new List<(string Name, string Path)>();

        foreach (var seed in seeds)
        {
            if (string.IsNullOrWhiteSpace(seed))
            {
                continue;
            }

            var candidate = Path.IsPathRooted(seed) ? seed : Path.Combine(directory, seed);

            if (!File.Exists(candidate))
            {
                Console.Error.WriteLine($"[determinism] seed missing: {seed}");
                continue;
            }

            targets.Add((Path.GetFileName(candidate), candidate));
        }

        return targets;
    }

    private static string DescribeDifference(int[] baseline, int[] candidate)
    {
        if (baseline.Length == 0 && candidate.Length == 0)
        {
            return "diff=none";
        }

        var missing = FindDifference(baseline, candidate);
        var extra = FindDifference(candidate, baseline);

        return $"missing={FormatEdges(missing)} extra={FormatEdges(extra)}";
    }

    private static List<int> FindDifference(IReadOnlyList<int> left, IReadOnlyList<int> right)
    {
        if (left.Count == 0)
        {
            return new List<int>();
        }

        var rightSet = new HashSet<int>(right);
        var difference = new List<int>();

        foreach (var value in left)
        {
            if (!rightSet.Contains(value))
            {
                difference.Add(value);
            }
        }

        difference.Sort();
        return difference;
    }

    private static string FormatEdges(IReadOnlyList<int> edges)
    {
        if (edges.Count == 0)
        {
            return "[]";
        }

        var limit = Math.Min(edges.Count, 8);
        var parts = new string[limit];

        for (var i = 0; i < limit; i++)
        {
            parts[i] = $"0x{edges[i]:x4}";
        }

        var suffix = edges.Count > limit ? "…" : string.Empty;
        return $"[{string.Join(",", parts)}{suffix}]";
    }

    public static void RunRandom(int iterations)
    {
        Console.Error.WriteLine($"[replay] running {iterations} random inputs");

        var random = new Random(0x53544F);
        using var memory = new MemoryStream(SourceFuncFuzzer.MaxInputLength);
        var buffer = new byte[SourceFuncFuzzer.MaxInputLength];

        for (var i = 0; i < iterations; i++)
        {
            var length = random.Next(1, SourceFuncFuzzer.MaxInputLength + 1);
            random.NextBytes(buffer.AsSpan(0, length));

            memory.Position = 0;
            memory.SetLength(0);
            memory.Write(buffer, 0, length);
            memory.Position = 0;

            try
            {
                SourceFuncFuzzer.BeginProfilingInput($"random-{i:000000}", length);

                try
                {
                    SourceFuncFuzzer.Run(memory);
                }
                finally
                {
                    SourceFuncFuzzer.EndProfilingInput();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[replay] random iteration {i} threw: {ex}");
                throw;
            }

            if ((i + 1) % 1_000_000 == 0)
            {
                var managed = GC.GetTotalMemory(false);
                Console.Error.WriteLine($"[replay] iteration={i + 1} managed_bytes={managed}");
            }
        }

        Console.Error.WriteLine("[replay] random run completed");
        SourceFuncFuzzer.EmitProfilingSummary();

        if (string.Equals(
                Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_REPLAY_HALT"),
                "1",
                StringComparison.Ordinal))
        {
            Console.Error.WriteLine("[replay] halt requested; press Enter to exit");
            Console.ReadLine();
        }
    }
}
