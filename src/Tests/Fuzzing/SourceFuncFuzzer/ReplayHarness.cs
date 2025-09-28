using System;
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
                SourceFuncFuzzer.Run(memory);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[replay] input {index}/{files.Length} '{Path.GetFileName(path)}' threw: {ex}");
                throw;
            }
        }

        Console.Error.WriteLine("[replay] completed without error");
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
                SourceFuncFuzzer.Run(memory);
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
