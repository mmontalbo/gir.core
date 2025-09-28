using System;
using System.IO;
using GObject;

namespace SourceFuncCrashRepro;

internal static class Program
{
    private const string FindingsDirectoryName = "Findings";

    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[repro] managed exception: {ex}");
            return 2;
        }
    }

    private static int Run(string[] args)
    {
        GLib.Module.Initialize();
        GObject.Module.Initialize();

        using var context = GLib.MainContext.RefThreadDefault();

        var findingPath = ResolveFindingPath(args);

        if (findingPath is null)
        {
            Console.Error.WriteLine("[repro] unable to locate a fuzz finding to replay");
            return 1;
        }

        ReplayFinding(findingPath, context);
        return 0;
    }

    private static void ReplayFinding(string findingPath, GLib.MainContext context)
    {
        Console.Error.WriteLine($"[repro] replaying finding: {findingPath}");

        using var stream = File.OpenRead(findingPath);
        FuzzFindingReplayer.Run(stream, context);

        ForceGc();
        Pump(context, 50);

        Console.Error.WriteLine("[repro] finding replay completed");
    }

    private static string? ResolveFindingPath(string[] args)
    {
        if (args.Length > 0)
        {
            var candidate = ResolveCandidate(args[0]);

            if (candidate is not null)
            {
                return candidate;
            }
        }

        var envFinding = Environment.GetEnvironmentVariable("SOURCEFUNC_REPLAY_FINDING");

        if (!string.IsNullOrWhiteSpace(envFinding))
        {
            var candidate = ResolveCandidate(envFinding);

            if (candidate is not null)
            {
                return candidate;
            }
        }

        var findingsDir = LocateFindingsDirectory();

        if (findingsDir is not null)
        {
            foreach (var file in Directory.EnumerateFiles(findingsDir))
            {
                if (!string.IsNullOrEmpty(file))
                {
                    return file;
                }
            }
        }

        return null;
    }

    private static string? ResolveCandidate(string value)
    {
        try
        {
            var path = Path.GetFullPath(value);
            return File.Exists(path) ? path : null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[repro] ignoring candidate '{value}': {ex.Message}");
            return null;
        }
    }

    private static string? LocateFindingsDirectory()
    {
        var path = AppContext.BaseDirectory;

        while (!string.IsNullOrEmpty(path))
        {
            var probe = Path.Combine(path, FindingsDirectoryName);

            if (Directory.Exists(probe))
            {
                return probe;
            }

            var parent = Path.GetDirectoryName(path);

            if (string.IsNullOrEmpty(parent) || string.Equals(parent, path, StringComparison.Ordinal))
            {
                break;
            }

            path = parent;
        }

        return null;
    }

    private static void ForceGc()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
    }

    private static void Pump(GLib.MainContext context, int iterations)
    {
        for (var i = 0; i < iterations; i++)
        {
            context.Iteration(false);
        }
    }
}
