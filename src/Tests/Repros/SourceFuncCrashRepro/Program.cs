using System;
using GObject;
using GLib.Internal;

namespace SourceFuncCrashRepro;

internal static class Program
{
    private static int Main()
    {
        try
        {
            return Run();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[repro] managed exception: {ex}");
            return 2;
        }
    }

    private static int Run()
    {
        GLib.Module.Initialize();
        GObject.Module.Initialize();

        using var context = GLib.MainContext.RefThreadDefault();

        ScheduleAndCollect();

        ForceGc();
        Pump(context, 50);

        Console.Error.WriteLine("[repro] completed without runtime abort");
        return 0;
    }

    private static void ScheduleAndCollect()
    {
        GLib.SourceFunc? callback = () =>
        {
            Console.Error.WriteLine("[repro] callback invoked");
            return false;
        };

        var sourceId = GLib.Functions.IdleAdd(GLib.Constants.PRIORITY_DEFAULT_IDLE, callback);

        Console.Error.WriteLine($"[repro] scheduled source id={sourceId}");

        callback = null;
    }

    private static void ForceGc()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static void Pump(GLib.MainContext context, int iterations)
    {
        for (var i = 0; i < iterations; i++)
        {
            context.Iteration(false);
        }
    }
}
