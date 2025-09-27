using System;
using System.Threading;
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

        // If we reached here without a runtime abort, treat as success.
        Console.Error.WriteLine("[repro] completed without runtime abort");
        return 0;
    }

    private static void ScheduleAndCollect()
    {
        var handler = new GLib.Internal.SourceFuncNotifiedHandler(() =>
        {
            Console.Error.WriteLine("[repro] callback invoked");
            return false;
        });

        GLib.Internal.DestroyNotify destroyWrapper = data =>
        {
            Console.Error.WriteLine("[repro] destroy-notify invoked");
            handler.DestroyNotify?.Invoke(data);
        };

        var sourceId = GLib.Internal.Functions.IdleAdd(
            GLib.Constants.PRIORITY_DEFAULT_IDLE,
            handler.NativeCallback,
            IntPtr.Zero,
            destroyWrapper);

        Console.Error.WriteLine($"[repro] scheduled source id={sourceId}");

        // Drop the managed references. Without additional rooting, the wrapper can be collected
        // before GLib invokes it, reproducing the crash we observed in real apps.
        handler = null!;
        destroyWrapper = null!;
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
