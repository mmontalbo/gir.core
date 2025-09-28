using System;
using System.Buffers;
using System.IO;
using GLib.Internal;
using ManagedSourceFunc = GLib.SourceFunc;
using NativeSourceFunc = GLib.Internal.SourceFunc;

namespace SourceFuncCrashRepro;

/*
Purpose
=======
This helper replays the raw byte sequences saved by our SourceFunc fuzz target.
Each sequence (a "finding") encodes the steps that originally triggered a crash in
GLib destroy-notify handling. Replaying the finding gives the regression test an
exact, deterministic way to reach the same code paths without running the fuzzer.

Key concepts
------------
- *Finding*: the byte slice emitted by the fuzzer when it discovered a failure.
- *Scenario*: a single GLib interaction described by a portion of the finding.
- *Scenario defaults*: fallback values derived from the header so the replay stays
  deterministic after the input bytes are exhausted.
- *Handler kinds*: GIR.Core generates four delegate flavors for GLib sources. They
  are not fuzzing concepts; they come from how GLib exposes callbacks and how our
  bindings normalize them:
    * `Async` handlers run once, scheduling the callback to execute asynchronously.
    * `Call` handlers run immediately on the current thread and can be invoked
      multiple times in sequence.
    * `Forever` handlers stay registered until they return `false`, so they model
      long-lived idle or timeout sources.
    * `Notified` handlers accept an explicit destroy-notify delegate, allowing the
      fuzzer to toggle whether that cleanup path runs before or after the callback.

How the finding was produced
----------------------------
- The fuzz target repeatedly called into GLib APIs while mutating an input byte
  slice.
- Coverage feedback (via `TraceEdge`) told the fuzzer which mutations explored new
  execution paths.
- Whenever a mutation caused a crash (e.g. a collected delegate being invoked),
  the corresponding input slice was stored on disk—these files are what the test
  now feeds into this replayer.

High-level data flow
--------------------
    +---------------------+      +------------------------+      +------------------------+
    | Finding (byte file) | ---> | FuzzFindingReplayer    | ---> | GLib main loop actions |
    +---------------------+      +------------------------+      +------------------------+

Replay steps
------------
1. `Run` copies up to 4 KiB from the finding stream into an array-pool buffer.
2. `Execute` wraps the bytes in `FuzzDataReader`, records high-level coverage with
   `TraceEdge`, then reads a header byte that drives the rest of the script.
3. The header selects an initial set of defaults (`ScenarioDefaults`) and the
   number of operations to perform (capped at 32 so even a fuzzed file cannot loop
   unboundedly).
4. For each operation `ExecuteScenario` consumes more bytes (when available) to
   decide:
      * which managed handler variant (`Async`, `Call`, `Forever`, `Notified`) to use,
      * how many times the handler should be invoked,
      * whether the destroy-notify callback is invoked before or after execution,
      * what `IntPtr` should back the `userData` argument,
      * and, for notified handlers, whether the managed delegate is intentionally
        omitted.
   When the byte stream runs out, the defaults continue the sequence deterministically
   so truncated findings still replay.
5. The concrete `Run*` methods translate those decisions into the real GLib APIs:
   they enqueue sources, optionally remove them early, and drive the provided
   `MainContext` until the desired number of callbacks fire. Any crash that happened
   during fuzzing reappears here because the same GLib interactions are executed in
   the same order.

Finding byte layout (conceptual)
-------------------------------
    +--------+------------------------------+
    | Byte 0 | Header bitfield              |
    +--------+------------------------------+
    | Bytes  | Operation directives (0..31) |
    | 1..N   |   · handler selector         |
    |        |   · invocation count hints   |
    |        |   · destroy-notify toggles   |
    |        |   · user data payload        |
    |        |   · misc modifiers           |
    +--------+------------------------------+

The replayer leaves `TraceEdge` calls in place even though they are no-ops now.
Keeping them avoids changing the meaning of saved findings (the fuzzer observed
the original coverage map), ensuring CI and developer machines replay exactly what
the harness discovered.

What is a trace edge?
---------------------
The fuzz target linked against libAFL-style coverage instrumentation. Every call
to `TraceEdge(id)` marks a distinct branch or state transition so the fuzzer can
see which parts of the program an input reaches. During fuzzing those IDs fed a
bitmap that guided new mutations. In replay mode the function is deliberately
empty, but the calls remain so the saved inputs still correspond to the same edge
IDs the fuzzer observed.

Crash scenario: `seed-gc-idle-drop`
----------------------------------
The failing finding checked into `Findings/seed-gc-idle-drop` contains the bytes
`00 04 03 00 00 00 00 00 00 00 01 00 00 01 01 01 01 00`. Replay unfolds as follows:

1. Header `0x00`
   - Requests a single scenario (`(0x00 & 0x1F) + 1`).
   - Seeds `ScenarioDefaults` with `0x01` (the constructor substitutes 1 for 0) so
     any missing bytes later have deterministic replacements.
2. Handler selector `0x04`
   - `0x04 % 4 == 0`, so the scenario uses the `Notified` handler flavor (GLib idle
     source with a destroy-notify delegate).
3. Invocation byte `0x03`
   - `(0x03 & 0x0F) + 1 == 4` loops inside `RunNotified`, so the replayer queues
     four idle sources.
4. Destroy flags `0x00`, `0x00`
   - Both `destroyBefore` and `destroyAfter` are false; GLib itself will decide when
     to tear down the source.
5. User data `0x00000000`
   - The exported `IntPtr` payload is zero, which also drives the optional priority
     overrides later in the script.
6. Skip-managed flag `0x00`
   - A managed callback is required, so `CreateCallback` reads the next bytes to
     configure one.
7. Callback body
   - Length byte `0x01` → a two-slot boolean pattern. The subsequent bits
     (`0x00`, `0x01`) decode to `[false, true]`.
   - Mode byte `0x01` flips each emitted result, so the callback returns
     `[true, false, true, false, …]` on successive invocations, mimicking an idle
     handler that keeps itself alive once and then asks GLib to remove the source.
8. Priority toggles `0x01 0x01 0x01 0x00`
   - For the first three loops `ReadBoolOrFallback` sees `true` and overrides the
     priority with the lower bits of `userData` (still zero). The final byte is `0x00`,
     leaving the default idle priority in place for the last registration.

When the replayer hands control back to `Program.ReplayFinding`, the harness forces
an aggressive garbage collection before pumping the `MainContext` for 50 iterations.
In the buggy build, the destroy-notify wrapper that should keep the managed idle
callback alive is not rooted, so the GC reclaims it. As GLib executes the queued
idle sources the second invocation of each returns `false`, prompting GLib to drop
the source and invoke the stale destroy-notify function pointer. That call jumps
into freed memory and triggers the "callback was made on a garbage collected
delegate" crash reproduced by the regression test.
*/
internal static class FuzzFindingReplayer
{
    private const int MaxInputLength = 4096;
    private const int MaxOperationCount = 32;
    private static readonly ManagedSourceFunc DefaultCallback = () => false;

    public static void Run(Stream stream, GLib.MainContext context)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var buffer = ArrayPool<byte>.Shared.Rent(MaxInputLength);

        try
        {
            var length = FillBuffer(stream, buffer);

            if (length == 0)
            {
                return;
            }

            var span = new ReadOnlySpan<byte>(buffer, 0, length);
            Execute(span, context);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static int FillBuffer(Stream stream, byte[] buffer)
    {
        var total = 0;

        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);

            if (read <= 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static void Execute(ReadOnlySpan<byte> data, GLib.MainContext context)
    {
        var reader = new FuzzDataReader(data);

        TraceEdge(0x7000 | Math.Min(data.Length, 0x3F));

        var prefixLimit = Math.Min(data.Length, 8);

        for (var i = 0; i < prefixLimit; i++)
        {
            TraceEdge(0x7100 | (i << 8) | data[i]);
        }

        if (!reader.TryReadByte(out var header))
        {
            return;
        }

        var defaults = new ScenarioDefaults(header);
        var operations = Math.Min(MaxOperationCount, (header & 0x1F) + 1);

        for (var i = 0; i < operations; i++)
        {
            if (!ExecuteScenario(ref reader, ref defaults, context))
            {
                break;
            }
        }
    }

    private static bool ExecuteScenario(ref FuzzDataReader reader, ref ScenarioDefaults defaults, GLib.MainContext context)
    {
        var exhausted = false;

        HandlerKind handler;

        if (reader.TryReadByte(out var handlerByte))
        {
            handler = (HandlerKind)(handlerByte % 4);
        }
        else
        {
            exhausted = true;
            handler = defaults.NextHandler();
        }

        var invocationRaw = ReadByteOrFallback(ref reader, ref defaults, ref exhausted);
        var invocationCount = 1 + (invocationRaw & 0x0F);

        var destroyBefore = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var destroyAfter = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var userData = new IntPtr(ReadInt32OrFallback(ref reader, ref defaults, ref exhausted));

        ManagedSourceFunc? managed;

        TraceEdge(0x1000 | (int)handler);
        TraceEdge(0x2000 | Math.Min(invocationCount, 0x1F));

        if (destroyBefore)
        {
            TraceEdge(0x3000);
        }
        else
        {
            TraceEdge(0x3001);
        }

        if (destroyAfter)
        {
            TraceEdge(0x3002);
        }
        else
        {
            TraceEdge(0x3003);
        }

        if (handler == HandlerKind.Notified)
        {
            var skipManaged = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
            TraceEdge(skipManaged ? 0x4000 : 0x4001);
            managed = skipManaged ? null : CreateCallback(ref reader, ref defaults, ref exhausted);
        }
        else
        {
            managed = CreateCallback(ref reader, ref defaults, ref exhausted);
        }

        if (handler == HandlerKind.Async && invocationCount > 1)
        {
            invocationCount = 1;
        }

        switch (handler)
        {
            case HandlerKind.Notified:
                RunNotified(managed, invocationCount, userData, destroyBefore, destroyAfter, context, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Async:
                RunAsync(managed ?? DefaultCallback, invocationCount, userData);
                break;
            case HandlerKind.Call:
                RunCall(managed ?? DefaultCallback, invocationCount, userData);
                break;
            case HandlerKind.Forever:
                RunForever(managed ?? DefaultCallback, invocationCount, userData);
                break;
        }

        var continuation = !exhausted || reader.RemainingBytes > 0;
        TraceEdge(0x5000 | (exhausted ? 0x1 : 0) | (reader.RemainingBytes > 0 ? 0x2 : 0));
        return continuation;
    }

    private static void TraceEdge(int id)
    {
        // Coverage hooks were only needed during fuzzing; keep a stub so existing inputs replay unchanged.
    }

    private static void RunNotified(ManagedSourceFunc? managed, int invocationCount, IntPtr userData, bool destroyBefore, bool destroyAfter, GLib.MainContext context, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var callback = managed ?? DefaultCallback;
        var cycles = Math.Max(1, invocationCount);

        for (var i = 0; i < cycles; i++)
        {
            var priority = GLib.Constants.PRIORITY_DEFAULT_IDLE;

            if (ReadBoolOrFallback(ref reader, ref defaults, ref exhausted))
            {
                priority = unchecked((int)(userData.ToInt64() & 0xFFFF));
            }

            TraceEdge(0x3500 | (priority & 0xFF));

            var sourceId = GLib.Functions.IdleAdd(priority, callback);

            if (destroyBefore)
            {
                GLib.Functions.SourceRemove(sourceId);
                continue;
            }

            if (destroyAfter)
            {
                var capturedId = sourceId;
                context.InvokeFull(priority, () =>
                {
                    GLib.Functions.SourceRemove(capturedId);
                    return false;
                });
            }
        }

        if (!destroyBefore)
        {
            exhausted = exhausted || reader.RemainingBytes == 0;
        }
    }

    private static void RunAsync(ManagedSourceFunc managed, int invocationCount, IntPtr userData)
    {
        var handler = new SourceFuncAsyncHandler(managed);
        InvokeNative(handler.NativeCallback, userData, invocationCount);
    }

    private static void RunCall(ManagedSourceFunc managed, int invocationCount, IntPtr userData)
    {
        var handler = new SourceFuncCallHandler(managed);
        InvokeNative(handler.NativeCallback, userData, invocationCount);
    }

    private static void RunForever(ManagedSourceFunc managed, int invocationCount, IntPtr userData)
    {
        var handler = new SourceFuncForeverHandler(managed);
        InvokeNative(handler.NativeCallback, userData, invocationCount);
    }

    private static void InvokeNative(NativeSourceFunc? callback, IntPtr userData, int invocationCount)
    {
        if (callback is null)
        {
            return;
        }

        for (var i = 0; i < invocationCount; i++)
        {
            callback(userData);
        }
    }

    private static ManagedSourceFunc CreateCallback(ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        if (!reader.TryReadByte(out var lengthByte))
        {
            exhausted = true;
            return DefaultCallback;
        }

        var length = 1 + (lengthByte & 0x07);
        TraceEdge(0x6000 | length);
        var pattern = new bool[length];

        for (var i = 0; i < pattern.Length; i++)
        {
            if (reader.TryReadBool(out var value))
            {
                pattern[i] = value;
            }
            else
            {
                pattern[i] = defaults.NextBool();
                exhausted = true;
            }

            var bitId = (i & 0x1F) << 1;
            TraceEdge(0x6100 | bitId | (pattern[i] ? 0x1 : 0x0));
        }

        byte mode;

        if (reader.TryReadByte(out var modeByte))
        {
            mode = modeByte;
        }
        else
        {
            mode = defaults.NextByte();
            exhausted = true;
        }

        TraceEdge(0x6200 | (mode & 0x3F));

        var callback = new CallbackPlan(pattern, mode);
        return callback.Invoke;
    }

    private enum HandlerKind
    {
        Notified,
        Async,
        Call,
        Forever,
    }

    private ref struct ScenarioDefaults
    {
        private uint state;

        public ScenarioDefaults(byte seed)
        {
            state = (uint)(seed == 0 ? 1 : seed);
        }

        public HandlerKind NextHandler()
        {
            return (HandlerKind)(NextByte() % 4);
        }

        public byte NextByte()
        {
            state = unchecked(state * 1103515245 + 12345);
            return (byte)(state >> 24);
        }

        public bool NextBool()
        {
            return (NextByte() & 1) != 0;
        }

        public ushort NextUInt16()
        {
            var lower = NextByte();
            var upper = NextByte();
            return (ushort)(lower | (upper << 8));
        }

        public int NextInt32()
        {
            var b0 = NextByte();
            var b1 = NextByte();
            var b2 = NextByte();
            var b3 = NextByte();
            return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }

        public long NextInt64()
        {
            var lower = (uint)NextInt32();
            var upper = (uint)NextInt32();
            return (long)lower | ((long)upper << 32);
        }
    }

    private sealed class CallbackPlan
    {
        private readonly bool[] pattern;
        private readonly byte mode;
        private int index;

        public CallbackPlan(bool[] pattern, byte mode)
        {
            this.pattern = pattern.Length == 0 ? new[] { false } : pattern;
            this.mode = mode;
        }

        public bool Invoke()
        {
            var slot = index % pattern.Length;
            var result = pattern[slot];
            TraceEdge(0x6300 | (slot & 0x1F));

            if ((mode & 0x1) != 0)
            {
                result = !result;
                TraceEdge(0x6400);
            }

            if ((mode & 0x2) != 0)
            {
                pattern[slot] = !pattern[slot];
                TraceEdge(0x6401);
            }

            if ((mode & 0x4) != 0 && index % 2 == 0)
            {
                result = false;
                TraceEdge(0x6402);
            }

            TraceEdge(0x6500 | (mode & 0x3F));
            TraceEdge(0x6600 | (result ? 0x1 : 0x0));
            index++;
            return result;
        }
    }
    private static byte ReadByteOrFallback(ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        if (reader.TryReadByte(out var value))
        {
            return value;
        }

        exhausted = true;
        return defaults.NextByte();
    }

    private static bool ReadBoolOrFallback(ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        if (reader.TryReadBool(out var value))
        {
            return value;
        }

        exhausted = true;
        return defaults.NextBool();
    }

    private static int ReadInt32OrFallback(ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        if (reader.TryReadInt32(out var value))
        {
            return value;
        }

        exhausted = true;
        return defaults.NextInt32();
    }
}

internal ref struct FuzzDataReader
{
    private readonly ReadOnlySpan<byte> data;
    private int offset;

    public FuzzDataReader(ReadOnlySpan<byte> data)
    {
        this.data = data;
        offset = 0;
    }

    public int RemainingBytes => data.Length - offset;

    public bool TryReadByte(out byte value)
    {
        if (offset >= data.Length)
        {
            value = 0;
            return false;
        }

        value = data[offset++];
        return true;
    }

    public bool TryReadBool(out bool value)
    {
        if (TryReadByte(out var raw))
        {
            value = (raw & 1) != 0;
            return true;
        }

        value = false;
        return false;
    }

    public bool TryReadUInt16(out ushort value)
    {
        if (RemainingBytes < 2)
        {
            value = 0;
            return false;
        }

        var lower = data[offset];
        var upper = data[offset + 1];
        offset += 2;
        value = (ushort)(lower | (upper << 8));
        return true;
    }

    public bool TryReadInt32(out int value)
    {
        if (RemainingBytes < 4)
        {
            value = 0;
            return false;
        }

        value = data[offset]
            | (data[offset + 1] << 8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24);
        offset += 4;
        return true;
    }

    public bool TryReadInt64(out long value)
    {
        if (RemainingBytes < 8)
        {
            value = 0;
            return false;
        }

        value = (long)data[offset]
            | ((long)data[offset + 1] << 8)
            | ((long)data[offset + 2] << 16)
            | ((long)data[offset + 3] << 24)
            | ((long)data[offset + 4] << 32)
            | ((long)data[offset + 5] << 40)
            | ((long)data[offset + 6] << 48)
            | ((long)data[offset + 7] << 56);
        offset += 8;
        return true;
    }

    public byte ReadByte()
    {
        if (!TryReadByte(out var value))
        {
            throw new EndOfStreamException("The fuzzing input terminated unexpectedly.");
        }

        return value;
    }

    public bool ReadBool()
    {
        return TryReadBool(out var value)
            ? value
            : throw new EndOfStreamException("The fuzzing input terminated unexpectedly.");
    }

    public ushort ReadUInt16()
    {
        return TryReadUInt16(out var value)
            ? value
            : throw new EndOfStreamException("The fuzzing input terminated unexpectedly.");
    }

    public int ReadInt32()
    {
        return TryReadInt32(out var value)
            ? value
            : throw new EndOfStreamException("The fuzzing input terminated unexpectedly.");
    }

    public long ReadInt64()
    {
        return TryReadInt64(out var value)
            ? value
            : throw new EndOfStreamException("The fuzzing input terminated unexpectedly.");
    }
}
