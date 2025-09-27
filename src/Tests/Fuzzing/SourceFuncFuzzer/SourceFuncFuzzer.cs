using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using GLib.Internal;
using System.Globalization;
using System.Text;
using ManagedSourceFunc = GLib.SourceFunc;

namespace GirCore.Fuzzing;

public static class SourceFuncFuzzer
{
    internal const int MaxInputLength = 4096;
    private const int MaxOperationCount = 32;
    private const int HandlerKindCount = 6;
    // Keep timeout scenarios responsive enough for persistent AFL workers.
    private const int TimeoutIntervalClampMilliseconds = 16;
    private static readonly ManagedSourceFunc DefaultCallback = () => false;
    private static readonly ScenarioProfiler? Profiler = ScenarioProfiler.TryCreate();
    private static readonly System.Collections.Generic.Dictionary<int, int> CoverageSlots = new();
    private static readonly object CoverageLock = new();
    private static int NextCoverageSlot;
    private static readonly byte[] DrainBuffer = new byte[1024];
    [ThreadStatic]
    private static FingerprintCollector? currentFingerprint;
    private static readonly bool TraceIdle =
        string.Equals(
            Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_TRACE_IDLE"),
            "1",
            StringComparison.Ordinal);
    private static readonly object IdleRegistryLock = new();
    private static readonly Dictionary<uint, IdleRegistration> IdleRegistry = new();
    private static long IdleScenarioCounter;
    private static readonly bool TraceIterations =
        string.Equals(
            Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_TRACE_ITER"),
            "1",
            StringComparison.Ordinal);

    private static readonly string TraceIterationPath =
        Path.Combine(AppContext.BaseDirectory, "SourceFuncFuzzer-iter.log");

    private static long IterationCounter;
    private static readonly Action<SourceFuncForeverHandler>? ForeverHandleReleaser = CreateForeverHandleReleaser();
    private static long ForeverHandlesAllocated;
    private static long ForeverHandlesReleased;

    public static void Run(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var iteration = Interlocked.Increment(ref IterationCounter);

        if (TraceIterations && iteration % 1000 == 0)
        {
            try
            {
                var managedBytes = GC.GetTotalMemory(false);
                File.AppendAllText(
                    TraceIterationPath,
                    $"iteration={iteration} handles={{allocated:{Interlocked.Read(ref ForeverHandlesAllocated)},released:{Interlocked.Read(ref ForeverHandlesReleased)}}} managed_bytes={managedBytes} coverage_slots={GetCoverageCount()}{Environment.NewLine}");
            }
            catch
            {
                // Diagnostics only; ignore logging failures.
            }
        }

        var buffer = ArrayPool<byte>.Shared.Rent(MaxInputLength);

        try
        {
            var length = FillBuffer(stream, buffer);

            if (length == 0)
            {
                return;
            }

            var span = new ReadOnlySpan<byte>(buffer, 0, length);
            Execute(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    internal static void BeginProfilingInput(string name, int length)
    {
        Profiler?.BeginInput(name, length);
    }

    internal static void EndProfilingInput()
    {
        Profiler?.EndInput();
    }

    internal static void EmitProfilingSummary()
    {
        Profiler?.EmitSummary();
    }

    internal static FingerprintResult RunWithFingerprint(ReadOnlySpan<byte> data)
    {
        var collector = new FingerprintCollector();
        var previous = currentFingerprint;
        currentFingerprint = collector;

        try
        {
            Execute(data);
            return collector.BuildResult();
        }
        finally
        {
            currentFingerprint = previous;
        }
    }

    private static int FillBuffer(Stream stream, byte[] buffer)
    {
        var total = 0;

        while (true)
        {
            int read;

            if (total < buffer.Length)
            {
                read = stream.Read(buffer, total, buffer.Length - total);
            }
            else
            {
                read = stream.Read(DrainBuffer, 0, DrainBuffer.Length);
            }

            if (read <= 0)
            {
                break;
            }

            total += read;
        }

        return Math.Min(total, buffer.Length);
    }

    private static void Execute(ReadOnlySpan<byte> data)
    {
        EnsureIdleRegistryCleared("pre-run");

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

        try
        {
            for (var i = 0; i < operations; i++)
            {
                if (!ExecuteScenario(ref reader, ref defaults))
                {
                    break;
                }
            }
        }
        finally
        {
            EnsureIdleRegistryCleared("post-run");
        }
    }

    private static bool ExecuteScenario(ref FuzzDataReader reader, ref ScenarioDefaults defaults)
    {
        var exhausted = false;

        HandlerKind handler;

        if (reader.TryReadByte(out var handlerByte))
        {
            handler = (HandlerKind)(handlerByte % HandlerKindCount);
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
        var skipManaged = false;

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
            skipManaged = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
            TraceEdge(skipManaged ? 0x4000 : 0x4001);
            managed = skipManaged ? null : CreateCallback(ref reader, ref defaults, ref exhausted);
        }
        else
        {
            managed = CreateCallback(ref reader, ref defaults, ref exhausted);
        }

        var forcedAsyncSingle = false;

        if (handler == HandlerKind.Async && invocationCount > 1)
        {
            invocationCount = 1;
            forcedAsyncSingle = true;
        }

        switch (handler)
        {
            case HandlerKind.Notified:
                RunNotified(managed, invocationCount, userData, destroyBefore, destroyAfter, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Async:
                RunAsync(managed ?? DefaultCallback, invocationCount, userData, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Call:
                RunCall(managed ?? DefaultCallback, invocationCount, userData, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Forever:
                RunForever(managed ?? DefaultCallback, invocationCount, userData, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Idle:
                RunIdleAdd(managed ?? DefaultCallback, invocationCount, userData, destroyBefore, destroyAfter, ref reader, ref defaults, ref exhausted);
                break;
            case HandlerKind.Timeout:
                RunTimeoutAdd(managed ?? DefaultCallback, invocationCount, userData, destroyBefore, destroyAfter, ref reader, ref defaults, ref exhausted);
                break;
        }

        var continuation = !exhausted || reader.RemainingBytes > 0;
        TraceEdge(0x5000 | (exhausted ? 0x1 : 0) | (reader.RemainingBytes > 0 ? 0x2 : 0));
        Profiler?.RecordScenario(
            handler,
            invocationCount,
            destroyBefore,
            destroyAfter,
            skipManaged,
            forcedAsyncSingle,
            exhausted,
            reader.RemainingBytes);
        return continuation;
    }

    private static bool IsTracingEnabled()
    {
        var value = System.Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_TRACE");
        return string.Equals(value, "1", System.StringComparison.Ordinal);
    }

    private static unsafe void TraceEdge(int id)
    {
        var shared = TraceAccessor.GetSharedMem();

        if (IsTracingEnabled())
        {
            var state = shared is null ? "trace: shared null" : $"trace: shared ready {id:x4}";
            System.Console.Error.WriteLine(state);
        }

        if (shared is null)
        {
            return;
        }

        var index = GetCoverageSlot(id);
        var slot = shared + index;
        *slot |= 1;

        currentFingerprint?.RecordEdge(id);
    }

    private static int GetCoverageSlot(int key)
    {
        lock (CoverageLock)
        {
            if (!CoverageSlots.TryGetValue(key, out var index))
            {
                index = NextCoverageSlot++ & 0xFFFF;
                CoverageSlots[key] = index;
            }

            return index;
        }
    }

    private static int GetCoverageCount()
    {
        lock (CoverageLock)
        {
            return CoverageSlots.Count;
        }
    }

    private static class TraceAccessor
    {
        private static readonly System.Reflection.FieldInfo? SharedMemField;
        private static readonly object LocalMemoryLock = new();
        private static bool LocalMemoryInitialized;
        private static GCHandle LocalMemoryHandle;
        private static byte[]? LocalMemoryBuffer;
        private static IntPtr LocalMemoryPointer;

        static TraceAccessor()
        {
            var traceType = Type.GetType("SharpFuzz.Common.Trace, SharpFuzz.Common");

            if (traceType is null)
            {
                return;
            }

            SharedMemField = traceType.GetField("SharedMem", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        }

        public static unsafe byte* GetSharedMem()
        {
            var fromField = TryGetSharedMemFromField();

            if (fromField is not null)
            {
                return fromField;
            }

            lock (LocalMemoryLock)
            {
                fromField = TryGetSharedMemFromField();

                if (fromField is not null)
                {
                    return fromField;
                }

                if (!LocalMemoryInitialized)
                {
                    LocalMemoryBuffer = new byte[1 << 16];
                    LocalMemoryHandle = GCHandle.Alloc(LocalMemoryBuffer, GCHandleType.Pinned);
                    LocalMemoryPointer = LocalMemoryHandle.AddrOfPinnedObject();
                    LocalMemoryInitialized = true;
                    TrySetSharedMemField(LocalMemoryPointer);
                }

                return (byte*)LocalMemoryPointer;
            }
        }

        private static unsafe byte* TryGetSharedMemFromField()
        {
            if (SharedMemField is null)
            {
                return null;
            }

            var value = SharedMemField.GetValue(null);

            switch (value)
            {
                case IntPtr ip when ip != IntPtr.Zero:
                    return (byte*)ip;
                case UIntPtr up when up != UIntPtr.Zero:
                    return (byte*)(void*)up;
                case System.Reflection.Pointer pointer:
                    return (byte*)System.Reflection.Pointer.Unbox(pointer);
                default:
                    return null;
            }
        }

        private static void TrySetSharedMemField(IntPtr pointer)
        {
            if (SharedMemField is null)
            {
                return;
            }

            try
            {
                var fieldType = SharedMemField.FieldType;

                if (fieldType == typeof(IntPtr))
                {
                    SharedMemField.SetValue(null, pointer);
                }
                else if (fieldType == typeof(UIntPtr))
                {
                    SharedMemField.SetValue(null, (UIntPtr)(ulong)(nuint)pointer);
                }
                else if (fieldType.IsPointer)
                {
                    unsafe
                    {
                        SharedMemField.SetValue(null, System.Reflection.Pointer.Box(pointer.ToPointer(), fieldType));
                    }
                }
            }
            catch
            {
                // Fallback trace setup best-effort only.
            }
        }
    }

    internal readonly struct FingerprintResult
    {
        public FingerprintResult(int hashCode, int edgeCount, int[] edges)
        {
            HashCode = hashCode;
            EdgeCount = edgeCount;
            Edges = edges;
        }

        public int HashCode { get; }
        public int EdgeCount { get; }
        public int[] Edges { get; }
    }

    private sealed class FingerprintCollector
    {
        private readonly HashSet<int> edges = new();

        public void RecordEdge(int id)
        {
            edges.Add(id);
        }

        public FingerprintResult BuildResult()
        {
            if (edges.Count == 0)
            {
                return new FingerprintResult(0, 0, System.Array.Empty<int>());
            }

            var buffer = new int[edges.Count];
            edges.CopyTo(buffer);
            System.Array.Sort(buffer);

            var hash = new HashCode();

            foreach (var edge in buffer)
            {
                hash.Add(edge);
            }

            return new FingerprintResult(hash.ToHashCode(), buffer.Length, buffer);
        }
    }

    private sealed class ScenarioProfiler
    {
        private readonly struct ScenarioRecord
        {
            public ScenarioRecord(
                HandlerKind handler,
                int invocationCount,
                bool destroyBefore,
                bool destroyAfter,
                bool skipManaged,
                bool forcedAsyncSingle,
                bool exhausted,
                int remainingBytes)
            {
                Handler = handler;
                InvocationCount = invocationCount;
                DestroyBefore = destroyBefore;
                DestroyAfter = destroyAfter;
                SkipManaged = skipManaged;
                ForcedAsyncSingle = forcedAsyncSingle;
                Exhausted = exhausted;
                RemainingBytes = remainingBytes;
            }

            public HandlerKind Handler { get; }
            public int InvocationCount { get; }
            public bool DestroyBefore { get; }
            public bool DestroyAfter { get; }
            public bool SkipManaged { get; }
            public bool ForcedAsyncSingle { get; }
            public bool Exhausted { get; }
            public int RemainingBytes { get; }
        }

        private sealed class InputContext
        {
            public InputContext(string name, int length)
            {
                Name = name;
                Length = length;
            }

            public string Name { get; }
            public int Length { get; }
            public int ScenarioCount { get; set; }
            public bool HadExhaustion { get; set; }
            public HandlerKind? FirstHandler { get; set; }
        }

        private readonly Dictionary<HandlerKind, long> handlerCounts = new();
        private readonly Dictionary<HandlerKind, long> firstHandlerCounts = new();
        private readonly Dictionary<int, long> invocationCounts = new();

        private long totalInputs;
        private long inputsWithOperations;
        private long totalScenarios;
        private long destroyBeforeTrue;
        private long destroyAfterTrue;
        private long destroyBothTrue;
        private long notifiedScenarios;
        private long notifiedSkipManaged;
        private long asyncScenarios;
        private long asyncForcedSingle;
        private long exhaustedScenarios;
        private long inputsWithExhaustion;
        private long scenariosWithTrailingBytes;
        private long scenariosWithoutTrailingBytes;

        private long totalInputLength;
        private int minInputLength = int.MaxValue;
        private int maxInputLength;

        private InputContext? current;
        private readonly string? outputPath;

        private ScenarioProfiler(string? outputPath)
        {
            this.outputPath = string.IsNullOrWhiteSpace(outputPath) ? null : outputPath;
        }

        public static ScenarioProfiler? TryCreate()
        {
            var enabled = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_PROFILE_QUEUE");

            if (!string.Equals(enabled, "1", StringComparison.Ordinal))
            {
                return null;
            }

            var outputPath = Environment.GetEnvironmentVariable("SOURCEFUNC_FUZZ_PROFILE_OUTPUT");

            try
            {
                if (!string.IsNullOrWhiteSpace(outputPath))
                {
                    var directory = Path.GetDirectoryName(outputPath);

                    if (!string.IsNullOrEmpty(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }
                }
            }
            catch
            {
                // Ignore filesystem issues when preparing the output path.
            }

            return new ScenarioProfiler(outputPath);
        }

        public void BeginInput(string name, int length)
        {
            current = new InputContext(name, length);
        }

        public void EndInput()
        {
            if (current is null)
            {
                return;
            }

            totalInputs++;
            totalInputLength += current.Length;
            minInputLength = Math.Min(minInputLength, current.Length);
            maxInputLength = Math.Max(maxInputLength, current.Length);

            if (current.ScenarioCount > 0)
            {
                inputsWithOperations++;
                totalScenarios += current.ScenarioCount;

                if (current.HadExhaustion)
                {
                    inputsWithExhaustion++;
                }
            }

            current = null;
        }

        public void RecordScenario(
            HandlerKind handler,
            int invocationCount,
            bool destroyBefore,
            bool destroyAfter,
            bool skipManaged,
            bool forcedAsyncSingle,
            bool exhausted,
            int remainingBytes)
        {
            if (current is null)
            {
                return;
            }

            current.ScenarioCount++;

            if (current.FirstHandler is null)
            {
                current.FirstHandler = handler;
                firstHandlerCounts.TryGetValue(handler, out var firstCount);
                firstHandlerCounts[handler] = firstCount + 1;
            }

            handlerCounts.TryGetValue(handler, out var handlerCount);
            handlerCounts[handler] = handlerCount + 1;

            invocationCounts.TryGetValue(invocationCount, out var invocationTotal);
            invocationCounts[invocationCount] = invocationTotal + 1;

            if (destroyBefore)
            {
                destroyBeforeTrue++;
            }

            if (destroyAfter)
            {
                destroyAfterTrue++;
            }

            if (destroyBefore && destroyAfter)
            {
                destroyBothTrue++;
            }

            if (handler == HandlerKind.Notified)
            {
                notifiedScenarios++;

                if (skipManaged)
                {
                    notifiedSkipManaged++;
                }
            }

            if (handler == HandlerKind.Async)
            {
                asyncScenarios++;

                if (forcedAsyncSingle)
                {
                    asyncForcedSingle++;
                }
            }

            if (exhausted)
            {
                exhaustedScenarios++;
                current.HadExhaustion = true;
            }

            if (remainingBytes > 0)
            {
                scenariosWithTrailingBytes++;
            }
            else
            {
                scenariosWithoutTrailingBytes++;
            }
        }

        public void EmitSummary()
        {
            if (totalInputs == 0)
            {
                return;
            }

            var lines = BuildSummary();

            foreach (var line in lines)
            {
                Console.Out.WriteLine(line);
            }

            if (!string.IsNullOrEmpty(outputPath))
            {
                try
                {
                    File.WriteAllLines(outputPath!, lines);
                }
                catch
                {
                    // Ignore failures writing the summary file.
                }
            }
        }

        private List<string> BuildSummary()
        {
            var lines = new List<string>();
            var culture = CultureInfo.InvariantCulture;
            var averageScenarios = inputsWithOperations > 0
                ? (double)totalScenarios / inputsWithOperations
                : 0.0;
            var averageLength = totalInputs > 0 ? (double)totalInputLength / totalInputs : 0.0;

            lines.Add("[profile] SourceFunc queue summary");
            lines.Add(string.Format(culture, "[profile] inputs={0} with_ops={1} exhausted_inputs={2}", totalInputs, inputsWithOperations, inputsWithExhaustion));
            lines.Add(string.Format(culture, "[profile] avg_scenarios_per_input={0:F2} avg_input_bytes={1:F1} min={2} max={3}", averageScenarios, averageLength, minInputLength == int.MaxValue ? 0 : minInputLength, maxInputLength));

            if (totalScenarios > 0)
            {
                lines.Add(string.Format(culture, "[profile] destroy_before={0} ({1:P1}) destroy_after={2} ({3:P1}) both={4} ({5:P1})",
                    destroyBeforeTrue,
                    destroyBeforeTrue / (double)totalScenarios,
                    destroyAfterTrue,
                    destroyAfterTrue / (double)totalScenarios,
                    destroyBothTrue,
                    destroyBothTrue / (double)totalScenarios));

                lines.Add(string.Format(culture, "[profile] scenarios_with_defaults={0} ({1:P1}) trailing_bytes>0={2} ({3:P1})",
                    exhaustedScenarios,
                    exhaustedScenarios / (double)totalScenarios,
                    scenariosWithTrailingBytes,
                    scenariosWithTrailingBytes / (double)totalScenarios));

                var handlerBuilder = new StringBuilder();
                handlerBuilder.Append("[profile] handler_mix:");

                foreach (HandlerKind kind in Enum.GetValues(typeof(HandlerKind)))
                {
                    handlerCounts.TryGetValue(kind, out var count);
                    handlerBuilder.Append(' ');
                    handlerBuilder.Append(kind);
                    handlerBuilder.Append('=');
                    handlerBuilder.Append(count);
                    handlerBuilder.Append(' ');
                    handlerBuilder.AppendFormat(culture, "({0:P1})", totalScenarios == 0 ? 0.0 : count / (double)totalScenarios);
                }

                lines.Add(handlerBuilder.ToString());

                if (firstHandlerCounts.Count > 0)
                {
                    var firstBuilder = new StringBuilder();
                    firstBuilder.Append("[profile] first_handler:");

                    foreach (HandlerKind kind in Enum.GetValues(typeof(HandlerKind)))
                    {
                        firstHandlerCounts.TryGetValue(kind, out var count);
                        if (count == 0)
                        {
                            continue;
                        }

                        firstBuilder.Append(' ');
                        firstBuilder.Append(kind);
                        firstBuilder.Append('=');
                        firstBuilder.Append(count);
                        firstBuilder.Append(' ');
                        firstBuilder.AppendFormat(culture, "({0:P1})", count / (double)inputsWithOperations);
                    }

                    lines.Add(firstBuilder.ToString());
                }

                if (notifiedScenarios > 0)
                {
                    lines.Add(string.Format(culture, "[profile] notified_skip_managed={0}/{1} ({2:P1})",
                        notifiedSkipManaged,
                        notifiedScenarios,
                        notifiedSkipManaged / (double)notifiedScenarios));
                }

                if (asyncScenarios > 0)
                {
                    lines.Add(string.Format(culture, "[profile] async_forced_single={0}/{1} ({2:P1})",
                        asyncForcedSingle,
                        asyncScenarios,
                        asyncForcedSingle / (double)asyncScenarios));
                }

                if (invocationCounts.Count > 0)
                {
                    var topCounts = new List<KeyValuePair<int, long>>(invocationCounts);
                    topCounts.Sort((a, b) => b.Value.CompareTo(a.Value));
                    var limit = Math.Min(6, topCounts.Count);
                    var builder = new StringBuilder();
                    builder.Append("[profile] invocation_counts:");

                    for (var i = 0; i < limit; i++)
                    {
                        var (count, value) = topCounts[i];
                        builder.Append(' ');
                        builder.Append(count);
                        builder.Append('=');
                        builder.Append(value);
                        builder.Append(' ');
                        builder.AppendFormat(culture, "({0:P1})", value / (double)totalScenarios);
                    }

                    lines.Add(builder.ToString());
                }
            }

            return lines;
        }
    }

    private sealed class IdleRegistration
    {
        public IdleRegistration(uint sourceId, long scenarioId, string kind, GLib.Internal.DestroyNotify? destroyNotify)
        {
            SourceId = sourceId;
            ScenarioId = scenarioId;
            Kind = kind;
            CreatedAt = Environment.TickCount64;
            DestroyNotify = destroyNotify;
        }

        public uint SourceId { get; }
        public long ScenarioId { get; }
        public string Kind { get; }
        public long CreatedAt { get; }
        public bool DestroyNotified { get; private set; }
        public bool Removed { get; private set; }
        public string? DestroyReason { get; private set; }
        public string? RemoveReason { get; private set; }
        public GLib.Internal.DestroyNotify? DestroyNotify { get; }

        public void MarkDestroy(string reason)
        {
            DestroyNotified = true;
            DestroyReason = reason;
        }

        public void MarkRemoved(string reason)
        {
            Removed = true;
            RemoveReason = reason;
        }
    }

    private static void TraceIdleEvent(string message)
    {
        if (!TraceIdle)
        {
            return;
        }

        Console.Error.WriteLine(message);
    }

    private static IdleRegistration RegisterIdle(uint sourceId, long scenarioId, string kind, GLib.Internal.DestroyNotify? destroyNotify)
    {
        var registration = new IdleRegistration(sourceId, scenarioId, kind, destroyNotify);

        lock (IdleRegistryLock)
        {
            IdleRegistry[sourceId] = registration;
        }

        TraceIdleEvent($"[idle] register id={sourceId} scenario={scenarioId} kind={kind}");
        return registration;
    }

    private static void MarkIdleDestroyed(uint sourceId, string reason)
    {
        IdleRegistration? registration = null;

        lock (IdleRegistryLock)
        {
            if (IdleRegistry.TryGetValue(sourceId, out registration))
            {
                registration.MarkDestroy(reason);
                IdleRegistry.Remove(sourceId);
            }
        }

        TraceIdleEvent($"[idle] destroy id={sourceId} scenario={registration?.ScenarioId ?? -1} reason={reason}");
    }

    private static bool RemoveIdleSource(uint sourceId, string reason)
    {
        if (sourceId == 0)
        {
            return false;
        }

        var removed = GLib.Functions.SourceRemove(sourceId);
        IdleRegistration? registration = null;

        lock (IdleRegistryLock)
        {
            if (IdleRegistry.TryGetValue(sourceId, out registration))
            {
                registration.MarkRemoved($"{reason} result={removed}");

                if (removed || registration.DestroyNotified)
                {
                    IdleRegistry.Remove(sourceId);
                }
            }
        }

        TraceIdleEvent($"[idle] remove id={sourceId} scenario={registration?.ScenarioId ?? -1} reason={reason} removed={removed}");
        return removed;
    }

    private static bool IsIdleActive(uint sourceId)
    {
        lock (IdleRegistryLock)
        {
            return IdleRegistry.ContainsKey(sourceId);
        }
    }

    private static void EnsureIdleRegistryCleared(string stage)
    {
        List<IdleRegistration>? leaked = null;

        lock (IdleRegistryLock)
        {
            if (IdleRegistry.Count > 0)
            {
                leaked = new List<IdleRegistration>(IdleRegistry.Values);
                IdleRegistry.Clear();
            }
        }

        if (leaked is null)
        {
            return;
        }

        foreach (var registration in leaked)
        {
            var removed = GLib.Functions.SourceRemove(registration.SourceId);
            TraceIdleEvent(
                $"[idle] leak cleanup stage={stage} id={registration.SourceId} scenario={registration.ScenarioId} removed={removed}");
        }

        throw new InvalidOperationException($"Idle registry leak detected at {stage} (count={leaked.Count}).");
    }

    private static void ForceGarbageCollection()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static int MapIdlePriority(byte raw)
    {
        return raw % 4 switch
        {
            0 => GLib.Constants.PRIORITY_HIGH,
            1 => GLib.Constants.PRIORITY_DEFAULT_IDLE,
            2 => GLib.Constants.PRIORITY_HIGH_IDLE,
            _ => GLib.Constants.PRIORITY_LOW,
        };
    }

    private static void PumpMainContext(int iterations, bool mayBlock)
    {
        if (iterations <= 0)
        {
            return;
        }

        using var context = GLib.MainContext.RefThreadDefault();

        for (var i = 0; i < iterations; i++)
        {
            context.Iteration(mayBlock);
        }
    }

    private static void RunIdleAdd(ManagedSourceFunc managed, int invocationCount, IntPtr userData, bool destroyBefore, bool destroyAfter, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var priorityRaw = ReadByteOrFallback(ref reader, ref defaults, ref exhausted);
        var dropManaged = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcBeforeIterations = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcBetweenIterations = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcAfterRemoval = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var mayBlock = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);

        var priority = MapIdlePriority(priorityRaw);
        var scenarioId = Interlocked.Increment(ref IdleScenarioCounter);

        var handler = new SourceFuncNotifiedHandler(managed);
        var handlerRef = new WeakReference<SourceFuncNotifiedHandler>(handler);
        uint sourceId = 0;

        GLib.Internal.DestroyNotify destroyWrapper = data =>
        {
            if (handlerRef.TryGetTarget(out var target) && target.DestroyNotify is not null)
            {
                target.DestroyNotify(data);
            }

            MarkIdleDestroyed(sourceId, "destroy-notify");
        };

        var nativeCallback = handler.NativeCallback ?? throw new InvalidOperationException("IdleAdd created null native callback");
        sourceId = GLib.Internal.Functions.IdleAdd(priority, nativeCallback, IntPtr.Zero, destroyWrapper);
        RegisterIdle(sourceId, scenarioId, "idle", destroyWrapper);
        TraceEdge(0x7200 | (priorityRaw & 0xFF));

        if (dropManaged)
        {
            handler = null!;
            managed = null!;
            ForceGarbageCollection();
        }

        if (gcBeforeIterations)
        {
            ForceGarbageCollection();
        }

        if (destroyBefore)
        {
            RemoveIdleSource(sourceId, "destroy-before");
        }

        var iterations = Math.Clamp(invocationCount, 1, 16);

        using (var context = GLib.MainContext.RefThreadDefault())
        {
            for (var i = 0; i < iterations; i++)
            {
                if (!IsIdleActive(sourceId))
                {
                    break;
                }

                context.Iteration(mayBlock);

                if (gcBetweenIterations)
                {
                    ForceGarbageCollection();
                }

                if (!IsIdleActive(sourceId))
                {
                    break;
                }
            }
        }

        if (destroyAfter)
        {
            RemoveIdleSource(sourceId, "destroy-after");
        }

        PumpMainContext(2, false);

        if (gcAfterRemoval)
        {
            ForceGarbageCollection();
        }

        RemoveIdleSource(sourceId, "cleanup");
    }

    private static void RunTimeoutAdd(ManagedSourceFunc managed, int invocationCount, IntPtr userData, bool destroyBefore, bool destroyAfter, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var priorityRaw = ReadByteOrFallback(ref reader, ref defaults, ref exhausted);
        var intervalRaw = ReadInt32OrFallback(ref reader, ref defaults, ref exhausted);
        var dropManaged = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcBeforeIterations = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcBetweenIterations = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var gcAfterRemoval = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);
        var mayBlock = ReadBoolOrFallback(ref reader, ref defaults, ref exhausted);

        var priority = MapIdlePriority(priorityRaw);
        var requestedInterval = 1 + (intervalRaw & 0x03FF);
        var interval = Math.Clamp(requestedInterval, 1, TimeoutIntervalClampMilliseconds);
        var scenarioId = Interlocked.Increment(ref IdleScenarioCounter);

        var handler = new SourceFuncNotifiedHandler(managed);
        var handlerRef = new WeakReference<SourceFuncNotifiedHandler>(handler);
        uint sourceId = 0;

        GLib.Internal.DestroyNotify destroyWrapper = data =>
        {
            if (handlerRef.TryGetTarget(out var target) && target.DestroyNotify is not null)
            {
                target.DestroyNotify(data);
            }

            MarkIdleDestroyed(sourceId, "destroy-notify");
        };

        var nativeCallback = handler.NativeCallback ?? throw new InvalidOperationException("TimeoutAdd created null native callback");
        sourceId = GLib.Internal.Functions.TimeoutAdd(priority, (uint)interval, nativeCallback, IntPtr.Zero, destroyWrapper);
        RegisterIdle(sourceId, scenarioId, "timeout", destroyWrapper);
        TraceEdge(0x7300 | (interval & 0xFF));
        TraceEdge(0x7400 | (Math.Min(requestedInterval, 0xFF))); // Preserve coverage for the original request.
        if (interval != requestedInterval)
        {
            TraceEdge(0x73FE);
        }

        if (dropManaged)
        {
            handler = null!;
            managed = null!;
            ForceGarbageCollection();
        }

        if (gcBeforeIterations)
        {
            ForceGarbageCollection();
        }

        if (destroyBefore)
        {
            RemoveIdleSource(sourceId, "destroy-before");
        }

        var iterations = Math.Clamp(invocationCount, 1, mayBlock ? 4 : 16);

        using (var context = GLib.MainContext.RefThreadDefault())
        {
            for (var i = 0; i < iterations; i++)
            {
                if (!IsIdleActive(sourceId))
                {
                    break;
                }

                context.Iteration(mayBlock);

                if (gcBetweenIterations)
                {
                    ForceGarbageCollection();
                }

                if (!IsIdleActive(sourceId))
                {
                    break;
                }
            }
        }

        if (destroyAfter)
        {
            RemoveIdleSource(sourceId, "destroy-after");
        }

        PumpMainContext(2, false);

        if (gcAfterRemoval)
        {
            ForceGarbageCollection();
        }

        RemoveIdleSource(sourceId, "cleanup");
    }

    private static void RunNotified(ManagedSourceFunc? managed, int invocationCount, IntPtr userData, bool destroyBefore, bool destroyAfter, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var handler = new SourceFuncNotifiedHandler(managed);

        if (destroyBefore)
        {
            InvokeDelegate(handler.DestroyNotify, ref reader, ref defaults, userData, 1, ref exhausted);
        }

        InvokeDelegate(handler.NativeCallback, ref reader, ref defaults, userData, invocationCount, ref exhausted);

        if (destroyAfter)
        {
            InvokeDelegate(handler.DestroyNotify, ref reader, ref defaults, userData, 1, ref exhausted);
        }

        handler.DestroyNotify?.Invoke(userData);
    }

    private static void RunAsync(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var handler = new SourceFuncAsyncHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, ref defaults, userData, invocationCount, ref exhausted);
    }

    private static void RunCall(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        var handler = new SourceFuncCallHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, ref defaults, userData, invocationCount, ref exhausted);
    }

    private static void RunForever(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader, ref ScenarioDefaults defaults, ref bool exhausted)
    {
        Interlocked.Increment(ref ForeverHandlesAllocated);
        var handler = new SourceFuncForeverHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, ref defaults, userData, invocationCount, ref exhausted);
        ReleaseForeverHandle(handler);
    }

    private static void InvokeDelegate(Delegate? callback, ref FuzzDataReader reader, ref ScenarioDefaults defaults, IntPtr userData, int invocationCount, ref bool exhausted)
    {
        if (callback is null)
        {
            return;
        }

        var parameters = callback.Method.GetParameters();

        for (var i = 0; i < invocationCount; i++)
        {
            var arguments = CreateArguments(parameters, ref reader, ref defaults, userData, ref exhausted);

            try
            {
                callback.DynamicInvoke(arguments);
            }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            {
                throw ex.InnerException;
            }
        }
    }

    private static void ReleaseForeverHandle(SourceFuncForeverHandler handler)
    {
        ForeverHandleReleaser?.Invoke(handler);
        Interlocked.Increment(ref ForeverHandlesReleased);
    }

    private static Action<SourceFuncForeverHandler>? CreateForeverHandleReleaser()
    {
        try
        {
            var field = typeof(SourceFuncForeverHandler).GetField(
                "gch",
                BindingFlags.Instance | BindingFlags.NonPublic);

            if (field is null || field.FieldType != typeof(GCHandle))
            {
                return null;
            }

            return handler =>
            {
                try
                {
                    var handle = (GCHandle)field.GetValue(handler)!;

                    if (handle.IsAllocated)
                    {
                        handle.Free();
                        field.SetValue(handler, default(GCHandle));
                    }
                }
                catch
                {
                    // Ignore failures; fuzzing should keep running even if the handle cannot be released.
                }
            };
        }
        catch
        {
            return null;
        }
    }

    private static object?[] CreateArguments(ParameterInfo[] parameters, ref FuzzDataReader reader, ref ScenarioDefaults defaults, IntPtr userData, ref bool exhausted)
    {
        if (parameters.Length == 0)
        {
            return System.Array.Empty<object?>();
        }

        var arguments = new object?[parameters.Length];

        for (var i = 0; i < parameters.Length; i++)
        {
            arguments[i] = CreateArgument(parameters[i], ref reader, ref defaults, userData, ref exhausted);
        }

        return arguments;
    }

    private static object? CreateArgument(ParameterInfo parameter, ref FuzzDataReader reader, ref ScenarioDefaults defaults, IntPtr userData, ref bool exhausted)
    {
        var parameterType = parameter.ParameterType;
        var elementType = parameterType.IsByRef ? parameterType.GetElementType()! : parameterType;

        return CreateValue(elementType, ref reader, ref defaults, userData, ref exhausted);
    }

    private static object? CreateValue(Type type, ref FuzzDataReader reader, ref ScenarioDefaults defaults, IntPtr userData, ref bool exhausted)
    {
        if (type == typeof(IntPtr) || type == typeof(nint))
        {
            return userData;
        }

        if (type == typeof(UIntPtr) || type == typeof(nuint))
        {
            if (reader.TryReadInt32(out var raw))
            {
                return (nuint)(ulong)(uint)raw;
            }

            exhausted = true;
            return (nuint)(ulong)(uint)defaults.NextInt32();
        }

        if (type == typeof(bool))
        {
            if (reader.TryReadBool(out var value))
            {
                return value;
            }

            exhausted = true;
            return defaults.NextBool();
        }

        if (type == typeof(byte))
        {
            if (reader.TryReadByte(out var value))
            {
                return value;
            }

            exhausted = true;
            return defaults.NextByte();
        }

        if (type == typeof(sbyte))
        {
            if (reader.TryReadByte(out var value))
            {
                return unchecked((sbyte)value);
            }

            exhausted = true;
            return unchecked((sbyte)defaults.NextByte());
        }

        if (type == typeof(short))
        {
            if (reader.TryReadUInt16(out var value))
            {
                return unchecked((short)value);
            }

            exhausted = true;
            return unchecked((short)defaults.NextUInt16());
        }

        if (type == typeof(ushort))
        {
            if (reader.TryReadUInt16(out var value))
            {
                return value;
            }

            exhausted = true;
            return defaults.NextUInt16();
        }

        if (type == typeof(int))
        {
            if (reader.TryReadInt32(out var value))
            {
                return value;
            }

            exhausted = true;
            return defaults.NextInt32();
        }

        if (type == typeof(uint))
        {
            if (reader.TryReadInt32(out var value))
            {
                return unchecked((uint)value);
            }

            exhausted = true;
            return unchecked((uint)defaults.NextInt32());
        }

        if (type == typeof(long))
        {
            if (reader.TryReadInt64(out var value))
            {
                return value;
            }

            exhausted = true;
            return defaults.NextInt64();
        }

        if (type == typeof(ulong))
        {
            if (reader.TryReadInt64(out var value))
            {
                return unchecked((ulong)value);
            }

            exhausted = true;
            return unchecked((ulong)defaults.NextInt64());
        }

        if (type.IsEnum)
        {
            var underlying = Enum.GetUnderlyingType(type);
            var raw = CreateValue(underlying, ref reader, ref defaults, userData, ref exhausted);
            return raw is null ? Activator.CreateInstance(type) : Enum.ToObject(type, raw);
        }

        if (!type.IsValueType)
        {
            return null;
        }

        return Activator.CreateInstance(type);
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
        var patternBits = 0;

        for (var i = 0; i < length; i++)
        {
            bool value;

            if (reader.TryReadBool(out var readValue))
            {
                value = readValue;
            }
            else
            {
                value = defaults.NextBool();
                exhausted = true;
            }

            if (value)
            {
                patternBits |= 1 << i;
            }

            var bitId = (i & 0x1F) << 1;
            TraceEdge(0x6100 | bitId | (value ? 0x1 : 0x0));
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

        var callback = new CallbackPlan(patternBits, length, mode);
        return callback.Invoke;
    }

    private enum HandlerKind
    {
        Notified,
        Async,
        Call,
        Forever,
        Idle,
        Timeout,
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
            return (HandlerKind)(NextByte() % HandlerKindCount);
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
        private int patternBits;
        private readonly int length;
        private readonly byte mode;
        private int index;

        public CallbackPlan(int patternBits, int length, byte mode)
        {
            this.patternBits = patternBits;
            this.length = Math.Max(length, 1);
            this.mode = mode;
        }

        public bool Invoke()
        {
            var slot = index % length;
            var slotMask = 1 << slot;
            var result = (patternBits & slotMask) != 0;
            TraceEdge(0x6300 | (slot & 0x1F));

            if ((mode & 0x1) != 0)
            {
                result = !result;
                TraceEdge(0x6400);
            }

            if ((mode & 0x2) != 0)
            {
                patternBits ^= slotMask;
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
