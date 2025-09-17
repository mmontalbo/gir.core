using System;
using System.Buffers;
using System.IO;
using System.Reflection;
using GLib.Internal;
using ManagedSourceFunc = GLib.SourceFunc;

namespace GirCore.Fuzzing;

public static class SourceFuncFuzzer
{
    private const int MaxInputLength = 4096;
    private const int MaxOperationCount = 32;
    private static readonly ManagedSourceFunc DefaultCallback = () => false;
    private static readonly System.Collections.Generic.Dictionary<int, int> CoverageSlots = new();
    private static readonly object CoverageLock = new();
    private static int NextCoverageSlot;

    public static void Run(Stream stream)
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
            Execute(span);
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

    private static void Execute(ReadOnlySpan<byte> data)
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
            if (!ExecuteScenario(ref reader, ref defaults))
            {
                break;
            }
        }
    }

    private static bool ExecuteScenario(ref FuzzDataReader reader, ref ScenarioDefaults defaults)
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
        }

        var continuation = !exhausted || reader.RemainingBytes > 0;
        TraceEdge(0x5000 | (exhausted ? 0x1 : 0) | (reader.RemainingBytes > 0 ? 0x2 : 0));
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

    private static class TraceAccessor
    {
        private static readonly System.Reflection.FieldInfo? SharedMemField;

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
        var handler = new SourceFuncForeverHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, ref defaults, userData, invocationCount, ref exhausted);
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
