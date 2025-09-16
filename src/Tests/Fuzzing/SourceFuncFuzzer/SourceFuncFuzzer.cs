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
        var operations = Math.Min(MaxOperationCount, (reader.ReadByte() & 0x1F) + 1);

        for (var i = 0; i < operations; i++)
        {
            ExecuteScenario(ref reader);
        }
    }

    private static void ExecuteScenario(ref FuzzDataReader reader)
    {
        var handler = (HandlerKind)(reader.ReadByte() % 4);
        var invocationCount = 1 + (reader.ReadByte() & 0x0F);
        var destroyBefore = reader.ReadBool();
        var destroyAfter = reader.ReadBool();
        var userData = new IntPtr(reader.ReadInt32());

        ManagedSourceFunc? managed = handler == HandlerKind.Notified && reader.ReadBool()
            ? null
            : CreateCallback(ref reader);

        switch (handler)
        {
            case HandlerKind.Notified:
                RunNotified(managed, invocationCount, userData, destroyBefore, destroyAfter, ref reader);
                break;
            case HandlerKind.Async:
                RunAsync(managed ?? DefaultCallback, invocationCount, userData, ref reader);
                break;
            case HandlerKind.Call:
                RunCall(managed ?? DefaultCallback, invocationCount, userData, ref reader);
                break;
            case HandlerKind.Forever:
                RunForever(managed ?? DefaultCallback, invocationCount, userData, ref reader);
                break;
        }
    }

    private static void RunNotified(ManagedSourceFunc? managed, int invocationCount, IntPtr userData, bool destroyBefore, bool destroyAfter, ref FuzzDataReader reader)
    {
        var handler = new SourceFuncNotifiedHandler(managed);

        if (destroyBefore)
        {
            InvokeDelegate(handler.DestroyNotify, ref reader, userData, 1);
        }

        InvokeDelegate(handler.NativeCallback, ref reader, userData, invocationCount);

        if (destroyAfter)
        {
            InvokeDelegate(handler.DestroyNotify, ref reader, userData, 1);
        }
    }

    private static void RunAsync(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader)
    {
        var handler = new SourceFuncAsyncHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, userData, invocationCount);
    }

    private static void RunCall(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader)
    {
        var handler = new SourceFuncCallHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, userData, invocationCount);
    }

    private static void RunForever(ManagedSourceFunc managed, int invocationCount, IntPtr userData, ref FuzzDataReader reader)
    {
        var handler = new SourceFuncForeverHandler(managed);
        InvokeDelegate(handler.NativeCallback, ref reader, userData, invocationCount);
    }

    private static void InvokeDelegate(Delegate? callback, ref FuzzDataReader reader, IntPtr userData, int invocationCount)
    {
        if (callback is null)
        {
            return;
        }

        var parameters = callback.Method.GetParameters();

        for (var i = 0; i < invocationCount; i++)
        {
            var arguments = CreateArguments(parameters, ref reader, userData);

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

    private static object?[] CreateArguments(ParameterInfo[] parameters, ref FuzzDataReader reader, IntPtr userData)
    {
        if (parameters.Length == 0)
        {
            return Array.Empty<object?>();
        }

        var arguments = new object?[parameters.Length];

        for (var i = 0; i < parameters.Length; i++)
        {
            arguments[i] = CreateArgument(parameters[i], ref reader, userData);
        }

        return arguments;
    }

    private static object? CreateArgument(ParameterInfo parameter, ref FuzzDataReader reader, IntPtr userData)
    {
        var parameterType = parameter.ParameterType;
        var elementType = parameterType.IsByRef ? parameterType.GetElementType()! : parameterType;

        return CreateValue(elementType, ref reader, userData);
    }

    private static object? CreateValue(Type type, ref FuzzDataReader reader, IntPtr userData)
    {
        if (type == typeof(IntPtr) || type == typeof(nint))
        {
            return userData;
        }

        if (type == typeof(UIntPtr) || type == typeof(nuint))
        {
            return (nuint)(ulong)(uint)reader.ReadInt32();
        }

        if (type == typeof(bool))
        {
            return reader.ReadBool();
        }

        if (type == typeof(byte))
        {
            return reader.ReadByte();
        }

        if (type == typeof(sbyte))
        {
            return unchecked((sbyte)reader.ReadByte());
        }

        if (type == typeof(short))
        {
            return unchecked((short)reader.ReadUInt16());
        }

        if (type == typeof(ushort))
        {
            return reader.ReadUInt16();
        }

        if (type == typeof(int))
        {
            return reader.ReadInt32();
        }

        if (type == typeof(uint))
        {
            return unchecked((uint)reader.ReadInt32());
        }

        if (type == typeof(long))
        {
            return reader.ReadInt64();
        }

        if (type == typeof(ulong))
        {
            return unchecked((ulong)reader.ReadInt64());
        }

        if (type.IsEnum)
        {
            var underlying = Enum.GetUnderlyingType(type);
            var raw = CreateValue(underlying, ref reader, userData);
            return raw is null ? Activator.CreateInstance(type) : Enum.ToObject(type, raw);
        }

        if (!type.IsValueType)
        {
            return null;
        }

        return Activator.CreateInstance(type);
    }

    private static ManagedSourceFunc CreateCallback(ref FuzzDataReader reader)
    {
        var length = 1 + (reader.ReadByte() & 0x07);
        var pattern = new bool[length];

        for (var i = 0; i < pattern.Length; i++)
        {
            pattern[i] = reader.ReadBool();
        }

        var mode = reader.ReadByte();
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

            if ((mode & 0x1) != 0)
            {
                result = !result;
            }

            if ((mode & 0x2) != 0)
            {
                pattern[slot] = !pattern[slot];
            }

            if ((mode & 0x4) != 0 && index % 2 == 0)
            {
                result = false;
            }

            index++;
            return result;
        }
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

    public byte ReadByte()
    {
        if (offset >= data.Length)
        {
            return 0;
        }

        return data[offset++];
    }

    public bool ReadBool()
    {
        return (ReadByte() & 1) != 0;
    }

    public ushort ReadUInt16()
    {
        var lower = ReadByte();
        var upper = ReadByte();
        return (ushort)(lower | (upper << 8));
    }

    public int ReadInt32()
    {
        var value = 0;

        for (var i = 0; i < 4; i++)
        {
            value |= ReadByte() << (8 * i);
        }

        return value;
    }

    public long ReadInt64()
    {
        long value = 0;

        for (var i = 0; i < 8; i++)
        {
            value |= (long)ReadByte() << (8 * i);
        }

        return value;
    }
}
