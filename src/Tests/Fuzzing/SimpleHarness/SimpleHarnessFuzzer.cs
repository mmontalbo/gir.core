using System;
using System.Buffers;
using System.IO;

namespace GirCore.Fuzzing;

public static class SimpleHarnessFuzzer
{
    private const int MaxInputLength = 8;
    private static readonly System.Collections.Generic.Dictionary<int, int> CoverageSlots = new();
    private static readonly object CoverageLock = new();
    private static int NextCoverageSlot;

    public static void Run(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (IsTracingEnabled())
        {
            Console.Error.WriteLine($"trace: stream={stream.GetType().FullName}");
        }

        Span<byte> buffer = stackalloc byte[MaxInputLength];
        var total = 0;

        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);

            if (read <= 0)
            {
                break;
            }

            total += read;
        }

        if (IsTracingEnabled())
        {
            Console.Error.WriteLine($"trace: bytes={total}");
        }

        if (total == 0)
        {
            return;
        }

        var data = buffer[..total];
        TraceEdge(0x1000 | (data[0] & 0xFF));
        TraceEdge(0x1100 | Math.Min(total, 0xFF));

        if (data[0] == (byte)'A')
        {
            TraceEdge(0x2000);
            BranchA(data);
        }
        else if (data[0] == (byte)'B')
        {
            TraceEdge(0x2001);
            BranchB(data);
        }
        else
        {
            TraceEdge(0x2002);
            BranchDefault(data);
        }
    }

    private static void BranchA(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            TraceEdge(0x3000);
            return;
        }

        if (data[1] == (byte)'F')
        {
            TraceEdge(0x3001);

            if (data.Length >= 3 && data[2] == (byte)'Z')
            {
                TraceEdge(0x3002);

                if (data.Length >= 4 && data[3] == (byte)'Z')
                {
                    TraceEdge(0x3003);
                    throw new InvalidOperationException("Reached the deep branch");
                }
            }
        }
        else
        {
            TraceEdge(0x3004 | (data[1] & 0xFF));
        }
    }

    private static void BranchB(ReadOnlySpan<byte> data)
    {
        TraceEdge(0x4000 | Math.Min(data.Length, 0xFF));

        if (data.Length >= 2 && data[1] == 0)
        {
            TraceEdge(0x4001);
            throw new ArgumentException("Detected zero byte after 'B'");
        }
    }

    private static void BranchDefault(ReadOnlySpan<byte> data)
    {
        TraceEdge(0x5000 | Math.Min(data.Length, 0xFF));

        if (data.Length >= 3 && data[0] == data[2])
        {
            TraceEdge(0x5001);
            throw new InvalidDataException("Mirrored bytes");
        }
    }

    private static bool IsTracingEnabled()
    {
        var value = Environment.GetEnvironmentVariable("SIMPLE_HARNESS_TRACE");
        return string.Equals(value, "1", StringComparison.Ordinal);
    }

    private static unsafe void TraceEdge(int id)
    {
        var shared = TraceAccessor.GetSharedMem();

        if (IsTracingEnabled())
        {
            var state = shared is null ? "trace: shared null" : $"trace: shared ready {id:x4}";
            Console.Error.WriteLine(state);
        }

        if (shared is null)
        {
            return;
        }

        var index = GetCoverageSlot(id);
        var slot = shared + index;

        if (IsTracingEnabled())
        {
            Console.Error.WriteLine($"trace: slot {index:x4}");
        }

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
}
