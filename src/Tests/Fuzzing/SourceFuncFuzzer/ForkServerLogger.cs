using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GirCore.Fuzzing;

internal static unsafe class ForkServerLogger
{
    private const string SharedMemoryVariable = "__AFL_SHM_ID";
    private const string ControlHandleVariable = "198";
    private const string StatusHandleVariable = "199";
    private const string LogTimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffffffZ";
    private const int SlowOperationThresholdMs = 100;
    private const long StatisticsLogInterval = 1_000_000;

    private static long ControlReadMax;
    private static long StatusWritePidMax;
    private static long ExecuteMax;
    private static long StatusWriteResultMax;

    public static void Run(Action<Stream> action, string? logPath)
    {
        if (string.IsNullOrEmpty(logPath))
        {
            SharpFuzz.Fuzzer.Run(action);
            return;
        }

        using var logStream = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read);
        using var logWriter = new StreamWriter(logStream, Encoding.UTF8) { AutoFlush = true };
        Log(logWriter, "forkserver logging enabled");

        try
        {
            RunInternal(action, logWriter);
        }
        catch (Exception ex)
        {
            Log(logWriter, $"forkserver fatal exception: {ex}");
            throw;
        }
    }

    private static void RunInternal(Action<Stream> action, StreamWriter log)
    {
        var shmValue = Environment.GetEnvironmentVariable(SharedMemoryVariable);

        using var stdin = Console.OpenStandardInput();
        using var stream = new NonDisposingStreamWrapper(stdin);

        if (!int.TryParse(shmValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var shmid))
        {
            Log(log, "no shared memory id found; falling back to default runner");
            SharpFuzz.Fuzzer.Run(action);
            return;
        }

        using var shared = AttachSharedMemory(shmid);
        var sharedPtr = (byte*)shared.DangerousGetHandle();
        var trace = new TraceBridge(sharedPtr);
        var pid = Process.GetCurrentProcess().Id;

        using var controlPipe = new AnonymousPipeClientStream(PipeDirection.In, ControlHandleVariable);
        using var statusPipe = new AnonymousPipeClientStream(PipeDirection.Out, StatusHandleVariable);
        using var control = new BinaryReader(controlPipe);
        using var status = new BinaryWriter(statusPipe);

        Log(log, $"attached shared memory (pid={pid}, shmid={shmid}, ptr=0x{new IntPtr(sharedPtr).ToInt64():x})");
        Log(log, $"pipe handles control={controlPipe.SafePipeHandle.DangerousGetHandle()} status={statusPipe.SafePipeHandle.DangerousGetHandle()}");

        status.Write(0);
        status.Flush();

        using var scratch = new NonDisposingStreamWrapper(new MemoryStream());

        stream.CopyTo(scratch.InnerStream);
        scratch.InnerStream.Seek(0, SeekOrigin.Begin);
        scratch.Position = 0;

        Setup(action, scratch, sharedPtr, trace);
        scratch.InnerStream.Seek(0, SeekOrigin.Begin);
        scratch.Position = 0;

        var stageTimer = Stopwatch.StartNew();

        stageTimer.Restart();
        var initialCommand = control.ReadInt32();
        LogLatency(log, "control-read", 0, stageTimer.ElapsedMilliseconds, ref ControlReadMax);
        if (initialCommand != 0)
        {
            Log(log, $"received control command={initialCommand} during initial handshake; terminating");
            return;
        }

        stageTimer.Restart();
        status.Write(pid);
        status.Flush();
        LogLatency(log, "status-write-pid", 0, stageTimer.ElapsedMilliseconds, ref StatusWritePidMax);

        trace.ResetPrevLocation();

        stageTimer.Restart();
        var initialResult = Execute(action, scratch, log, 0);
        LogLatency(log, "execute", 0, stageTimer.ElapsedMilliseconds, ref ExecuteMax);

        stageTimer.Restart();
        status.Write(initialResult);
        status.Flush();
        LogLatency(log, "status-write-result", 0, stageTimer.ElapsedMilliseconds, ref StatusWriteResultMax);

        var iterations = 0L;
        var lastLog = Stopwatch.StartNew();

        while (true)
        {
            try
            {
                stageTimer.Restart();
                var controlCommand = control.ReadInt32();
                LogLatency(log, "control-read", iterations + 1, stageTimer.ElapsedMilliseconds, ref ControlReadMax);

                if (controlCommand != 0)
                {
                    if (controlCommand == 1)
                    {
                        Log(log, $"received kill command at iteration={iterations}");
                        return;
                    }

                    Log(log, $"received unknown control command={controlCommand} at iteration={iterations}; terminating");
                    return;
                }
            }
            catch (Exception ex)
            {
                Log(log, $"control pipe read failed at iteration={iterations}: {ex.GetType().Name} {ex.Message}");
                throw;
            }

            try
            {
                stageTimer.Restart();
                status.Write(pid);
                status.Flush();
                LogLatency(log, "status-write-pid", iterations + 1, stageTimer.ElapsedMilliseconds, ref StatusWritePidMax);
            }
            catch (Exception ex)
            {
                Log(log, $"status write (pid) failed at iteration={iterations}: {ex.GetType().Name} {ex.Message}");
                throw;
            }

            trace.ResetPrevLocation();
            stageTimer.Restart();
            var result = Execute(action, stream, log, iterations + 1);
            LogLatency(log, "execute", iterations + 1, stageTimer.ElapsedMilliseconds, ref ExecuteMax);
            try
            {
                stageTimer.Restart();
                status.Write(result);
                status.Flush();
                LogLatency(log, "status-write-result", iterations + 1, stageTimer.ElapsedMilliseconds, ref StatusWriteResultMax);
            }
            catch (Exception ex)
            {
                Log(log, $"status write (result={result}) failed at iteration={iterations}: {ex.GetType().Name} {ex.Message}");
                throw;
            }

            iterations++;

            if (lastLog.ElapsedMilliseconds >= 5_000)
            {
                Log(log, $"heartbeat iterations={iterations}");
                lastLog.Restart();
            }

            MaybeLogStatistics(log, iterations);
        }
    }

    private static void Setup(Action<Stream> action, NonDisposingStreamWrapper stream, byte* sharedMem, TraceBridge trace)
    {
        Execute(action, stream, null, -1);
        trace.ResetPrevLocation();
        new Span<byte>(sharedMem, 1 << 16).Clear();
    }

    private static int Execute(Action<Stream> action, Stream stream, StreamWriter? log, long iteration)
    {
        try
        {
            action(stream);
            return FaultNone;
        }
        catch (Exception ex)
        {
            log?.WriteLine($"{Timestamp()} [fork] iteration={iteration} exception={ex.GetType().FullName}: {ex.Message}");
            return FaultCrash;
        }
    }

    private static void Log(StreamWriter writer, string message)
    {
        writer.WriteLine($"{Timestamp()} [fork] {message}");
    }

    private static void LogLatency(StreamWriter log, string stage, long iteration, long elapsedMs, ref long maxValue)
    {
        if (elapsedMs > maxValue)
        {
            maxValue = elapsedMs;
        }

        if (elapsedMs > SlowOperationThresholdMs)
        {
            Log(log, $"slow {stage} iteration={iteration} elapsed={elapsedMs}ms");
        }
    }

    private static void MaybeLogStatistics(StreamWriter log, long iteration)
    {
        if (iteration == 0 || iteration % StatisticsLogInterval != 0)
        {
            return;
        }

        Log(
            log,
            $"stats iteration={iteration} max={{control:{ControlReadMax}ms,statusPid:{StatusWritePidMax}ms,execute:{ExecuteMax}ms,statusResult:{StatusWriteResultMax}ms}}"
        );

        ControlReadMax = 0;
        StatusWritePidMax = 0;
        ExecuteMax = 0;
        StatusWriteResultMax = 0;
    }

    private static string Timestamp() => DateTime.UtcNow.ToString(LogTimestampFormat, CultureInfo.InvariantCulture);

    private static SharedMemoryHandle AttachSharedMemory(int shmid)
    {
        var pointer = Shmat(shmid, IntPtr.Zero, 0);

        if (pointer == new IntPtr(-1))
        {
            var errno = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"shmat failed (errno={errno})");
        }

        var handle = new SharedMemoryHandle();
        handle.Initialize(pointer);
        return handle;
    }

    private sealed class NonDisposingStreamWrapper : Stream
    {
        public Stream InnerStream { get; }

        public NonDisposingStreamWrapper(Stream inner)
        {
            InnerStream = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override bool CanRead => InnerStream.CanRead;
        public override bool CanSeek => InnerStream.CanSeek;
        public override bool CanWrite => InnerStream.CanWrite;
        public override long Length => InnerStream.Length;
        public override long Position { get => InnerStream.Position; set => InnerStream.Position = value; }

        public override void Flush() => InnerStream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => InnerStream.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => InnerStream.Seek(offset, origin);
        public override void SetLength(long value) => InnerStream.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => InnerStream.Write(buffer, offset, count);
        protected override void Dispose(bool disposing)
        {
            // Intentionally no-op to keep the underlying stream open.
        }
    }

    private sealed class TraceBridge
    {
        private readonly Action? resetPrevLocation;
        private readonly Action? resetCorePrevLocation;

        public TraceBridge(byte* sharedMem)
        {
            var traceType = Type.GetType("SharpFuzz.Common.Trace, SharpFuzz.Common");
            resetPrevLocation = InitialiseTrace(traceType, sharedMem);

            var coreTraceType = typeof(object).Assembly.GetType(traceType?.FullName ?? "SharpFuzz.Common.Trace");

            resetCorePrevLocation = InitialiseTrace(coreTraceType, sharedMem);
        }

        public void ResetPrevLocation()
        {
            resetCorePrevLocation?.Invoke();
            resetPrevLocation?.Invoke();
        }

        private static Action? InitialiseTrace(Type? traceType, byte* sharedMem)
        {
            if (traceType is null)
            {
                return null;
            }

            var sharedField = traceType.GetField("SharedMem", BindingFlags.Public | BindingFlags.Static);
            sharedField?.SetValue(null, Pointer.Box(sharedMem, typeof(byte*)));

            var prevField = traceType.GetField("PrevLocation", BindingFlags.Public | BindingFlags.Static);

            if (prevField is null)
            {
                return null;
            }

            var assign = Expression.Assign(Expression.Field(null, prevField), Expression.Constant(0));
            var reset = Expression.Lambda<Action>(assign).Compile();
            reset();
            return reset;
        }
    }

    private sealed class SharedMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SharedMemoryHandle() : base(true)
        {
        }

        public void Initialize(IntPtr pointer)
        {
            SetHandle(pointer);
        }

        protected override bool ReleaseHandle()
        {
            return Shmdt(handle) == 0;
        }
    }

    private const int FaultNone = 0;
    private const int FaultCrash = 2;

    [DllImport("libc", EntryPoint = "shmat", SetLastError = true)]
    private static extern IntPtr Shmat(int shmid, IntPtr shmaddr, int shmflg);

    [DllImport("libc", EntryPoint = "shmdt", SetLastError = true)]
    private static extern int Shmdt(IntPtr shmaddr);
}
