using System;
using System.Buffers;
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
    private const string DumpDirectoryVariable = "SOURCEFUNC_FUZZ_FORK_DUMP_DIR";
    private const string LogTimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffffffZ";
    private const string WorkerVariable = "AFL_FUZZER_ID";
    private const string DefaultLogFileName = "sourcefunc-fork.log";
    private const string DefaultDumpDirectoryName = "sourcefunc-fork-dumps";
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

        var workerIdentity = ResolveWorkerIdentity();
        var resolvedLogPath = ResolveLogPath(logPath, workerIdentity);
        EnsureParentDirectory(resolvedLogPath);

        using var logStream = new FileStream(resolvedLogPath, FileMode.Append, FileAccess.Write, FileShare.Read);
        using var logWriter = new StreamWriter(logStream, Encoding.UTF8) { AutoFlush = true };
        Log(logWriter, $"forkserver logging enabled (worker={workerIdentity})");

        try
        {
            RunInternal(action, logWriter, workerIdentity);
        }
        catch (Exception ex)
        {
            Log(logWriter, $"forkserver fatal exception: {ex}");
            throw;
        }
    }

    private static void RunInternal(Action<Stream> action, StreamWriter log, string workerIdentity)
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
        var capture = new InputCapture(SourceFuncFuzzer.MaxInputLength, workerIdentity);

        try
        {
            stream.CopyTo(scratch.InnerStream);
            scratch.InnerStream.Seek(0, SeekOrigin.Begin);
            scratch.Position = 0;

            Setup(action, scratch, sharedPtr, trace);
            scratch.InnerStream.Seek(0, SeekOrigin.Begin);
            scratch.Position = 0;

            var stageTimer = Stopwatch.StartNew();

            try
            {
                stageTimer.Restart();
                var initialCommand = control.ReadInt32();
                LogLatency(log, "control-read", 0, stageTimer.ElapsedMilliseconds, ref ControlReadMax);
                if (initialCommand != 0)
                {
                    Log(log, $"received control command={initialCommand} during initial handshake; terminating");
                    return;
                }
            }
            catch (Exception ex)
            {
                capture.RecordFailure("handshake-control-read", ex);
                throw;
            }

            try
            {
                stageTimer.Restart();
                status.Write(pid);
                status.Flush();
                LogLatency(log, "status-write-pid", 0, stageTimer.ElapsedMilliseconds, ref StatusWritePidMax);
            }
            catch (Exception ex)
            {
                capture.RecordFailure("handshake-status-write-pid", ex);
                throw;
            }

            trace.ResetPrevLocation();

            stageTimer.Restart();
            var initialResult = Execute(action, scratch, log, 0, capture);
            LogLatency(log, "execute", 0, stageTimer.ElapsedMilliseconds, ref ExecuteMax);

            try
            {
                stageTimer.Restart();
                status.Write(initialResult);
                status.Flush();
                LogLatency(log, "status-write-result", 0, stageTimer.ElapsedMilliseconds, ref StatusWriteResultMax);
            }
            catch (Exception ex)
            {
                capture.RecordFailure("handshake-status-write-result", ex);
                throw;
            }

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
                    capture.RecordFailure("control-read", ex);
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
                    capture.RecordFailure("status-write-pid", ex);
                    Log(log, $"status write (pid) failed at iteration={iterations}: {ex.GetType().Name} {ex.Message}");
                    throw;
                }

                trace.ResetPrevLocation();
                stageTimer.Restart();
                var result = Execute(action, stream, log, iterations + 1, capture);
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
                    capture.RecordFailure("status-write-result", ex);
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
        catch (Exception ex)
        {
            capture.RecordFailure("unhandled", ex);
            capture.DumpFailure(log);
            throw;
        }
    }

    private static void Setup(Action<Stream> action, NonDisposingStreamWrapper stream, byte* sharedMem, TraceBridge trace)
    {
        Execute(action, stream, null, -1);
        trace.ResetPrevLocation();
        new Span<byte>(sharedMem, 1 << 16).Clear();
    }

    private static int Execute(Action<Stream> action, Stream stream, StreamWriter? log, long iteration, InputCapture? capture = null)
    {
        CapturingStream? capturingStream = null;

        try
        {
            if (capture is not null)
            {
                capturingStream = capture.BeginIteration(stream, iteration);
                stream = capturingStream;
            }

            action(stream);
            return FaultNone;
        }
        catch (Exception ex)
        {
            capture?.RecordFailure("execute", ex);
            log?.WriteLine($"{Timestamp()} [fork] iteration={iteration} exception={ex.GetType().FullName}: {ex.Message}");
            return FaultCrash;
        }
        finally
        {
            capturingStream?.Dispose();
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

    private sealed class InputCapture
    {
        private readonly int maxLength;
        private readonly string dumpDirectory;
        private readonly object gate = new();

        private byte[] lastInput = Array.Empty<byte>();
        private int lastLength;
        private long lastIteration = -1;
        private bool failureRecorded;
        private string? failureStage;
        private Exception? failureException;

        public InputCapture(int maxLength, string workerIdentity)
        {
            this.maxLength = Math.Max(0, maxLength);
            var configured = Environment.GetEnvironmentVariable(DumpDirectoryVariable);
            var baseDirectory = string.IsNullOrEmpty(configured)
                ? Path.Combine(Path.GetTempPath(), DefaultDumpDirectoryName)
                : configured;
            dumpDirectory = ResolveDumpDirectory(baseDirectory, workerIdentity);
        }

        public CapturingStream BeginIteration(Stream inner, long iteration)
        {
            lock (gate)
            {
                failureRecorded = false;
                failureStage = null;
                failureException = null;
            }

            return new CapturingStream(inner, this, iteration, maxLength);
        }

        public void Update(ReadOnlySpan<byte> data, long iteration)
        {
            lock (gate)
            {
                if (data.Length > 0)
                {
                    if (lastInput.Length < data.Length)
                    {
                        lastInput = new byte[data.Length];
                    }

                    data.CopyTo(lastInput);
                    lastLength = data.Length;
                }
                else
                {
                    lastLength = 0;
                }

                lastIteration = iteration;
            }
        }

        public void RecordFailure(string stage, Exception exception)
        {
            lock (gate)
            {
                if (failureRecorded)
                {
                    return;
                }

                failureRecorded = true;
                failureStage = stage;
                failureException = exception;
            }
        }

        public void DumpFailure(StreamWriter log)
        {
            string? stage;
            Exception? exception;
            byte[]? snapshot = null;
            long iteration;
            int length;

            lock (gate)
            {
                if (!failureRecorded)
                {
                    return;
                }

                failureRecorded = false;
                stage = failureStage;
                exception = failureException;
                iteration = lastIteration;
                length = lastLength;

                if (length > 0 && lastInput.Length >= length)
                {
                    snapshot = new byte[length];
                    Array.Copy(lastInput, snapshot, length);
                }
            }

            stage ??= "unknown";

            try
            {
                if (snapshot is null)
                {
                    log.WriteLine($"{Timestamp()} [fork] failure stage={stage} iteration={iteration} had no captured input");
                }
                else
                {
                    Directory.CreateDirectory(dumpDirectory);
                    var fileName = $"failure-{iteration:D10}-{DateTime.UtcNow:yyyyMMddHHmmssfff}.bin";
                    var path = Path.Combine(dumpDirectory, fileName);
                    File.WriteAllBytes(path, snapshot);
                    log.WriteLine($"{Timestamp()} [fork] saved input iteration={iteration} bytes={snapshot.Length} stage={stage} path={path}");
                }

                if (exception is not null)
                {
                    log.WriteLine($"{Timestamp()} [fork] failure exception={exception.GetType().FullName}: {exception.Message}");
                }
            }
            catch (Exception ex)
            {
                log.WriteLine($"{Timestamp()} [fork] failed to persist failure input: {ex.GetType().Name} {ex.Message}");
            }
        }
    }

    private static string ResolveWorkerIdentity()
    {
        var configured = Environment.GetEnvironmentVariable(WorkerVariable);
        var pid = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);

        if (string.IsNullOrWhiteSpace(configured))
        {
            return pid;
        }

        var trimmed = configured.Trim();
        var sanitized = SanitizeForFileName(trimmed);

        if (string.IsNullOrEmpty(sanitized))
        {
            sanitized = "worker";
        }

        return sanitized.Contains(pid, StringComparison.Ordinal) ? sanitized : $"{sanitized}-{pid}";
    }

    private static string ResolveLogPath(string basePath, string workerIdentity)
    {
        if (IsDirectoryPath(basePath))
        {
            return Path.Combine(basePath, AppendIdentity(DefaultLogFileName, workerIdentity));
        }

        var directory = Path.GetDirectoryName(basePath);
        var fileName = Path.GetFileName(basePath);

        if (string.IsNullOrEmpty(fileName))
        {
            var targetDirectory = string.IsNullOrEmpty(directory)
                ? Path.GetTempPath()
                : directory;
            return Path.Combine(targetDirectory, AppendIdentity(DefaultLogFileName, workerIdentity));
        }

        var nameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        var augmentedName = string.IsNullOrEmpty(extension)
            ? AppendIdentity(nameWithoutExtension, workerIdentity)
            : AppendIdentity(nameWithoutExtension, workerIdentity) + extension;

        return string.IsNullOrEmpty(directory)
            ? augmentedName
            : Path.Combine(directory, augmentedName);
    }

    private static string ResolveDumpDirectory(string baseDirectory, string workerIdentity)
    {
        if (string.IsNullOrEmpty(baseDirectory))
        {
            baseDirectory = Path.Combine(Path.GetTempPath(), DefaultDumpDirectoryName);
        }

        if (IsDirectoryPath(baseDirectory) || !Path.HasExtension(baseDirectory))
        {
            return Path.Combine(baseDirectory, workerIdentity);
        }

        var directory = Path.GetDirectoryName(baseDirectory);
        if (!string.IsNullOrEmpty(directory))
        {
            var fileName = Path.GetFileName(baseDirectory);
            return Path.Combine(directory, AppendIdentity(fileName, workerIdentity));
        }

        return Path.Combine(Path.GetTempPath(), AppendIdentity(DefaultDumpDirectoryName, workerIdentity));
    }

    private static string AppendIdentity(string name, string workerIdentity)
    {
        if (string.IsNullOrEmpty(name))
        {
            return workerIdentity;
        }

        var nameWithoutExtension = Path.GetFileNameWithoutExtension(name);
        var extension = Path.GetExtension(name);
        var combined = $"{nameWithoutExtension}-{workerIdentity}";
        return string.IsNullOrEmpty(extension) ? combined : combined + extension;
    }

    private static bool IsDirectoryPath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return false;
        }

        var lastChar = path[path.Length - 1];
        if (lastChar == Path.DirectorySeparatorChar || lastChar == Path.AltDirectorySeparatorChar)
        {
            return true;
        }

        return string.IsNullOrEmpty(Path.GetFileName(path));
    }

    private static string SanitizeForFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);

        foreach (var ch in value)
        {
            builder.Append(Array.IndexOf(invalid, ch) >= 0 ? '_' : ch);
        }

        var sanitized = builder.ToString().Trim('_');
        return sanitized.Length == 0 ? string.Empty : sanitized;
    }

    private static void EnsureParentDirectory(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private sealed class CapturingStream : Stream
    {
        private readonly Stream inner;
        private readonly InputCapture owner;
        private readonly int maxLength;
        private readonly long iteration;
        private readonly byte[] buffer;
        private int length;
        private bool disposed;

        public CapturingStream(Stream inner, InputCapture owner, long iteration, int maxLength)
        {
            this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
            this.owner = owner ?? throw new ArgumentNullException(nameof(owner));
            this.iteration = iteration;
            this.maxLength = Math.Max(0, maxLength);
            buffer = ArrayPool<byte>.Shared.Rent(Math.Max(1, this.maxLength));
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => inner.Position = value;
        }

        public override void Flush() => inner.Flush();

        public override int Read(byte[] destination, int offset, int count)
        {
            var read = inner.Read(destination, offset, count);
            if (read > 0)
            {
                Capture(new ReadOnlySpan<byte>(destination, offset, read));
            }

            return read;
        }

        public override int Read(Span<byte> destination)
        {
            var read = inner.Read(destination);
            if (read > 0)
            {
                Capture(destination[..read]);
            }

            return read;
        }

        public override int ReadByte()
        {
            var value = inner.ReadByte();

            if (value >= 0)
            {
                Span<byte> temp = stackalloc byte[1];
                temp[0] = (byte)value;
                Capture(temp);
            }

            return value;
        }

        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] source, int offset, int count) => inner.Write(source, offset, count);
        public override void Write(ReadOnlySpan<byte> source) => inner.Write(source);
        public override void WriteByte(byte value) => inner.WriteByte(value);

        private void Capture(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty || maxLength == 0)
            {
                return;
            }

            var remaining = maxLength - length;

            if (remaining <= 0)
            {
                return;
            }

            var toCopy = Math.Min(remaining, data.Length);
            data[..toCopy].CopyTo(buffer.AsSpan(length, toCopy));
            length += toCopy;
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposed)
            {
                disposed = true;

                if (disposing)
                {
                    owner.Update(buffer.AsSpan(0, Math.Min(length, maxLength)), iteration);
                }

                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
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
