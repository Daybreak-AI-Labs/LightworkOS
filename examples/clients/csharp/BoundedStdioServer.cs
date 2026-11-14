using System.Diagnostics;
using System.Text;
using ModelContextProtocol.Protocol;

// The SDK's stdio transport owns an unbounded StreamReader. Its public stream
// transport lets this example enforce byte limits before that reader allocates.
internal sealed class BoundedStdioServer : IAsyncDisposable
{
    private readonly Process process;
    private readonly CancellationTokenSource stopped = new();
    private readonly Task stderrTask;
    private readonly Queue<string> stderrTail = new();
    private Exception? failure;
    private bool forced;

    public StreamClientTransport Transport { get; }

    public BoundedStdioServer()
    {
        ProcessStartInfo start = new()
        {
            FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "maverick",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        // Preserve the pinned SDK's Windows launcher contract; every argument
        // is fixed, and no server-provided value participates in the command.
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("/c");
            start.ArgumentList.Add("maverick");
        }
        start.ArgumentList.Add("mcp");
        process = Process.Start(start) ?? throw new IOException("Could not start MCP server");
        Transport = new StreamClientTransport(process.StandardInput.BaseStream,
            new BoundedLineStream(process.StandardOutput.BaseStream, 16 * 1024 * 1024, "stdout", Fail));
        stderrTask = DrainStderrAsync();
    }

    private void Fail(Exception error)
    {
        Interlocked.CompareExchange(ref failure, error, null);
        Terminate();
    }

    private void Terminate()
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                forced = true;
            }
        }
        catch (InvalidOperationException) when (process.HasExited) { }
    }

    private async Task DrainStderrAsync()
    {
        try
        {
            using var lines = new StreamReader(new BoundedLineStream(
                process.StandardError.BaseStream, 64 * 1024, "stderr", Fail), Encoding.UTF8);
            while (await lines.ReadLineAsync(stopped.Token) is { } line)
            {
                lock (stderrTail)
                {
                    if (stderrTail.Count == 10) stderrTail.Dequeue();
                    stderrTail.Enqueue(line);
                }
            }
        }
        catch (OperationCanceledException) when (stopped.IsCancellationRequested) { }
        catch (Exception) when (stopped.IsCancellationRequested) { }
        catch (Exception error) { Fail(error); }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            // The read-only exchange is finished. Terminate while the root is
            // alive: closing stdin first can let it exit and re-parent children
            // before a delayed stderr-size refusal gets to kill the tree.
            Terminate();
            process.StandardInput.Close();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
            await stderrTask.WaitAsync(TimeSpan.FromSeconds(2));
            if (failure is not null) throw new IOException("MCP transport refused server output", failure);
            if (!forced && process.ExitCode != 0)
            {
                string tail;
                lock (stderrTail) tail = string.Join(Environment.NewLine, stderrTail);
                throw new IOException($"MCP server exited with code {process.ExitCode}: {tail}");
            }
        }
        finally
        {
            stopped.Cancel();
            try
            {
                // A close/read failure must not skip process termination.
                if (!process.HasExited)
                {
                    Terminate();
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
                }
            }
            finally
            {
                process.StandardOutput.Close();
                process.StandardError.Close();
                stopped.Dispose();
                process.Dispose();
            }
        }
    }
}

internal sealed class BoundedLineStream(Stream inner, int limit, string name, Action<Exception> fail) : Stream
{
    private int lineBytes;

    private void Check(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
        {
            if (lineBytes == limit)
            {
                var error = new IOException($"MCP {name} line exceeds the transport size limit");
                fail(error);
                throw error;
            }
            lineBytes++;
            if (value == (byte)'\n') lineBytes = 0;
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = inner.Read(buffer, offset, count);
        Check(buffer.AsSpan(offset, read));
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await inner.ReadAsync(buffer, cancellationToken);
        Check(buffer.Span[..read]);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    {
        if (disposing) inner.Dispose();
        base.Dispose(disposing);
    }
}
