using FxSsh.Logging;
using FxSsh.Services.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The SFTP engine logs a failed request at a level that matches its cause: errors that clients cause in
/// normal use (a missing path, denied access, an existing target) are not server faults and must not be
/// logged as errors; an unexpected exception is an error, with the exception.
/// <para>
/// The FxSsh log is static, so this class captures it in a collection that runs alone.
/// </para>
/// </summary>
[Collection(Name)]
public sealed class SftpFailureLoggingTests : SftpEngineTestBase
{
    public const string Name = "FxSsh static log";

    private readonly CapturingSink _sink = new();

    public SftpFailureLoggingTests()
    {
        Log.Configure(new LogOptions { MinLevel = LogLevel.Trace, Sink = _sink });
    }

    [Fact]
    public void Missing_path_and_denied_access_are_logged_at_debug_level()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_STAT, "/missing-for-log"));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Open("/missing-for-log", SftpOpenFlags.Read).StatusCode);
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_RMDIR, "/"));

        var entries = _sink.SftpFailures();
        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal(LogLevel.Debug, e.Level));
        Assert.All(entries, e => Assert.Null(e.Exception));
    }

    [Fact]
    public void Failure_of_a_file_operation_is_logged_at_information_level()
    {
        Directory.CreateDirectory(Physical("/full"));
        File.WriteAllText(Physical("/full/a.txt"), "a");

        Assert.Equal(SSH_FX_FAILURE, Client.Status(SSH_FXP_RMDIR, "/full"));   // not empty
        Assert.Equal(SSH_FX_FAILURE, Client.MakeDirectory("/full"));           // exists

        var entries = _sink.SftpFailures();
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal(LogLevel.Info, e.Level));
    }

    [Fact]
    public void Unexpected_exception_is_logged_as_an_error_with_the_exception()
    {
        using var client = new SftpEngineClient(new ThrowingFileSystem(() => new InvalidOperationException("bug in the file system")));
        client.Service.OnData(Init());

        Assert.Equal(SSH_FX_FAILURE, client.SendPath(SSH_FXP_STAT, "/a.txt").StatusCode);

        var entry = Assert.Single(_sink.SftpFailures());
        Assert.Equal(LogLevel.Fail, entry.Level);
        Assert.IsType<InvalidOperationException>(entry.Exception);
    }

    public override void Dispose()
    {
        Log.Configure(new LogOptions());
        base.Dispose();
    }

    private sealed class CapturingSink : ILogSink
    {
        private readonly List<(LogLevel Level, string Message, Exception? Exception)> _entries = [];

        public void Write(LogLevel level, string message, Exception? exception = null)
        {
            lock (_entries)
                _entries.Add((level, message, exception));
        }

        public List<(LogLevel Level, string Message, Exception? Exception)> SftpFailures()
        {
            lock (_entries)
                return _entries.Where(e => e.Message.StartsWith("SFTP request failed", StringComparison.Ordinal)).ToList();
        }
    }
}

[CollectionDefinition(SftpFailureLoggingTests.Name, DisableParallelization = true)]
public sealed class FxSshStaticLogCollection;
