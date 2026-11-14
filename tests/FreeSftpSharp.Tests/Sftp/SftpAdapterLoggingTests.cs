using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Storage;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The log of <c>SftpFileSystemAdapter</c> for a failed request. A storage failure (FileSystemError.Failure, for example
/// an S3 error or an I/O error of the disk) is not caused by the client: it is logged as a warning with the exception, so
/// an operator sees the real cause behind SSH_FX_FAILURE. Errors that a client causes (a missing path, ...) stay at debug.
/// </summary>
public sealed class SftpAdapterLoggingTests
{
    [Fact]
    public void A_storage_failure_is_logged_as_a_warning_with_the_cause()
    {
        var logger = new ListLogger();
        var cause = new InvalidOperationException("The storage request failed (S3 404 NoSuchBucket, request id 42)");
        using var client = Connect(new ThrowingFileSystem(() => new FileSystemException(FileSystemError.Failure, cause.Message, cause)), logger);

        Assert.Equal(SSH_FX_FAILURE, client.MakeDirectory("/dir"));

        var entry = Assert.Single(logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("/dir", entry.Message);
        var exception = Assert.IsType<FileSystemException>(entry.Exception);
        Assert.Contains("NoSuchBucket", exception.Message);
    }

    [Theory]
    [InlineData(FileSystemError.NoSuchFile)]
    [InlineData(FileSystemError.PermissionDenied)]
    [InlineData(FileSystemError.AlreadyExists)]
    [InlineData(FileSystemError.OpNotSupported)]
    public void An_error_that_the_client_causes_stays_at_debug(FileSystemError error)
    {
        var logger = new ListLogger();
        using var client = Connect(new ThrowingFileSystem(() => new FileSystemException(error, "detail")), logger);

        client.MakeDirectory("/dir");

        Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Information && e.Exception != null);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Debug && e.Exception is FileSystemException);
    }

    private static SftpEngineClient Connect(IFileSystem fileSystem, ILogger logger)
    {
        var client = new SftpEngineClient(fileSystem, logger: logger);
        client.Service.OnData(Init());
        client.Responses.Clear();
        return client;
    }

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
                Entries.Add((logLevel, formatter(state, exception), exception));
        }
    }
}
