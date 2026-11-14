using System.IO.Compression;
using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Storage;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.WebClient;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.TwoFactor;

namespace FreeSftpSharp.Tests.WebClient;

public sealed class ContentRangeTests
{
    [Theory]
    [InlineData("bytes 0-99/1000", 0, 99, 1000)]
    [InlineData("bytes 900-999/1000", 900, 999, 1000)]
    [InlineData("bytes */0", 0, -1, 0)]
    public void Valid_ranges_are_parsed(string header, long first, long last, long total)
    {
        Assert.True(ContentRange.TryParse(header, out var range));
        Assert.Equal(new ContentRange(first, last, total), range);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("bytes 0-99/*")]
    [InlineData("bytes 100-99/1000")]
    [InlineData("bytes 0-1000/1000")]
    [InlineData("bytes */100")]
    [InlineData("items 0-9/10")]
    [InlineData("bytes -1-5/10")]
    public void Invalid_ranges_are_refused(string? header)
    {
        Assert.False(ContentRange.TryParse(header!, out _));
    }

    [Fact]
    public void The_last_chunk_is_known()
    {
        Assert.True(ContentRange.TryParse("bytes 10-19/20", out var last));
        Assert.True(last.IsLastChunk);
        Assert.Equal(10, last.Length);
        Assert.True(ContentRange.TryParse("bytes 0-9/20", out var first));
        Assert.False(first.IsLastChunk);
    }
}

public sealed class ByteRangeTests
{
    private static readonly DateTimeOffset Modified = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

    [Theory]
    [InlineData("bytes=0-9", 0, 10)]
    [InlineData("bytes=90-", 90, 10)]
    [InlineData("bytes=-5", 95, 5)]
    [InlineData("bytes=50-500", 50, 50)]
    public void One_range_is_partial(string header, long first, long length)
    {
        var range = ByteRange.Select(header, StringValues.Empty, Modified, 100);
        Assert.True(range.IsPartial);
        Assert.Equal(first, range.First);
        Assert.Equal(length, range.Length);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("bytes=0-1,5-6")]
    [InlineData("pages=1-2")]
    [InlineData("nonsense")]
    public void Otherwise_the_whole_file_is_sent(string? header)
    {
        var range = ByteRange.Select(header, StringValues.Empty, Modified, 100);
        Assert.False(range.IsPartial);
        Assert.Equal(100, range.Length);
    }

    [Fact]
    public void A_range_after_the_end_is_unsatisfiable()
    {
        Assert.True(ByteRange.Select("bytes=100-", StringValues.Empty, Modified, 100).Unsatisfiable);
    }

    [Fact]
    public void If_range_with_another_date_gives_the_whole_file()
    {
        Assert.False(ByteRange.Select("bytes=0-9", "Fri, 01 Jan 2021 00:00:00 GMT", Modified, 100).IsPartial);
        Assert.True(ByteRange.Select("bytes=0-9", Modified.ToString("R"), Modified, 100).IsPartial);
    }
}

public sealed class UploadSessionsTests
{
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly InMemoryFileSystem _storage = new();
    private readonly UploadSessions _uploads;
    private readonly Guid _session = Guid.NewGuid();

    public UploadSessionsTests()
    {
        _uploads = new UploadSessions(_time, Options.Create(new WebClientOptions { MaxUploadsPerSession = 2 }), NullLogger<UploadSessions>.Instance);
    }

    private Func<CancellationToken, ValueTask<IFileHandle>> Open(string path) =>
        ct => _storage.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, ct);

    private Task<UploadProgress> WriteAsync(string id, string path, byte[] data, int first, int length, int total) =>
        _uploads.WriteChunkAsync(_session, id, path, new ContentRange(first, first + length - 1, total), new MemoryStream(data, first, length), Open(path),
            TestContext.Current.CancellationToken);

    private async Task<byte[]> ReadAsync(string path)
    {
        await using var handle = await _storage.OpenAsync(path, FileOpenFlags.Read, null, TestContext.Current.CancellationToken);
        var size = (await handle.StatAsync(TestContext.Current.CancellationToken)).Size;
        var buffer = new byte[size];
        var read = await handle.ReadAsync(0, buffer, TestContext.Current.CancellationToken);
        Assert.Equal(size, read);
        return buffer;
    }

    [Fact]
    public async Task Chunks_in_order_make_the_file_and_the_last_one_closes_it()
    {
        var data = new byte[1_000_000];
        Random.Shared.NextBytes(data);

        Assert.Equal(new UploadProgress(400_000, false), await WriteAsync("upload-1", "/f.bin", data, 0, 400_000, data.Length));
        Assert.Equal(400_000, _uploads.GetOffset(_session, "upload-1", "/f.bin"));
        Assert.Equal(new UploadProgress(800_000, false), await WriteAsync("upload-1", "/f.bin", data, 400_000, 400_000, data.Length));
        Assert.Equal(new UploadProgress(1_000_000, true), await WriteAsync("upload-1", "/f.bin", data, 800_000, 200_000, data.Length));

        Assert.Equal(0, _uploads.Count);
        Assert.Null(_uploads.GetOffset(_session, "upload-1", "/f.bin"));
        Assert.Equal(data, await ReadAsync("/f.bin"));
    }

    [Fact]
    public async Task A_chunk_that_is_not_the_next_one_is_refused_with_the_offset()
    {
        var data = new byte[300];
        await WriteAsync("upload-2", "/g.bin", data, 0, 100, 300);

        var gap = await Assert.ThrowsAsync<UploadException>(() => WriteAsync("upload-2", "/g.bin", data, 200, 100, 300));
        Assert.Equal(409, gap.StatusCode);
        Assert.Equal(100, gap.Offset);
        var again = await Assert.ThrowsAsync<UploadException>(() => WriteAsync("upload-2", "/g.bin", data, 0, 100, 300));
        Assert.Equal(100, again.Offset);
    }

    [Fact]
    public async Task An_unknown_upload_must_start_at_zero()
    {
        var error = await Assert.ThrowsAsync<UploadException>(() => WriteAsync("upload-3", "/h.bin", new byte[200], 100, 100, 200));
        Assert.Equal(0, error.Offset);
        Assert.Null(await _storage.StatAsync("/h.bin", true, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_short_body_is_refused_and_the_upload_continues_from_what_arrived()
    {
        var data = new byte[200];
        var error = await Assert.ThrowsAsync<UploadException>(() => _uploads.WriteChunkAsync(_session, "upload-4", "/s.bin",
            new ContentRange(0, 99, 200), new MemoryStream(data, 0, 60), Open("/s.bin"), TestContext.Current.CancellationToken));
        Assert.Equal(400, error.StatusCode);
        Assert.Equal(60, _uploads.GetOffset(_session, "upload-4", "/s.bin"));
    }

    [Fact]
    public async Task An_empty_file_is_one_request()
    {
        var progress = await _uploads.WriteChunkAsync(_session, "upload-5", "/empty", new ContentRange(0, -1, 0), new MemoryStream(), Open("/empty"),
            TestContext.Current.CancellationToken);
        Assert.True(progress.Complete);
        Assert.Equal(0, (await _storage.StatAsync("/empty", true, TestContext.Current.CancellationToken))!.Size);
    }

    [Fact]
    public async Task The_number_of_open_uploads_of_a_session_is_limited()
    {
        await WriteAsync("upload-a1", "/a1", new byte[10], 0, 5, 10);
        await WriteAsync("upload-a2", "/a2", new byte[10], 0, 5, 10);
        var error = await Assert.ThrowsAsync<UploadException>(() => WriteAsync("upload-a3", "/a3", new byte[10], 0, 5, 10));
        Assert.Equal(429, error.StatusCode);
    }

    [Fact]
    public async Task Idle_and_ended_uploads_are_aborted()
    {
        await WriteAsync("upload-i1", "/i1", new byte[10], 0, 5, 10);
        _time.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(1, await _uploads.SweepAsync());
        Assert.Equal(0, _uploads.Count);

        await WriteAsync("upload-i2", "/i2", new byte[10], 0, 5, 10);
        await _uploads.AbortSessionAsync(_session);
        Assert.Equal(0, _uploads.Count);
    }

    [Theory]
    [InlineData("abcdefgh", true)]
    [InlineData("0123456789abcdef0123456789abcdef", true)]
    [InlineData("short", false)]
    [InlineData("../../etc", false)]
    [InlineData(null, false)]
    public void Upload_ids_are_checked(string? id, bool valid) => Assert.Equal(valid, UploadSessions.IsValidId(id!));
}

public sealed class ZipStreamerTests
{
    [Fact]
    public async Task A_folder_and_a_file_are_streamed_into_one_archive()
    {
        var storage = new InMemoryFileSystem();
        await storage.CreateDirectoryAsync("/docs", TestContext.Current.CancellationToken);
        await storage.CreateDirectoryAsync("/docs/empty", TestContext.Current.CancellationToken);
        await WriteAsync(storage, "/docs/a.txt", "alpha");
        await WriteAsync(storage, "/top.txt", "top");
        var big = new byte[500_000];
        Random.Shared.NextBytes(big);
        await WriteAsync(storage, "/docs/big.bin", big);

        var items = await ZipStreamer.CollectAsync(storage, ["/docs", "/top.txt", "/top.txt"], TestContext.Current.CancellationToken);
        var output = new NonSeekableStream();
        await ZipStreamer.WriteAsync(storage, items, output, NullLogger.Instance, TestContext.Current.CancellationToken);

        using var archive = new ZipArchive(new MemoryStream(output.ToArray()));
        Assert.Equal(["docs/a.txt", "docs/big.bin", "docs/empty/", "top.txt"], archive.Entries.Select(e => e.FullName).Order().ToArray());
        Assert.Equal("alpha", new StreamReader(archive.GetEntry("docs/a.txt")!.Open()).ReadToEnd());
        using var copy = new MemoryStream();
        archive.GetEntry("docs/big.bin")!.Open().CopyTo(copy);
        Assert.Equal(big, copy.ToArray());
    }

    [Fact]
    public async Task A_missing_path_or_the_root_is_refused_before_anything_is_written()
    {
        var storage = new InMemoryFileSystem();
        Assert.Equal(FileSystemError.NoSuchFile, (await Assert.ThrowsAsync<FileSystemException>(() => ZipStreamer.CollectAsync(storage, ["/nope"], TestContext.Current.CancellationToken))).Error);
        Assert.Equal(FileSystemError.InvalidPath, (await Assert.ThrowsAsync<FileSystemException>(() => ZipStreamer.CollectAsync(storage, ["/"], TestContext.Current.CancellationToken))).Error);
    }

    private static Task WriteAsync(IFileSystem storage, string path, string text) => WriteAsync(storage, path, System.Text.Encoding.UTF8.GetBytes(text));

    private static async Task WriteAsync(IFileSystem storage, string path, byte[] data)
    {
        await using var handle = await storage.OpenAsync(path, FileOpenFlags.Write | FileOpenFlags.Create, null, TestContext.Current.CancellationToken);
        await handle.WriteAsync(0, data, TestContext.Current.CancellationToken);
    }

    /// <summary>A response body: write only, no seek, no synchronous writes.</summary>
    private sealed class NonSeekableStream : Stream
    {
        private readonly MemoryStream _inner = new();
        public byte[] ToArray() => _inner.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException("Synchronous write");
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => _inner.WriteAsync(buffer, cancellationToken);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _inner.WriteAsync(buffer, offset, count, cancellationToken);
    }
}

public sealed class ClientPermissionMapTests
{
    [Fact]
    public void The_controls_follow_the_most_specific_directory()
    {
        var map = new ClientPermissionMap(new EffectivePermissions(new Dictionary<string, FilePermissions>
        {
            ["/"] = FilePermissions.All,
            ["/incoming"] = FilePermissions.Upload,
            ["/outgoing"] = FilePermissions.List | FilePermissions.Download,
        }, new Dictionary<string, PathFilter>()), caseInsensitivePaths: false);

        Assert.Equal(new DirectoryActions(true, true, true, true, true, true, true), map.For("/"));
        Assert.Equal(new DirectoryActions(false, false, true, false, false, false, false), map.For("/incoming/2026"));
        var outgoing = map.For("/outgoing");
        Assert.True(outgoing.Download);
        Assert.False(outgoing.AnyChange);
    }

    [Fact]
    public void Case_insensitive_storage_matches_another_spelling()
    {
        var map = new ClientPermissionMap(new EffectivePermissions(new Dictionary<string, FilePermissions>
        {
            ["/"] = FilePermissions.All,
            ["/incoming"] = FilePermissions.Upload,
        }, new Dictionary<string, PathFilter>()), caseInsensitivePaths: true);

        Assert.False(map.For("/INCOMING").Download);
    }
}

/// <summary>The interactive login of <see cref="PasswordLoginService"/> (the web client): it asks for the second step itself.</summary>
public sealed class InteractivePasswordLoginTests
{
    private const string Password = "Interactive-42";
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());

    private User AddUser(string name, Action<User>? change = null)
    {
        var user = new User { Username = name, UserRootDirectory = "/tmp", HashedPassword = PasswordHasher.Hash(Password, PasswordHasher.MinimumIterations) };
        change?.Invoke(user);
        _repository.AddUser(user);
        return user;
    }

    private PasswordLoginService Service(ITwoFactorVerifier? twoFactor = null) =>
        new(_repository, new LoginBanTracker(_time), NullLogger<PasswordLoginService>.Instance, twoFactor: twoFactor);

    [Fact]
    public async Task A_user_with_a_second_factor_gets_the_code_step_instead_of_a_refusal()
    {
        var user = AddUser("totp");
        var twoFactor = TwoFactorTestKit.CreateService(_time);
        await TwoFactorTestKit.EnrolAsync(twoFactor, TwoFactorSubject.ForUser(user), _time);
        var service = Service(twoFactor);

        var plain = await service.LoginAsync("WebDAV", UserProtocols.WebDav, "totp", Password, IPAddress.Loopback, TestContext.Current.CancellationToken);
        var interactive = await service.LoginAsync("HTTP", UserProtocols.Web, "totp", Password, IPAddress.Loopback, TestContext.Current.CancellationToken, PasswordLoginOptions.Interactive);

        Assert.Equal(PasswordLoginStatus.Failed, plain.Status);
        Assert.Equal(PasswordLoginStatus.Ok, interactive.Status);
        Assert.True(interactive.SecondFactorRequired);
    }

    [Fact]
    public async Task An_expired_password_is_reported_instead_of_refused()
    {
        _repository.ServerSettings.PasswordMaxAgeDays = 30;
        AddUser("old", u => u.PasswordChangedAt = _time.GetUtcNow().UtcDateTime.AddDays(-60));
        var service = Service();

        var plain = await service.LoginAsync("WebDAV", UserProtocols.WebDav, "old", Password, IPAddress.Loopback, TestContext.Current.CancellationToken);
        var interactive = await service.LoginAsync("HTTP", UserProtocols.Web, "old", Password, IPAddress.Loopback, TestContext.Current.CancellationToken, PasswordLoginOptions.Interactive);
        var wrong = await service.LoginAsync("HTTP", UserProtocols.Web, "old", "wrong", IPAddress.Loopback, TestContext.Current.CancellationToken, PasswordLoginOptions.Interactive);

        Assert.Equal(PasswordLoginStatus.Failed, plain.Status);
        Assert.Equal(PasswordLoginStatus.Ok, interactive.Status);
        Assert.True(interactive.PasswordExpired);
        Assert.Equal(PasswordLoginStatus.Failed, wrong.Status);
    }

    [Fact]
    public async Task The_web_protocol_flag_is_checked()
    {
        AddUser("sftponly", u => u.AllowedProtocols = UserProtocols.Sftp);

        var result = await Service().LoginAsync("HTTP", UserProtocols.Web, "sftponly", Password, IPAddress.Loopback, TestContext.Current.CancellationToken, PasswordLoginOptions.Interactive);

        Assert.Equal(PasswordLoginStatus.ProtocolNotAllowed, result.Status);
    }
}
