using System.Text;
using FxSsh.Services.Sftp;
using LocalFileSystem = SshServer.Filesystem.LocalDisk.LocalFileSystem;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The OpenSSH SFTP extensions (OpenSSH PROTOCOL, section 4): the VERSION reply announces them, and each
/// one works through <see cref="SftpService"/> + <see cref="SshServerModule.Sftp.SftpFileSystemAdapter"/> +
/// <see cref="LocalFileSystem"/>, inside the user root only.
/// </summary>
public sealed class SftpExtensionTests : SftpEngineTestBase
{
    private const ulong ST_RDONLY = 1;

    // ---- SSH_FXP_VERSION ----

    [Fact]
    public void Version_announces_the_openssh_extensions()
    {
        var extensions = VersionExtensions(Client);

        Assert.Equal("1", extensions["posix-rename@openssh.com"]);
        Assert.Equal("1", extensions["fsync@openssh.com"]);
        Assert.Equal("1", extensions["limits@openssh.com"]);
        Assert.Equal("1", extensions["expand-path@openssh.com"]);
        Assert.Equal("2", extensions["statvfs@openssh.com"]);
    }

    [Fact]
    public void Version_does_not_announce_hardlink_or_other_link_extensions()
    {
        var extensions = VersionExtensions(Client);

        Assert.DoesNotContain("hardlink@openssh.com", extensions.Keys);
        Assert.DoesNotContain("fstatvfs@openssh.com", extensions.Keys);
    }

    [Fact]
    public void Version_of_a_file_system_without_the_optional_capabilities_announces_only_the_engine_extensions()
    {
        using var service = new SftpService(new MinimalFileSystem());
        byte[]? version = null;
        service.DataReceived += (_, packet) => version = packet;

        service.OnData(Init());

        var extensions = ParseVersion(version!);
        Assert.Equal(new[] { "expand-path@openssh.com", "limits@openssh.com" }, extensions.Keys.Order(StringComparer.Ordinal));
    }

    // ---- posix-rename@openssh.com ----

    [Fact]
    public void PosixRename_replaces_an_existing_file()
    {
        File.WriteAllText(Physical("/new.txt"), "new content");
        File.WriteAllText(Physical("/old.txt"), "old content");

        Assert.Equal(SSH_FX_OK, PosixRename("/new.txt", "/old.txt"));

        Assert.False(File.Exists(Physical("/new.txt")));
        Assert.Equal("new content", File.ReadAllText(Physical("/old.txt")));
    }

    [Fact]
    public void PosixRename_to_a_new_name_moves_a_file_and_a_directory()
    {
        File.WriteAllText(Physical("/a.txt"), "a");
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/dir/inner.txt"), "i");

        Assert.Equal(SSH_FX_OK, PosixRename("/a.txt", "/b.txt"));
        Assert.Equal(SSH_FX_OK, PosixRename("/dir", "/moved"));

        Assert.Equal("a", File.ReadAllText(Physical("/b.txt")));
        Assert.Equal("i", File.ReadAllText(Physical("/moved/inner.txt")));
        Assert.False(Directory.Exists(Physical("/dir")));
    }

    [Fact]
    public void PosixRename_of_a_missing_file_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, PosixRename("/missing.txt", "/x.txt"));
        Assert.False(File.Exists(Physical("/x.txt")));
    }

    [Fact]
    public void PosixRename_of_a_file_onto_a_directory_fails_and_keeps_both()
    {
        File.WriteAllText(Physical("/a.txt"), "a");
        Directory.CreateDirectory(Physical("/dir"));

        Assert.Equal(SSH_FX_FAILURE, PosixRename("/a.txt", "/dir"));

        Assert.Equal("a", File.ReadAllText(Physical("/a.txt")));
        Assert.True(Directory.Exists(Physical("/dir")));
    }

    [Fact]
    public void PosixRename_of_a_directory_onto_an_existing_path_fails()
    {
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_FAILURE, PosixRename("/dir", "/a.txt"));

        Assert.True(Directory.Exists(Physical("/dir")));
        Assert.Equal("a", File.ReadAllText(Physical("/a.txt")));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/..")]
    public void PosixRename_of_the_root_is_denied(string root)
    {
        Assert.Equal(SSH_FX_PERMISSION_DENIED, PosixRename(root, "/elsewhere"));
        Assert.True(Directory.Exists(Root));
    }

    [Fact]
    public void PosixRename_of_a_file_onto_the_root_is_denied()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_PERMISSION_DENIED, PosixRename("/a.txt", "/"));

        Assert.Equal("a", File.ReadAllText(Physical("/a.txt")));
    }

    [Theory]
    [InlineData("/../config.db")]
    [InlineData("../../config.db")]
    [InlineData("..\\config.db")]
    public void PosixRename_cannot_take_a_file_from_outside_the_root(string path)
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, PosixRename(path, "/stolen.db"));

        Assert.Equal(SecretContent, File.ReadAllText(SecretFilePath));
        Assert.False(File.Exists(Physical("/stolen.db")));
    }

    [Theory]
    [InlineData("/../config.db")]
    [InlineData("/a/../../../config.db")]
    public void PosixRename_onto_a_path_outside_the_root_lands_inside_the_root(string target)
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_OK, PosixRename("/a.txt", target));

        Assert.Equal("a", File.ReadAllText(Physical("/config.db")));
        Assert.Equal(SecretContent, File.ReadAllText(SecretFilePath));
    }

    [Fact]
    public void PosixRename_status_message_does_not_contain_the_physical_path()
    {
        var response = Client.Extended("posix-rename@openssh.com", w =>
        {
            w.Write("/missing.txt", Encoding.UTF8);
            w.Write("/x.txt", Encoding.UTF8);
        });

        Assert.DoesNotContain(TempDirectory, response.StatusMessage);
    }

    [Fact]
    public void PosixRename_on_a_read_only_server_is_denied()
    {
        File.WriteAllText(Physical("/a.txt"), "a");
        using var readOnly = ReadOnlyClient();

        var status = readOnly.Extended("posix-rename@openssh.com", w =>
        {
            w.Write("/a.txt", Encoding.UTF8);
            w.Write("/b.txt", Encoding.UTF8);
        }).StatusCode;

        Assert.Equal(SSH_FX_PERMISSION_DENIED, status);
        Assert.True(File.Exists(Physical("/a.txt")));
        Assert.False(File.Exists(Physical("/b.txt")));
    }

    // ---- fsync@openssh.com ----

    [Fact]
    public void Fsync_of_a_written_file_gives_ok_and_the_data_is_on_disk_before_close()
    {
        var handle = Client.OpenHandle("/a.txt", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("durable")));

        Assert.Equal(SSH_FX_OK, Fsync(handle));

        using (var reader = new FileStream(Physical("/a.txt"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            Assert.Equal("durable", new StreamReader(reader).ReadToEnd());
        Assert.Equal(SSH_FX_OK, Client.Close(handle));
    }

    [Fact]
    public void Fsync_of_an_unknown_or_a_directory_handle_fails()
    {
        Directory.CreateDirectory(Physical("/dir"));
        var directory = Client.OpenDirHandle("/dir");

        Assert.Equal(SSH_FX_FAILURE, Fsync("no-such-handle"));
        Assert.Equal(SSH_FX_FAILURE, Fsync(directory));
    }

    [Fact]
    public void Fsync_of_a_closed_handle_fails()
    {
        var handle = Client.OpenHandle("/a.txt", SftpOpenFlags.Write | SftpOpenFlags.Create);
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal(SSH_FX_FAILURE, Fsync(handle));
    }

    // ---- limits@openssh.com ----

    [Fact]
    public void Limits_gives_the_packet_read_and_write_limits_of_the_engine()
    {
        var response = Client.Extended("limits@openssh.com");

        Assert.Equal(SSH_FXP_EXTENDED_REPLY, response.Type);
        var maxPacketLength = response.Payload.ReadUInt64();
        var maxReadLength = response.Payload.ReadUInt64();
        var maxWriteLength = response.Payload.ReadUInt64();
        var maxOpenHandles = response.Payload.ReadUInt64();
        Assert.Equal(0, response.Payload.DataAvailable);

        Assert.Equal(1024ul * 1024, maxPacketLength);
        Assert.Equal(64ul * 1024, maxReadLength);
        Assert.Equal(64ul * 1024, maxWriteLength);
        Assert.Equal(0ul, maxOpenHandles); // no own limit
    }

    [Fact]
    public void A_write_and_a_read_of_the_announced_limits_are_served_whole()
    {
        var data = new byte[64 * 1024];
        new Random(7).NextBytes(data);
        var handle = Client.OpenHandle("/big.bin", SftpOpenFlags.Read | SftpOpenFlags.Write | SftpOpenFlags.Create);

        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, data));
        var read = Client.Read(handle, 0, (uint)data.Length);

        Assert.Equal(SSH_FXP_DATA, read.Type);
        Assert.Equal(data, read.Payload.ReadBinary());
        Assert.Equal(SSH_FX_OK, Client.Close(handle));
    }

    // ---- expand-path@openssh.com ----

    [Theory]
    [InlineData("~", "/")]
    [InlineData("~/", "/")]
    [InlineData("~/a/b", "/a/b")]
    [InlineData("~/../..", "/")]
    [InlineData("~/../config.db", "/config.db")]
    [InlineData("/x/../y", "/y")]
    [InlineData("a/./b", "/a/b")]
    [InlineData("", "/")]
    [InlineData("/~", "/~")]
    public void ExpandPath_gives_the_virtual_path_with_the_root_as_home(string input, string expected)
    {
        var response = ExpandPath(input);

        var name = Assert.Single(response.Names());
        Assert.Equal(expected, name.Name);
        Assert.DoesNotContain(Root, name.Name);
        Assert.DoesNotContain(Root, name.LongName);
    }

    [Theory]
    [InlineData("~root")]
    [InlineData("~test_person/a")]
    public void ExpandPath_of_another_users_home_gives_no_such_file(string input)
    {
        var response = ExpandPath(input);

        Assert.Equal(SSH_FX_NO_SUCH_FILE, response.StatusCode);
        Assert.DoesNotContain(TempDirectory, response.StatusMessage);
    }

    // ---- statvfs@openssh.com ----

    [Fact]
    public void Statvfs_of_the_root_gives_the_space_of_the_disk_under_the_root()
    {
        var response = Statvfs("/");

        Assert.Equal(SSH_FXP_EXTENDED_REPLY, response.Type);
        var stats = ReadStatvfs(response);
        var drive = new DriveInfo(OperatingSystem.IsWindows() ? Path.GetPathRoot(Root)! : Root);

        Assert.True(stats.FragmentSize > 0);
        Assert.Equal(stats.FragmentSize, stats.BlockSize);
        Assert.Equal((ulong)drive.TotalSize / stats.FragmentSize, stats.Blocks);
        Assert.InRange(stats.AvailableBlocks, 0ul, stats.FreeBlocks);
        Assert.InRange(stats.FreeBlocks, 0ul, stats.Blocks);
        Assert.Equal(255ul, stats.MaxNameLength);
        Assert.Equal(0ul, stats.Flags & ST_RDONLY);
    }

    [Fact]
    public void Statvfs_of_a_file_and_of_the_parent_of_the_root_works()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FXP_EXTENDED_REPLY, Statvfs("/a.txt").Type);
        Assert.Equal(SSH_FXP_EXTENDED_REPLY, Statvfs("/../..").Type);
    }

    [Fact]
    public void Statvfs_of_a_missing_path_gives_no_such_file_without_the_physical_path()
    {
        var response = Statvfs("/missing");

        Assert.Equal(SSH_FX_NO_SUCH_FILE, response.StatusCode);
        Assert.DoesNotContain(TempDirectory, response.StatusMessage);
    }

    [Fact]
    public void Statvfs_on_a_read_only_server_sets_the_read_only_flag()
    {
        using var readOnly = ReadOnlyClient();

        var stats = ReadStatvfs(readOnly.Extended("statvfs@openssh.com", w => w.Write("/", Encoding.UTF8)));

        Assert.Equal(ST_RDONLY, stats.Flags & ST_RDONLY);
    }

    // ---- not supported ----

    [Fact]
    public void Hardlink_gives_op_unsupported_and_creates_nothing()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        var status = Client.Extended("hardlink@openssh.com", w =>
        {
            w.Write("/a.txt", Encoding.UTF8);
            w.Write("/link.txt", Encoding.UTF8);
        }).StatusCode;

        Assert.Equal(SSH_FX_OP_UNSUPPORTED, status);
        Assert.False(File.Exists(Physical("/link.txt")));
    }

    [Fact]
    public void Symlink_gives_op_unsupported_in_both_argument_orders_and_creates_nothing()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        // OpenSSH sends SSH_FXP_SYMLINK with the target first and the link path second, the opposite of the
        // draft. Links are not supported, so both orders are refused.
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, Client.Send(SSH_FXP_SYMLINK, w => { w.Write("/a.txt", Encoding.UTF8); w.Write("/l1", Encoding.UTF8); }).StatusCode);
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, Client.Send(SSH_FXP_SYMLINK, w => { w.Write("/l2", Encoding.UTF8); w.Write("/a.txt", Encoding.UTF8); }).StatusCode);

        Assert.False(File.Exists(Physical("/l1")));
        Assert.False(File.Exists(Physical("/l2")));
    }

    [Theory]
    [InlineData("fstatvfs@openssh.com")]
    [InlineData("lsetstat@openssh.com")]
    [InlineData("copy-data")]
    [InlineData("unknown@example.com")]
    public void Not_announced_extensions_give_op_unsupported(string name)
    {
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, Client.Extended(name, w => w.Write("/", Encoding.UTF8)).StatusCode);
    }

    [Fact]
    public void Truncated_extension_request_gives_a_status_and_the_session_continues()
    {
        var response = Client.Extended("posix-rename@openssh.com", w => w.Write("/only-one-path", Encoding.UTF8));

        Assert.Equal(SSH_FXP_STATUS, response.Type);
        Assert.NotEqual(SSH_FX_OK, response.StatusCode);
        Assert.Equal("/", Client.RealPath("."));
    }

    // ---- helpers ----

    private uint PosixRename(string oldPath, string newPath) => Client.Extended("posix-rename@openssh.com", w =>
    {
        w.Write(oldPath, Encoding.UTF8);
        w.Write(newPath, Encoding.UTF8);
    }).StatusCode;

    private uint Fsync(string handle) => Client.Extended("fsync@openssh.com", w => w.Write(handle, Encoding.ASCII)).StatusCode;

    private Response ExpandPath(string path) => Client.Extended("expand-path@openssh.com", w => w.Write(path, Encoding.UTF8));

    private Response Statvfs(string path) => Client.Extended("statvfs@openssh.com", w => w.Write(path, Encoding.UTF8));

    private SftpEngineClient ReadOnlyClient()
    {
        var client = new SftpEngineClient(new LocalFileSystem(Root), readOnly: true);
        client.Service.OnData(Init());
        client.Responses.Clear();
        return client;
    }

    private static Dictionary<string, string> VersionExtensions(SftpEngineClient client)
    {
        client.Service.OnData(Init());
        return ParseVersion(client.Responses[^1]);
    }

    /// <summary>The extension pairs of an SSH_FXP_VERSION packet (with its length).</summary>
    private static Dictionary<string, string> ParseVersion(byte[] packet)
    {
        var response = Response.Parse(packet);
        Assert.Equal(SSH_FXP_VERSION, response.Type);
        Assert.Equal(3u, response.Payload.ReadUInt32());

        var extensions = new Dictionary<string, string>();
        while (response.Payload.DataAvailable > 0)
            extensions.Add(response.Payload.ReadString(Encoding.ASCII), response.Payload.ReadString(Encoding.ASCII));
        return extensions;
    }

    private static StatvfsReply ReadStatvfs(Response response)
    {
        Assert.True(SSH_FXP_EXTENDED_REPLY == response.Type, $"Expected EXTENDED_REPLY, got {response}");
        var r = response.Payload;
        var stats = new StatvfsReply(r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(),
            r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64(), r.ReadUInt64());
        Assert.Equal(0, r.DataAvailable);
        return stats;
    }

    private sealed record StatvfsReply(ulong BlockSize, ulong FragmentSize, ulong Blocks, ulong FreeBlocks, ulong AvailableBlocks,
        ulong Files, ulong FreeFiles, ulong AvailableFiles, ulong FileSystemId, ulong Flags, ulong MaxNameLength);

    /// <summary>An <see cref="ISftpFileSystem"/> with only the required members (no optional capability).</summary>
    private sealed class MinimalFileSystem : ISftpFileSystem
    {
        public ISftpFileHandle OpenFile(string path, SftpOpenFlags flags, SftpFileAttributes attributes) => throw new NotSupportedException();
        public ISftpDirectoryHandle OpenDirectory(string path) => throw new NotSupportedException();
        public SftpFileAttributes GetAttributes(string path, bool followLinks) => throw new NotSupportedException();
        public void SetAttributes(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
        public void RemoveFile(string path) => throw new NotSupportedException();
        public void Rename(string oldPath, string newPath) => throw new NotSupportedException();
        public void MakeDirectory(string path, SftpFileAttributes attributes) => throw new NotSupportedException();
        public void RemoveDirectory(string path) => throw new NotSupportedException();
        public string RealPath(string path) => path;
    }
}
