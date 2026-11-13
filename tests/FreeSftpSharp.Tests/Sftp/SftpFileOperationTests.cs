using System.Text;
using FxSsh.Services.Sftp;
using static FreeSftpSharp.Tests.Sftp.SftpEngineClient;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The SFTP requests through the upstream engine and <c>SftpFileSystemAdapter</c> on a real
/// <c>LocalFileSystem</c>: the status codes of the failure cases and what is written on disk.
/// </summary>
public sealed class SftpFileOperationTests : SftpEngineTestBase
{
    private const SftpOpenFlags WriteCreateTruncate = SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate;

    // ---- REMOVE ----

    [Fact]
    public void Remove_deletes_the_file()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_OK, Client.Status(SSH_FXP_REMOVE, "/a.txt"));
        Assert.False(File.Exists(Physical("/a.txt")));
    }

    [Fact]
    public void Remove_of_a_missing_file_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_REMOVE, "/missing.txt"));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_REMOVE, "/missing-dir/missing.txt"));
    }

    [Fact]
    public void Remove_of_a_directory_gives_permission_denied_and_keeps_the_directory()
    {
        Directory.CreateDirectory(Physical("/dir"));

        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_REMOVE, "/dir"));
        Assert.True(Directory.Exists(Physical("/dir")));
    }

    // ---- RMDIR ----

    [Fact]
    public void RemoveDirectory_deletes_an_empty_directory()
    {
        Directory.CreateDirectory(Physical("/dir"));

        Assert.Equal(SSH_FX_OK, Client.Status(SSH_FXP_RMDIR, "/dir"));
        Assert.False(Directory.Exists(Physical("/dir")));
    }

    [Fact]
    public void RemoveDirectory_of_a_missing_directory_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_RMDIR, "/missing"));
    }

    [Fact]
    public void RemoveDirectory_of_a_file_fails_and_keeps_the_file()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_FAILURE, Client.Status(SSH_FXP_RMDIR, "/a.txt"));
        Assert.True(File.Exists(Physical("/a.txt")));
    }

    [Fact]
    public void RemoveDirectory_of_a_directory_that_is_not_empty_fails()
    {
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/dir/a.txt"), "a");

        Assert.Equal(SSH_FX_FAILURE, Client.Status(SSH_FXP_RMDIR, "/dir"));
        Assert.True(File.Exists(Physical("/dir/a.txt")));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/..")]
    [InlineData("")]
    public void RemoveDirectory_of_the_root_gives_permission_denied(string path)
    {
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Status(SSH_FXP_RMDIR, path));
        Assert.True(Directory.Exists(Root));
    }

    // ---- MKDIR ----

    [Fact]
    public void MakeDirectory_creates_the_directory()
    {
        Assert.Equal(SSH_FX_OK, Client.MakeDirectory("/new"));
        Assert.True(Directory.Exists(Physical("/new")));
    }

    [Fact]
    public void MakeDirectory_of_an_existing_directory_or_file_fails()
    {
        Directory.CreateDirectory(Physical("/dir"));
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_FAILURE, Client.MakeDirectory("/dir"));
        Assert.Equal(SSH_FX_FAILURE, Client.MakeDirectory("/a.txt"));
        Assert.True(File.Exists(Physical("/a.txt")));
    }

    [Fact]
    public void MakeDirectory_without_the_parent_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.MakeDirectory("/missing/new"));
        Assert.False(Directory.Exists(Physical("/missing")));
    }

    [Fact]
    public void MakeDirectory_applies_the_permissions()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "POSIX permissions");

        Assert.Equal(SSH_FX_OK, Client.MakeDirectory("/private", new SftpFileAttributes { Permissions = 0x41C0 })); // drwx------

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Physical("/private")));
    }

    // ---- RENAME ----

    [Fact]
    public void Rename_moves_a_file_and_a_directory()
    {
        File.WriteAllText(Physical("/old.txt"), "x");
        Directory.CreateDirectory(Physical("/olddir"));

        Assert.Equal(SSH_FX_OK, Client.Rename("/old.txt", "/new.txt"));
        Assert.Equal(SSH_FX_OK, Client.Rename("/olddir", "/newdir"));

        Assert.Equal("x", File.ReadAllText(Physical("/new.txt")));
        Assert.False(File.Exists(Physical("/old.txt")));
        Assert.True(Directory.Exists(Physical("/newdir")));
    }

    [Fact]
    public void Rename_of_a_missing_file_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Rename("/missing.txt", "/new.txt"));
    }

    [Fact]
    public void Rename_to_an_existing_file_fails_and_changes_nothing()
    {
        File.WriteAllText(Physical("/a.txt"), "a");
        File.WriteAllText(Physical("/b.txt"), "b");

        Assert.Equal(SSH_FX_FAILURE, Client.Rename("/a.txt", "/b.txt"));

        Assert.Equal("a", File.ReadAllText(Physical("/a.txt")));
        Assert.Equal("b", File.ReadAllText(Physical("/b.txt")));
    }

    [Fact]
    public void Rename_of_the_root_fails()
    {
        Assert.NotEqual(SSH_FX_OK, Client.Rename("/", "/moved"));
        Assert.True(Directory.Exists(Root));
    }

    // ---- OPEN, READ, WRITE, CLOSE ----

    [Fact]
    public void Open_write_read_eof_close_cycle()
    {
        var handle = Client.OpenHandle("/file.bin", SftpOpenFlags.Read | WriteCreateTruncate);

        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("hello")));
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 5, Encoding.ASCII.GetBytes(" world")));

        var data = Client.Read(handle, 0, 100);
        Assert.Equal(SSH_FXP_DATA, data.Type);
        Assert.Equal("hello world", Encoding.ASCII.GetString(data.Payload.ReadBinary()));
        Assert.Equal(SSH_FX_EOF, Client.Read(handle, 11, 100).StatusCode);

        Assert.Equal(SSH_FX_OK, Client.Close(handle));
        Assert.Equal("hello world", File.ReadAllText(Physical("/file.bin")));
        Assert.Equal(SSH_FX_FAILURE, Client.Close(handle)); // the handle is gone
    }

    [Fact]
    public void Open_of_a_missing_file_for_reading_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Open("/missing.txt", SftpOpenFlags.Read).StatusCode);
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Open("/missing-dir/new.txt", WriteCreateTruncate).StatusCode);
    }

    [Fact]
    public void Open_of_a_directory_as_a_file_gives_permission_denied()
    {
        Directory.CreateDirectory(Physical("/dir"));

        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Open("/dir", SftpOpenFlags.Read).StatusCode);
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.Open("/dir", WriteCreateTruncate).StatusCode);
        Assert.True(Directory.Exists(Physical("/dir")));
    }

    [Fact]
    public void Exclusive_create_of_an_existing_file_fails_and_keeps_the_content()
    {
        File.WriteAllText(Physical("/a.txt"), "keep");

        Assert.Equal(SSH_FX_FAILURE, Client.Open("/a.txt", SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Exclusive).StatusCode);
        Assert.Equal("keep", File.ReadAllText(Physical("/a.txt")));
    }

    [Fact]
    public void Create_truncate_without_writes_gives_an_empty_file()
    {
        File.WriteAllText(Physical("/a.txt"), "old content");

        var handle = Client.OpenHandle("/a.txt", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal(0, new FileInfo(Physical("/a.txt")).Length);
    }

    [Fact]
    public void Append_writes_at_the_end_whatever_the_offset()
    {
        File.WriteAllText(Physical("/a.txt"), "abc");

        var handle = Client.OpenHandle("/a.txt", SftpOpenFlags.Write | SftpOpenFlags.Append);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("def")));
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal("abcdef", File.ReadAllText(Physical("/a.txt")));
    }

    [Theory]
    [InlineData(0u)]                                                         // neither READ nor WRITE
    [InlineData((uint)(SftpOpenFlags.Write | SftpOpenFlags.Truncate))]       // TRUNC without CREAT
    [InlineData((uint)(SftpOpenFlags.Write | SftpOpenFlags.Exclusive))]      // EXCL without CREAT
    public void Open_with_invalid_flags_gives_bad_message(uint flags)
    {
        Assert.Equal(SSH_FX_BAD_MESSAGE, Client.Open("/a.txt", (SftpOpenFlags)flags).StatusCode);
        Assert.False(File.Exists(Physical("/a.txt")));
    }

    [Fact]
    public void Read_length_is_limited_to_64_KiB()
    {
        File.WriteAllBytes(Physical("/big.bin"), new byte[200_000]);
        var handle = Client.OpenHandle("/big.bin", SftpOpenFlags.Read);

        var data = Client.Read(handle, 0, 1_000_000);

        Assert.Equal(64 * 1024, data.Payload.ReadBinary().Length);
    }

    [Fact]
    public void Unknown_handles_and_directory_handles_cannot_be_used_for_file_requests()
    {
        Directory.CreateDirectory(Physical("/dir"));
        var dirHandle = Client.OpenDirHandle("/dir");

        Assert.Equal(SSH_FX_FAILURE, Client.Read("no-such-handle", 0, 10).StatusCode);
        Assert.Equal(SSH_FX_FAILURE, Client.Write("no-such-handle", 0, [1]));
        Assert.Equal(SSH_FX_FAILURE, Client.Read(dirHandle, 0, 10).StatusCode);
        Assert.Equal(SSH_FX_FAILURE, Client.Send(SSH_FXP_READDIR, w => w.Write("no-such-handle", Encoding.ASCII)).StatusCode);
    }

    // ---- STAT, FSTAT ----

    [Fact]
    public void Stat_of_a_file_gives_size_regular_file_type_and_times()
    {
        File.WriteAllBytes(Physical("/a.bin"), new byte[1234]);
        var mtime = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(Physical("/a.bin"), mtime);

        foreach (var type in new[] { SSH_FXP_STAT, SSH_FXP_LSTAT })
        {
            var response = Client.SendPath(type, "/a.bin");
            Assert.Equal(SSH_FXP_ATTRS, response.Type);
            var attributes = SftpFileAttributes.Read(response.Payload);

            Assert.Equal(1234ul, attributes.Size);
            Assert.Equal(0x8000u, attributes.Permissions & 0xF000);
            Assert.Equal((uint)new DateTimeOffset(mtime).ToUnixTimeSeconds(), attributes.ModificationTime);
            Assert.NotNull(attributes.AccessTime);
        }
    }

    [Fact]
    public void Stat_of_a_directory_gives_directory_type()
    {
        Directory.CreateDirectory(Physical("/dir"));

        var attributes = Client.Stat("/dir");

        Assert.Equal(0x4000u, attributes.Permissions & 0xF000);
    }

    [Fact]
    public void Stat_of_a_missing_path_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_STAT, "/missing"));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_LSTAT, "/missing"));
    }

    [Fact]
    public void Fstat_gives_the_size_of_the_open_file_before_close()
    {
        var handle = Client.OpenHandle("/a.bin", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, new byte[300]));

        var response = Client.Send(SSH_FXP_FSTAT, w => w.Write(handle, Encoding.ASCII));

        Assert.Equal(SSH_FXP_ATTRS, response.Type);
        var attributes = SftpFileAttributes.Read(response.Payload);
        Assert.Equal(300ul, attributes.Size);
        Assert.Equal(0x8000u, attributes.Permissions & 0xF000);
        Assert.Equal(SSH_FX_OK, Client.Close(handle));
    }

    // ---- SETSTAT, FSETSTAT ----

    [Fact]
    public void SetStat_size_truncates_and_extends_the_file()
    {
        File.WriteAllText(Physical("/a.txt"), "abcdef");

        Assert.Equal(SSH_FX_OK, Client.SetStat("/a.txt", new SftpFileAttributes { Size = 2 }));
        Assert.Equal("ab", File.ReadAllText(Physical("/a.txt")));

        Assert.Equal(SSH_FX_OK, Client.SetStat("/a.txt", new SftpFileAttributes { Size = 10 }));
        Assert.Equal(10, new FileInfo(Physical("/a.txt")).Length);
    }

    [Fact]
    public void SetStat_times_set_the_access_and_modification_time()
    {
        File.WriteAllText(Physical("/a.txt"), "a");
        Directory.CreateDirectory(Physical("/dir"));

        Assert.Equal(SSH_FX_OK, Client.SetStat("/a.txt", new SftpFileAttributes { AccessTime = 1_600_000_000, ModificationTime = 1_700_000_000 }));
        Assert.Equal(SSH_FX_OK, Client.SetStat("/dir", new SftpFileAttributes { AccessTime = 1_600_000_000, ModificationTime = 1_700_000_000 }));

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).UtcDateTime, File.GetLastWriteTimeUtc(Physical("/a.txt")));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000).UtcDateTime, File.GetLastAccessTimeUtc(Physical("/a.txt")));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).UtcDateTime, Directory.GetLastWriteTimeUtc(Physical("/dir")));
        Assert.Equal(1_700_000_000u, Client.Stat("/a.txt").ModificationTime);
    }

    [Fact]
    public void SetStat_permissions_change_the_file_mode()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "POSIX permissions");
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_OK, Client.SetStat("/a.txt", new SftpFileAttributes { Permissions = 0x8000 | 0x1A0 })); // rw-r-----

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead, File.GetUnixFileMode(Physical("/a.txt")));
        Assert.Equal(0x81A0u, Client.Stat("/a.txt").Permissions);
    }

    [Fact]
    public void SetStat_permissions_ignore_setuid_setgid_and_sticky_bits()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "POSIX permissions");
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_OK, Client.SetStat("/a.txt", new SftpFileAttributes { Permissions = 0xFED })); // rwsr-sr-t

        Assert.Equal((UnixFileMode)0x1ED, File.GetUnixFileMode(Physical("/a.txt")));
    }

    [Fact]
    public void SetStat_permissions_of_the_root_give_permission_denied()
    {
        Assert.Equal(SSH_FX_PERMISSION_DENIED, Client.SetStat("/", new SftpFileAttributes { Permissions = 0 }));
    }

    [Fact]
    public void SetStat_of_a_missing_path_gives_no_such_file()
    {
        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.SetStat("/missing", new SftpFileAttributes { Size = 1 }));
        Assert.False(File.Exists(Physical("/missing")));
    }

    [Fact]
    public void FSetStat_size_and_times_apply_to_the_open_file()
    {
        var handle = Client.OpenHandle("/a.txt", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("abcdef")));

        var status = Client.Send(SSH_FXP_FSETSTAT, w =>
        {
            w.Write(handle, Encoding.ASCII);
            new SftpFileAttributes { Size = 3, AccessTime = 1_600_000_000, ModificationTime = 1_700_000_000 }.Write(w);
        }).StatusCode;
        Assert.Equal(SSH_FX_OK, status);
        Assert.Equal(SSH_FX_OK, Client.Close(handle));

        Assert.Equal("abc", File.ReadAllText(Physical("/a.txt")));
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).UtcDateTime, File.GetLastWriteTimeUtc(Physical("/a.txt")));
    }

    // ---- OPENDIR, READDIR ----

    [Fact]
    public void ReadDir_lists_dot_dot_dot_directories_and_files_with_attributes()
    {
        Directory.CreateDirectory(Physical("/dir/sub"));
        File.WriteAllBytes(Physical("/dir/a.bin"), new byte[7]);

        var entries = Client.ReadDirectory("/dir").ToDictionary(e => e.Name, e => e.Attributes);

        Assert.Equal([".", "..", "a.bin", "sub"], entries.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(7ul, entries["a.bin"].Size);
        Assert.Equal(0x8000u, entries["a.bin"].Permissions & 0xF000);
        Assert.Equal(0x4000u, entries["sub"].Permissions & 0xF000);
        Assert.Equal(0x4000u, entries[".."].Permissions & 0xF000);
    }

    [Fact]
    public void ReadDir_of_the_root_has_dot_dot_for_the_root_itself()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        var names = Client.ReadDirectory("/").Select(e => e.Name).ToList();

        Assert.Equal([".", "..", "a.txt"], names.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void ReadDir_of_a_large_directory_is_sent_in_several_batches()
    {
        Directory.CreateDirectory(Physical("/many"));
        for (var i = 0; i < 300; i++)
            File.WriteAllText(Physical($"/many/f{i:D3}"), "");

        var handle = Client.OpenDirHandle("/many");
        var first = Client.Send(SSH_FXP_READDIR, w => w.Write(handle, Encoding.ASCII)).Names();
        Client.Close(handle);

        Assert.InRange(first.Count, 1, 299);
        Assert.Equal(302, Client.ReadDirectory("/many").Count);
    }

    [Fact]
    public void OpenDir_of_a_missing_directory_gives_no_such_file_and_of_a_file_fails()
    {
        File.WriteAllText(Physical("/a.txt"), "a");

        Assert.Equal(SSH_FX_NO_SUCH_FILE, Client.Status(SSH_FXP_OPENDIR, "/missing"));
        Assert.Equal(SSH_FX_FAILURE, Client.Status(SSH_FXP_OPENDIR, "/a.txt"));
    }

    // ---- other requests and the session ----

    [Theory]
    [InlineData(SSH_FXP_READLINK)]
    [InlineData(SSH_FXP_SYMLINK)]
    [InlineData(SSH_FXP_EXTENDED)]
    [InlineData((byte)99)]
    public void Unsupported_and_unknown_requests_give_op_unsupported(byte type)
    {
        Assert.Equal(SSH_FX_OP_UNSUPPORTED, Client.SendPath(type, "/x").StatusCode);
    }

    [Fact]
    public void OnClose_closes_every_open_handle()
    {
        var handle = Client.OpenHandle("/a.txt", WriteCreateTruncate);
        Assert.Equal(SSH_FX_OK, Client.Write(handle, 0, Encoding.ASCII.GetBytes("data")));
        uint? exitCode = null;
        Client.Service.CloseReceived += (_, code) => exitCode = code;

        Client.Service.OnClose();

        Assert.Equal(0u, exitCode);
        Assert.Equal("data", File.ReadAllText(Physical("/a.txt"))); // flushed
        Assert.Equal(SSH_FX_FAILURE, Client.Write(handle, 0, [1]));
    }
}
