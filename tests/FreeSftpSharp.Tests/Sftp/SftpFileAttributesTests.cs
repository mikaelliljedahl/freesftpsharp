using FxSsh;
using FxSsh.Services.Sftp;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// The ATTRS wire format (draft-ietf-secsh-filexfer-02 section 5) of the upstream <see cref="SftpFileAttributes"/>.
/// The flag SSH_FILEXFER_ATTR_UIDGID means "uid and gid follow", and SSH_FILEXFER_ATTR_ACMODTIME means
/// "atime and mtime follow", so a writer must always write both fields of a pair.
/// </summary>
public sealed class SftpFileAttributesTests
{
    [Fact]
    public void Empty_attributes_have_zero_flags_and_only_the_flags_field()
    {
        var bytes = Write(new SftpFileAttributes());

        Assert.Equal(new byte[4], bytes);
    }

    [Fact]
    public void All_fields_round_trip()
    {
        var attrs = new SftpFileAttributes
        {
            Size = 0x1122334455667788,
            UserId = 1000,
            GroupId = 2000,
            Permissions = 0x81A4,
            AccessTime = 1700000000,
            ModificationTime = 1700000001,
            Extended = [("name@openssh.com", "value")],
        };

        var parsed = RoundTrip(attrs);

        Assert.Equal(attrs.Size, parsed.Size);
        Assert.Equal(attrs.UserId, parsed.UserId);
        Assert.Equal(attrs.GroupId, parsed.GroupId);
        Assert.Equal(attrs.Permissions, parsed.Permissions);
        Assert.Equal(attrs.AccessTime, parsed.AccessTime);
        Assert.Equal(attrs.ModificationTime, parsed.ModificationTime);
        var extended = Assert.Single(parsed.Extended);
        Assert.Equal(("name@openssh.com", "value"), extended);
    }

    [Fact]
    public void Only_uid_writes_both_uid_and_gid()
    {
        var attrs = new SftpFileAttributes { UserId = 1000, Permissions = 0x81A4 };

        var bytes = Write(attrs);
        var parsed = SftpFileAttributes.Read(new SshDataReader(bytes));

        Assert.Equal(4 + 4 + 4 + 4, bytes.Length); // flags, uid, gid, permissions
        Assert.Equal(1000u, parsed.UserId);
        Assert.Equal(0u, parsed.GroupId);
        Assert.Equal(0x81A4u, parsed.Permissions);
    }

    [Fact]
    public void Only_gid_writes_both_uid_and_gid()
    {
        var parsed = RoundTrip(new SftpFileAttributes { GroupId = 2000, Permissions = 0x41ED });

        Assert.Equal(0u, parsed.UserId);
        Assert.Equal(2000u, parsed.GroupId);
        Assert.Equal(0x41EDu, parsed.Permissions);
    }

    [Fact]
    public void Only_atime_writes_both_atime_and_mtime()
    {
        var attrs = new SftpFileAttributes { AccessTime = 1700000000, Extended = [("a@b", "c")] };

        var bytes = Write(attrs);
        var parsed = SftpFileAttributes.Read(new SshDataReader(bytes));

        Assert.Equal(1700000000u, parsed.AccessTime);
        Assert.Equal(0u, parsed.ModificationTime);
        Assert.Equal(("a@b", "c"), Assert.Single(parsed.Extended));
    }

    [Fact]
    public void Only_mtime_writes_both_atime_and_mtime()
    {
        var parsed = RoundTrip(new SftpFileAttributes { ModificationTime = 1700000001, Size = 5 });

        Assert.Equal(5ul, parsed.Size);
        Assert.Equal(0u, parsed.AccessTime);
        Assert.Equal(1700000001u, parsed.ModificationTime);
    }

    [Fact]
    public void Read_of_empty_flags_gives_null_fields()
    {
        var parsed = SftpFileAttributes.Read(new SshDataReader(new byte[4]));

        Assert.Null(parsed.Size);
        Assert.Null(parsed.UserId);
        Assert.Null(parsed.GroupId);
        Assert.Null(parsed.Permissions);
        Assert.Null(parsed.AccessTime);
        Assert.Null(parsed.ModificationTime);
        Assert.Null(parsed.Extended);
    }

    private static byte[] Write(SftpFileAttributes attrs)
    {
        using var writer = new SshDataWriter();
        attrs.Write(writer);
        return writer.ToByteArray();
    }

    private static SftpFileAttributes RoundTrip(SftpFileAttributes attrs)
    {
        var reader = new SshDataReader(Write(attrs));
        var parsed = SftpFileAttributes.Read(reader);
        Assert.Equal(0L, reader.DataAvailable);
        return parsed;
    }
}
