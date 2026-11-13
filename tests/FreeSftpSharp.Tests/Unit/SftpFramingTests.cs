using System.Buffers.Binary;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Filesystem.LocalDisk;
using SshServerModule.Services;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// Feeds raw SFTP v3 bytes to <see cref="SftpSubsystem.OnInput"/> and checks the responses.
/// Every packet starts with uint32 length, so the subsystem never enters its legacy "Windows client" mode
/// (that mode starts only when the first length is larger than 1,000,000).
/// </summary>
public sealed class SftpFramingTests : IDisposable
{
    private const byte SSH_FXP_INIT = 1;
    private const byte SSH_FXP_VERSION = 2;
    private const byte SSH_FXP_STAT = 17;
    private const byte SSH_FXP_REALPATH = 16;
    private const byte SSH_FXP_STATUS = 101;
    private const byte SSH_FXP_NAME = 104;
    private const byte SSH_FXP_ATTRS = 105;
    private const uint SSH_FX_NO_SUCH_FILE = 2;

    private readonly string _root;
    private readonly SftpSubsystem _subsystem;
    private readonly List<byte[]> _responses = new();

    public SftpFramingTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(Path.Combine(_root, "dir"));
        _subsystem = new SftpSubsystem(NullLogger.Instance, new LocalFileSystem(_root), "test_person");
        _subsystem.OnOutput += (_, data) => _responses.Add(data.ToArray());
    }

    public void Dispose()
    {
        _subsystem.Dispose();
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void Init_in_one_call_gives_one_version_response()
    {
        _subsystem.OnInput(Init());

        var response = Assert.Single(_responses);
        Assert.Equal(SSH_FXP_VERSION, TypeOf(response));
        Assert.Equal(3u, ReadUInt32(response, 5)); // version
    }

    [Fact]
    public void Init_split_into_single_bytes_gives_one_response()
    {
        foreach (var b in Init())
            _subsystem.OnInput(new[] { b });

        var response = Assert.Single(_responses);
        Assert.Equal(SSH_FXP_VERSION, TypeOf(response));
    }

    [Fact]
    public void Packet_split_over_several_calls_gives_one_response()
    {
        _subsystem.OnInput(Init());
        _responses.Clear();

        var packet = RealPath(7, "/dir/../dir/.");
        _subsystem.OnInput(packet[..2]);    // part of the length
        _subsystem.OnInput(packet[2..6]);   // rest of the length, type, part of the id
        Assert.Empty(_responses);
        _subsystem.OnInput(packet[6..^3]);
        Assert.Empty(_responses);
        _subsystem.OnInput(packet[^3..]);

        var response = Assert.Single(_responses);
        Assert.Equal(SSH_FXP_NAME, TypeOf(response));
        Assert.Equal(7u, RequestIdOf(response));
        Assert.Equal("/dir", ReadFirstName(response));
    }

    [Fact]
    public void Several_packets_in_one_call_give_one_response_each()
    {
        var data = Concat(Init(), RealPath(1, "."), Stat(2, "/dir"), Stat(3, "/missing"), RealPath(4, "/a/../.."));

        _subsystem.OnInput(data);

        Assert.Equal(5, _responses.Count);
        Assert.Equal(SSH_FXP_VERSION, TypeOf(_responses[0]));

        Assert.Equal(SSH_FXP_NAME, TypeOf(_responses[1]));
        Assert.Equal(1u, RequestIdOf(_responses[1]));
        Assert.Equal("/", ReadFirstName(_responses[1]));

        Assert.Equal(SSH_FXP_ATTRS, TypeOf(_responses[2]));
        Assert.Equal(2u, RequestIdOf(_responses[2]));

        Assert.Equal(SSH_FXP_STATUS, TypeOf(_responses[3]));
        Assert.Equal(3u, RequestIdOf(_responses[3]));
        Assert.Equal(SSH_FX_NO_SUCH_FILE, ReadUInt32(_responses[3], 9));

        Assert.Equal(SSH_FXP_NAME, TypeOf(_responses[4]));
        Assert.Equal(4u, RequestIdOf(_responses[4]));
        Assert.Equal("/", ReadFirstName(_responses[4]));
    }

    [Fact]
    public void Complete_packets_are_answered_and_a_partial_packet_waits_for_the_rest()
    {
        var second = Stat(2, "/dir");
        var data = Concat(Init(), RealPath(1, "/"), second[..5]);

        _subsystem.OnInput(data);
        Assert.Equal(2, _responses.Count);

        _subsystem.OnInput(second[5..]);
        Assert.Equal(3, _responses.Count);
        Assert.Equal(SSH_FXP_ATTRS, TypeOf(_responses[2]));
        Assert.Equal(2u, RequestIdOf(_responses[2]));
    }

    [Fact]
    public void Every_response_has_a_correct_length_prefix()
    {
        _subsystem.OnInput(Concat(Init(), RealPath(1, "/"), Stat(2, "/dir"), Stat(3, "/missing")));

        Assert.Equal(4, _responses.Count);
        foreach (var response in _responses)
            Assert.Equal((uint)(response.Length - 4), ReadUInt32(response, 0));
    }

    // ---- packet helpers (SFTP v3, big endian) ----

    private static byte[] Init() => Packet(SSH_FXP_INIT, UInt32(3));

    private static byte[] RealPath(uint id, string path) => Packet(SSH_FXP_REALPATH, UInt32(id), SshString(path));

    private static byte[] Stat(uint id, string path) => Packet(SSH_FXP_STAT, UInt32(id), SshString(path));

    private static byte[] Packet(byte type, params byte[][] parts)
    {
        var payload = Concat(new[] { type }, Concat(parts));
        return Concat(UInt32((uint)payload.Length), payload);
    }

    private static byte[] UInt32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] SshString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        return Concat(UInt32((uint)bytes.Length), bytes);
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static byte TypeOf(byte[] response) => response[4];

    private static uint RequestIdOf(byte[] response) => ReadUInt32(response, 5);

    private static uint ReadUInt32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));

    /// <summary>Reads the first filename of an SSH_FXP_NAME response.</summary>
    private static string ReadFirstName(byte[] response)
    {
        // uint32 length, byte type, uint32 id, uint32 count, string filename, ...
        Assert.Equal(1u, ReadUInt32(response, 9));
        var nameLength = (int)ReadUInt32(response, 13);
        return Encoding.UTF8.GetString(response, 17, nameLength);
    }
}
