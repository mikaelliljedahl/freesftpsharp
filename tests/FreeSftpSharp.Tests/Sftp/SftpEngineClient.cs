using System.Text;
using FxSsh;
using FxSsh.Services.Sftp;
using Microsoft.Extensions.Logging.Abstractions;
using SshServer.Interfaces;
using SshServerModule.Sftp;

namespace FreeSftpSharp.Tests.Sftp;

/// <summary>
/// Drives the upstream SFTP engine (<see cref="SftpService"/>) with our <see cref="SftpFileSystemAdapter"/>
/// without SSH: it feeds hand-built SFTP v3 packets to <see cref="SftpService.OnData"/> and collects the
/// packets that the engine sends. The packet builders follow upstream FxSsh.Tests/Sftp/SftpServiceTests.
/// </summary>
internal sealed class SftpEngineClient : IDisposable
{
    public const byte SSH_FXP_INIT = 1;
    public const byte SSH_FXP_VERSION = 2;
    public const byte SSH_FXP_OPEN = 3;
    public const byte SSH_FXP_CLOSE = 4;
    public const byte SSH_FXP_READ = 5;
    public const byte SSH_FXP_WRITE = 6;
    public const byte SSH_FXP_LSTAT = 7;
    public const byte SSH_FXP_FSTAT = 8;
    public const byte SSH_FXP_SETSTAT = 9;
    public const byte SSH_FXP_FSETSTAT = 10;
    public const byte SSH_FXP_OPENDIR = 11;
    public const byte SSH_FXP_READDIR = 12;
    public const byte SSH_FXP_REMOVE = 13;
    public const byte SSH_FXP_MKDIR = 14;
    public const byte SSH_FXP_RMDIR = 15;
    public const byte SSH_FXP_REALPATH = 16;
    public const byte SSH_FXP_STAT = 17;
    public const byte SSH_FXP_RENAME = 18;
    public const byte SSH_FXP_READLINK = 19;
    public const byte SSH_FXP_SYMLINK = 20;
    public const byte SSH_FXP_EXTENDED = 200;

    public const byte SSH_FXP_STATUS = 101;
    public const byte SSH_FXP_HANDLE = 102;
    public const byte SSH_FXP_DATA = 103;
    public const byte SSH_FXP_NAME = 104;
    public const byte SSH_FXP_ATTRS = 105;

    public const uint SSH_FX_OK = 0;
    public const uint SSH_FX_EOF = 1;
    public const uint SSH_FX_NO_SUCH_FILE = 2;
    public const uint SSH_FX_PERMISSION_DENIED = 3;
    public const uint SSH_FX_FAILURE = 4;
    public const uint SSH_FX_BAD_MESSAGE = 5;
    public const uint SSH_FX_OP_UNSUPPORTED = 8;

    private uint _nextId = 100;

    public SftpEngineClient(IFileSystem fileSystem)
    {
        Service = new SftpService(new SftpFileSystemAdapter(fileSystem, NullLogger.Instance, "test_person"));
        Service.DataReceived += (_, packet) => Responses.Add(packet);
    }

    public SftpService Service { get; }

    /// <summary>Every packet that the engine sent, with its uint32 length.</summary>
    public List<byte[]> Responses { get; } = [];

    public void Dispose() => Service.Dispose();

    // ---- requests ----

    public static byte[] Frame(Action<SshDataWriter> writePayload)
    {
        using var payload = new SshDataWriter();
        writePayload(payload);
        var bytes = payload.ToByteArray();

        var frame = new byte[4 + bytes.Length];
        frame[0] = (byte)(bytes.Length >> 24);
        frame[1] = (byte)(bytes.Length >> 16);
        frame[2] = (byte)(bytes.Length >> 8);
        frame[3] = (byte)bytes.Length;
        bytes.CopyTo(frame, 4);
        return frame;
    }

    public static byte[] Init(uint version = 3) => Frame(w =>
    {
        w.Write(SSH_FXP_INIT);
        w.Write(version);
    });

    public static byte[] Request(byte type, uint requestId, Action<SshDataWriter>? writeFields = null) => Frame(w =>
    {
        w.Write(type);
        w.Write(requestId);
        writeFields?.Invoke(w);
    });

    public static byte[] PathRequest(byte type, uint requestId, string path)
        => Request(type, requestId, w => w.Write(path, Encoding.UTF8));

    /// <summary>Sends one request and returns the one response to it.</summary>
    public Response Send(byte[] request)
    {
        var before = Responses.Count;
        Service.OnData(request);
        Assert.Equal(before + 1, Responses.Count);
        return Response.Parse(Responses[^1]);
    }

    public Response Send(byte type, Action<SshDataWriter>? writeFields = null)
    {
        var id = _nextId++;
        var response = Send(Request(type, id, writeFields));
        Assert.Equal(id, response.Id);
        return response;
    }

    public Response SendPath(byte type, string path) => Send(type, w => w.Write(path, Encoding.UTF8));

    public uint Status(byte type, string path) => SendPath(type, path).StatusCode;

    public Response Open(string path, SftpOpenFlags flags, SftpFileAttributes? attributes = null) => Send(SSH_FXP_OPEN, w =>
    {
        w.Write(path, Encoding.UTF8);
        w.Write((uint)flags);
        (attributes ?? new SftpFileAttributes()).Write(w);
    });

    public string OpenHandle(string path, SftpOpenFlags flags)
    {
        var response = Open(path, flags);
        Assert.True(SSH_FXP_HANDLE == response.Type, $"OPEN {path} gave {response}");
        return response.Payload.ReadString(Encoding.ASCII);
    }

    public string OpenDirHandle(string path)
    {
        var response = SendPath(SSH_FXP_OPENDIR, path);
        Assert.True(SSH_FXP_HANDLE == response.Type, $"OPENDIR {path} gave {response}");
        return response.Payload.ReadString(Encoding.ASCII);
    }

    public uint Write(string handle, ulong offset, byte[] data) => Send(SSH_FXP_WRITE, w =>
    {
        w.Write(handle, Encoding.ASCII);
        w.Write(offset);
        w.WriteBinary((ReadOnlySpan<byte>)data);
    }).StatusCode;

    public Response Read(string handle, ulong offset, uint length) => Send(SSH_FXP_READ, w =>
    {
        w.Write(handle, Encoding.ASCII);
        w.Write(offset);
        w.Write(length);
    });

    public uint Close(string handle) => Send(SSH_FXP_CLOSE, w => w.Write(handle, Encoding.ASCII)).StatusCode;

    public SftpFileAttributes Stat(string path)
    {
        var response = SendPath(SSH_FXP_STAT, path);
        Assert.True(SSH_FXP_ATTRS == response.Type, $"STAT {path} gave {response}");
        return SftpFileAttributes.Read(response.Payload);
    }

    public uint SetStat(string path, SftpFileAttributes attributes) => Send(SSH_FXP_SETSTAT, w =>
    {
        w.Write(path, Encoding.UTF8);
        attributes.Write(w);
    }).StatusCode;

    public uint MakeDirectory(string path, SftpFileAttributes? attributes = null) => Send(SSH_FXP_MKDIR, w =>
    {
        w.Write(path, Encoding.UTF8);
        (attributes ?? new SftpFileAttributes()).Write(w);
    }).StatusCode;

    public uint Rename(string oldPath, string newPath) => Send(SSH_FXP_RENAME, w =>
    {
        w.Write(oldPath, Encoding.UTF8);
        w.Write(newPath, Encoding.UTF8);
    }).StatusCode;

    public string RealPath(string path) => Assert.Single(SendPath(SSH_FXP_REALPATH, path).Names()).Name;

    /// <summary>All entries of a directory: READDIR until EOF.</summary>
    public List<(string Name, SftpFileAttributes Attributes)> ReadDirectory(string path)
    {
        var handle = OpenDirHandle(path);
        var entries = new List<(string, SftpFileAttributes)>();
        while (true)
        {
            var response = Send(SSH_FXP_READDIR, w => w.Write(handle, Encoding.ASCII));
            if (response.Type == SSH_FXP_STATUS)
            {
                Assert.Equal(SSH_FX_EOF, response.StatusCode);
                break;
            }
            entries.AddRange(response.Names().Select(n => (n.Name, n.Attributes)));
        }
        Assert.Equal(SSH_FX_OK, Close(handle));
        return entries;
    }

    /// <summary>One parsed response packet. <see cref="Payload"/> is positioned after the request id.</summary>
    internal sealed class Response
    {
        private readonly byte[] _payload;

        private Response(byte type, uint id, byte[] payload, SshDataReader reader)
        {
            Type = type;
            Id = id;
            _payload = payload;
            Payload = reader;
        }

        public byte Type { get; }
        public uint Id { get; }
        public SshDataReader Payload { get; }

        public static Response Parse(byte[] packet)
        {
            var reader = new SshDataReader(packet);
            var length = reader.ReadUInt32();
            Assert.Equal((uint)(packet.Length - 4), length);
            var payload = reader.ReadBytes((int)length);

            var response = new SshDataReader(payload);
            var type = response.ReadByte();
            var id = type == SSH_FXP_VERSION ? 0u : response.ReadUInt32();
            return new Response(type, id, payload, response);
        }

        /// <summary>The status code of an SSH_FXP_STATUS response. Fails for another response type.</summary>
        public uint StatusCode
        {
            get
            {
                Assert.True(SSH_FXP_STATUS == Type, $"Expected STATUS, got {this}");
                return Fresh().ReadUInt32();
            }
        }

        /// <summary>The error message of an SSH_FXP_STATUS response.</summary>
        public string StatusMessage
        {
            get
            {
                Assert.Equal(SSH_FXP_STATUS, Type);
                var reader = Fresh();
                reader.ReadUInt32();
                return reader.ReadString(Encoding.UTF8);
            }
        }

        public List<(string Name, string LongName, SftpFileAttributes Attributes)> Names()
        {
            Assert.True(SSH_FXP_NAME == Type, $"Expected NAME, got {this}");
            var reader = Fresh();
            var count = reader.ReadUInt32();
            var names = new List<(string, string, SftpFileAttributes)>();
            for (var i = 0; i < count; i++)
                names.Add((reader.ReadString(Encoding.UTF8), reader.ReadString(Encoding.UTF8), SftpFileAttributes.Read(reader)));
            return names;
        }

        private SshDataReader Fresh()
        {
            var reader = new SshDataReader(_payload);
            reader.ReadByte();
            if (Type != SSH_FXP_VERSION)
                reader.ReadUInt32();
            return reader;
        }

        public override string ToString()
            => Type == SSH_FXP_STATUS ? $"STATUS {Fresh().ReadUInt32()} \"{StatusMessage}\"" : $"type {Type}";
    }
}
