using System.Net.Sockets;
using System.Text;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The algorithms that the server offers (its SSH_MSG_KEXINIT) and negotiates with SSH.NET.
/// Weak algorithms (ssh-rsa SHA-1 signatures, diffie-hellman-group1-sha1, *-sha1 kex, hmac-md5, hmac-sha1,
/// CBC ciphers) must not be offered.
/// </summary>
public sealed class AlgorithmNegotiationTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public AlgorithmNegotiationTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public async Task Server_offers_only_the_sha2_rsa_and_ecdsa_host_key_algorithms()
    {
        var kexInit = await ReadServerKexInitAsync();

        Assert.Equal(
            new[] { "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512" },
            kexInit.HostKeyAlgorithms.Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task Server_does_not_offer_weak_algorithms()
    {
        var kexInit = await ReadServerKexInitAsync();

        Assert.DoesNotContain("ssh-rsa", kexInit.HostKeyAlgorithms);
        Assert.DoesNotContain("ssh-dss", kexInit.HostKeyAlgorithms);
        Assert.DoesNotContain(kexInit.KexAlgorithms, a => a.EndsWith("-sha1", StringComparison.Ordinal));
        Assert.DoesNotContain("diffie-hellman-group1-sha1", kexInit.KexAlgorithms);
        foreach (var ciphers in new[] { kexInit.CiphersClientToServer, kexInit.CiphersServerToClient })
        {
            Assert.DoesNotContain(ciphers, c => c.Contains("-cbc", StringComparison.Ordinal) || c.StartsWith("3des", StringComparison.Ordinal));
            Assert.DoesNotContain("arcfour", ciphers);
            Assert.DoesNotContain("none", ciphers);
        }
        foreach (var macs in new[] { kexInit.MacsClientToServer, kexInit.MacsServerToClient })
        {
            Assert.DoesNotContain(macs, m => m.Contains("md5", StringComparison.Ordinal));
            Assert.DoesNotContain(macs, m => m.StartsWith("hmac-sha1", StringComparison.Ordinal));
            Assert.DoesNotContain("none", macs);
        }
    }

    [Fact]
    public async Task Server_offers_modern_kex_ciphers_and_macs()
    {
        var kexInit = await ReadServerKexInitAsync();

        Assert.Contains("curve25519-sha256", kexInit.KexAlgorithms);
        Assert.Contains("diffie-hellman-group14-sha256", kexInit.KexAlgorithms);
        Assert.Contains("aes256-gcm@openssh.com", kexInit.CiphersServerToClient);
        Assert.Contains("aes256-ctr", kexInit.CiphersServerToClient);
        Assert.Contains("hmac-sha2-256-etm@openssh.com", kexInit.MacsServerToClient);
        Assert.Contains("hmac-sha2-256", kexInit.MacsServerToClient);
    }

    [Fact]
    public void SshNet_negotiates_a_sha2_rsa_or_ecdsa_host_key()
    {
        using var client = _server.Connect();

        var hostKey = client.ConnectionInfo.CurrentHostKeyAlgorithm;
        Assert.True(hostKey is "rsa-sha2-512" or "rsa-sha2-256" or "ecdsa-sha2-nistp256", $"Negotiated host key: {hostKey}");
    }

    [Theory]
    [InlineData("rsa-sha2-512")]
    [InlineData("rsa-sha2-256")]
    [InlineData("ecdsa-sha2-nistp256")]
    public void SshNet_connects_with_each_host_key_algorithm(string algorithm)
    {
        using var client = _server.CreateClient();
        KeepOnly(client.ConnectionInfo.HostKeyAlgorithms, algorithm);

        client.Connect();

        Assert.Equal(algorithm, client.ConnectionInfo.CurrentHostKeyAlgorithm);
        Assert.NotNull(client.ListDirectory("/"));
    }

    [Fact]
    public void SshNet_cannot_connect_with_only_ssh_rsa_sha1_signatures()
    {
        using var client = _server.CreateClient();
        KeepOnly(client.ConnectionInfo.HostKeyAlgorithms, "ssh-rsa");

        Assert.Throws<SshConnectionException>(() => client.Connect());
    }

    [Fact]
    public void SshNet_cannot_connect_with_only_diffie_hellman_group1_sha1()
    {
        using var client = _server.CreateClient();
        KeepOnly(client.ConnectionInfo.KeyExchangeAlgorithms, "diffie-hellman-group1-sha1");

        Assert.Throws<SshConnectionException>(() => client.Connect());
    }

    private static void KeepOnly<TValue>(IDictionary<string, TValue> algorithms, string name)
    {
        Assert.True(algorithms.ContainsKey(name), $"SSH.NET does not know {name}.");
        foreach (var key in algorithms.Keys.Where(k => k != name).ToList())
            algorithms.Remove(key);
    }

    private sealed record KexInit(
        string[] KexAlgorithms,
        string[] HostKeyAlgorithms,
        string[] CiphersClientToServer,
        string[] CiphersServerToClient,
        string[] MacsClientToServer,
        string[] MacsServerToClient);

    /// <summary>Does the version exchange and reads the server's SSH_MSG_KEXINIT (RFC 4253 section 7.1).</summary>
    private async Task<KexInit> ReadServerKexInitAsync()
    {
        using var tcp = new TcpClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await tcp.ConnectAsync(SftpServerFixture.Host, _server.Port, cts.Token);
        var stream = tcp.GetStream();
        await stream.WriteAsync("SSH-2.0-FreeSftpSharpKexProbe\r\n"u8.ToArray(), cts.Token);

        // The server may send other lines before its identification line (RFC 4253 section 4.2).
        string line;
        do
        {
            line = await ReadLineAsync(stream, cts.Token);
        } while (!line.StartsWith("SSH-", StringComparison.Ordinal));
        Assert.StartsWith("SSH-2.0-", line);

        var header = new byte[5];
        await stream.ReadExactlyAsync(header, cts.Token);
        var packetLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        var paddingLength = header[4];
        Assert.InRange(packetLength, 16, 35000);
        var rest = new byte[packetLength - 1];
        await stream.ReadExactlyAsync(rest, cts.Token);
        var payload = rest.AsSpan(0, rest.Length - paddingLength).ToArray();

        Assert.Equal(20, payload[0]); // SSH_MSG_KEXINIT
        var offset = 1 + 16; // message type, cookie
        var lists = new string[10][];
        for (var i = 0; i < lists.Length; i++)
        {
            var length = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
            offset += 4;
            var text = Encoding.ASCII.GetString(payload, offset, length);
            offset += length;
            lists[i] = text.Length == 0 ? Array.Empty<string>() : text.Split(',');
        }

        return new KexInit(lists[0], lists[1], lists[2], lists[3], lists[4], lists[5]);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            await stream.ReadExactlyAsync(one, cancellationToken);
            if (one[0] == '\n')
                return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r');
            bytes.Add(one[0]);
            Assert.True(bytes.Count < 1024, "The server sent a line longer than 1024 bytes before its KEXINIT.");
        }
    }
}
