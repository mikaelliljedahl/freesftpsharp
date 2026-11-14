using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using Renci.SshNet;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// <see cref="ServerInfo"/> gives the admin UI the host key fingerprints and the algorithms. The fingerprints must be
/// the ones that a client sees, so they are compared with what SSH.NET receives from the running server.
/// </summary>
public sealed class ServerInfoTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public ServerInfoTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Theory]
    [InlineData("ecdsa-sha2-nistp256")]
    [InlineData("rsa-sha2-512")]
    [InlineData("rsa-sha2-256")]
    public void Host_key_fingerprint_is_the_one_the_client_receives(string algorithm)
    {
        string? received = null;
        using var client = _server.CreateClient();
        foreach (var other in client.ConnectionInfo.HostKeyAlgorithms.Keys.Where(k => k != algorithm).ToList())
            client.ConnectionInfo.HostKeyAlgorithms.Remove(other);
        client.HostKeyReceived += (_, e) => received = "SHA256:" + e.FingerPrintSHA256;

        client.Connect();

        var fingerprints = ServerInfo.GetHostKeyFingerprints(_server.Repository.ServerSettings);
        var expected = fingerprints.Single(f => f.Algorithms.Contains(algorithm));
        Assert.Null(expected.Error);
        Assert.Equal(received, expected.Fingerprint);
    }

    [Fact]
    public void Missing_host_keys_are_reported_without_an_exception()
    {
        var fingerprints = ServerInfo.GetHostKeyFingerprints(new SshServer.Interfaces.ServerSettings { ServerRsaKey = "not a key" });

        Assert.Contains(fingerprints, f => f.KeyType == "RSA" && f.Error != null && f.Fingerprint == null);
        Assert.Contains(fingerprints, f => f.KeyType == "ECDSA" && f.Error != null && f.Fingerprint == null);
    }

    [Fact]
    public void Algorithms_are_the_ones_the_server_offers()
    {
        var algorithms = ServerInfo.GetAlgorithms();

        Assert.Equal(new[] { "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512" }, algorithms.HostKey.Order(StringComparer.Ordinal));
        Assert.Contains("curve25519-sha256", algorithms.KeyExchange);
        Assert.Contains("aes256-gcm@openssh.com", algorithms.Encryption);
        Assert.Contains("hmac-sha2-256-etm@openssh.com", algorithms.Mac);
        Assert.DoesNotContain(algorithms.KeyExchange, k => k.EndsWith("sha1", StringComparison.Ordinal));
        Assert.DoesNotContain("ssh-rsa", algorithms.HostKey);
        Assert.NotEmpty(algorithms.Compression);
    }
}
