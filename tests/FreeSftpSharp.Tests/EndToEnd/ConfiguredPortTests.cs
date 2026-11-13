using System.Net.Sockets;
using FxSsh.SshServerModule;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>The stored port is 1 (nobody listens there); the configured port is the free test port.</summary>
public sealed class ConfiguredPortFixture : SftpServerFixture
{
    protected override void ConfigureSettings(ServerSettings settings)
    {
        settings.ListenToPort = 1;
    }

    protected override SshServerOptions? CreateListenOptions(int port) =>
        new() { Port = port.ToString(), BindToAddress = new List<string> { "127.0.0.1" } };
}

/// <summary>The configuration overrides the port in the settings; the settings are not changed.</summary>
public sealed class ConfiguredPortTests : IClassFixture<ConfiguredPortFixture>
{
    private readonly ConfiguredPortFixture _server;

    public ConfiguredPortTests(ConfiguredPortFixture server)
    {
        _server = server;
    }

    [Fact]
    public void The_server_listens_on_the_configured_port_and_SSH_NET_connects()
    {
        Assert.NotEqual(1, _server.Port);
        using var client = _server.Connect();
        Assert.True(client.IsConnected);
        Assert.Equal(_server.Port, client.ConnectionInfo.Port);
    }

    [Fact]
    public void The_stored_port_is_not_changed_by_the_override()
    {
        Assert.Equal(1, _server.Repository.ServerSettings.ListenToPort);
    }

    [Fact]
    public async Task Nothing_listens_on_the_stored_port()
    {
        using var tcp = new TcpClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAnyAsync<Exception>(() => tcp.ConnectAsync("127.0.0.1", 1, cts.Token).AsTask());
    }
}
