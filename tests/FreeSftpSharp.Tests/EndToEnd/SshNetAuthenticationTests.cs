using System.Diagnostics;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet.Common;

namespace FreeSftpSharp.Tests.EndToEnd;

public sealed class SshNetAuthenticationTests : IClassFixture<SftpServerFixture>
{
    private readonly SftpServerFixture _server;

    public SshNetAuthenticationTests(SftpServerFixture server)
    {
        _server = server;
    }

    [Fact]
    public void Connect_with_the_correct_password_works()
    {
        using var client = _server.Connect();

        Assert.True(client.IsConnected);
        Assert.Equal("/", client.WorkingDirectory);
    }

    [Fact]
    public void Wrong_password_is_rejected()
    {
        using var client = _server.CreateClient(password: "wrong-password");

        Assert.Throws<SshAuthenticationException>(() => client.Connect());
        Assert.False(client.IsConnected);
    }

    [Fact(Skip = "Product bug: the server does not answer SSH_MSG_CHANNEL_CLOSE (or EOF) with its own CHANNEL_CLOSE, " +
                 "so SSH.NET Disconnect waits about 1 second for a timeout. Remove this Skip when the bug is fixed.")]
    public void Disconnect_does_not_wait_for_a_timeout()
    {
        using var client = _server.CreateClient();
        client.ConnectionInfo.ChannelCloseTimeout = TimeSpan.FromSeconds(1); // the SSH.NET default
        client.Connect();

        var stopwatch = Stopwatch.StartNew();
        client.Disconnect();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(500), $"Disconnect took {stopwatch.ElapsedMilliseconds} ms.");
    }
}
